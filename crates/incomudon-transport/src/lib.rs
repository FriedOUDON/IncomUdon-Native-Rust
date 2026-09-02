//! Bounded UDP transport for the IncomUdon Relay protocol.
//!
//! A session owns one connected UDP socket and one worker thread. Commands are
//! bounded so a stalled relay cannot make the client retain unbounded stale
//! control or media packets.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use incomudon_core::EncryptionMode;
use incomudon_crypto::{
    decrypt_aes_gcm_v2, derive_aes_gcm_v2_key, derive_password_key, encrypt_aes_gcm_v2,
    normalize_password, AES_GCM_V2_KEY_ID,
};
use incomudon_protocol::{
    Packet, PacketHeader, PacketType, ProtocolError, SecurityHeader, AUTH_TAG_LEN,
    FIXED_HEADER_LEN, SECURITY_HEADER_LEN,
};
use rand::random;
use thiserror::Error;

pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_COMMAND_CAPACITY: usize = 64;
pub const DEFAULT_EVENT_CAPACITY: usize = 128;
const READ_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub relay_addr: SocketAddr,
    pub channel_id: u32,
    pub sender_id: u32,
    pub encryption: EncryptionMode,
    pub password: String,
    pub keepalive_interval: Duration,
}

impl RelayConfig {
    pub fn new(
        relay_addr: SocketAddr,
        channel_id: u32,
        sender_id: u32,
        encryption: EncryptionMode,
    ) -> Self {
        Self {
            relay_addr,
            channel_id,
            sender_id,
            encryption,
            password: String::new(),
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RelayCommand {
    Send(Packet),
    SendPcm(Vec<u8>),
    SendControl {
        packet_type: PacketType,
        payload: Vec<u8>,
    },
    Disconnect,
}

#[derive(Debug)]
pub enum RelayEvent {
    Connected { local_addr: SocketAddr },
    Sent { packet_type: PacketType },
    Received { packet: Packet },
    PcmReceived { sender_id: u32, frame: Vec<u8> },
    ReceiveRejected { error: ProtocolError },
    IoError { message: String },
    Stopped,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("failed to open UDP socket: {0}")]
    OpenSocket(#[source] io::Error),
    #[error("failed to connect UDP socket: {0}")]
    ConnectSocket(#[source] io::Error),
    #[error("failed to read UDP socket address: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("relay transport worker is unavailable")]
    WorkerUnavailable,
}

pub struct RelaySession {
    commands: SyncSender<RelayCommand>,
    events: Receiver<RelayEvent>,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl RelaySession {
    pub fn connect(config: RelayConfig) -> Result<Self, TransportError> {
        let bind_addr = if config.relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).map_err(TransportError::OpenSocket)?;
        socket
            .connect(config.relay_addr)
            .map_err(TransportError::ConnectSocket)?;
        socket
            .set_read_timeout(Some(READ_POLL_INTERVAL))
            .map_err(TransportError::OpenSocket)?;
        let local_addr = socket.local_addr().map_err(TransportError::LocalAddress)?;

        let (command_tx, command_rx) = mpsc::sync_channel(DEFAULT_COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::sync_channel(DEFAULT_EVENT_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::Builder::new()
            .name("incomudon-relay".to_owned())
            .spawn(move || {
                run_worker(
                    socket,
                    config,
                    command_rx,
                    event_tx,
                    worker_running,
                    local_addr,
                )
            })
            .map_err(TransportError::OpenSocket)?;

        Ok(Self {
            commands: command_tx,
            events: event_rx,
            running,
            worker: Some(worker),
        })
    }

    pub fn send(&self, packet: Packet) -> Result<(), TransportError> {
        self.commands
            .try_send(RelayCommand::Send(packet))
            .map_err(|_| TransportError::WorkerUnavailable)
    }

    /// Queues a Relay control packet. The worker assigns its sequence number so
    /// control, keepalive, and future media packets share one ordered stream.
    pub fn send_control(
        &self,
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.commands
            .try_send(RelayCommand::SendControl {
                packet_type,
                payload,
            })
            .map_err(|_| TransportError::WorkerUnavailable)
    }

    pub fn send_pcm_frame(&self, frame: Vec<u8>) -> Result<(), TransportError> {
        self.commands
            .try_send(RelayCommand::SendPcm(frame))
            .map_err(|_| TransportError::WorkerUnavailable)
    }

    pub fn try_next_event(&self) -> Option<RelayEvent> {
        self.events.try_recv().ok()
    }

    pub fn disconnect(&mut self) {
        if !self.running.swap(false, Ordering::AcqRel) {
            return;
        }
        let _ = self.commands.try_send(RelayCommand::Disconnect);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for RelaySession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn run_worker(
    socket: UdpSocket,
    config: RelayConfig,
    commands: Receiver<RelayCommand>,
    events: SyncSender<RelayEvent>,
    running: Arc<AtomicBool>,
    local_addr: SocketAddr,
) {
    let _ = events.try_send(RelayEvent::Connected { local_addr });
    let mut sequence = 0_u16;
    let mut media = MediaState::new(&config);
    send_control(
        &socket,
        &config,
        &mut sequence,
        PacketType::Join,
        Vec::new(),
        &events,
    );
    let mut last_keepalive = Instant::now();
    let mut buffer = [0_u8; 2048];

    while running.load(Ordering::Acquire) {
        match commands.recv_timeout(Duration::from_millis(1)) {
            Ok(RelayCommand::Send(packet)) => send_packet(&socket, packet, &events),
            Ok(RelayCommand::SendPcm(frame)) => {
                send_pcm(&socket, &config, &mut sequence, &mut media, frame, &events)
            }
            Ok(RelayCommand::SendControl {
                packet_type,
                payload,
            }) => send_control(
                &socket,
                &config,
                &mut sequence,
                packet_type,
                payload,
                &events,
            ),
            Ok(RelayCommand::Disconnect) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        loop {
            match commands.try_recv() {
                Ok(RelayCommand::Send(packet)) => send_packet(&socket, packet, &events),
                Ok(RelayCommand::SendPcm(frame)) => {
                    send_pcm(&socket, &config, &mut sequence, &mut media, frame, &events)
                }
                Ok(RelayCommand::SendControl {
                    packet_type,
                    payload,
                }) => send_control(
                    &socket,
                    &config,
                    &mut sequence,
                    packet_type,
                    payload,
                    &events,
                ),
                Ok(RelayCommand::Disconnect) | Err(TryRecvError::Disconnected) => {
                    running.store(false, Ordering::Release);
                    break;
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if !running.load(Ordering::Acquire) {
            break;
        }
        if last_keepalive.elapsed() >= config.keepalive_interval {
            send_control(
                &socket,
                &config,
                &mut sequence,
                PacketType::Keepalive,
                Vec::new(),
                &events,
            );
            last_keepalive = Instant::now();
        }
        match socket.recv(&mut buffer) {
            Ok(length) => match Packet::decode(&buffer[..length]) {
                Ok(packet) => {
                    if let Some((sender_id, frame)) = decode_pcm(&packet, &media.key) {
                        send_event(&events, RelayEvent::PcmReceived { sender_id, frame });
                    } else {
                        send_event(&events, RelayEvent::Received { packet });
                    }
                }
                Err(error) => send_event(&events, RelayEvent::ReceiveRejected { error }),
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => send_event(
                &events,
                RelayEvent::IoError {
                    message: error.to_string(),
                },
            ),
        }
    }

    send_control(
        &socket,
        &config,
        &mut sequence,
        PacketType::Leave,
        Vec::new(),
        &events,
    );
    let _ = events.try_send(RelayEvent::Stopped);
}

fn send_control(
    socket: &UdpSocket,
    config: &RelayConfig,
    sequence: &mut u16,
    packet_type: PacketType,
    payload: Vec<u8>,
    events: &SyncSender<RelayEvent>,
) {
    let header = PacketHeader {
        version: incomudon_protocol::PROTOCOL_VERSION,
        packet_type,
        header_len: if config.encryption == EncryptionMode::None {
            FIXED_HEADER_LEN
        } else {
            (FIXED_HEADER_LEN as usize + SECURITY_HEADER_LEN) as u16
        },
        channel_id: config.channel_id,
        sender_id: config.sender_id,
        sequence: *sequence,
        flags: 0,
    };
    *sequence = sequence.wrapping_add(1);
    let packet = if config.encryption == EncryptionMode::None {
        Packet::Plain { header, payload }
    } else {
        Packet::Secured {
            header,
            security: SecurityHeader {
                nonce: 0,
                key_id: 0,
            },
            payload,
            auth_tag: [0; AUTH_TAG_LEN],
        }
    };
    send_packet(socket, packet, events);
}

fn send_packet(socket: &UdpSocket, packet: Packet, events: &SyncSender<RelayEvent>) {
    let packet_type = match &packet {
        Packet::Plain { header, .. } | Packet::Secured { header, .. } => header.packet_type,
    };
    let bytes = match packet.encode() {
        Ok(bytes) => bytes,
        Err(error) => {
            send_event(
                events,
                RelayEvent::IoError {
                    message: error.to_string(),
                },
            );
            return;
        }
    };
    match socket.send(&bytes) {
        Ok(_) => send_event(events, RelayEvent::Sent { packet_type }),
        Err(error) => send_event(
            events,
            RelayEvent::IoError {
                message: error.to_string(),
            },
        ),
    }
}

fn send_event(events: &SyncSender<RelayEvent>, event: RelayEvent) {
    let _ = events.try_send(event);
}

struct MediaState {
    key: Option<[u8; 32]>,
    audio_sequence: u16,
    nonce: u64,
}

impl MediaState {
    fn new(config: &RelayConfig) -> Self {
        Self {
            key: media_key(config),
            audio_sequence: 0,
            nonce: random(),
        }
    }
}

fn media_key(config: &RelayConfig) -> Option<[u8; 32]> {
    if config.encryption != EncryptionMode::AesGcmV2 {
        return None;
    }
    derive_aes_gcm_v2_key(derive_password_key(
        normalize_password(&config.password),
        config.channel_id,
    ))
    .ok()
}

fn send_pcm(
    socket: &UdpSocket,
    config: &RelayConfig,
    sequence: &mut u16,
    media: &mut MediaState,
    frame: Vec<u8>,
    events: &SyncSender<RelayEvent>,
) {
    if frame.len() != 320 {
        send_event(
            events,
            RelayEvent::IoError {
                message: "invalid PCM frame length".to_owned(),
            },
        );
        return;
    }
    let mut plaintext = Vec::with_capacity(322);
    plaintext.extend_from_slice(&media.audio_sequence.to_be_bytes());
    plaintext.extend_from_slice(&frame);
    media.audio_sequence = media.audio_sequence.wrapping_add(1);
    let header = PacketHeader {
        version: incomudon_protocol::PROTOCOL_VERSION,
        packet_type: PacketType::Audio,
        header_len: if config.encryption == EncryptionMode::None {
            FIXED_HEADER_LEN
        } else {
            28
        },
        channel_id: config.channel_id,
        sender_id: config.sender_id,
        sequence: *sequence,
        flags: if config.encryption == EncryptionMode::AesGcmV2 {
            incomudon_protocol::FLAG_AES_GCM_V2
        } else {
            0
        },
    };
    *sequence = sequence.wrapping_add(1);
    let packet = if config.encryption == EncryptionMode::None {
        Packet::Plain {
            header,
            payload: plaintext,
        }
    } else if let Some(key) = media.key {
        let security = SecurityHeader {
            nonce: media.nonce,
            key_id: AES_GCM_V2_KEY_ID,
        };
        media.nonce = media.nonce.wrapping_add(1);
        let mut aad = header.encode();
        aad.extend_from_slice(&security.encode());
        match encrypt_aes_gcm_v2(key, security.nonce, &plaintext, &aad) {
            Ok(mut encrypted) => {
                let tag_start = encrypted.len() - AUTH_TAG_LEN;
                let tag: [u8; AUTH_TAG_LEN] = encrypted
                    .split_off(tag_start)
                    .try_into()
                    .expect("tag length");
                Packet::Secured {
                    header,
                    security,
                    payload: encrypted,
                    auth_tag: tag,
                }
            }
            Err(_) => {
                send_event(
                    events,
                    RelayEvent::IoError {
                        message: "PCM encryption failed".to_owned(),
                    },
                );
                return;
            }
        }
    } else {
        send_event(
            events,
            RelayEvent::IoError {
                message: "AES-GCM v2 media key is unavailable".to_owned(),
            },
        );
        return;
    };
    send_packet(socket, packet, events);
}

fn decode_pcm(packet: &Packet, key: &Option<[u8; 32]>) -> Option<(u32, Vec<u8>)> {
    let (header, payload) = match packet {
        Packet::Plain { header, payload } if header.packet_type == PacketType::Audio => {
            (header, payload.clone())
        }
        Packet::Secured {
            header,
            security,
            payload,
            auth_tag,
        } if header.packet_type == PacketType::Audio
            && header.flags & incomudon_protocol::FLAG_AES_GCM_V2 != 0 =>
        {
            let key = key.as_ref()?;
            let mut encrypted = payload.clone();
            encrypted.extend_from_slice(auth_tag);
            let plaintext =
                decrypt_aes_gcm_v2(*key, security.nonce, &encrypted, &packet.aad()?).ok()?;
            (header, plaintext)
        }
        _ => return None,
    };
    if payload.len() != 322 {
        return None;
    }
    Some((header.sender_id, payload[2..].to_vec()))
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    fn session_sequences_ptt_controls_with_plain_secure_framing() {
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let config = RelayConfig::new(
            relay.local_addr().unwrap(),
            111,
            1002,
            EncryptionMode::AesGcmV2,
        );
        let mut session = RelaySession::connect(config).unwrap();

        let mut buffer = [0_u8; 128];
        let join_len = relay.recv(&mut buffer).unwrap();
        let join = Packet::decode(&buffer[..join_len]).unwrap();
        assert_control_packet(&join, PacketType::Join, 0);

        session.send_control(PacketType::PttOn, Vec::new()).unwrap();
        let ptt_on_len = relay.recv(&mut buffer).unwrap();
        let ptt_on = Packet::decode(&buffer[..ptt_on_len]).unwrap();
        assert_control_packet(&ptt_on, PacketType::PttOn, 1);

        session
            .send_control(PacketType::PttOff, Vec::new())
            .unwrap();
        let ptt_off_len = relay.recv(&mut buffer).unwrap();
        let ptt_off = Packet::decode(&buffer[..ptt_off_len]).unwrap();
        assert_control_packet(&ptt_off, PacketType::PttOff, 2);

        session.disconnect();
        let leave_len = relay.recv(&mut buffer).unwrap();
        let leave = Packet::decode(&buffer[..leave_len]).unwrap();
        assert_control_packet(&leave, PacketType::Leave, 3);
    }

    #[test]
    fn session_encrypts_and_decodes_pcm_media_frames() {
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let config = RelayConfig::new(
            relay.local_addr().unwrap(),
            111,
            1002,
            EncryptionMode::AesGcmV2,
        );
        let key = media_key(&config);
        let mut session = RelaySession::connect(config).unwrap();

        let mut buffer = [0_u8; 1024];
        let join_len = relay.recv(&mut buffer).unwrap();
        assert_control_packet(
            &Packet::decode(&buffer[..join_len]).unwrap(),
            PacketType::Join,
            0,
        );

        let frame = vec![0x5a; 320];
        session.send_pcm_frame(frame.clone()).unwrap();
        let audio_len = relay.recv(&mut buffer).unwrap();
        let audio = Packet::decode(&buffer[..audio_len]).unwrap();
        let (sender_id, decoded) = decode_pcm(&audio, &key).expect("PCM media packet");
        assert_eq!(sender_id, 1002);
        assert_eq!(decoded, frame);

        session.disconnect();
    }

    fn assert_control_packet(packet: &Packet, expected_type: PacketType, expected_sequence: u16) {
        match packet {
            Packet::Secured {
                header,
                security,
                payload,
                auth_tag,
            } => {
                assert_eq!(header.packet_type, expected_type);
                assert_eq!(header.channel_id, 111);
                assert_eq!(header.sender_id, 1002);
                assert_eq!(header.sequence, expected_sequence);
                assert_eq!(header.header_len, 28);
                assert_eq!(
                    *security,
                    SecurityHeader {
                        nonce: 0,
                        key_id: 0
                    }
                );
                assert!(payload.is_empty());
                assert_eq!(*auth_tag, [0; AUTH_TAG_LEN]);
            }
            Packet::Plain { .. } => panic!("expected plain-secure control packet"),
        }
    }
}
