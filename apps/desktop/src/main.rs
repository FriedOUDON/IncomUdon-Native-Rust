slint::include_modules!();

mod profile_storage;

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

use incomudon_core::{
    validate_profile, validate_relay_endpoint, Codec, EncryptionMode, ProfileStore, RelayEndpoint,
    TransceiverProfile,
};
use incomudon_protocol::{Packet, PacketType};
use incomudon_transport::{RelayConfig, RelayEvent, RelaySession};
use slint::{ComponentHandle, SharedString, Timer, TimerMode};

type SharedRelaySession = Arc<Mutex<Option<RelaySession>>>;

fn main() -> Result<(), slint::PlatformError> {
    let (store, load_status) = load_profile_store();
    let store = Arc::new(Mutex::new(store));
    let session: SharedRelaySession = Arc::new(Mutex::new(None));
    let window = AppWindow::new()?;

    {
        let store = store.lock().expect("profile store lock poisoned");
        apply_profile_to_window(&window, store.active());
        apply_relay_to_window(&window, &store.relay);
    }
    window.set_connection_status(SharedString::from("Disconnected"));
    window.set_active_talker(SharedString::from("No active speaker"));
    window.set_profile_save_status(SharedString::from(load_status));

    let pressed_window = window.as_weak();
    let pressed_session = Arc::clone(&session);
    window.on_ptt_pressed(move || {
        let Some(window) = pressed_window.upgrade() else {
            return;
        };
        if window.get_receive_only() {
            return;
        }
        match send_ptt_control(&pressed_session, PacketType::PttOn) {
            Ok(()) => window.set_connection_status(SharedString::from("Requesting talk")),
            Err(error) => window.set_connection_status(SharedString::from(error)),
        }
    });

    let released_window = window.as_weak();
    let released_session = Arc::clone(&session);
    window.on_ptt_released(move || {
        let Some(window) = released_window.upgrade() else {
            return;
        };
        match send_ptt_control(&released_session, PacketType::PttOff) {
            Ok(()) => window.set_connection_status(SharedString::from("Connected")),
            Err(error) if error == "Connect to the relay first" => {}
            Err(error) => window.set_connection_status(SharedString::from(error)),
        }
    });

    let save_window = window.as_weak();
    let save_store = Arc::clone(&store);
    window.on_save_profile(move || {
        let Some(window) = save_window.upgrade() else {
            return;
        };
        let profile = match profile_from_window(&window) {
            Ok(profile) => profile,
            Err(error) => {
                set_save_status(&window, format!("Not saved: {error}"));
                return;
            }
        };

        let mut store = save_store.lock().expect("profile store lock poisoned");
        if let Err(error) = store.replace_active(profile) {
            set_save_status(&window, format!("Not saved: {error}"));
            return;
        }
        match save_profile_store(&store) {
            Ok(()) => set_save_status(&window, "Profile saved".to_owned()),
            Err(error) => set_save_status(&window, format!("Not saved: {error}")),
        }
    });

    let relay_save_window = window.as_weak();
    let relay_save_store = Arc::clone(&store);
    window.on_save_relay_settings(move || {
        let Some(window) = relay_save_window.upgrade() else {
            return;
        };
        let relay = match relay_from_window(&window) {
            Ok(relay) => relay,
            Err(error) => {
                set_save_status(&window, format!("Not saved: {error}"));
                return;
            }
        };

        let mut store = relay_save_store
            .lock()
            .expect("profile store lock poisoned");
        if let Err(error) = store.replace_relay(relay) {
            set_save_status(&window, format!("Not saved: {error}"));
            return;
        }
        match save_profile_store(&store) {
            Ok(()) => set_save_status(&window, "Relay settings saved".to_owned()),
            Err(error) => set_save_status(&window, format!("Not saved: {error}")),
        }
    });

    let connect_window = window.as_weak();
    let connect_store = Arc::clone(&store);
    let connect_session = Arc::clone(&session);
    window.on_connect_relay(move || {
        let Some(window) = connect_window.upgrade() else {
            return;
        };
        if connect_session
            .lock()
            .expect("relay session lock poisoned")
            .is_some()
        {
            window.set_connection_status(SharedString::from("Already connected"));
            return;
        }

        let relay = match relay_from_window(&window) {
            Ok(relay) => relay,
            Err(error) => {
                window.set_connection_status(SharedString::from(format!("Invalid relay: {error}")));
                return;
            }
        };
        let relay_addr = match resolve_relay(&relay) {
            Ok(address) => address,
            Err(error) => {
                window.set_connection_status(SharedString::from(format!(
                    "Relay unavailable: {error}"
                )));
                return;
            }
        };
        let profile = connect_store
            .lock()
            .expect("profile store lock poisoned")
            .active()
            .clone();
        let config = RelayConfig::new(
            relay_addr,
            profile.channel_id,
            profile.sender_id,
            profile.encryption,
        );
        match RelaySession::connect(config) {
            Ok(relay_session) => {
                *connect_session.lock().expect("relay session lock poisoned") = Some(relay_session);
                window.set_connection_status(SharedString::from("Connecting"));
            }
            Err(error) => {
                window.set_connection_status(SharedString::from(format!(
                    "Connection failed: {error}"
                )));
            }
        }
    });

    let disconnect_window = window.as_weak();
    let disconnect_session = Arc::clone(&session);
    window.on_disconnect_relay(move || {
        let mut session = disconnect_session
            .lock()
            .expect("relay session lock poisoned");
        if let Some(mut relay_session) = session.take() {
            relay_session.disconnect();
        }
        if let Some(window) = disconnect_window.upgrade() {
            window.set_connection_status(SharedString::from("Disconnected"));
            window.set_active_talker(SharedString::from("No active speaker"));
        }
    });

    window.on_profile_value_changed(|| {
        // The save button persists a complete, validated profile in one operation.
    });

    let event_window = window.as_weak();
    let event_session = Arc::clone(&session);
    let event_timer = Timer::default();
    event_timer.start(TimerMode::Repeated, Duration::from_millis(50), move || {
        let Some(window) = event_window.upgrade() else {
            return;
        };
        let mut stopped = false;
        {
            let session = event_session.lock().expect("relay session lock poisoned");
            if let Some(relay_session) = session.as_ref() {
                while let Some(event) = relay_session.try_next_event() {
                    stopped |= apply_relay_event(&window, event);
                }
            }
        }
        if stopped {
            let _ = event_session
                .lock()
                .expect("relay session lock poisoned")
                .take();
        }
    });

    let result = window.run();
    if let Some(mut relay_session) = session.lock().expect("relay session lock poisoned").take() {
        relay_session.disconnect();
    }
    result
}

fn load_profile_store() -> (ProfileStore, String) {
    match profile_storage::default_profile_path() {
        Ok(path) if path.exists() => match profile_storage::load_from_path(&path) {
            Ok(store) => (store, "Profile restored".to_owned()),
            Err(error) => (ProfileStore::default(), format!("Using defaults: {error}")),
        },
        Ok(_) => (
            ProfileStore::default(),
            "Unsaved default profile".to_owned(),
        ),
        Err(error) => (ProfileStore::default(), format!("Using defaults: {error}")),
    }
}

fn save_profile_store(store: &ProfileStore) -> Result<(), profile_storage::ProfileStorageError> {
    let path = profile_storage::default_profile_path()?;
    profile_storage::save_to_path(&path, store)
}

fn apply_profile_to_window(window: &AppWindow, profile: &TransceiverProfile) {
    window.set_profile_name(SharedString::from(profile.name.as_str()));
    window.set_channel_id(SharedString::from(profile.channel_id.to_string()));
    window.set_sender_id(SharedString::from(profile.sender_id.to_string()));
    window.set_receive_only(profile.receive_only);
    window.set_mute_self_id(profile.mute_self_id);
    window.set_codec_index(codec_to_index(profile.codec));
    window.set_bitrate_bps(profile.bitrate_bps.unwrap_or_default() as i32);
}

fn apply_relay_to_window(window: &AppWindow, relay: &RelayEndpoint) {
    window.set_relay_host(SharedString::from(relay.host.as_str()));
    window.set_relay_port(i32::from(relay.port));
    window.set_force_ipv4(relay.force_ipv4);
}

fn profile_from_window(window: &AppWindow) -> Result<TransceiverProfile, String> {
    let channel_id = window
        .get_channel_id()
        .parse::<u32>()
        .map_err(|_| "channel ID must be an unsigned integer")?;
    let sender_id = window
        .get_sender_id()
        .parse::<u32>()
        .map_err(|_| "sender ID must be an unsigned integer")?;
    let codec = codec_from_index(window.get_codec_index())?;
    let bitrate_bps = if codec == Codec::Pcm {
        None
    } else {
        u32::try_from(window.get_bitrate_bps())
            .ok()
            .filter(|value| *value > 0)
    };
    let profile = TransceiverProfile {
        name: window.get_profile_name().trim().to_owned(),
        channel_id,
        sender_id,
        codec,
        bitrate_bps,
        encryption: EncryptionMode::AesGcmV2,
        receive_only: window.get_receive_only(),
        mute_self_id: window.get_mute_self_id(),
    };
    validate_profile(&profile).map_err(|error| error.to_string())?;
    Ok(profile)
}

fn relay_from_window(window: &AppWindow) -> Result<RelayEndpoint, String> {
    let port = u16::try_from(window.get_relay_port()).map_err(|_| "relay port is invalid")?;
    let relay = RelayEndpoint {
        host: window.get_relay_host().trim().to_owned(),
        port,
        force_ipv4: window.get_force_ipv4(),
    };
    validate_relay_endpoint(&relay).map_err(|error| error.to_string())?;
    Ok(relay)
}

fn resolve_relay(relay: &RelayEndpoint) -> Result<SocketAddr, String> {
    let mut addresses: Vec<_> = (relay.host.as_str(), relay.port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .filter(|address| !relay.force_ipv4 || address.is_ipv4())
        .collect();
    addresses.sort_by_key(|address| !address.is_ipv6());
    addresses
        .into_iter()
        .next()
        .ok_or_else(|| "no usable IPv4/IPv6 address was resolved".to_owned())
}
fn send_ptt_control(session: &SharedRelaySession, packet_type: PacketType) -> Result<(), String> {
    let session = session.lock().expect("relay session lock poisoned");
    let Some(relay_session) = session.as_ref() else {
        return Err("Connect to the relay first".to_owned());
    };
    relay_session
        .send_control(packet_type, Vec::new())
        .map_err(|error| format!("PTT send failed: {error}"))
}

fn apply_relay_event(window: &AppWindow, event: RelayEvent) -> bool {
    match event {
        RelayEvent::Connected { local_addr } => {
            window.set_connection_status(SharedString::from(format!("Connected ({local_addr})")));
        }
        RelayEvent::Sent { packet_type } => {
            if packet_type == PacketType::Leave {
                window.set_connection_status(SharedString::from("Disconnecting"));
            }
        }
        RelayEvent::Received { packet } => update_talker_from_packet(window, &packet),
        RelayEvent::ReceiveRejected { error } => {
            window.set_connection_status(SharedString::from(format!(
                "Ignored relay packet: {error}"
            )));
        }
        RelayEvent::IoError { .. } => {
            window.set_connection_status(SharedString::from("Relay network error"));
        }
        RelayEvent::Stopped => {
            window.set_connection_status(SharedString::from("Disconnected"));
            window.set_active_talker(SharedString::from("No active speaker"));
            return true;
        }
    }
    false
}

fn update_talker_from_packet(window: &AppWindow, packet: &Packet) {
    let header = match packet {
        Packet::Plain { header, .. } | Packet::Secured { header, .. } => header,
    };
    match header.packet_type {
        PacketType::Grant => {
            window.set_active_talker(SharedString::from(format!("Sender {}", header.sender_id)));
        }
        PacketType::Release => {
            window.set_active_talker(SharedString::from("No active speaker"));
        }
        PacketType::Deny => {
            window.set_connection_status(SharedString::from("Talk request denied"));
        }
        _ => {}
    }
}

fn set_save_status(window: &AppWindow, status: String) {
    window.set_profile_save_status(SharedString::from(status));
}

fn codec_to_index(codec: Codec) -> i32 {
    match codec {
        Codec::Opus => 0,
        Codec::Codec2 => 1,
        Codec::Pcm => 2,
    }
}

fn codec_from_index(index: i32) -> Result<Codec, String> {
    match index {
        0 => Ok(Codec::Opus),
        1 => Ok(Codec::Codec2),
        2 => Ok(Codec::Pcm),
        _ => Err("unknown codec selection".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_numeric_ipv4_relay() {
        let endpoint = RelayEndpoint {
            host: "127.0.0.1".to_owned(),
            port: 50_000,
            force_ipv4: false,
        };
        assert_eq!(
            resolve_relay(&endpoint).unwrap(),
            "127.0.0.1:50000".parse().unwrap()
        );
    }

    #[test]
    fn rejects_a_zero_relay_port() {
        let endpoint = RelayEndpoint {
            host: "127.0.0.1".to_owned(),
            port: 0,
            force_ipv4: false,
        };
        assert!(validate_relay_endpoint(&endpoint).is_err());
    }
}
