//! Platform-neutral application state.

use incomudon_protocol::PacketType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Opus,
    Codec2,
    Pcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    AesGcmV2,
    AesGcmV1,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransceiverProfile {
    pub name: String,
    pub channel_id: u32,
    pub sender_id: u32,
    pub codec: Codec,
    pub bitrate_bps: Option<u32>,
    pub encryption: EncryptionMode,
    pub receive_only: bool,
    pub mute_self_id: bool,
}

impl Default for TransceiverProfile {
    fn default() -> Self {
        Self {
            name: "Default".to_owned(),
            channel_id: 0,
            sender_id: 0,
            codec: Codec::Opus,
            bitrate_bps: Some(16_000),
            encryption: EncryptionMode::AesGcmV2,
            receive_only: false,
            mute_self_id: true,
        }
    }
}

pub fn packet_is_audio(packet_type: PacketType) -> bool {
    matches!(packet_type, PacketType::Audio | PacketType::Fec)
}
