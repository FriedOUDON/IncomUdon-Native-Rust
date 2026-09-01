//! Platform-neutral application state and persisted profile data.

use incomudon_protocol::PacketType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROFILE_STORE_VERSION: u32 = 1;
const MAX_PROFILE_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Codec {
    Opus,
    Codec2,
    Pcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    AesGcmV2,
    AesGcmV1,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    pub host: String,
    pub port: u16,
    pub force_ipv4: bool,
}

impl Default for RelayEndpoint {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 50_000,
            force_ipv4: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStore {
    pub version: u32,
    pub active_profile: usize,
    #[serde(default)]
    pub relay: RelayEndpoint,
    pub profiles: Vec<TransceiverProfile>,
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self {
            version: PROFILE_STORE_VERSION,
            active_profile: 0,
            relay: RelayEndpoint::default(),
            profiles: vec![TransceiverProfile::default()],
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("unsupported profile store version {0}")]
    UnsupportedStoreVersion(u32),
    #[error("at least one profile is required")]
    MissingProfiles,
    #[error("active profile index {active} is outside {len} profiles")]
    InvalidActiveProfile { active: usize, len: usize },
    #[error("profile name must be between 1 and {MAX_PROFILE_NAME_LEN} characters")]
    InvalidName,
    #[error("profile name '{0}' is duplicated")]
    DuplicateName(String),
    #[error("codec {codec:?} requires a non-zero bitrate")]
    MissingBitrate { codec: Codec },
    #[error("PCM profiles must not define a bitrate")]
    PcmBitrateSet,
    #[error("relay host must not be empty")]
    EmptyRelayHost,
    #[error("relay port must be between 1 and 65535")]
    InvalidRelayPort,
}

impl ProfileStore {
    pub fn active(&self) -> &TransceiverProfile {
        &self.profiles[self.active_profile]
    }

    pub fn replace_relay(&mut self, relay: RelayEndpoint) -> Result<(), ProfileError> {
        validate_relay_endpoint(&relay)?;
        self.relay = relay;
        self.validate()
    }

    pub fn replace_active(&mut self, profile: TransceiverProfile) -> Result<(), ProfileError> {
        validate_profile(&profile)?;
        self.profiles[self.active_profile] = profile;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.version != PROFILE_STORE_VERSION {
            return Err(ProfileError::UnsupportedStoreVersion(self.version));
        }
        validate_relay_endpoint(&self.relay)?;
        if self.profiles.is_empty() {
            return Err(ProfileError::MissingProfiles);
        }
        if self.active_profile >= self.profiles.len() {
            return Err(ProfileError::InvalidActiveProfile {
                active: self.active_profile,
                len: self.profiles.len(),
            });
        }
        for (index, profile) in self.profiles.iter().enumerate() {
            validate_profile(profile)?;
            if self.profiles[..index]
                .iter()
                .any(|previous| previous.name.eq_ignore_ascii_case(&profile.name))
            {
                return Err(ProfileError::DuplicateName(profile.name.clone()));
            }
        }
        Ok(())
    }
}

pub fn validate_relay_endpoint(endpoint: &RelayEndpoint) -> Result<(), ProfileError> {
    if endpoint.host.trim().is_empty() {
        return Err(ProfileError::EmptyRelayHost);
    }
    if endpoint.port == 0 {
        return Err(ProfileError::InvalidRelayPort);
    }
    Ok(())
}

pub fn validate_profile(profile: &TransceiverProfile) -> Result<(), ProfileError> {
    let name = profile.name.trim();
    if name.is_empty() || name.chars().count() > MAX_PROFILE_NAME_LEN {
        return Err(ProfileError::InvalidName);
    }
    match (profile.codec, profile.bitrate_bps) {
        (Codec::Pcm, Some(_)) => Err(ProfileError::PcmBitrateSet),
        (Codec::Pcm, None) => Ok(()),
        (_, Some(value)) if value > 0 => Ok(()),
        (codec, _) => Err(ProfileError::MissingBitrate { codec }),
    }
}

pub fn packet_is_audio(packet_type: PacketType) -> bool {
    matches!(packet_type, PacketType::Audio | PacketType::Fec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_store_is_valid_and_serializable() {
        let store = ProfileStore::default();
        store.validate().unwrap();

        let json = serde_json::to_string_pretty(&store).unwrap();
        let decoded: ProfileStore = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, store);
    }

    #[test]
    fn rejects_duplicate_profile_names_case_insensitively() {
        let mut store = ProfileStore::default();
        let duplicate = TransceiverProfile {
            name: "default".to_owned(),
            ..TransceiverProfile::default()
        };
        store.profiles.push(duplicate);

        assert_eq!(
            store.validate(),
            Err(ProfileError::DuplicateName("default".to_owned()))
        );
    }

    #[test]
    fn rejects_empty_relay_host() {
        let endpoint = RelayEndpoint {
            host: "  ".to_owned(),
            ..RelayEndpoint::default()
        };
        assert_eq!(
            validate_relay_endpoint(&endpoint),
            Err(ProfileError::EmptyRelayHost)
        );
    }

    #[test]
    fn rejects_pcm_bitrate() {
        let profile = TransceiverProfile {
            codec: Codec::Pcm,
            bitrate_bps: Some(8_000),
            ..TransceiverProfile::default()
        };
        assert_eq!(validate_profile(&profile), Err(ProfileError::PcmBitrateSet));
    }
}
