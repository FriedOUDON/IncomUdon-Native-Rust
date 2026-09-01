//! Versioned IncomUdon packet framing.
//!
//! The normative source is IncomUdon-Spec `v0.1.0-draft`.

use std::convert::TryFrom;

use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 1;
pub const LEGACY_HEADER_LEN: u16 = 14;
pub const FIXED_HEADER_LEN: u16 = 16;
pub const SECURITY_HEADER_LEN: usize = 12;
pub const AUTH_TAG_LEN: usize = 16;
pub const FLAG_AES_GCM_V2: u16 = 0x0001;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("packet is too short")]
    PacketTooShort,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported packet type {0:#04x}")]
    UnsupportedPacketType(u8),
    #[error("unsupported header length {0}")]
    UnsupportedHeaderLength(u16),
    #[error("packet length is inconsistent with its header")]
    InvalidPacketLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Audio = 0x01,
    PttOn = 0x02,
    PttOff = 0x03,
    Keepalive = 0x04,
    Join = 0x05,
    Leave = 0x06,
    Grant = 0x07,
    Release = 0x08,
    Deny = 0x09,
    KeyExchange = 0x0a,
    CodecConfig = 0x0b,
    Fec = 0x0c,
    ServerConfig = 0x0d,
    Ping = 0x0e,
    Pong = 0x0f,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Audio),
            0x02 => Ok(Self::PttOn),
            0x03 => Ok(Self::PttOff),
            0x04 => Ok(Self::Keepalive),
            0x05 => Ok(Self::Join),
            0x06 => Ok(Self::Leave),
            0x07 => Ok(Self::Grant),
            0x08 => Ok(Self::Release),
            0x09 => Ok(Self::Deny),
            0x0a => Ok(Self::KeyExchange),
            0x0b => Ok(Self::CodecConfig),
            0x0c => Ok(Self::Fec),
            0x0d => Ok(Self::ServerConfig),
            0x0e => Ok(Self::Ping),
            0x0f => Ok(Self::Pong),
            other => Err(ProtocolError::UnsupportedPacketType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub header_len: u16,
    pub channel_id: u32,
    pub sender_id: u32,
    pub sequence: u16,
    pub flags: u16,
}

impl PacketHeader {
    pub fn new(packet_type: PacketType, channel_id: u32, sender_id: u32, sequence: u16) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type,
            header_len: FIXED_HEADER_LEN,
            channel_id,
            sender_id,
            sequence,
            flags: 0,
        }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header_len as usize);
        bytes.push(self.version);
        bytes.push(self.packet_type as u8);
        bytes.extend_from_slice(&self.header_len.to_be_bytes());
        bytes.extend_from_slice(&self.channel_id.to_be_bytes());
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        if self.header_len != LEGACY_HEADER_LEN {
            bytes.extend_from_slice(&self.flags.to_be_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < LEGACY_HEADER_LEN as usize {
            return Err(ProtocolError::PacketTooShort);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[0]));
        }
        let header_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        if header_len != LEGACY_HEADER_LEN && header_len < FIXED_HEADER_LEN {
            return Err(ProtocolError::UnsupportedHeaderLength(header_len));
        }
        if bytes.len() < header_len as usize {
            return Err(ProtocolError::InvalidPacketLength);
        }
        let flags = if header_len == LEGACY_HEADER_LEN {
            0
        } else {
            u16::from_be_bytes([bytes[14], bytes[15]])
        };
        Ok(Self {
            version: bytes[0],
            packet_type: PacketType::try_from(bytes[1])?,
            header_len,
            channel_id: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            sender_id: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            sequence: u16::from_be_bytes([bytes[12], bytes[13]]),
            flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityHeader {
    pub nonce: u64,
    pub key_id: u32,
}

impl SecurityHeader {
    pub fn encode(self) -> [u8; SECURITY_HEADER_LEN] {
        let mut bytes = [0; SECURITY_HEADER_LEN];
        bytes[..8].copy_from_slice(&self.nonce.to_be_bytes());
        bytes[8..].copy_from_slice(&self.key_id.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < SECURITY_HEADER_LEN {
            return Err(ProtocolError::PacketTooShort);
        }
        Ok(Self {
            nonce: u64::from_be_bytes(bytes[..8].try_into().expect("slice length checked")),
            key_id: u32::from_be_bytes(bytes[8..12].try_into().expect("slice length checked")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Plain {
        header: PacketHeader,
        payload: Vec<u8>,
    },
    Secured {
        header: PacketHeader,
        security: SecurityHeader,
        payload: Vec<u8>,
        auth_tag: [u8; AUTH_TAG_LEN],
    },
}

impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Plain { header, payload } => {
                if header.header_len != LEGACY_HEADER_LEN && header.header_len != FIXED_HEADER_LEN {
                    return Err(ProtocolError::UnsupportedHeaderLength(header.header_len));
                }
                let mut bytes = header.encode();
                bytes.extend_from_slice(payload);
                Ok(bytes)
            }
            Self::Secured {
                header,
                security,
                payload,
                auth_tag,
            } => {
                if header.header_len != (FIXED_HEADER_LEN as usize + SECURITY_HEADER_LEN) as u16 {
                    return Err(ProtocolError::UnsupportedHeaderLength(header.header_len));
                }
                let mut bytes = header.encode();
                bytes.extend_from_slice(&security.encode());
                bytes.extend_from_slice(payload);
                bytes.extend_from_slice(auth_tag);
                Ok(bytes)
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let header = PacketHeader::decode(bytes)?;
        let payload_start = header.header_len as usize;
        if header.header_len < (FIXED_HEADER_LEN as usize + SECURITY_HEADER_LEN) as u16 {
            return Ok(Self::Plain {
                header,
                payload: bytes[payload_start..].to_vec(),
            });
        }
        if bytes.len() < payload_start + AUTH_TAG_LEN {
            return Err(ProtocolError::InvalidPacketLength);
        }
        let security = SecurityHeader::decode(&bytes[FIXED_HEADER_LEN as usize..payload_start])?;
        let tag_start = bytes.len() - AUTH_TAG_LEN;
        let mut auth_tag = [0; AUTH_TAG_LEN];
        auth_tag.copy_from_slice(&bytes[tag_start..]);
        Ok(Self::Secured {
            header,
            security,
            payload: bytes[payload_start..tag_start].to_vec(),
            auth_tag,
        })
    }

    pub fn aad(&self) -> Option<Vec<u8>> {
        match self {
            Self::Secured {
                header, security, ..
            } if header.flags & FLAG_AES_GCM_V2 != 0 => {
                let mut aad = header.encode();
                aad.extend_from_slice(&security.encode());
                Some(aad)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_v2_header_matches_spec_vector() {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Audio,
            header_len: 28,
            channel_id: 1234,
            sender_id: 5678,
            sequence: 42,
            flags: FLAG_AES_GCM_V2,
        };
        let packet = Packet::Secured {
            header,
            security: SecurityHeader {
                nonce: 0x0102_0304_0506_0708,
                key_id: 2,
            },
            payload: vec![],
            auth_tag: [0; AUTH_TAG_LEN],
        };
        assert_eq!(
            packet.aad().unwrap(),
            vec![
                0x01, 0x01, 0x00, 0x1c, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x2a,
                0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x02,
            ]
        );
    }
}
