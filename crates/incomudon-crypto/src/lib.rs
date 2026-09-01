//! Password normalization, IncomUdon session-key derivation, and AES-GCM helpers.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const AES_GCM_V2_KEY_ID: u32 = 2;
const V2_INFO: &[u8] = b"incomudon-session-aesgcm-v2";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES-GCM operation failed")]
    Aead,
    #[error("HKDF expansion failed")]
    Hkdf,
}

pub fn normalize_password(password: &str) -> [u8; 32] {
    let trimmed = password.trim();
    if trimmed.is_empty() {
        return [0; 32];
    }
    let hex_value = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if hex_value.len() == 64 {
        let mut decoded = [0_u8; 32];
        if decode_hex_32(hex_value, &mut decoded) {
            return decoded;
        }
    }
    Sha256::digest(password.as_bytes()).into()
}

pub fn derive_password_key(normalized_password: [u8; 32], channel_id: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(normalized_password);
    hasher.update(channel_id.to_be_bytes());
    hasher.finalize().into()
}

pub fn derive_aes_gcm_v2_key(password_key: [u8; 32]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, &password_key);
    let mut key = [0_u8; 32];
    hkdf.expand(V2_INFO, &mut key)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(key)
}

pub fn packet_nonce(packet_nonce: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&packet_nonce.to_be_bytes());
    nonce
}

pub fn encrypt_aes_gcm_v2(
    key: [u8; 32],
    nonce_counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Aead)?;
    cipher
        .encrypt(
            Nonce::from_slice(&packet_nonce(nonce_counter)),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

pub fn decrypt_aes_gcm_v2(
    key: [u8; 32],
    nonce_counter: u64,
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(
            Nonce::from_slice(&packet_nonce(nonce_counter)),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

fn decode_hex_32(value: &str, output: &mut [u8; 32]) -> bool {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || pairs.len() != output.len() {
        return false;
    }
    for (index, pair) in pairs.iter().enumerate() {
        let Some(high) = hex_nibble(pair[0]) else {
            return false;
        };
        let Some(low) = hex_nibble(pair[1]) else {
            return false;
        };
        output[index] = (high << 4) | low;
    }
    true
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_v2_matches_spec_vector() {
        let normalized = normalize_password("test-password");
        assert_eq!(
            normalized,
            [
                0xc6, 0x38, 0x83, 0x3f, 0x69, 0xbb, 0xfb, 0x3c, 0x26, 0x7a, 0xfa, 0x0a, 0x74, 0x43,
                0x48, 0x12, 0x43, 0x6b, 0x8f, 0x08, 0xa8, 0x1f, 0xd2, 0x63, 0xc6, 0xbe, 0x68, 0x71,
                0xde, 0x4f, 0x12, 0x65,
            ]
        );
        let key = derive_aes_gcm_v2_key(derive_password_key(normalized, 1234)).unwrap();
        assert_eq!(
            key,
            [
                0x5a, 0x1a, 0xb7, 0xdb, 0x20, 0xac, 0xb0, 0x06, 0x12, 0xf7, 0xea, 0xbb, 0xc2, 0xe3,
                0x79, 0xe4, 0x77, 0x7b, 0x6b, 0xbb, 0x53, 0xbe, 0x7e, 0x10, 0x6d, 0x5c, 0xa1, 0xa3,
                0xce, 0x20, 0x68, 0x7d,
            ]
        );
        let aad = [
            0x01, 0x01, 0x00, 0x1c, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x2a,
            0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x02,
        ];
        let encrypted = encrypt_aes_gcm_v2(
            key,
            0x0102_0304_0506_0708,
            &[0x00, 0x2a, 0x11, 0x22, 0x33, 0x44],
            &aad,
        )
        .unwrap();
        assert_eq!(
            encrypted,
            vec![
                0x5d, 0x9c, 0xde, 0x40, 0x9e, 0x17, 0xdc, 0xcf, 0x50, 0xe0, 0x15, 0x9c, 0x74, 0xef,
                0x44, 0xa5, 0xe2, 0x1e, 0xdf, 0xff, 0x0f, 0x08,
            ]
        );
    }
}
