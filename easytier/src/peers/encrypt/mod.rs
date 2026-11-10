use crate::{
    common::{config::EncryptionAlgorithm, log},
    tunnel::packet_def::ZCPacket,
};
use std::sync::Arc;

#[cfg(feature = "wireguard")]
pub mod ring;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "openssl-crypto")]
pub mod openssl;

#[allow(dead_code)]
pub mod xor;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid tag. tag: {0:?}")]
    InvalidTag(Vec<u8>),
}

pub trait Encryptor: Send + Sync + 'static {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
    }
}

pub struct NullCipher;

impl Encryptor for NullCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }
}

/// Refuses every packet. Used instead of a weak or unknown cipher (Jay hardening).
pub struct RejectCipher;

impl Encryptor for RejectCipher {
    fn decrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Err(Error::DecryptionFailed)
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Err(Error::EncryptionFailed)
    }
}

// Jay builds always need a real AEAD cipher.
#[cfg(not(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto")))]
compile_error!("Jay's EasyTier build needs an AEAD cipher: enable the wireguard, aes-gcm or openssl-crypto feature");

/// Create an encryptor based on the algorithm name
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    #[allow(unused_variables)] key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    // Jay hardening: never fall back silently. An unknown or weak algorithm name gets a
    // cipher that refuses every packet, so traffic is dropped instead of being sent with a
    // cipher the operator did not ask for.
    let algorithm = match EncryptionAlgorithm::try_from(algorithm) {
        Ok(algorithm) => algorithm,
        Err(_) => {
            log::error!(
                "Unknown encryption algorithm: {}, refusing to encrypt or decrypt",
                algorithm
            );
            return Arc::new(RejectCipher);
        }
    };

    match algorithm {
        EncryptionAlgorithm::Xor => {
            log::error!("xor is not encryption; this build refuses to use it");
            Arc::new(RejectCipher)
        }

        #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::AesGcm => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_aes128_gcm(key_128)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_aes128_gcm(key_128)),
                feature = "aes-gcm" => Arc::new(aes_gcm::AesGcmCipher::new_128(key_128)),
            }
        }

        #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::Aes256Gcm => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_aes256_gcm(key_256)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_aes256_gcm(key_256)),
                feature = "aes-gcm" => Arc::new(aes_gcm::AesGcmCipher::new_256(key_256)),
            }
        }

        #[cfg(any(feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::ChaCha20 => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_chacha20(key_256)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_chacha20(key_256)),
            }
        }
    }
}

#[cfg(test)]
mod jay_tests {
    use super::*;

    #[test]
    fn unknown_algorithm_refuses_instead_of_falling_back() {
        let cipher = create_encryptor("no-such-cipher", [1; 16], [2; 32]);
        let mut packet = ZCPacket::new_with_payload(b"hello");
        packet.fill_peer_manager_hdr(0, 0, 0);
        assert!(cipher.encrypt(&mut packet).is_err());
        assert!(cipher.decrypt(&mut packet).is_err());
    }

    #[test]
    fn xor_is_refused() {
        let cipher = create_encryptor("xor", [1; 16], [2; 32]);
        let mut packet = ZCPacket::new_with_payload(b"hello");
        packet.fill_peer_manager_hdr(0, 0, 0);
        assert!(cipher.encrypt(&mut packet).is_err());
    }

    #[test]
    fn real_ciphers_still_round_trip() {
        for name in ["aes-gcm", "aes-256-gcm", "chacha20"] {
            let cipher = create_encryptor(name, [1; 16], [2; 32]);
            let mut packet = ZCPacket::new_with_payload(b"hello");
            packet.fill_peer_manager_hdr(0, 0, 0);
            cipher.encrypt(&mut packet).unwrap();
            assert_ne!(packet.payload(), b"hello", "{name} did not encrypt");
            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"hello", "{name} did not round-trip");
        }
    }
}
