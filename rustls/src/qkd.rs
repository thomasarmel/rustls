use std::prelude::rust_2015::{String, Vec};
use std::prelude::rust_2021::ToOwned;
use ring::aead::UnboundKey;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use crate::crypto::cipher::{BorrowedPlainMessage, make_tls13_aad, MessageDecrypter, MessageEncrypter, Nonce, OpaqueMessage, PlainMessage};
use crate::{ContentType, Error, ProtocolVersion};
use crate::msgs::codec::Codec;

pub(crate) const QKD_KEY_SIZE_BYTES: usize = 32;
pub(crate) const QKD_IV_SIZE_BYTES: usize = 12;

pub(crate) struct QkdEncrypter {
    key: ring::aead::LessSafeKey,
    iv: crate::crypto::cipher::Iv,
}
impl QkdEncrypter {

    pub(crate) fn new(key: &[u8; QKD_KEY_SIZE_BYTES], iv: &[u8; QKD_IV_SIZE_BYTES]) -> Self {
        let key = ring::aead::LessSafeKey::new(UnboundKey::new(&ring::aead::AES_256_GCM, key).unwrap());
        Self { key, iv: crate::crypto::cipher::Iv::new(iv.to_owned()) }
    }
}

impl MessageEncrypter for QkdEncrypter {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = ring::aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = ring::aead::Aad::from(make_tls13_aad(total_len));
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::QKDv1_0,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.key.algorithm().tag_len()
    }
}

pub(crate) struct QkdDecrypter {
    key: ring::aead::LessSafeKey,
    iv: crate::crypto::cipher::Iv,
}

impl QkdDecrypter {
    pub(crate) fn new(key: &[u8; QKD_KEY_SIZE_BYTES], iv: &[u8; QKD_IV_SIZE_BYTES]) -> Self {
        let key = ring::aead::LessSafeKey::new(UnboundKey::new(&ring::aead::AES_256_GCM, key).unwrap());
        Self { key, iv: crate::crypto::cipher::Iv::new(iv.to_owned()) }
    }
}

impl MessageDecrypter for QkdDecrypter {
    fn decrypt(&mut self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = msg.payload_mut();
        if payload.len() < self.key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = ring::aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = ring::aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}


#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdKey {
    pub(crate) key_ID: String,
    pub(crate) key: String,
}

/// List of keys
#[derive(Deserialize, Debug)]
pub(crate) struct ResponseQkdKeysList {
    pub(crate) keys: Vec<ResponseQkdKey>,
}

/// SAE information (id)
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct ResponseQkdSAEInfo {
    pub(crate) SAE_ID: i64,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestQkdKey {
    pub(crate) key_ID: String,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestQkdKeysList {
    pub(crate) key_IDs: Vec<RequestQkdKey>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct QkdTlsRequestExtension {
    pub(crate) key_uuid: String,
    pub(crate) origin_sae_id: i64,
    pub(crate) iv: [u8; QKD_IV_SIZE_BYTES],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct QkdChallenge {
    pub(crate) random_seed: [u8; Self::RANDOM_SEED_SIZE],
    pub(crate) challenge: [u8; Self::CHALLENGE_SIZE],
}

impl QkdChallenge {
    pub(crate) const CHALLENGE_SIZE: usize = 32;
    pub(crate) const RANDOM_SEED_SIZE: usize = 32;

    pub(crate) fn new() -> Self {
        let mut challenge = [0u8; Self::CHALLENGE_SIZE];
        let mut random_seed = [0u8; Self::RANDOM_SEED_SIZE];
        let system_random = ring::rand::SystemRandom::new();
        system_random.fill(&mut challenge).unwrap();
        system_random.fill(&mut random_seed).unwrap();
        Self { challenge, random_seed }
    }

    /// Check if the challenge is the same, and the random seed is different
    /// It should avoid replay attack (but you should increase seed sequence number too when sending back the challenge)
    /// # Arguments
    /// * `other` - The other challenge to compare with
    /// # Returns
    /// True if the challenge is the same and the random seed is different, false otherwise
    pub(crate) fn check_correspondence(&self, other: &Self) -> bool {
        self.challenge == other.challenge && self.random_seed != other.random_seed
    }

    /// Keep challenge and change random seed
    pub(crate) fn reseed(self) -> Self {
        let mut random_seed = [0u8; Self::RANDOM_SEED_SIZE];
        let system_random = ring::rand::SystemRandom::new();
        loop {
            system_random.fill(&mut random_seed).unwrap();
            // Ensure random seed is different, in order to avoid replay attack
            if random_seed != self.random_seed {
                break;
            }
        }
        Self {
            challenge: self.challenge,
            random_seed
        }
    }

    pub(crate) fn encrypt_qkd_encrypter(&self, key: &[u8; QKD_KEY_SIZE_BYTES], iv: &[u8; QKD_IV_SIZE_BYTES], seq: u64) -> Vec<u8> {
        QkdEncrypter::new(
            key,
            iv
        ).encrypt(BorrowedPlainMessage {
            typ: ContentType::QkdKeyChallenge,
            version: ProtocolVersion::QKDv1_0,
            payload: postcard::to_allocvec(self).unwrap().as_ref(),
        }, seq).unwrap().payload().to_owned()
    }

    pub(crate) fn decrypt_qkd_decrypter(msg: Vec<u8>, key: &[u8; QKD_KEY_SIZE_BYTES], iv: &[u8; QKD_IV_SIZE_BYTES], seq: u64) -> Result<Self, Error> {
        let mut decrypter = QkdDecrypter::new(
            key,
            iv
        );
        let opaque_msg = OpaqueMessage::new(ContentType::QkdKeyChallenge, ProtocolVersion::QKDv1_0, msg);
        let plain_msg = decrypter.decrypt(opaque_msg, seq)?;
        Ok(postcard::from_bytes(&plain_msg.payload.0).map_err(|_| Error::PeerMisbehaved(crate::PeerMisbehaved::InconsistentQkdChallenge))?)
    }
}