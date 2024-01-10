use std::prelude::rust_2015::{String, Vec};
use std::prelude::rust_2021::ToOwned;
use ring::aead::UnboundKey;
use serde::{Deserialize, Serialize};
use crate::crypto::cipher::{BorrowedPlainMessage, make_tls13_aad, MessageDecrypter, MessageEncrypter, Nonce, OpaqueMessage, PlainMessage};
use crate::{ContentType, Error, ProtocolVersion};
use crate::msgs::codec::Codec;

pub(crate) const QKD_KEY_SIZE_BYTES: usize = 32;

pub(crate) struct QkdEncrypter {
    key: ring::aead::LessSafeKey,
    iv: crate::crypto::cipher::Iv,
}
impl QkdEncrypter {
    pub(crate) const KEY_SIZE: usize = 32;
    pub(crate) const IV_SIZE: usize = 12;

    pub(crate) fn new(key: &[u8; Self::KEY_SIZE], iv: &[u8; Self::IV_SIZE]) -> Self {
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
    pub(crate) const KEY_SIZE: usize = 32;
    pub(crate) const IV_SIZE: usize = 12;
    pub(crate) fn new(key: &[u8; Self::KEY_SIZE], iv: &[u8; Self::IV_SIZE]) -> Self {
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