use std::prelude::rust_2015::{String, Vec};
use serde::{Deserialize, Serialize};
use crate::crypto::cipher::{BorrowedPlainMessage, MessageDecrypter, MessageEncrypter, OpaqueMessage, PlainMessage};
use crate::{Error, ProtocolVersion};
use crate::msgs::base::Payload;

pub(crate) const QKD_KEY_SIZE_BYTES: usize = 32;

#[allow(dead_code)] // temp
pub(crate) struct QkdEncrypter {
    key: [u8; Self::KEY_SIZE],
    iv: [u8; Self::IV_SIZE],
}
impl QkdEncrypter {
    const KEY_SIZE: usize = 32;
    const IV_SIZE: usize = 16;
    pub(crate) fn new(key: &[u8; Self::KEY_SIZE], iv: &[u8; Self::IV_SIZE]) -> Self {
        Self { key: key.clone(), iv: iv.clone() }
    }
}

impl MessageEncrypter for QkdEncrypter {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> { // TODO
        let encrypted = msg.payload;
        Ok(OpaqueMessage::new(msg.typ, ProtocolVersion::QKDv1_0, encrypted.to_vec()))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

#[allow(dead_code)] // temp
pub(crate) struct QkdDecrypter {
    key: [u8; Self::KEY_SIZE],
    iv: [u8; Self::IV_SIZE],
}

impl QkdDecrypter {
    const KEY_SIZE: usize = 32;
    const IV_SIZE: usize = 16;
    pub(crate) fn new(key: &[u8; Self::KEY_SIZE], iv: &[u8; Self::IV_SIZE]) -> Self {
        Self { key: key.clone(), iv: iv.clone() }
    }
}

impl MessageDecrypter for QkdDecrypter {
    fn decrypt(&mut self, msg: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        let decrypted = msg.payload();
        Ok(PlainMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload(decrypted.to_vec()),
        })
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