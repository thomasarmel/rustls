use crate::crypto::cipher::{BorrowedPlainMessage, MessageDecrypter, MessageEncrypter, OpaqueMessage, PlainMessage};
use crate::{Error, ProtocolVersion};
use crate::msgs::base::Payload;

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