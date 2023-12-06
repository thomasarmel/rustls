use crate::crypto::cipher::{BorrowedPlainMessage, MessageEncrypter, OpaqueMessage};
use crate::{ContentType, Error, ProtocolVersion};

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
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> { // TODO
        let encrypted = msg.payload;
        Ok(OpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::QKDv1_0, encrypted.to_vec()))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}