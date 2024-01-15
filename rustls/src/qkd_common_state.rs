//! State of protocol in case it uses QKD (Quantum Key Distribution) for key exchange

use std::prelude::rust_2021::String;
use zeroize::Zeroize;
use crate::qkd::{QKD_IV_SIZE_BYTES, QKD_KEY_SIZE_BYTES};

/// Current state of QKD setup, shall be set to Used in both size to make QKD connection working
#[derive(Clone, Debug)]
pub(crate) enum CurrentQkdState {
    /// QKD is disabled and definitely not used
    NotUsed,
    /// QKD is enabled in client side, server did not confirmed support yet
    /// State only used in client side
    ClientInitiatedWaitServerConfirmation(QkdCommonState),
    /// QKD is enabled in both sides
    Used(QkdCommonState),
}

/// Optional QKD configuration, to be placed in CommonState structs. Should be None in case QKD is not used
#[derive(Clone, Debug)]
pub(crate) struct QkdCommonState {
    /// UUID of the QKD key used for encryption, shall be passed to KME in order to retrieve the key
    pub(crate) encryption_key_uuid: String,
    /// Common symmetric key between client and server, retrieved from the KME
    pub(crate) shared_encryption_key: [u8; QKD_KEY_SIZE_BYTES],
    /// Random IV (initialization vector) used for encryption, shared publicly
    pub(crate) negotiated_iv: [u8; QKD_IV_SIZE_BYTES],
    /// SAE ID of the origin SAE, ie the client who initiated the QKD key exchange, used to identify the key with the KME
    pub(crate) origin_sae_id: i64,
}

impl Drop for QkdCommonState {
    fn drop(&mut self) {
        // Zeroize the key when the struct is dropped, in order to avoid it being present in memory after the program exits
        self.shared_encryption_key.zeroize();
    }
}