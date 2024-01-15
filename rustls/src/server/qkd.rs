//! QKD specific config and states for server side

use std::prelude::rust_2015::Box;
use std::prelude::rust_2021::ToOwned;
use std::sync::Arc;
use log::trace;
use crate::common_state::{Context, State};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::ServerConnectionData;
use crate::{ContentType, Error, PeerMisbehaved};
use crate::check::{inappropriate_message, inappropriate_qkd_challenge_response_message};



/// Wrapper to ensure normal flow isn't triggered when QKD is used
#[derive(Debug)]
pub struct QkdServerConfig {
    wrapped_server_config: crate::ServerConfig,
}

impl QkdServerConfig {
    pub(crate) fn new(config: crate::ServerConfig) -> Self {
        Self {
            wrapped_server_config: config,
        }
    }

    /// How to output key material for debugging. The default does nothing
    /// Implements SSLKEYLOGFILE standard
    pub fn set_key_log(&mut self, key_log_file: Arc<crate::KeyLogFile>) {
        self.wrapped_server_config.key_log = key_log_file;
    }

    pub(crate) fn get_server_config(&self) -> Arc<crate::ServerConfig> {
        Arc::new(self.wrapped_server_config.clone())
    }
}


pub(crate) struct ExpectQkdChallengeResponse {
    /// Common state for QKD exchange, shared by client and server
    qkd_common_state: crate::qkd_common_state::QkdCommonState,
}

impl State<ServerConnectionData> for ExpectQkdChallengeResponse {
    fn handle(self: Box<Self>, cx: &mut Context<'_, ServerConnectionData>, message: Message) -> crate::server::hs::NextStateOrError {
        let challenge_reponse_payload = match message.payload {
            MessagePayload::QkdKeyChallenge(payload) => {
                payload
            },
            payload => {
                return Err(inappropriate_qkd_challenge_response_message(
                    &payload,
                    &[ContentType::QkdKeyChallenge],
                ));
            }
        };

        let qkd_key = &self.qkd_common_state.shared_encryption_key;
        let qkd_iv = &self.qkd_common_state.negotiated_iv;
        let challenge_response_obj = crate::qkd::QkdChallenge::decrypt_qkd_decrypter(challenge_reponse_payload.0.to_owned(), qkd_key, qkd_iv, 1)?;

        if cx.data.sent_qkd_challenge.as_ref().unwrap().check_correspondence(&challenge_response_obj) {
        } else {
            trace!("QKD challenge response does not correspond to challenge");
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InconsistentQkdChallenge));
        }
        self.set_qkd_encrypter_decrypter_and_start_traffic(cx);
        Ok(Box::new(ExpectQkdExchange {}))
    }
}

impl ExpectQkdChallengeResponse {
    pub(crate) fn new(qkd_common_state: crate::qkd_common_state::QkdCommonState) -> Self {
        Self {
            qkd_common_state,
        }
    }

    fn set_qkd_encrypter_decrypter_and_start_traffic(&self, cx: &mut crate::server::hs::ServerContext) {
        let key = &self.qkd_common_state.shared_encryption_key;
        let iv = &self.qkd_common_state.negotiated_iv;
        cx.common.record_layer.set_message_decrypter(Box::new(
            crate::qkd::QkdDecrypter::new(
                key,
                iv))
        );
        cx.common.record_layer.set_message_encrypter(Box::new(
            crate::qkd::QkdEncrypter::new(
                key,
                iv))
        );
        cx.common.start_traffic();
    }
}


pub(crate) struct ExpectQkdExchange {}

impl State<ServerConnectionData> for ExpectQkdExchange {
    fn handle(self: Box<Self>, cx: &mut Context<'_, ServerConnectionData>, message: Message) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
        match message.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }
        Ok(self)
    }
}