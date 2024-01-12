//! Blablabla TODO

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

    /// Blablabla TODO
    pub fn set_key_log(&mut self, key_log_file: Arc<crate::KeyLogFile>) {
        self.wrapped_server_config.key_log = key_log_file;
    }

    pub(crate) fn get_server_config(&self) -> Arc<crate::ServerConfig> {
        Arc::new(self.wrapped_server_config.clone())
    }
}


pub(crate) struct ExpectQkdChallengeResponse {
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

        let qkd_key = cx.common.qkd_retrieved_key.as_ref().unwrap();
        let qkd_iv = cx.common.qkd_negociated_iv.as_ref().unwrap();
        let challenge_response_obj = crate::qkd::QkdChallenge::decrypt_qkd_decrypter(challenge_reponse_payload.0.to_owned(), qkd_key, qkd_iv, 1)?;

        if cx.data.sent_qkd_challenge.as_ref().unwrap().check_correspondence(&challenge_response_obj) {
        } else {
            trace!("QKD challenge response does not correspond to challenge");
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InconsistentQkdChallenge));
        }
        set_qkd_encrypter_and_decrypter(cx);
        Ok(Box::new(ExpectQkdExchange {}))
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

pub(crate) fn set_qkd_encrypter_and_decrypter(cx: &mut crate::server::hs::ServerContext) {
    let key = cx.common.qkd_retrieved_key.as_ref().unwrap();
    let iv = cx.common.qkd_negociated_iv.as_ref().unwrap();
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