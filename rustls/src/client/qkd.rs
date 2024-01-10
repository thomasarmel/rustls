use std::prelude::rust_2015::Box;
use std::sync::Arc;
use pki_types::ServerName;
use crate::{ClientConfig, ContentType, Error};
use crate::check::inappropriate_message;
use crate::client::{ClientConnectionData, ClientSessionStore};
use crate::client::hs::{ClientContext, NextStateOrError};
use crate::common_state::{Context, State};
use crate::msgs::message::{Message, MessagePayload};

pub(super) fn start_qkd_handshake(server_name: ServerName<'static>,
                                  config: Arc<ClientConfig>,
                                  cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let key = cx.common.qkd_retrieved_key.as_ref().unwrap();
    cx.common.record_layer.set_message_encrypter(Box::new(crate::qkd::QkdEncrypter::new(
        key,
        &[0; crate::qkd::QkdDecrypter::IV_SIZE],
    )));
    cx.common.record_layer.set_message_decrypter(Box::new(
        crate::qkd::QkdDecrypter::new(
            key,
            &[0; crate::qkd::QkdDecrypter::IV_SIZE]))
    );
    cx.common.start_traffic();
    Ok(Box::new(ExpectTrafficQkd { session_storage: Arc::clone(&config.resumption.store), server_name }))
}

#[allow(dead_code)]
pub(crate) struct ExpectTrafficQkd {
    pub(crate) session_storage: Arc<dyn ClientSessionStore>,
    pub(crate) server_name: ServerName<'static>,
}

impl State<ClientConnectionData> for ExpectTrafficQkd {
    fn handle(self: Box<Self>, cx: &mut Context<'_, ClientConnectionData>, message: Message) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
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