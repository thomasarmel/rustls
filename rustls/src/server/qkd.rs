use std::prelude::rust_2015::Box;
use std::println;
use std::sync::Arc;
use crate::common_state::{Context, State};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::hs::ServerContext;
use crate::server::ServerConnectionData;
use crate::{ContentType, Error, ServerConfig};
use crate::check::inappropriate_message;

#[allow(dead_code)] // temp
pub(crate) struct ExpectQkdExchange {
    pub(crate) config: Arc<ServerConfig>
}

impl State<ServerConnectionData> for ExpectQkdExchange {
    fn handle(self: Box<Self>, cx: &mut Context<'_, ServerConnectionData>, message: Message) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
        println!("ExpectQkdExchange: {:?}, shall be encoded with {:?}", message, cx.common.qkd_retrieved_key);
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

pub(crate) fn receive_qkd_key(cx: &mut ServerContext) {
    // receive key here !!
    cx.common.record_layer.set_message_decrypter(Box::new(
        crate::qkd::QkdDecrypter::new(
            &[0; 32],
            &[0; 16]))
    );
    cx.common.record_layer.set_message_encrypter(Box::new(
        crate::qkd::QkdEncrypter::new(
            &[0; 32],
            &[0; 16]))
    );
    cx.common.start_traffic();
}