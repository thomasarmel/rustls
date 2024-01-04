use std::prelude::rust_2015::Box;
use std::println;
use std::sync::Arc;
//use cipher::crypto_common::rand_core::RngCore;
use pki_types::ServerName;
use rand::RngCore;
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
    println!("{}", server_name.to_str());
    //let mut stream = std::net::TcpStream::connect(format!("{}:8999", server_name.to_str())).unwrap();
    let mut key_iv = [0u8; 32 + 16];
    rand::thread_rng().fill_bytes(&mut key_iv);
    //stream.write(&key_iv).unwrap();
    cx.common.record_layer.set_message_encrypter(Box::new(crate::qkd::QkdEncrypter::new(
        <&[u8; 32]>::try_from(&key_iv[0..32]).unwrap(),
        <&[u8; 16]>::try_from(&key_iv[32..48]).unwrap(),
    )));
    cx.common.record_layer.set_message_decrypter(Box::new(
        crate::qkd::QkdDecrypter::new(
            &[0; 32],
            &[0; 16]))
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
        println!("ExpectTrafficQkd: {:?}, shall be encoded with {:?}", message, cx.common.qkd_retrieved_key);
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