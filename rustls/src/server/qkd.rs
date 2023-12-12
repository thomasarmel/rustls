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
        println!("ExpectQkdExchange: {:?}", message);
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
        // Create a TCP server on port 8999 in order to receive the QKD key from the QKD server
        // and assume that is corresponds to a real QKD key exchange.
        /*let listener = TcpListener::bind("0.0.0.0:8999").unwrap(); // obvious security flaw :)
        let mut stream = listener.accept().unwrap().0;
        let mut buf = [0; 32 + 16];
        stream.read(&mut buf).unwrap();*/
        //let iv: [u8; 12] = [0; 12]; // Obviously, this is not secure. But it is just a demo.
        /*cx.common.record_layer.prepare_message_encrypter(Box::new(crate::crypto::ring::tls13::Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, buf.as_ref()).unwrap()),
            iv: Iv::from(iv),
        }));*/
        //todo!();
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