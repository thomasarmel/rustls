use std::prelude::rust_2015::Box;
use crate::{ContentType, Error};
use crate::check::inappropriate_message;
use crate::client::ClientConnectionData;
use crate::client::hs::NextStateOrError;
use crate::common_state::{Context, State};
use crate::msgs::message::{Message, MessagePayload};
use crate::qkd_common_state::QkdCommonState;

pub(super) fn set_qkd_encryption_parameters_and_start_traffic(cx: &mut Context<'_, ClientConnectionData>, qkd_common_state: &QkdCommonState) -> NextStateOrError {
    let key = &qkd_common_state.shared_encryption_key;
    let iv = &qkd_common_state.negotiated_iv;
    cx.common.record_layer.set_message_encrypter(Box::new(crate::qkd::QkdEncrypter::new(
        key,
        iv,
    )));
    cx.common.record_layer.set_message_decrypter(Box::new(
        crate::qkd::QkdDecrypter::new(
            key,
            iv))
    );
    cx.common.start_traffic();
    Ok(Box::new(ExpectTrafficQkd {}))
}

pub(crate) struct ExpectTrafficQkd {
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