use crate::{
    connection::{IpmiCommand, Message, NetFn},
    storage::Timestamp,
};

/// Get the SEL's current 32-bit timestamp (Storage command 0x48).
pub struct GetSelTime;

/// Invalid length for a SEL time response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelTimeResponseError(pub usize);

impl IpmiCommand for GetSelTime {
    type Output = Timestamp;
    type Error = SelTimeResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let bytes: [u8; 4] = data
            .try_into()
            .map_err(|_| SelTimeResponseError(data.len()))?;
        Ok(Timestamp::from(u32::from_le_bytes(bytes)))
    }
}

impl From<GetSelTime> for Message {
    fn from(_: GetSelTime) -> Self {
        Message::new_request(NetFn::Storage, 0x48, Vec::new())
    }
}

/// Set the SEL clock to an explicitly supplied 32-bit timestamp (Storage 0x49).
pub struct SetSelTime(pub Timestamp);

impl IpmiCommand for SetSelTime {
    type Output = ();
    type Error = SelTimeResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(SelTimeResponseError(data.len()))
        }
    }
}

impl From<SetSelTime> for Message {
    fn from(value: SetSelTime) -> Self {
        Message::new_request(
            NetFn::Storage,
            0x49,
            value.0.seconds().to_le_bytes().to_vec(),
        )
    }
}

impl super::SelMutation for SetSelTime {}
