//! BMC Global Enables; a Set replaces the entire byte, without a hidden read.

use bitflags::bitflags;

use crate::connection::{IpmiCommand, Message, NetFn};

bitflags! {
    /// Seven defined BMC Global Enables bits (App `0x2e`/`0x2f`).
    ///
    /// Bit 4 is reserved. Constructing from readback rejects it, rather than
    /// silently dropping unknown controller state during a subsequent write.
    pub struct BmcGlobalEnables: u8 {
        /// Receive Message Queue Interrupt.
        const RECEIVE_MESSAGE_INTERRUPT = 0x01;
        /// Event Message Buffer Full Interrupt.
        const EVENT_MESSAGE_INTERRUPT = 0x02;
        /// Event Message Buffer.
        const EVENT_MESSAGE_BUFFER = 0x04;
        /// System Event Logging.
        const SYSTEM_EVENT_LOG = 0x08;
        /// OEM 0.
        const OEM_0 = 0x20;
        /// OEM 1.
        const OEM_1 = 0x40;
        /// OEM 2.
        const OEM_2 = 0x80;
    }
}

/// Get BMC Global Enables (App `0x2f`).
#[derive(Clone, Copy, Debug)]
pub struct GetBmcGlobalEnables;

impl From<GetBmcGlobalEnables> for Message {
    fn from(_: GetBmcGlobalEnables) -> Self {
        Message::new_request(NetFn::App, 0x2f, vec![])
    }
}

impl IpmiCommand for GetBmcGlobalEnables {
    type Output = BmcGlobalEnables;
    type Error = GlobalEnablesError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 1 {
            return Err(GlobalEnablesError::Length(data.len()));
        }
        BmcGlobalEnables::from_bits(data[0]).ok_or(GlobalEnablesError::ReservedBits(data[0]))
    }
}

/// Explicitly replace all seven BMC Global Enables bits (App `0x2e`).
///
/// This can disable logging, alerts, or interrupts. Read first if preserving
/// current settings matters; a lost response may mean the write took effect.
#[derive(Clone, Copy, Debug)]
pub struct SetBmcGlobalEnables(pub BmcGlobalEnables);

impl From<SetBmcGlobalEnables> for Message {
    fn from(value: SetBmcGlobalEnables) -> Self {
        Message::new_request(NetFn::App, 0x2e, vec![value.0.bits()])
    }
}

impl IpmiCommand for SetBmcGlobalEnables {
    type Output = ();
    type Error = GlobalEnablesError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(GlobalEnablesError::Length(data.len()))
        }
    }
}

/// Invalid response from a Global Enables command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalEnablesError {
    /// Unexpected response byte count.
    Length(usize),
    /// A reserved bit (bit 4) was set in the returned byte.
    ReservedBits(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_enable_wire_and_validation_fixtures() {
        let get: Message = GetBmcGlobalEnables.into();
        assert_eq!((get.netfn_raw(), get.cmd(), get.data()), (6, 0x2f, &[][..]));
        let flags = GetBmcGlobalEnables::parse_success_response(&[0xa9]).unwrap();
        assert!(flags.contains(BmcGlobalEnables::SYSTEM_EVENT_LOG));
        assert_eq!(flags.bits(), 0xa9);
        let set: Message = SetBmcGlobalEnables(flags).into();
        assert_eq!(
            (set.netfn_raw(), set.cmd(), set.data()),
            (6, 0x2e, &[0xa9][..])
        );
        assert_eq!(SetBmcGlobalEnables::parse_success_response(&[]), Ok(()));
        assert_eq!(
            GetBmcGlobalEnables::parse_success_response(&[0x10]),
            Err(GlobalEnablesError::ReservedBits(0x10))
        );
        for n in [0, 2] {
            assert_eq!(
                GetBmcGlobalEnables::parse_success_response(&vec![0; n]),
                Err(GlobalEnablesError::Length(n))
            );
        }
        assert_eq!(
            SetBmcGlobalEnables::parse_success_response(&[0]),
            Err(GlobalEnablesError::Length(1))
        );
    }
}
