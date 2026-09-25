//! Tyan's IPMI 1.5 OEM serial console commands (NetFn 0x30).
//! These commands do not activate standard IPMI 2.0 SOL or Intel ISOL.

use std::net::Ipv4Addr;

use crate::connection::{IpmiCommand, Message, NetFn};

/// Address to which a Tyan BMC should send console datagrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsolEndpoint {
    address: Ipv4Addr,
    port: u16,
}

impl TsolEndpoint {
    /// Reject destinations which cannot identify a single IPv4 listener.
    pub fn new(address: Ipv4Addr, port: u16) -> Option<Self> {
        (port != 0
            && !address.is_unspecified()
            && !address.is_multicast()
            && !address.is_broadcast())
        .then_some(Self { address, port })
    }

    /// The listener's IPv4 address.
    pub fn address(self) -> Ipv4Addr {
        self.address
    }

    /// The listener's UDP port.
    pub fn port(self) -> u16 {
        self.port
    }

    fn payload(self) -> Vec<u8> {
        let mut data = self.address.octets().to_vec();
        data.extend_from_slice(&self.port.to_be_bytes());
        data
    }
}

/// Unexpected data returned after an otherwise successful OEM command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnexpectedTsolResponse(pub usize);

fn empty_response(data: &[u8]) -> Result<(), UnexpectedTsolResponse> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(UnexpectedTsolResponse(data.len()))
    }
}

/// Explicitly start Tyan TSOL to a previously bound IPv4 UDP listener.
#[derive(Clone, Copy, Debug)]
pub struct TsolStart(pub TsolEndpoint);

impl From<TsolStart> for Message {
    fn from(command: TsolStart) -> Self {
        Message::new_request(NetFn::Reserved(0x30), 0x06, command.0.payload())
    }
}

impl IpmiCommand for TsolStart {
    type Output = ();
    type Error = UnexpectedTsolResponse;

    fn parse_success_response(data: &[u8]) -> Result<(), Self::Error> {
        empty_response(data)
    }
}

/// Explicitly stop Tyan TSOL for the same listener used by Start.
#[derive(Clone, Copy, Debug)]
pub struct TsolStop(pub TsolEndpoint);

impl From<TsolStop> for Message {
    fn from(command: TsolStop) -> Self {
        Message::new_request(NetFn::Reserved(0x30), 0x02, command.0.payload())
    }
}

impl IpmiCommand for TsolStop {
    type Output = ();
    type Error = UnexpectedTsolResponse;

    fn parse_success_response(data: &[u8]) -> Result<(), Self::Error> {
        empty_response(data)
    }
}

/// One Tyan keystroke message: at most 14 bytes, plus a per-session sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsolKeystroke {
    bytes: Vec<u8>,
    sequence: u8,
}

impl TsolKeystroke {
    /// Empty or oversized keystrokes cannot be encoded by ipmitool's 16-byte frame.
    pub fn new(bytes: &[u8], sequence: u8) -> Option<Self> {
        (1..=14).contains(&bytes.len()).then(|| Self {
            bytes: bytes.to_vec(),
            sequence,
        })
    }

    /// Bytes sent in this single IPMI request.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// This command always contains at least one byte.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl From<TsolKeystroke> for Message {
    fn from(command: TsolKeystroke) -> Self {
        let mut data = Vec::with_capacity(command.bytes.len() + 2);
        data.push(command.bytes.len() as u8 + 1);
        data.extend_from_slice(&command.bytes);
        data.push(command.sequence);
        Message::new_request(NetFn::Reserved(0x30), 0x03, data)
    }
}

impl IpmiCommand for TsolKeystroke {
    type Output = ();
    type Error = UnexpectedTsolResponse;

    fn parse_success_response(data: &[u8]) -> Result<(), Self::Error> {
        empty_response(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_derived_wire_fixtures() {
        let address = Ipv4Addr::new(192, 168, 168, 120);
        let endpoint = TsolEndpoint::new(address, 0x1a0a).unwrap();
        for (message, command) in [
            (Message::from(TsolStart(endpoint)), 0x06),
            (Message::from(TsolStop(endpoint)), 0x02),
        ] {
            assert_eq!(message.netfn_raw(), 0x30);
            assert_eq!(message.cmd(), command);
            assert_eq!(message.data(), [0xc0, 0xa8, 0xa8, 0x78, 0x1a, 0x0a]);
        }
        let keys: Message = TsolKeystroke::new(b"\x1b[C", 7).unwrap().into();
        assert_eq!(keys.netfn_raw(), 0x30);
        assert_eq!(keys.cmd(), 0x03);
        assert_eq!(keys.data(), [4, 0x1b, b'[', b'C', 7]);
        assert_eq!(TsolStart::parse_success_response(&[]), Ok(()));
        assert_eq!(
            TsolStop::parse_success_response(&[1]),
            Err(UnexpectedTsolResponse(1))
        );
    }

    #[test]
    fn invalid_endpoints_and_keystrokes_are_not_constructible() {
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(TsolEndpoint::new(ip, 6230).is_none());
        }
        assert!(TsolEndpoint::new(Ipv4Addr::LOCALHOST, 0).is_none());
        assert!(TsolKeystroke::new(b"", 0).is_none());
        assert!(TsolKeystroke::new(&[1; 15], 0).is_none());
        assert_eq!(
            Message::from(TsolKeystroke::new(&[1; 14], 255).unwrap()).data(),
            [&[15][..], &[1; 14], &[255]].concat()
        );
    }
}
