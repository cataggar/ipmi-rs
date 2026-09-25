//! Bounded I2C Master Write-Read (App netfn, command 52h).
//!
//! The write bytes precede the read in a single I2C transaction. A write-only
//! transaction can change device state; never replay one after an uncertain
//! transport result. Even a read with a register pointer may change that pointer.

use crate::connection::{
    Address, Channel, CompletionErrorCode, IpmiCommand, LogicalUnit, Message, NetFn,
};

/// Maximum number of I2C write or read bytes in one command.
pub const MAX_TRANSFER: usize = 64;

/// A public bus or one of eight controller-private busses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cBusKind {
    /// Public IPMB bus.
    Public,
    /// Private I2C bus number 0 through 7.
    Private(u8),
}

/// The channel and bus encoded in the first command byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I2cBus {
    channel: u8,
    kind: I2cBusKind,
}

impl I2cBus {
    /// Construct an I2C bus. The IPMI command has a four-bit channel field.
    pub fn new(channel: u8, kind: I2cBusKind) -> Result<Self, I2cValidationError> {
        if channel > 15 {
            return Err(I2cValidationError::InvalidChannel(channel));
        }
        if let I2cBusKind::Private(bus) = kind {
            if bus > 7 {
                return Err(I2cValidationError::InvalidBus(bus));
            }
        }
        Ok(Self { channel, kind })
    }

    /// Encoded channel, bus ID, and private-bus bit.
    pub fn wire_value(self) -> u8 {
        (self.channel << 4)
            | match self.kind {
                I2cBusKind::Public => 0,
                I2cBusKind::Private(bus) => (bus << 1) | 1,
            }
    }
}

/// Eight-bit I2C write address (seven-bit slave address shifted left).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I2cAddress(u8);

impl I2cAddress {
    /// Accept a nonzero, even, eight-bit write address.
    pub fn new(wire_value: u8) -> Result<Self, I2cValidationError> {
        if wire_value == 0 || wire_value & 1 != 0 {
            return Err(I2cValidationError::InvalidAddress(wire_value));
        }
        Ok(Self(wire_value))
    }

    /// Construct from a seven-bit slave address.
    pub fn from_7bit(value: u8) -> Result<Self, I2cValidationError> {
        if value == 0 || value > 0x7f {
            return Err(I2cValidationError::InvalidAddress(value));
        }
        Ok(Self(value << 1))
    }

    /// Return the eight-bit write address.
    pub fn wire_value(self) -> u8 {
        self.0
    }
}

/// Invalid command or SDR locator parameters (rejected before sending).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cValidationError {
    /// The channel does not fit in the command's four-bit field.
    InvalidChannel(u8),
    /// The private bus does not fit in the three-bit bus ID field.
    InvalidBus(u8),
    /// Address is zero, odd, or outside the seven-bit I2C address range.
    InvalidAddress(u8),
    /// A transfer exceeds the IPMI command's 64-byte write/read limit.
    TransferTooLong { write: usize, read: usize },
    /// The requested address index exceeds the locator's address span.
    AddressOutsideSpan(u8),
    /// An explicit generic-device write requires at least one data byte.
    EmptyWrite,
    /// A generic-device read requires at least one byte.
    EmptyRead,
}

/// An I2C command error, including command-specific completion codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cError {
    /// Arbitration was lost (81h).
    LostArbitration,
    /// Bus error (82h).
    BusError,
    /// Device did not acknowledge the write (83h).
    NakOnWrite,
    /// The controller truncated its read (84h).
    TruncatedRead,
    /// Response data was not exactly the number of bytes requested.
    InvalidLength { expected: usize, actual: usize },
    /// A request-dependent parser was called without the three command bytes.
    InvalidRequestLength(usize),
}

/// A single bounded I2C Master Write-Read transaction.
#[derive(Clone, Debug)]
pub struct MasterWriteRead {
    bus: I2cBus,
    address: I2cAddress,
    read_len: u8,
    write_data: Vec<u8>,
    controller: Option<(Address, Channel, LogicalUnit)>,
    local_lun: LogicalUnit,
}

impl MasterWriteRead {
    /// Construct a single I2C transaction. Zero/zero is legal for devices
    /// accepting an address-only write, e.g. DDR4 SPD page-select devices.
    pub fn new(
        bus: I2cBus,
        address: I2cAddress,
        write_data: impl Into<Vec<u8>>,
        read_len: usize,
    ) -> Result<Self, I2cValidationError> {
        let write_data = write_data.into();
        if write_data.len() > MAX_TRANSFER || read_len > MAX_TRANSFER {
            return Err(I2cValidationError::TransferTooLong {
                write: write_data.len(),
                read: read_len,
            });
        }
        Ok(Self {
            bus,
            address,
            read_len: read_len as u8,
            write_data,
            controller: None,
            local_lun: LogicalUnit::Zero,
        })
    }

    /// Address the management controller in a generic-device SDR locator.
    ///
    /// Satellite targets require a transport with bridged routing support.
    pub fn with_controller(mut self, address: Address, channel: Channel, lun: LogicalUnit) -> Self {
        self.controller = Some((address, channel, lun));
        self
    }

    /// Address a nonzero LUN on the local BMC.
    pub fn with_local_lun(mut self, lun: LogicalUnit) -> Self {
        self.local_lun = lun;
        self
    }
}

impl From<MasterWriteRead> for Message {
    fn from(value: MasterWriteRead) -> Self {
        let mut data = Vec::with_capacity(3 + value.write_data.len());
        data.extend_from_slice(&[
            value.bus.wire_value(),
            value.address.wire_value(),
            value.read_len,
        ]);
        data.extend(value.write_data);
        Message::new_request(NetFn::App, 0x52, data)
    }
}

impl IpmiCommand for MasterWriteRead {
    type Output = Vec<u8>;
    type Error = I2cError;

    fn target(&self) -> Option<(Address, Channel)> {
        self.controller
            .map(|(address, channel, _)| (address, channel))
    }

    fn target_lun(&self) -> LogicalUnit {
        self.controller.map_or(self.local_lun, |(_, _, lun)| lun)
    }

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        match code {
            CompletionErrorCode::CommandSpecific(0x81) => Some(I2cError::LostArbitration),
            CompletionErrorCode::CommandSpecific(0x82) => Some(I2cError::BusError),
            CompletionErrorCode::CommandSpecific(0x83) => Some(I2cError::NakOnWrite),
            CompletionErrorCode::CommandSpecific(0x84) => Some(I2cError::TruncatedRead),
            _ => None,
        }
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() > MAX_TRANSFER {
            return Err(I2cError::InvalidLength {
                expected: MAX_TRANSFER,
                actual: data.len(),
            });
        }
        Ok(data.to_vec())
    }

    fn parse_success_response_for_request(
        request_data: &[u8],
        data: &[u8],
    ) -> Result<Self::Output, Self::Error> {
        let expected = usize::from(
            *request_data
                .get(2)
                .ok_or(I2cError::InvalidRequestLength(request_data.len()))?,
        );
        if data.len() != expected {
            return Err(I2cError::InvalidLength {
                expected,
                actual: data.len(),
            });
        }
        Self::parse_success_response(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_boundaries_and_validation() {
        let bus = I2cBus::new(15, I2cBusKind::Private(7)).unwrap();
        let addr = I2cAddress::new(0xa0).unwrap();
        let command = MasterWriteRead::new(bus, addr, vec![0x55; 64], 64).unwrap();
        let message: Message = command.into();
        assert_eq!(message.netfn(), NetFn::App);
        assert_eq!(message.cmd(), 0x52);
        assert_eq!(&message.data()[..4], &[0xff, 0xa0, 64, 0x55]);
        assert_eq!(message.data().len(), 67);
        assert!(MasterWriteRead::new(bus, addr, vec![0; 65], 0).is_err());
        assert!(MasterWriteRead::new(bus, addr, [], 65).is_err());
        assert!(I2cBus::new(16, I2cBusKind::Public).is_err());
        assert!(I2cBus::new(0, I2cBusKind::Private(8)).is_err());
        for address in [0, 0xa1] {
            assert!(I2cAddress::new(address).is_err());
        }
        assert!(I2cAddress::from_7bit(128).is_err());
        assert_eq!(I2cBus::new(0, I2cBusKind::Public).unwrap().wire_value(), 0);
    }

    #[test]
    fn exact_response_and_completion_codes() {
        assert_eq!(
            MasterWriteRead::parse_success_response_for_request(&[1, 0xa0, 2], &[7]),
            Err(I2cError::InvalidLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            MasterWriteRead::parse_success_response_for_request(&[1, 0xa0, 0], &[]),
            Ok(vec![])
        );
        assert!(MasterWriteRead::parse_success_response_for_request(&[1, 0xa0, 0], &[7]).is_err());
        assert_eq!(
            MasterWriteRead::parse_success_response_for_request(&[], &[]),
            Err(I2cError::InvalidRequestLength(0))
        );
        for (raw, error) in [
            (0x81, I2cError::LostArbitration),
            (0x82, I2cError::BusError),
            (0x83, I2cError::NakOnWrite),
            (0x84, I2cError::TruncatedRead),
        ] {
            assert_eq!(
                MasterWriteRead::handle_completion_code(
                    CompletionErrorCode::try_from(raw).unwrap(),
                    &[]
                ),
                Some(error)
            );
        }
    }
}
