//! Kontron FRU identity queries, CP6012 boot control and buffer negotiation.

use crate::{
    app::DeviceId,
    connection::{Address, Channel, LogicalUnit, Message, NetFn, NotEnoughData},
};

use super::OemCommand;

const OEM_PREFIX: [u8; 4] = [0xB4, 0x90, 0x91, 0x8B];

/// Pin an OEM command to the same explicit IPMB destination used for its
/// LUN-zero identity lookup. `None` selects the session BMC.
#[derive(Debug, Clone, Copy)]
pub struct Routed<C> {
    command: C,
    target: Option<(Address, Channel)>,
}

impl<C> Routed<C> {
    /// Select a destination without changing the command's logical unit.
    pub const fn new(command: C, target: Option<(Address, Channel)>) -> Self {
        Self { command, target }
    }
}

impl<C: OemCommand> OemCommand for Routed<C> {
    type Output = C::Output;
    type Error = C::Error;
    const MANUFACTURER_ID: u32 = C::MANUFACTURER_ID;
    const PRODUCT_ID: Option<u16> = C::PRODUCT_ID;

    fn into_message(self) -> Message {
        self.command.into_message()
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        C::parse_success_response(data)
    }

    fn handle_completion_code(
        code: crate::connection::CompletionErrorCode,
        data: &[u8],
    ) -> Option<Self::Error> {
        C::handle_completion_code(code, data)
    }

    fn target(&self) -> Option<(Address, Channel)> {
        self.target
    }

    fn lun(&self) -> LogicalUnit {
        self.command.lun()
    }

    fn supports(&self, device: &DeviceId) -> bool {
        self.command.supports(device)
    }
}

/// Read the three raw FRU manufacturing-date bytes from the Kontron OEM command.
///
/// This only queries the controller; `kontronoem setmfgdate` also modifies
/// the FRU board area. Use the guarded preparation/apply API for that write.
#[derive(Debug, Clone, Copy)]
pub struct GetManufacturingDate;

impl GetManufacturingDate {
    /// Route to an IPMB destination; the query itself uses LUN 3.
    pub const fn at(self, target: Option<(Address, Channel)>) -> Routed<Self> {
        Routed::new(self, target)
    }
}

impl OemCommand for GetManufacturingDate {
    type Output = [u8; 3];
    type Error = NotEnoughData;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        Message::new_request(NetFn::Reserved(0x3E), 0x0E, OEM_PREFIX.to_vec())
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        data.try_into().map_err(|_| NotEnoughData)
    }

    fn lun(&self) -> LogicalUnit {
        LogicalUnit::Three
    }
}

/// Read the Kontron serial-number bytes used by `kontronoem setsn`.
#[derive(Debug, Clone, Copy)]
pub struct GetSerialNumber;

impl GetSerialNumber {
    /// Route to an IPMB destination; the query itself uses LUN 3.
    pub const fn at(self, target: Option<(Address, Channel)>) -> Routed<Self> {
        Routed::new(self, target)
    }
}

/// Invalid OEM serial number (the FRU serial fields must retain their length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    /// An empty or longer-than-63-byte serial cannot be a FRU field.
    Length,
    /// Only printable ASCII is accepted for a safety-checked FRU update.
    NonPrintable,
}

impl OemCommand for GetSerialNumber {
    type Output = Vec<u8>;
    type Error = SerialError;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        Message::new_request(NetFn::Reserved(0x3E), 0x0C, OEM_PREFIX.to_vec())
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() || data.len() > 63 {
            return Err(SerialError::Length);
        }
        if !data.iter().all(|b| (0x20..=0x7e).contains(b)) {
            return Err(SerialError::NonPrintable);
        }
        Ok(data.to_vec())
    }

    fn lun(&self) -> LogicalUnit {
        LogicalUnit::Three
    }
}

/// CP6012's next boot device (not the standard chassis boot-options command).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDevice {
    /// Boot from BIOS.
    Bios,
    /// Boot from a floppy disk.
    Floppy,
    /// Boot from a hard drive.
    HardDrive,
    /// Boot from a CD-ROM.
    CdRom,
    /// Boot over the network.
    Network,
}

/// Select a Kontron CP6012's next boot device.
///
/// This writes boot configuration. If the response is lost, the outcome is
/// unknown: do not resend automatically.
#[derive(Debug, Clone, Copy)]
pub struct SetNextBoot(pub BootDevice);

impl SetNextBoot {
    /// Route the CP6012 command to an IPMB destination on LUN 3.
    pub const fn at(self, target: Option<(Address, Channel)>) -> Routed<Self> {
        Routed::new(self, target)
    }
}

/// A successful next-boot reply unexpectedly contained data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnexpectedResponseLength(pub usize);

impl OemCommand for SetNextBoot {
    type Output = ();
    type Error = UnexpectedResponseLength;
    const MANUFACTURER_ID: u32 = 15000;
    const PRODUCT_ID: Option<u16> = Some(6012);

    fn into_message(self) -> Message {
        let selection = match self.0 {
            BootDevice::Bios => 0,
            BootDevice::Floppy => 1,
            BootDevice::HardDrive => 2,
            BootDevice::CdRom => 3,
            BootDevice::Network => 4,
        };
        Message::new_request(
            NetFn::Reserved(0x3E),
            0x02,
            [OEM_PREFIX.as_slice(), &[0x9D, selection, 0xFF]].concat(),
        )
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(UnexpectedResponseLength(data.len()))
        }
    }

    fn lun(&self) -> LogicalUnit {
        LogicalUnit::Three
    }
}

/// Configure Kontron's channel buffer size. `channel` is 0x0e (current
/// interface) or 0x00 (IPMB); size zero restores the default buffer.
#[derive(Debug, Clone, Copy)]
pub struct SetLargeBuffer {
    /// 0x0e for the current interface, 0x00 for IPMB.
    pub channel: BufferChannel,
    /// Negotiated size, or zero to restore the default.
    pub size: u8,
}

/// The two channels configured by ipmitool's `set_large_buffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferChannel {
    /// The current interface (0x0e).
    Current,
    /// The local controller's IPMB interface (0x00).
    Ipmb,
}

impl SetLargeBuffer {
    /// Route to an IPMB destination; the buffer command itself uses LUN 0.
    pub const fn at(self, target: Option<(Address, Channel)>) -> Routed<Self> {
        Routed::new(self, target)
    }
}

impl OemCommand for SetLargeBuffer {
    type Output = ();
    type Error = UnexpectedResponseLength;
    const MANUFACTURER_ID: u32 = 15000;

    fn into_message(self) -> Message {
        Message::new_request(
            NetFn::Reserved(0x3E),
            0x82,
            vec![
                match self.channel {
                    BufferChannel::Current => 0x0e,
                    BufferChannel::Ipmb => 0,
                },
                self.size,
            ],
        )
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        SetNextBoot::parse_success_response(data)
    }
}
