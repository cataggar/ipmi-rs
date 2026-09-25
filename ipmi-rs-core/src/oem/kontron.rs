//! Kontron CP6012 next-boot control and Kontron manufacturing-date query.

use crate::connection::{LogicalUnit, Message, NetFn, NotEnoughData};

use super::OemCommand;

const OEM_PREFIX: [u8; 4] = [0xB4, 0x90, 0x91, 0x8B];

/// Read the three raw FRU manufacturing-date bytes from the Kontron OEM command.
///
/// This only queries the controller; `kontronoem setmfgdate` additionally
/// modifies the FRU board area and is not represented here.
#[derive(Debug, Clone, Copy)]
pub struct GetManufacturingDate;

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
