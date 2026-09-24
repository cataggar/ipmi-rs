//! Bounded Get/Set System Boot Options (IPMI Chassis commands `0x09`/`0x08`).

use std::marker::PhantomData;

use bitflags::bitflags;

use crate::connection::{CompletionErrorCode, IpmiCommand, Message, NetFn};

/// Boot-option selectors supported by these commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOptionSelector {
    /// Parameter 0: set-in-progress.
    SetInProgress,
    /// Parameter 3: boot-flag valid-bit clearing policy.
    ValidBitClearing,
    /// Parameter 4: boot-info acknowledgements.
    BootInfoAcknowledge,
    /// Parameter 5: boot flags.
    BootFlags,
}

impl BootOptionSelector {
    /// The seven-bit parameter selector sent on the wire.
    pub const fn value(self) -> u8 {
        match self {
            Self::SetInProgress => 0,
            Self::ValidBitClearing => 3,
            Self::BootInfoAcknowledge => 4,
            Self::BootFlags => 5,
        }
    }
}

impl TryFrom<u8> for BootOptionSelector {
    type Error = BootOptionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SetInProgress),
            3 => Ok(Self::ValidBitClearing),
            4 => Ok(Self::BootInfoAcknowledge),
            5 => Ok(Self::BootFlags),
            _ => Err(BootOptionError::UnsupportedSelector(value)),
        }
    }
}

/// A boot-option completion code with a command-specific meaning.
///
/// `Ipmi::send_recv` retains the original completion code alongside this
/// error. Other nonzero codes continue to be returned as `IpmiError::Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOptionRejection {
    /// `0x80`: the controller does not support the parameter.
    UnsupportedParameter,
    /// `0x81`: cannot set in-progress unless the current state is complete.
    AlreadyInProgress,
    /// `0x82`: the parameter is read-only.
    ReadOnly,
}

/// A malformed boot option or a command-specific rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOptionError {
    /// Only selectors 0, 3, 4 and 5 are supported.
    UnsupportedSelector(u8),
    /// The response echoed a different selector (expected, actual).
    UnexpectedSelector { expected: u8, actual: u8 },
    /// Expected and actual response or parameter-data lengths.
    InvalidLength { expected: usize, actual: usize },
    /// Only boot parameter version 1 is understood.
    UnsupportedRevision(u8),
    /// The response selector has its invalid/locked bit set.
    InvalidOrLocked(u8),
    /// Invalid value for a parameter selector.
    InvalidValue { selector: u8, value: u8 },
    /// Boot-device encoding not supported by this implementation.
    UnsupportedBootDevice(u8),
    /// Unmodelled flag bits in a boot-flags byte (zero-based index, value).
    UnsupportedBootFlags { byte: usize, value: u8 },
    /// Controller rejected the command (the completion code is also retained).
    Rejected(BootOptionRejection),
}

fn completion_error(code: CompletionErrorCode) -> Option<BootOptionError> {
    let rejection = match code {
        CompletionErrorCode::CommandSpecific(0x80) => BootOptionRejection::UnsupportedParameter,
        CompletionErrorCode::CommandSpecific(0x81) => BootOptionRejection::AlreadyInProgress,
        CompletionErrorCode::CommandSpecific(0x82) => BootOptionRejection::ReadOnly,
        _ => return None,
    };
    Some(BootOptionError::Rejected(rejection))
}

mod private {
    pub trait Sealed {}
}

/// One of the four supported, fixed-size System Boot Options parameters.
///
/// The trait is sealed: Get responses always have a known selector, length,
/// and output type, allowing the echoed selector to be checked.
pub trait BootParameter: private::Sealed + Sized {
    /// Parameter selector.
    const SELECTOR: BootOptionSelector;
    /// Length of parameter data, excluding revision and selector.
    const LENGTH: usize;

    /// Validate and parse parameter data without its revision or selector.
    fn parse(data: &[u8]) -> Result<Self, BootOptionError>;
}

fn check_parameter_length<P: BootParameter>(data: &[u8]) -> Result<(), BootOptionError> {
    if data.len() != P::LENGTH {
        return Err(BootOptionError::InvalidLength {
            expected: P::LENGTH,
            actual: data.len(),
        });
    }
    Ok(())
}

fn parse_parameter<P: BootParameter>(data: &[u8]) -> Result<P, BootOptionError> {
    check_parameter_length::<P>(data)?;
    P::parse(data)
}

/// Get exactly one supported boot option from the BMC.
///
/// For example, `GetSystemBootOptions::<BootFlags>::new()` returns
/// [`BootFlags`], while `GetSystemBootOptions::<SetInProgress>::new()` returns
/// [`SetInProgress`]. No other selector, set selector, or block selector can be
/// sent using this command.
#[derive(Debug, Clone, Copy)]
pub struct GetSystemBootOptions<P: BootParameter>(PhantomData<P>);

impl<P: BootParameter> GetSystemBootOptions<P> {
    /// Create a request for this parameter type.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P: BootParameter> Default for GetSystemBootOptions<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: BootParameter> From<GetSystemBootOptions<P>> for Message {
    fn from(_: GetSystemBootOptions<P>) -> Self {
        Message::new_request(NetFn::Chassis, 0x09, vec![P::SELECTOR.value(), 0, 0])
    }
}

impl<P: BootParameter> IpmiCommand for GetSystemBootOptions<P> {
    type Output = P;
    type Error = BootOptionError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let expected = 2 + P::LENGTH;
        if data.len() != expected {
            return Err(BootOptionError::InvalidLength {
                expected,
                actual: data.len(),
            });
        }
        if data[0] != 0x01 {
            return Err(BootOptionError::UnsupportedRevision(data[0]));
        }
        let selector = data[1] & 0x7F;
        if selector != P::SELECTOR.value() {
            return Err(BootOptionError::UnexpectedSelector {
                expected: P::SELECTOR.value(),
                actual: selector,
            });
        }
        if data[1] & 0x80 != 0 {
            return Err(BootOptionError::InvalidOrLocked(selector));
        }
        parse_parameter::<P>(&data[2..])
    }
}

/// The set-in-progress state (parameter 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetInProgress {
    /// A set is complete (`0`).
    Complete,
    /// A set is in progress (`1`).
    InProgress,
    /// Commit the preceding write (`2`).
    CommitWrite,
}

impl SetInProgress {
    fn value(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::InProgress => 1,
            Self::CommitWrite => 2,
        }
    }
}

impl private::Sealed for SetInProgress {}
impl BootParameter for SetInProgress {
    const SELECTOR: BootOptionSelector = BootOptionSelector::SetInProgress;
    const LENGTH: usize = 1;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        match data[0] {
            0 => Ok(Self::Complete),
            1 => Ok(Self::InProgress),
            2 => Ok(Self::CommitWrite),
            value => Err(BootOptionError::InvalidValue { selector: 0, value }),
        }
    }
}

bitflags! {
    /// Parameter 3: conditions under which the BMC must NOT clear the boot-flag valid bit.
    ///
    /// An empty value permits the normal automatic valid-bit clearing behavior.
    pub struct BootValidBitClearing: u8 {
        /// Retain on PEF reset or power cycle.
        const PEF = 0x10;
        /// Retain on automatic timeout.
        const TIMEOUT = 0x08;
        /// Retain on watchdog reset or power cycle.
        const WATCHDOG = 0x04;
        /// Retain on push-button or soft reset.
        const RESET = 0x02;
        /// Retain on power-up via push button or wake event.
        const POWER = 0x01;
    }
}

impl private::Sealed for BootValidBitClearing {}
impl BootParameter for BootValidBitClearing {
    const SELECTOR: BootOptionSelector = BootOptionSelector::ValidBitClearing;
    const LENGTH: usize = 1;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        Self::from_bits(data[0]).ok_or(BootOptionError::InvalidValue {
            selector: 3,
            value: data[0],
        })
    }
}

bitflags! {
    /// Boot-info acknowledgement actors; only the five defined bits are supported.
    pub struct BootInfoActors: u8 {
        /// BIOS/POST.
        const BIOS_POST = 0x01;
        /// OS loader.
        const OS_LOADER = 0x02;
        /// OS or service partition.
        const OS_SERVICE_PARTITION = 0x04;
        /// System management software.
        const SMS = 0x08;
        /// OEM.
        const OEM = 0x10;
    }
}

/// Parameter 4: acknowledgement write mask and flags.
///
/// Setting this parameter affects only the actors selected in `write_mask`;
/// it is never changed implicitly while setting parameter 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfoAcknowledge {
    /// Actors whose acknowledgement bits should be written.
    pub write_mask: BootInfoActors,
    /// Acknowledgement flags for the selected actors.
    pub flags: BootInfoActors,
}

impl BootInfoAcknowledge {
    /// Specify exactly which acknowledgement bits to write.
    pub fn new(write_mask: BootInfoActors, flags: BootInfoActors) -> Self {
        Self { write_mask, flags }
    }
}

impl private::Sealed for BootInfoAcknowledge {}
impl BootParameter for BootInfoAcknowledge {
    const SELECTOR: BootOptionSelector = BootOptionSelector::BootInfoAcknowledge;
    const LENGTH: usize = 2;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        let write_mask =
            BootInfoActors::from_bits(data[0]).ok_or(BootOptionError::InvalidValue {
                selector: 4,
                value: data[0],
            })?;
        let flags = BootInfoActors::from_bits(data[1]).ok_or(BootOptionError::InvalidValue {
            selector: 4,
            value: data[1],
        })?;
        Ok(Self { write_mask, flags })
    }
}

/// Boot-device selector (parameter 5, second byte, bits `[5:2]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDevice {
    /// Use the normal boot order.
    NoOverride,
    /// Boot from PXE.
    Pxe,
    /// Boot from the default hard drive.
    HardDrive,
    /// Boot from the default hard drive in safe mode.
    SafeMode,
    /// Boot from the diagnostic partition.
    DiagnosticPartition,
    /// Boot from CD/DVD.
    CdRom,
    /// Enter BIOS setup.
    BiosSetup,
    /// Boot from a remotely connected floppy.
    RemoteFloppy,
    /// Boot from a remotely connected CD/DVD.
    RemoteCdRom,
    /// Boot from the primary remote media.
    RemotePrimaryMedia,
    /// Boot from a remotely connected hard drive.
    RemoteHardDrive,
    /// Boot from a floppy or primary removable media.
    Floppy,
}

impl BootDevice {
    /// The unshifted four-bit boot-device code.
    pub const fn value(self) -> u8 {
        match self {
            Self::NoOverride => 0,
            Self::Pxe => 1,
            Self::HardDrive => 2,
            Self::SafeMode => 3,
            Self::DiagnosticPartition => 4,
            Self::CdRom => 5,
            Self::BiosSetup => 6,
            Self::RemoteFloppy => 7,
            Self::RemoteCdRom => 8,
            Self::RemotePrimaryMedia => 9,
            Self::RemoteHardDrive => 11,
            Self::Floppy => 15,
        }
    }
}

impl TryFrom<u8> for BootDevice {
    type Error = BootOptionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoOverride),
            1 => Ok(Self::Pxe),
            2 => Ok(Self::HardDrive),
            3 => Ok(Self::SafeMode),
            4 => Ok(Self::DiagnosticPartition),
            5 => Ok(Self::CdRom),
            6 => Ok(Self::BiosSetup),
            7 => Ok(Self::RemoteFloppy),
            8 => Ok(Self::RemoteCdRom),
            9 => Ok(Self::RemotePrimaryMedia),
            11 => Ok(Self::RemoteHardDrive),
            15 => Ok(Self::Floppy),
            _ => Err(BootOptionError::UnsupportedBootDevice(value)),
        }
    }
}

/// Whether a valid boot override applies once or to all future boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOverrideDuration {
    /// Only the next boot (`0x80` in the first flag byte).
    OneTime,
    /// All future boots (`0xC0` in the first flag byte).
    Persistent,
}

/// The supported portion of parameter 5's five boot-flag bytes.
///
/// Encoding always marks the override valid. EFI and clear-CMOS are opt-in;
/// all other boot-flag fields are zero, not copied from a previous readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootOverride {
    /// Target boot device.
    pub device: BootDevice,
    /// One-time or persistent override.
    pub duration: BootOverrideDuration,
    /// Request EFI rather than legacy boot.
    pub efi: bool,
    /// Request clearing CMOS during boot.
    pub clear_cmos: bool,
}

impl BootOverride {
    /// Create a valid override with EFI and clear-CMOS disabled.
    pub fn new(device: BootDevice, duration: BootOverrideDuration) -> Self {
        Self {
            device,
            duration,
            efi: false,
            clear_cmos: false,
        }
    }

    /// Explicitly request (or disable) EFI boot.
    pub fn with_efi(mut self, efi: bool) -> Self {
        self.efi = efi;
        self
    }

    /// Explicitly request (or disable) clearing CMOS during boot.
    pub fn with_clear_cmos(mut self, clear_cmos: bool) -> Self {
        self.clear_cmos = clear_cmos;
        self
    }

    /// The full five-byte boot-flags payload, excluding parameter selector 5.
    pub fn to_bytes(self) -> [u8; 5] {
        let first =
            0x80 | if self.duration == BootOverrideDuration::Persistent {
                0x40
            } else {
                0
            } | if self.efi { 0x20 } else { 0 };
        let second = (self.device.value() << 2) | if self.clear_cmos { 0x80 } else { 0 };
        [first, second, 0, 0, 0]
    }
}

/// Readback of parameter 5. An invalid flag is not an active boot override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFlags {
    /// Valid bit is clear; other fields must not be treated as an active override.
    Invalid,
    /// Valid bit is set; contains the explicitly modelled boot flags.
    Valid(BootOverride),
}

impl private::Sealed for BootFlags {}
impl BootParameter for BootFlags {
    const SELECTOR: BootOptionSelector = BootOptionSelector::BootFlags;
    const LENGTH: usize = 5;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        for (byte, (value, allowed)) in data.iter().zip([0xE0, 0xBC, 0x00, 0x00, 0x00]).enumerate()
        {
            if value & !allowed != 0 {
                return Err(BootOptionError::UnsupportedBootFlags {
                    byte,
                    value: *value,
                });
            }
        }
        let device = BootDevice::try_from((data[1] >> 2) & 0x0F)?;
        if data[0] & 0x80 == 0 {
            return Ok(Self::Invalid);
        }
        Ok(Self::Valid(BootOverride {
            device,
            duration: if data[0] & 0x40 == 0 {
                BootOverrideDuration::OneTime
            } else {
                BootOverrideDuration::Persistent
            },
            efi: data[0] & 0x20 != 0,
            clear_cmos: data[1] & 0x80 != 0,
        }))
    }
}

/// A typed write to exactly one supported boot-option selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOptionWrite {
    /// Parameter 0.
    SetInProgress(SetInProgress),
    /// Parameter 3.
    ValidBitClearing(BootValidBitClearing),
    /// Parameter 4.
    BootInfoAcknowledge(BootInfoAcknowledge),
    /// Parameter 5, always marked valid.
    BootFlags(BootOverride),
}

impl BootOptionWrite {
    /// Parse a bounded write payload (excluding its selector) for supported selectors.
    ///
    /// Reserved bits, invalid boot devices, invalid flag state, and unexpected
    /// lengths are rejected rather than silently truncated or masked.
    pub fn try_from_raw(selector: u8, data: &[u8]) -> Result<Self, BootOptionError> {
        match BootOptionSelector::try_from(selector)? {
            BootOptionSelector::SetInProgress => {
                Ok(Self::SetInProgress(parse_parameter::<SetInProgress>(data)?))
            }
            BootOptionSelector::ValidBitClearing => Ok(Self::ValidBitClearing(parse_parameter::<
                BootValidBitClearing,
            >(data)?)),
            BootOptionSelector::BootInfoAcknowledge => {
                Ok(Self::BootInfoAcknowledge(parse_parameter::<
                    BootInfoAcknowledge,
                >(data)?))
            }
            BootOptionSelector::BootFlags => match parse_parameter::<BootFlags>(data)? {
                BootFlags::Valid(value) => Ok(Self::BootFlags(value)),
                BootFlags::Invalid => Err(BootOptionError::InvalidValue {
                    selector: 5,
                    value: data[0],
                }),
            },
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::SetInProgress(value) => vec![0, value.value()],
            Self::ValidBitClearing(value) => vec![3, value.bits()],
            Self::BootInfoAcknowledge(value) => {
                vec![4, value.write_mask.bits(), value.flags.bits()]
            }
            Self::BootFlags(value) => {
                let mut bytes = Vec::with_capacity(6);
                bytes.push(5);
                bytes.extend_from_slice(&value.to_bytes());
                bytes
            }
        }
    }
}

/// Set exactly one boot option. No Get/merge/Set, progress lock, acknowledgement
/// write, host control, or retry is performed implicitly.
///
/// Setting parameter 5 replaces *all five bytes* of boot flags, resetting
/// unmodelled options to zero. A timeout has an unknown outcome and should
/// not cause an automatic replay. Controller/BIOS support varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetSystemBootOptions(pub BootOptionWrite);

impl SetSystemBootOptions {
    /// Create a typed one-parameter write.
    pub fn new(option: BootOptionWrite) -> Self {
        Self(option)
    }

    /// Validate a selector and payload before constructing a write.
    pub fn try_from_raw(selector: u8, data: &[u8]) -> Result<Self, BootOptionError> {
        Ok(Self(BootOptionWrite::try_from_raw(selector, data)?))
    }
}

impl From<SetSystemBootOptions> for Message {
    fn from(value: SetSystemBootOptions) -> Self {
        Message::new_request(NetFn::Chassis, 0x08, value.0.to_bytes())
    }
}

impl IpmiCommand for SetSystemBootOptions {
    type Output = ();
    type Error = BootOptionError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(BootOptionError::InvalidLength {
                expected: 0,
                actual: data.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_message<P: BootParameter>() -> Message {
        Message::from(GetSystemBootOptions::<P>::new())
    }

    #[test]
    fn get_requests_use_only_supported_selectors_and_zero_set_and_block() {
        for (message, selector) in [
            (get_message::<SetInProgress>(), 0),
            (get_message::<BootValidBitClearing>(), 3),
            (get_message::<BootInfoAcknowledge>(), 4),
            (get_message::<BootFlags>(), 5),
        ] {
            assert_eq!(message.netfn_raw(), 0x00);
            assert_eq!(message.cmd(), 0x09);
            assert_eq!(message.data(), &[selector, 0, 0]);
        }
        for unsupported in [1, 2, 6, 7, 0x80, 0xFF] {
            assert_eq!(
                BootOptionSelector::try_from(unsupported),
                Err(BootOptionError::UnsupportedSelector(unsupported))
            );
        }
    }

    #[test]
    fn set_requests_are_full_explicit_payloads() {
        let pxe = BootOverride::new(BootDevice::Pxe, BootOverrideDuration::OneTime);
        let cd = BootOverride::new(BootDevice::CdRom, BootOverrideDuration::Persistent);
        let cases = [
            (
                BootOptionWrite::BootFlags(pxe),
                vec![5, 0x80, 0x04, 0, 0, 0],
            ),
            (BootOptionWrite::BootFlags(cd), vec![5, 0xC0, 0x14, 0, 0, 0]),
            (
                BootOptionWrite::BootFlags(pxe.with_clear_cmos(true)),
                vec![5, 0x80, 0x84, 0, 0, 0],
            ),
            (
                BootOptionWrite::BootFlags(pxe.with_efi(true)),
                vec![5, 0xA0, 0x04, 0, 0, 0],
            ),
            (
                BootOptionWrite::SetInProgress(SetInProgress::Complete),
                vec![0, 0],
            ),
            (
                BootOptionWrite::SetInProgress(SetInProgress::InProgress),
                vec![0, 1],
            ),
            (
                BootOptionWrite::SetInProgress(SetInProgress::CommitWrite),
                vec![0, 2],
            ),
            (
                BootOptionWrite::ValidBitClearing(
                    BootValidBitClearing::PEF | BootValidBitClearing::TIMEOUT,
                ),
                vec![3, 0x18],
            ),
            (
                BootOptionWrite::BootInfoAcknowledge(BootInfoAcknowledge::new(
                    BootInfoActors::BIOS_POST | BootInfoActors::SMS,
                    BootInfoActors::BIOS_POST,
                )),
                vec![4, 0x09, 0x01],
            ),
        ];
        for (option, data) in cases {
            let message = Message::from(SetSystemBootOptions::new(option));
            assert_eq!(message.netfn_raw(), 0x00);
            assert_eq!(message.cmd(), 0x08);
            assert_eq!(message.data(), data);
            assert_eq!(
                BootOptionWrite::try_from_raw(data[0], &data[1..]),
                Ok(option)
            );
        }
        assert_eq!(SetSystemBootOptions::parse_success_response(&[]), Ok(()));
        assert_eq!(
            SetSystemBootOptions::parse_success_response(&[1]),
            Err(BootOptionError::InvalidLength {
                expected: 0,
                actual: 1
            })
        );
    }

    #[test]
    fn get_returns_typed_fields_and_marks_invalid_flags_inactive() {
        assert_eq!(
            GetSystemBootOptions::<SetInProgress>::parse_success_response(&[1, 0, 1]),
            Ok(SetInProgress::InProgress)
        );
        assert_eq!(
            GetSystemBootOptions::<BootValidBitClearing>::parse_success_response(&[1, 3, 0x12]),
            Ok(BootValidBitClearing::PEF | BootValidBitClearing::RESET)
        );
        assert_eq!(
            GetSystemBootOptions::<BootInfoAcknowledge>::parse_success_response(&[1, 4, 1, 2]),
            Ok(BootInfoAcknowledge::new(
                BootInfoActors::BIOS_POST,
                BootInfoActors::OS_LOADER
            ))
        );
        let pxe = BootOverride::new(BootDevice::Pxe, BootOverrideDuration::OneTime);
        let cd = BootOverride::new(BootDevice::CdRom, BootOverrideDuration::Persistent);
        for (data, expected) in [
            ([1, 5, 0x80, 0x04, 0, 0, 0], BootFlags::Valid(pxe)),
            ([1, 5, 0xC0, 0x14, 0, 0, 0], BootFlags::Valid(cd)),
            (
                [1, 5, 0xA0, 0x84, 0, 0, 0],
                BootFlags::Valid(pxe.with_clear_cmos(true).with_efi(true)),
            ),
            ([1, 5, 0, 0, 0, 0, 0], BootFlags::Invalid),
            ([1, 5, 0, 4, 0, 0, 0], BootFlags::Invalid),
        ] {
            assert_eq!(
                GetSystemBootOptions::<BootFlags>::parse_success_response(&data),
                Ok(expected)
            );
        }
    }

    #[test]
    fn get_rejects_invalid_headers_lengths_and_values() {
        type Get = GetSystemBootOptions<BootFlags>;
        assert_eq!(
            Get::parse_success_response(&[1, 5, 0x80]),
            Err(BootOptionError::InvalidLength {
                expected: 7,
                actual: 3
            })
        );
        assert_eq!(
            Get::parse_success_response(&[1, 5, 0x80, 4, 0, 0, 0, 0]),
            Err(BootOptionError::InvalidLength {
                expected: 7,
                actual: 8
            })
        );
        assert_eq!(
            Get::parse_success_response(&[2, 5, 0x80, 4, 0, 0, 0]),
            Err(BootOptionError::UnsupportedRevision(2))
        );
        assert_eq!(
            Get::parse_success_response(&[1, 3, 0x80, 4, 0, 0, 0]),
            Err(BootOptionError::UnexpectedSelector {
                expected: 5,
                actual: 3
            })
        );
        assert_eq!(
            Get::parse_success_response(&[1, 0x85, 0x80, 4, 0, 0, 0]),
            Err(BootOptionError::InvalidOrLocked(5))
        );
        assert_eq!(
            GetSystemBootOptions::<SetInProgress>::parse_success_response(&[1, 0, 3]),
            Err(BootOptionError::InvalidValue {
                selector: 0,
                value: 3
            })
        );
        assert_eq!(
            GetSystemBootOptions::<BootValidBitClearing>::parse_success_response(&[1, 3, 0x80]),
            Err(BootOptionError::InvalidValue {
                selector: 3,
                value: 0x80
            })
        );
        assert_eq!(
            GetSystemBootOptions::<BootInfoAcknowledge>::parse_success_response(&[1, 4, 0, 0x20]),
            Err(BootOptionError::InvalidValue {
                selector: 4,
                value: 0x20
            })
        );
        assert_eq!(
            Get::parse_success_response(&[1, 5, 0x80, 0x28, 0, 0, 0]),
            Err(BootOptionError::UnsupportedBootDevice(10))
        );
        for (byte, data) in [
            (0, [1, 5, 0x81, 4, 0, 0, 0]),
            (1, [1, 5, 0x80, 0x44, 0, 0, 0]),
            (2, [1, 5, 0x80, 4, 1, 0, 0]),
            (3, [1, 5, 0x80, 4, 0, 1, 0]),
            (4, [1, 5, 0x80, 4, 0, 0, 1]),
        ] {
            assert_eq!(
                Get::parse_success_response(&data),
                Err(BootOptionError::UnsupportedBootFlags {
                    byte,
                    value: data[byte + 2]
                })
            );
        }
    }

    #[test]
    fn set_rejects_unsupported_and_malformed_inputs_before_sending() {
        for (expected, actual, error) in [
            (1, 0, SetInProgress::parse(&[]).map(|_| ()).unwrap_err()),
            (
                1,
                0,
                BootValidBitClearing::parse(&[]).map(|_| ()).unwrap_err(),
            ),
            (
                2,
                1,
                BootInfoAcknowledge::parse(&[0]).map(|_| ()).unwrap_err(),
            ),
            (5, 0, BootFlags::parse(&[]).map(|_| ()).unwrap_err()),
        ] {
            assert_eq!(error, BootOptionError::InvalidLength { expected, actual });
        }
        assert_eq!(
            BootOptionWrite::try_from_raw(6, &[1]),
            Err(BootOptionError::UnsupportedSelector(6))
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(0, &[3]),
            Err(BootOptionError::InvalidValue {
                selector: 0,
                value: 3
            })
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(3, &[0x80]),
            Err(BootOptionError::InvalidValue {
                selector: 3,
                value: 0x80
            })
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(4, &[0, 0]),
            Ok(BootOptionWrite::BootInfoAcknowledge(
                BootInfoAcknowledge::new(BootInfoActors::empty(), BootInfoActors::empty())
            ))
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(4, &[0]),
            Err(BootOptionError::InvalidLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(5, &[0, 4, 0, 0, 0]),
            Err(BootOptionError::InvalidValue {
                selector: 5,
                value: 0
            })
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(5, &[0x80, 4, 0, 0]),
            Err(BootOptionError::InvalidLength {
                expected: 5,
                actual: 4
            })
        );
        assert_eq!(
            BootDevice::try_from(10),
            Err(BootOptionError::UnsupportedBootDevice(10))
        );
    }
}
