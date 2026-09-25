//! Bounded Get/Set System Boot Options (IPMI Chassis commands `0x09`/`0x08`).

use std::marker::PhantomData;

use bitflags::bitflags;

use crate::connection::{CompletionErrorCode, IpmiCommand, Message, NetFn};

/// Standard System Boot Options parameter selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOptionSelector {
    /// Parameter 0: set-in-progress.
    SetInProgress,
    /// Parameter 1: service partition selector.
    ServicePartitionSelector,
    /// Parameter 2: service partition scan.
    ServicePartitionScan,
    /// Parameter 3: boot-flag valid-bit clearing policy.
    ValidBitClearing,
    /// Parameter 4: boot-info acknowledgements.
    BootInfoAcknowledge,
    /// Parameter 5: boot flags.
    BootFlags,
    /// Parameter 6: boot initiator information.
    BootInitiatorInfo,
    /// Parameter 7: block-addressed boot initiator mailbox.
    BootMailbox,
}

impl BootOptionSelector {
    /// The seven-bit parameter selector sent on the wire.
    pub const fn value(self) -> u8 {
        match self {
            Self::SetInProgress => 0,
            Self::ServicePartitionSelector => 1,
            Self::ServicePartitionScan => 2,
            Self::ValidBitClearing => 3,
            Self::BootInfoAcknowledge => 4,
            Self::BootFlags => 5,
            Self::BootInitiatorInfo => 6,
            Self::BootMailbox => 7,
        }
    }
}

impl TryFrom<u8> for BootOptionSelector {
    type Error = BootOptionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SetInProgress),
            1 => Ok(Self::ServicePartitionSelector),
            2 => Ok(Self::ServicePartitionScan),
            3 => Ok(Self::ValidBitClearing),
            4 => Ok(Self::BootInfoAcknowledge),
            5 => Ok(Self::BootFlags),
            6 => Ok(Self::BootInitiatorInfo),
            7 => Ok(Self::BootMailbox),
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
    /// The requested selector has no typed write/read interface.
    UnsupportedSelector(u8),
    /// The response echoed a different selector (expected, actual).
    UnexpectedSelector { expected: u8, actual: u8 },
    /// Expected and actual response or parameter-data lengths.
    InvalidLength { expected: usize, actual: usize },
    /// Response length is outside the allowed inclusive range.
    InvalidLengthRange {
        /// Minimum allowed number of bytes.
        minimum: usize,
        /// Maximum allowed number of bytes.
        maximum: usize,
        /// Number of bytes received or supplied.
        actual: usize,
    },
    /// Only boot parameter version 1 is understood.
    UnsupportedRevision(u8),
    /// The response selector has its invalid/locked bit set.
    InvalidOrLocked(u8),
    /// Invalid value for a parameter selector.
    InvalidValue { selector: u8, value: u8 },
    /// The mailbox block index in a reply differs from the requested block.
    UnexpectedBlock { expected: u8, actual: u8 },
    /// Block zero requires an IANA PEN; later blocks cannot carry one.
    InvalidMailboxIana,
    /// IANA PEN exceeds its 24-bit wire representation.
    InvalidIana(u32),
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

/// A supported fixed-size System Boot Options parameter.
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

/// Get exactly one fixed-size boot option from the BMC.
///
/// For example, `GetSystemBootOptions::<BootFlags>::new()` returns
/// [`BootFlags`], while `GetSystemBootOptions::<SetInProgress>::new()` returns
/// [`SetInProgress`]. Mailbox blocks have a separate block-addressed command.
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

/// Parameter 1: zero means unspecified; other values select a service partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePartitionSelector(pub u8);

impl private::Sealed for ServicePartitionSelector {}
impl BootParameter for ServicePartitionSelector {
    const SELECTOR: BootOptionSelector = BootOptionSelector::ServicePartitionSelector;
    const LENGTH: usize = 1;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        Ok(Self(data[0]))
    }
}

/// Parameter 2: BMC request and BIOS-discovered status are distinct bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePartitionScan {
    /// No scan requested or discovered.
    None,
    /// Request BIOS to scan for a service partition.
    ScanRequested,
    /// BIOS reported that it discovered a service partition.
    Discovered,
    /// Both bits were set.
    ScanRequestedAndDiscovered,
    /// Reserved or controller-specific bits, retained for read-only inspection.
    Unknown(u8),
}

impl private::Sealed for ServicePartitionScan {}
impl BootParameter for ServicePartitionScan {
    const SELECTOR: BootOptionSelector = BootOptionSelector::ServicePartitionScan;
    const LENGTH: usize = 1;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        Ok(match data[0] {
            0 => Self::None,
            1 => Self::ScanRequested,
            2 => Self::Discovered,
            3 => Self::ScanRequestedAndDiscovered,
            other => Self::Unknown(other),
        })
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

/// Parameter 6: information recorded about the boot initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInitiatorInfo {
    /// Channel byte, including reserved bits for lossless readback.
    pub raw_channel: u8,
    /// Session identifier in little-endian wire order.
    pub session_id: u32,
    /// IPMI timestamp in little-endian wire order.
    pub timestamp: u32,
}

impl BootInitiatorInfo {
    /// The four-bit channel number.
    pub const fn channel(self) -> u8 {
        self.raw_channel & 0x0f
    }
}

impl private::Sealed for BootInitiatorInfo {}
impl BootParameter for BootInitiatorInfo {
    const SELECTOR: BootOptionSelector = BootOptionSelector::BootInitiatorInfo;
    const LENGTH: usize = 9;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        Ok(Self {
            raw_channel: data[0],
            session_id: u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
            timestamp: u32::from_le_bytes([data[5], data[6], data[7], data[8]]),
        })
    }
}

/// A validated parameter 6 write, never constructed from unknown readback bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInitiatorInfoWrite {
    channel: u8,
    session_id: u32,
    timestamp: u32,
}

impl BootInitiatorInfoWrite {
    /// Create a boot initiator entry with a valid four-bit channel number.
    pub fn new(channel: u8, session_id: u32, timestamp: u32) -> Result<Self, BootOptionError> {
        if channel > 0x0f {
            return Err(BootOptionError::InvalidValue {
                selector: 6,
                value: channel,
            });
        }
        Ok(Self {
            channel,
            session_id,
            timestamp,
        })
    }

    fn to_bytes(self) -> [u8; 9] {
        let mut data = [0; 9];
        data[0] = self.channel;
        data[1..5].copy_from_slice(&self.session_id.to_le_bytes());
        data[5..9].copy_from_slice(&self.timestamp.to_le_bytes());
        data
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
    /// Unmodelled fields or device: raw bytes retained for read-only inspection.
    ///
    /// These bytes cannot be passed to a typed boot-flags write.
    Unknown([u8; 5]),
}

impl private::Sealed for BootFlags {}
impl BootParameter for BootFlags {
    const SELECTOR: BootOptionSelector = BootOptionSelector::BootFlags;
    const LENGTH: usize = 5;

    fn parse(data: &[u8]) -> Result<Self, BootOptionError> {
        check_parameter_length::<Self>(data)?;
        let raw: [u8; 5] = data.try_into().expect("checked boot flag length");
        for (value, allowed) in data.iter().zip([0xE0, 0xBC, 0x00, 0x00, 0x00]) {
            if value & !allowed != 0 {
                return Ok(Self::Unknown(raw));
            }
        }
        let device = match BootDevice::try_from((data[1] >> 2) & 0x0F) {
            Ok(device) => device,
            Err(_) => return Ok(Self::Unknown(raw)),
        };
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
    /// Parameter 1.
    ServicePartitionSelector(ServicePartitionSelector),
    /// Parameter 2: request or clear a BIOS scan; never writes discovered status.
    ServicePartitionScanRequest(bool),
    /// Parameter 3.
    ValidBitClearing(BootValidBitClearing),
    /// Parameter 4.
    BootInfoAcknowledge(BootInfoAcknowledge),
    /// Parameter 5, always marked valid.
    BootFlags(BootOverride),
    /// Parameter 6, with a validated channel number.
    BootInitiatorInfo(BootInitiatorInfoWrite),
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
            BootOptionSelector::ServicePartitionSelector => {
                Ok(Self::ServicePartitionSelector(parse_parameter::<
                    ServicePartitionSelector,
                >(data)?))
            }
            BootOptionSelector::ServicePartitionScan => {
                check_parameter_length::<ServicePartitionScan>(data)?;
                match data[0] {
                    0 | 1 => Ok(Self::ServicePartitionScanRequest(data[0] != 0)),
                    value => Err(BootOptionError::InvalidValue { selector: 2, value }),
                }
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
                BootFlags::Unknown(_) => {
                    for (byte, (value, allowed)) in
                        data.iter().zip([0xE0, 0xBC, 0, 0, 0]).enumerate()
                    {
                        if value & !allowed != 0 {
                            return Err(BootOptionError::UnsupportedBootFlags {
                                byte,
                                value: *value,
                            });
                        }
                    }
                    Err(BootOptionError::UnsupportedBootDevice(
                        (data[1] >> 2) & 0x0f,
                    ))
                }
            },
            BootOptionSelector::BootInitiatorInfo => {
                check_parameter_length::<BootInitiatorInfo>(data)?;
                Ok(Self::BootInitiatorInfo(BootInitiatorInfoWrite::new(
                    data[0],
                    u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
                    u32::from_le_bytes([data[5], data[6], data[7], data[8]]),
                )?))
            }
            BootOptionSelector::BootMailbox => Err(BootOptionError::UnsupportedSelector(7)),
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::SetInProgress(value) => vec![0, value.value()],
            Self::ServicePartitionSelector(value) => vec![1, value.0],
            Self::ServicePartitionScanRequest(scan) => vec![2, u8::from(scan)],
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
            Self::BootInitiatorInfo(value) => {
                let mut bytes = vec![6];
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

/// Lossless read-only response for unsupported or controller-specific selectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBootOption {
    /// Version byte as returned by the controller (not interpreted).
    pub revision: u8,
    /// Echoed parameter selector.
    pub selector: u8,
    /// Whether the BMC marked this parameter invalid or locked.
    pub invalid_or_locked: bool,
    /// Uninterpreted parameter bytes; never accepted by a typed write.
    pub data: Vec<u8>,
}

/// Read any seven-bit boot selector without enabling arbitrary writes.
///
/// The set and block selectors are passed through explicitly; use the typed
/// [`GetBootMailboxBlock`] for parameter 7 when block validation is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetRawBootOption {
    selector: u8,
    set_selector: u8,
    block_selector: u8,
}

impl GetRawBootOption {
    /// Reject selector bit 7, reserved for the response's invalid/locked flag.
    pub fn new(
        selector: u8,
        set_selector: u8,
        block_selector: u8,
    ) -> Result<Self, BootOptionError> {
        if selector & 0x80 != 0 {
            return Err(BootOptionError::UnsupportedSelector(selector));
        }
        Ok(Self {
            selector,
            set_selector,
            block_selector,
        })
    }
}

impl From<GetRawBootOption> for Message {
    fn from(request: GetRawBootOption) -> Self {
        Message::new_request(
            NetFn::Chassis,
            0x09,
            vec![
                request.selector,
                request.set_selector,
                request.block_selector,
            ],
        )
    }
}

impl IpmiCommand for GetRawBootOption {
    type Output = RawBootOption;
    type Error = BootOptionError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if !(2..=255).contains(&data.len()) {
            return Err(BootOptionError::InvalidLengthRange {
                minimum: 2,
                maximum: 255,
                actual: data.len(),
            });
        }
        Ok(RawBootOption {
            revision: data[0],
            selector: data[1] & 0x7f,
            invalid_or_locked: data[1] & 0x80 != 0,
            data: data[2..].to_vec(),
        })
    }
}

/// One variable-length block of boot initiator mailbox parameter 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootMailboxBlock {
    /// The requested and echoed block number.
    pub block: u8,
    /// Block 0's 24-bit little-endian IANA enterprise number.
    pub iana: Option<u32>,
    /// At most 13 bytes for block 0, or 16 bytes for any other block.
    pub data: Vec<u8>,
}

/// Read one block, without fetching any further blocks implicitly.
///
/// The compile-time block index permits `IpmiCommand` to verify the echoed
/// block even though its response parser does not receive the request value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetBootMailboxBlock<const BLOCK: u8>;

impl<const BLOCK: u8> GetBootMailboxBlock<BLOCK> {
    /// Select this block (0 through 255); `0xc9` may indicate end of mailbox.
    pub const fn new() -> Self {
        Self
    }

    /// Parse a response for the requested block, including its echoed index.
    pub fn parse_block_response(&self, data: &[u8]) -> Result<BootMailboxBlock, BootOptionError> {
        let minimum = if BLOCK == 0 { 6 } else { 3 };
        if !(minimum..=19).contains(&data.len()) {
            return Err(BootOptionError::InvalidLengthRange {
                minimum,
                maximum: 19,
                actual: data.len(),
            });
        }
        if data[0] != 1 {
            return Err(BootOptionError::UnsupportedRevision(data[0]));
        }
        let selector = data[1] & 0x7f;
        if selector != 7 {
            return Err(BootOptionError::UnexpectedSelector {
                expected: 7,
                actual: selector,
            });
        }
        if data[1] & 0x80 != 0 {
            return Err(BootOptionError::InvalidOrLocked(7));
        }
        if data[2] != BLOCK {
            return Err(BootOptionError::UnexpectedBlock {
                expected: BLOCK,
                actual: data[2],
            });
        }
        let iana = if BLOCK == 0 {
            Some(u32::from_le_bytes([data[3], data[4], data[5], 0]))
        } else {
            None
        };
        Ok(BootMailboxBlock {
            block: BLOCK,
            iana,
            data: data[minimum..].to_vec(),
        })
    }
}

impl<const BLOCK: u8> Default for GetBootMailboxBlock<BLOCK> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCK: u8> From<GetBootMailboxBlock<BLOCK>> for Message {
    fn from(_: GetBootMailboxBlock<BLOCK>) -> Self {
        Message::new_request(NetFn::Chassis, 0x09, vec![7, BLOCK, 0])
    }
}

impl<const BLOCK: u8> IpmiCommand for GetBootMailboxBlock<BLOCK> {
    type Output = BootMailboxBlock;
    type Error = BootOptionError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        completion_error(code)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() < 3 {
            return Err(BootOptionError::InvalidLengthRange {
                minimum: 3,
                maximum: 19,
                actual: data.len(),
            });
        }
        Self::new().parse_block_response(data)
    }
}

/// Write exactly one mailbox block. Does not lock, commit, clear boot-info
/// acknowledgements, write other blocks, or retry on an ambiguous failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetBootMailboxBlock {
    block: u8,
    iana: Option<u32>,
    data: Vec<u8>,
}

impl SetBootMailboxBlock {
    /// Specify an IANA PEN for block zero only, and 1..=13/16 data bytes.
    pub fn new(block: u8, iana: Option<u32>, data: Vec<u8>) -> Result<Self, BootOptionError> {
        if (block == 0) != iana.is_some() {
            return Err(BootOptionError::InvalidMailboxIana);
        }
        if let Some(value) = iana {
            if value > 0x00ff_ffff {
                return Err(BootOptionError::InvalidIana(value));
            }
        }
        let maximum = if block == 0 { 13 } else { 16 };
        if !(1..=maximum).contains(&data.len()) {
            return Err(BootOptionError::InvalidLengthRange {
                minimum: 1,
                maximum,
                actual: data.len(),
            });
        }
        Ok(Self { block, iana, data })
    }
}

impl From<SetBootMailboxBlock> for Message {
    fn from(request: SetBootMailboxBlock) -> Self {
        let mut payload = vec![7, request.block];
        if let Some(iana) = request.iana {
            payload.extend_from_slice(&iana.to_le_bytes()[..3]);
        }
        payload.extend_from_slice(&request.data);
        Message::new_request(NetFn::Chassis, 0x08, payload)
    }
}

impl IpmiCommand for SetBootMailboxBlock {
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
            (get_message::<ServicePartitionSelector>(), 1),
            (get_message::<ServicePartitionScan>(), 2),
            (get_message::<BootValidBitClearing>(), 3),
            (get_message::<BootInfoAcknowledge>(), 4),
            (get_message::<BootFlags>(), 5),
            (get_message::<BootInitiatorInfo>(), 6),
        ] {
            assert_eq!(message.netfn_raw(), 0x00);
            assert_eq!(message.cmd(), 0x09);
            assert_eq!(message.data(), &[selector, 0, 0]);
        }
        for unsupported in [8, 0x7f, 0x80, 0xFF] {
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
                BootOptionWrite::ServicePartitionSelector(ServicePartitionSelector(42)),
                vec![1, 42],
            ),
            (
                BootOptionWrite::ServicePartitionScanRequest(true),
                vec![2, 1],
            ),
            (
                BootOptionWrite::ServicePartitionScanRequest(false),
                vec![2, 0],
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
            (
                BootOptionWrite::BootInitiatorInfo(
                    BootInitiatorInfoWrite::new(1, 0x1234_5678, 0x5e0b_e100).unwrap(),
                ),
                vec![6, 1, 0x78, 0x56, 0x34, 0x12, 0, 0xe1, 0x0b, 0x5e],
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
            GetSystemBootOptions::<ServicePartitionSelector>::parse_success_response(&[1, 1, 42]),
            Ok(ServicePartitionSelector(42))
        );
        for (value, scan) in [
            (0, ServicePartitionScan::None),
            (1, ServicePartitionScan::ScanRequested),
            (2, ServicePartitionScan::Discovered),
            (3, ServicePartitionScan::ScanRequestedAndDiscovered),
            (0x80, ServicePartitionScan::Unknown(0x80)),
        ] {
            assert_eq!(
                GetSystemBootOptions::<ServicePartitionScan>::parse_success_response(&[
                    1, 2, value
                ]),
                Ok(scan)
            );
        }
        assert_eq!(
            GetSystemBootOptions::<BootInitiatorInfo>::parse_success_response(&[
                1, 6, 0x71, 0x78, 0x56, 0x34, 0x12, 0, 0xe1, 0x0b, 0x5e
            ]),
            Ok(BootInitiatorInfo {
                raw_channel: 0x71,
                session_id: 0x1234_5678,
                timestamp: 0x5e0b_e100
            })
        );
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
            Ok(BootFlags::Unknown([0x80, 0x28, 0, 0, 0]))
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
                Ok(BootFlags::Unknown(data[2..].try_into().unwrap()))
            );
            assert_eq!(
                BootOptionWrite::try_from_raw(5, &data[2..]),
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
            BootOptionWrite::try_from_raw(7, &[1]),
            Err(BootOptionError::UnsupportedSelector(7))
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(2, &[2]),
            Err(BootOptionError::InvalidValue {
                selector: 2,
                value: 2
            })
        );
        assert_eq!(
            BootInitiatorInfoWrite::new(0x71, 0, 0),
            Err(BootOptionError::InvalidValue {
                selector: 6,
                value: 0x71
            })
        );
        assert_eq!(
            BootOptionWrite::try_from_raw(6, &[0; 8]),
            Err(BootOptionError::InvalidLength {
                expected: 9,
                actual: 8
            })
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

    #[test]
    fn raw_read_preserves_unmodelled_and_locked_values_without_enabling_writes() {
        let request = GetRawBootOption::new(0x70, 5, 6).unwrap();
        let message = Message::from(request);
        assert_eq!(message.data(), [0x70, 5, 6]);
        assert_eq!(message.cmd(), 9);
        assert_eq!(
            GetRawBootOption::parse_success_response(&[0x42, 0xf0, 0xaa, 0xff]),
            Ok(RawBootOption {
                revision: 0x42,
                selector: 0x70,
                invalid_or_locked: true,
                data: vec![0xaa, 0xff]
            })
        );
        assert_eq!(
            GetRawBootOption::new(0x80, 0, 0),
            Err(BootOptionError::UnsupportedSelector(0x80))
        );
        for length in [0, 1, 256] {
            assert_eq!(
                GetRawBootOption::parse_success_response(&vec![0; length]),
                Err(BootOptionError::InvalidLengthRange {
                    minimum: 2,
                    maximum: 255,
                    actual: length
                })
            );
        }
        assert_eq!(
            BootOptionWrite::try_from_raw(0x70, &[0xaa]),
            Err(BootOptionError::UnsupportedSelector(0x70))
        );
    }

    #[test]
    fn mailbox_blocks_validate_headers_index_lengths_and_iana() {
        let block0 = GetBootMailboxBlock::<0>::new();
        let block1 = GetBootMailboxBlock::<1>::new();
        assert_eq!(Message::from(block0).data(), [7, 0, 0]);
        assert_eq!(Message::from(block1).data(), [7, 1, 0]);
        let first = [1, 7, 0, 0x57, 1, 0, 0x69, 0x70, 0x6d];
        assert_eq!(
            GetBootMailboxBlock::<0>::parse_success_response(&first),
            Ok(BootMailboxBlock {
                block: 0,
                iana: Some(343),
                data: vec![0x69, 0x70, 0x6d]
            })
        );
        assert_eq!(
            GetBootMailboxBlock::<1>::parse_success_response(&[1, 7, 1, 0xaa, 0xbb]),
            Ok(BootMailboxBlock {
                block: 1,
                iana: None,
                data: vec![0xaa, 0xbb]
            })
        );
        assert_eq!(
            GetBootMailboxBlock::<1>::parse_success_response(&first),
            Err(BootOptionError::UnexpectedBlock {
                expected: 1,
                actual: 0
            })
        );
        assert_eq!(
            GetBootMailboxBlock::<0>::parse_success_response(&[2, 7, 0, 0, 0, 0]),
            Err(BootOptionError::UnsupportedRevision(2))
        );
        assert_eq!(
            GetBootMailboxBlock::<0>::parse_success_response(&[1, 0x87, 0, 0, 0, 0]),
            Err(BootOptionError::InvalidOrLocked(7))
        );
        assert_eq!(
            GetBootMailboxBlock::<0>::parse_success_response(&[1, 6, 0, 0, 0, 0]),
            Err(BootOptionError::UnexpectedSelector {
                expected: 7,
                actual: 6
            })
        );
        for (length, minimum) in [(0, 3), (3, 6), (5, 6), (20, 6)] {
            let error = if length == 0 {
                GetBootMailboxBlock::<1>::parse_success_response(&[])
            } else {
                GetBootMailboxBlock::<0>::parse_success_response(&vec![0; length])
            };
            assert_eq!(
                error,
                Err(BootOptionError::InvalidLengthRange {
                    minimum,
                    maximum: 19,
                    actual: length
                })
            );
        }
    }

    #[test]
    fn mailbox_writes_are_bounded_and_never_write_other_blocks() {
        for (block, iana, data, expected) in [
            (0, Some(343), vec![1, 2, 3], vec![7, 0, 0x57, 1, 0, 1, 2, 3]),
            (1, None, vec![0xff], vec![7, 1, 0xff]),
            (255, None, vec![0; 16], [&[7, 255][..], &[0; 16]].concat()),
        ] {
            let request = Message::from(SetBootMailboxBlock::new(block, iana, data).unwrap());
            assert_eq!(request.netfn_raw(), 0);
            assert_eq!(request.cmd(), 8);
            assert_eq!(request.data(), expected);
        }
        assert_eq!(SetBootMailboxBlock::parse_success_response(&[]), Ok(()));
        assert_eq!(
            SetBootMailboxBlock::parse_success_response(&[1]),
            Err(BootOptionError::InvalidLength {
                expected: 0,
                actual: 1
            })
        );
        for (block, iana) in [(0, None), (1, Some(1))] {
            assert_eq!(
                SetBootMailboxBlock::new(block, iana, vec![1]),
                Err(BootOptionError::InvalidMailboxIana)
            );
        }
        assert_eq!(
            SetBootMailboxBlock::new(0, Some(0x0100_0000), vec![1]),
            Err(BootOptionError::InvalidIana(0x0100_0000))
        );
        for (block, iana, length, maximum) in [
            (0, Some(1), 0, 13),
            (0, Some(1), 14, 13),
            (1, None, 0, 16),
            (1, None, 17, 16),
        ] {
            assert_eq!(
                SetBootMailboxBlock::new(block, iana, vec![0; length]),
                Err(BootOptionError::InvalidLengthRange {
                    minimum: 1,
                    maximum,
                    actual: length
                })
            );
        }
    }
}
