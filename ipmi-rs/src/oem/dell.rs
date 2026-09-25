//! Dell iDRAC operations from ipmitool `lib/ipmi_delloem.c`.
//!
//! Use [`Ipmi::dell`] rather than sending individual wire commands: it checks
//! Dell IANA 674, the iDRAC model, and prerequisite read-only capabilities.
//! A failed write response leaves the outcome unknown; never blindly retry.

use std::marker::PhantomData;

use ipmi_rs_core::connection::{CompletionErrorCode, Message, NetFn};
pub use ipmi_rs_core::oem::dell::{GetPowerCapStatus, PowerCapStatus};

use crate::{connection::IpmiConnection, Ipmi};

use super::{OemCommand, OemError};

const OEM: NetFn = NetFn::Reserved(0x30);

/// Identified iDRAC generation and form factor (Get System Info 0xDD, block 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Controller {
    Idrac10,
    Idrac11 { modular: bool },
    Idrac12 { modular: bool },
    Idrac13 { modular: bool },
    MasterLite,
}

impl Controller {
    fn from_imc(value: u8) -> Result<Self, DecodeError> {
        match value {
            0x08 => Ok(Self::Idrac10),
            0x0A => Ok(Self::Idrac11 { modular: false }),
            0x0B => Ok(Self::Idrac11 { modular: true }),
            0x0D | 0x0E => Ok(Self::MasterLite),
            0x10 => Ok(Self::Idrac12 { modular: false }),
            0x11 => Ok(Self::Idrac12 { modular: true }),
            0x20 | 0x22 => Ok(Self::Idrac13 { modular: false }),
            0x21 => Ok(Self::Idrac13 { modular: true }),
            _ => Err(DecodeError::UnsupportedModel(value)),
        }
    }

    fn extended(self) -> bool {
        !matches!(self, Self::Idrac10)
    }

    fn modern_lan(self) -> bool {
        matches!(self, Self::Idrac12 { .. } | Self::Idrac13 { .. })
    }

    fn modular(self) -> bool {
        matches!(
            self,
            Self::Idrac11 { modular: true }
                | Self::Idrac12 { modular: true }
                | Self::Idrac13 { modular: true }
        )
    }
}

/// Explicit acknowledgement that a configuration-changing operation is intended.
///
/// No method accepting this value retries a write or assumes a lost reply
/// means the write did not take effect.
#[derive(Debug, Clone, Copy)]
pub struct WriteIntent;

/// Explicit assertion that vFlash is accessed through ipmitool's supported
/// local Open/WMI interface. The generic connection cannot verify its route.
#[derive(Debug, Clone, Copy)]
pub enum LocalVflash {
    Open,
    Wmi,
}

/// A malformed or unsupported Dell response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Short { expected: usize, actual: usize },
    UnsupportedModel(u8),
    Unsupported,
    Unlicensed,
    InvalidValue(u8),
    InvalidText,
    SdCardStatus(u8),
}

/// A Dell operation failed before or after the identity-checked send.
#[derive(Debug)]
pub enum DellError<E> {
    /// Includes failed identity discovery, wrong manufacturer, transport and
    /// completion-code errors. A failed write may have succeeded remotely.
    Dispatch(OemError<E, DecodeError>),
    /// The identified model cannot perform this operation.
    UnsupportedGeneration(Controller),
    /// A prerequisite read succeeded but the required capability is absent.
    Capability(&'static str),
    /// Invalid input; no command was sent.
    InvalidInput(&'static str),
}

trait Decode: Sized {
    fn decode(data: &[u8]) -> Result<Self, DecodeError>;
}

fn len(data: &[u8], required: usize) -> Result<(), DecodeError> {
    if data.len() < required {
        Err(DecodeError::Short {
            expected: required,
            actual: data.len(),
        })
    } else {
        Ok(())
    }
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("checked length"))
}

impl Decode for () {
    fn decode(_: &[u8]) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Decode for Controller {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 11)?;
        Self::from_imc(data[10])
    }
}

struct Wire<T> {
    message: Message,
    _output: PhantomData<T>,
}

impl<T> Wire<T> {
    fn new(netfn: NetFn, cmd: u8, data: &[u8]) -> Self {
        Self {
            message: Message::new_request(netfn, cmd, data.to_vec()),
            _output: PhantomData,
        }
    }

    fn oem(cmd: u8, data: &[u8]) -> Self {
        Self::new(OEM, cmd, data)
    }

    fn sysinfo(selector: u8, block: u8) -> Self {
        Self::new(NetFn::App, 0x59, &[0, selector, block, 0])
    }

    fn setinfo(data: &[u8]) -> Self {
        Self::new(NetFn::App, 0x58, data)
    }
}

impl<T: Decode> OemCommand for Wire<T> {
    type Output = T;
    type Error = DecodeError;
    const MANUFACTURER_ID: u32 = 674;

    fn into_message(self) -> Message {
        self.message
    }

    fn parse_success_response(data: &[u8]) -> Result<T, DecodeError> {
        T::decode(data)
    }

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<DecodeError> {
        match code {
            CompletionErrorCode::Oem(0x6F) => Some(DecodeError::Unlicensed),
            CompletionErrorCode::InvalidCommand
            | CompletionErrorCode::RequestedDatapointNotPresent => Some(DecodeError::Unsupported),
            _ => None,
        }
    }
}

/// Borrowed, generation-identified Dell controller. Obtain with [`Ipmi::dell`].
pub struct Dell<'a, CON: IpmiConnection> {
    ipmi: &'a mut Ipmi<CON>,
    controller: Controller,
}

impl<CON: IpmiConnection> Ipmi<CON> {
    /// Check manufacturer IANA 674 and the Dell 0xDD controller type.
    pub fn dell(&mut self) -> Result<Dell<'_, CON>, DellError<CON::Error>> {
        let controller = self
            .send_oem(Wire::<Controller>::sysinfo(0xDD, 2))
            .map_err(DellError::Dispatch)?;
        Ok(Dell {
            ipmi: self,
            controller,
        })
    }
}

impl<CON: IpmiConnection> Dell<'_, CON> {
    fn lcd_writable(&mut self) -> Result<LcdStatus, DellError<CON::Error>> {
        let status = self.lcd_status()?;
        if status.lock != LcdLock::ViewAndModify {
            return Err(DellError::Capability("LCD access is read-only or disabled"));
        }
        Ok(status)
    }

    /// The generation returned by Get System Info 0xDD, block 2.
    pub fn controller(&self) -> Controller {
        self.controller
    }

    fn send<T: Decode>(&mut self, wire: Wire<T>) -> Result<T, DellError<CON::Error>> {
        self.ipmi.send_oem(wire).map_err(DellError::Dispatch)
    }

    fn require(&self, allowed: bool) -> Result<(), DellError<CON::Error>> {
        if allowed {
            Ok(())
        } else {
            Err(DellError::UnsupportedGeneration(self.controller))
        }
    }

    fn before_write(&mut self) -> Result<(), DellError<CON::Error>> {
        let current = self.send(Wire::<Controller>::sysinfo(0xDD, 2))?;
        if current == self.controller {
            Ok(())
        } else {
            Err(DellError::UnsupportedGeneration(current))
        }
    }
}

/// The selected front-panel LCD text source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcdMode {
    Custom,
    Model,
    Blank,
    Ipv4,
    Mac,
    OsName,
    ServiceTag,
    Ipv6,
    AmbientTemperature,
    SystemWatts,
    AssetTag,
}

impl LcdMode {
    fn value(self) -> u32 {
        match self {
            Self::Custom => 0,
            Self::Model => 1,
            Self::Blank => 2,
            Self::Ipv4 => 4,
            Self::Mac => 8,
            Self::OsName => 0x10,
            Self::ServiceTag => 0x20,
            Self::Ipv6 => 0x40,
            Self::AmbientTemperature => 0x80,
            Self::SystemWatts => 0x100,
            Self::AssetTag => 0x200,
        }
    }
}

/// LCD configuration, retaining unknown capability and reserved bytes on writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcdConfig {
    pub mode: u32,
    pub qualifier: u16,
    pub capabilities: u32,
    pub error_display: u8,
    raw: [u8; 13],
}

impl Decode for LcdConfig {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 13)?;
        let raw: [u8; 13] = data[..13].try_into().expect("checked length");
        Ok(Self {
            mode: u32_at(data, 1),
            qualifier: u16_at(data, 5),
            capabilities: u32_at(data, 7),
            error_display: data[11],
            raw,
        })
    }
}

/// LCD KVM indicator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kvm {
    Inactive,
    Active,
}

/// LCD access setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcdLock {
    ViewAndModify,
    ViewOnly,
    Disabled,
}

/// LCD KVM and lock state. Unknown values are rejected, not overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcdStatus {
    pub kvm: Kvm,
    pub lock: LcdLock,
    raw: [u8; 5],
}

impl Decode for LcdStatus {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 5)?;
        let kvm = match data[1] {
            0 => Kvm::Inactive,
            1 => Kvm::Active,
            value => return Err(DecodeError::InvalidValue(value)),
        };
        let lock = match data[2] {
            0 => LcdLock::ViewAndModify,
            1 => LcdLock::ViewOnly,
            2 => LcdLock::Disabled,
            value => return Err(DecodeError::InvalidValue(value)),
        };
        Ok(Self {
            kvm,
            lock,
            raw: data[..5].try_into().expect("checked length"),
        })
    }
}

/// LCD line count and the supported length of the first four lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcdCaps {
    pub lines: u8,
    pub max_chars: [u8; 4],
}

impl Decode for LcdCaps {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 7)?;
        if data[2] > 4 || data[1] != 1 {
            return Err(DecodeError::InvalidValue(data[2]));
        }
        Ok(Self {
            lines: data[2],
            max_chars: data[3..7].try_into().expect("checked length"),
        })
    }
}

struct LcdBlock(Vec<u8>);
impl Decode for LcdBlock {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 2)?;
        Ok(Self(data.to_vec()))
    }
}

impl<CON: IpmiConnection> Dell<'_, CON> {
    /// Probe LCD status before using LCD features (App 0x59/E7).
    pub fn lcd_status(&mut self) -> Result<LcdStatus, DellError<CON::Error>> {
        self.send(Wire::sysinfo(0xE7, 0))
    }

    /// Read available LCD lines and their maximum lengths (App 0x59/CF).
    pub fn lcd_caps(&mut self) -> Result<LcdCaps, DellError<CON::Error>> {
        self.lcd_status()?;
        self.send(Wire::sysinfo(0xCF, 0))
    }

    /// Read the LCD setting. 10G uses the legacy single-byte mode;
    /// 11G–13G and Master Lite use the extended 13-byte setting.
    pub fn lcd_config(&mut self) -> Result<LcdConfig, DellError<CON::Error>> {
        self.lcd_status()?;
        if self.controller.extended() {
            self.send(Wire::sysinfo(0xC2, 0))
        } else {
            let block: LcdBlock = self.send(Wire::sysinfo(0xC2, 0))?;
            len(&block.0, 2).map_err(|_| DellError::Capability("short LCD configuration"))?;
            let mut data = [0; 13];
            data[..2].copy_from_slice(&block.0[..2]);
            Ok(LcdConfig::decode(&data).expect("padded"))
        }
    }

    fn lcd_string(&mut self, selector: u8, maximum: u8) -> Result<String, DellError<CON::Error>> {
        let mut text = Vec::new();
        let mut length = 0usize;
        for block in 0..4u8 {
            let reply: LcdBlock = self.send(Wire::sysinfo(selector, block))?;
            if block == 0 {
                len(&reply.0, 4).map_err(|_| DellError::Capability("short LCD text"))?;
                if reply.0[1] != 0 || reply.0[2] & 0x0f != 0 {
                    return Err(DellError::Capability("invalid LCD encoding or block"));
                }
                length = usize::from(reply.0[3]);
                if length > usize::from(maximum.min(62)) {
                    return Err(DellError::Capability("LCD text exceeds line capacity"));
                }
                let copy = length.min(14);
                len(&reply.0, copy + 4).map_err(|_| DellError::Capability("short LCD text"))?;
                text.extend_from_slice(&reply.0[4..4 + copy]);
            } else {
                if reply.0[1] != block {
                    return Err(DellError::Capability("LCD block mismatch"));
                }
                let copy = (length - text.len()).min(16);
                len(&reply.0, copy + 2).map_err(|_| DellError::Capability("short LCD text"))?;
                text.extend_from_slice(&reply.0[2..copy + 2]);
            }
            if text.len() == length {
                break;
            }
        }
        if text.len() != length || !text.iter().all(|&byte| (0x20..=0x7E).contains(&byte)) {
            return Err(DellError::Capability("invalid or incomplete LCD text"));
        }
        Ok(String::from_utf8(text).expect("printable ASCII"))
    }

    /// Read the model name presented on the LCD (App 0x59/D1).
    pub fn lcd_model_name(&mut self) -> Result<String, DellError<CON::Error>> {
        self.lcd_status()?;
        self.lcd_string(0xD1, 62)
    }

    /// Read the first-line custom text (App 0x59/C1).
    pub fn lcd_text(&mut self) -> Result<String, DellError<CON::Error>> {
        let caps = self.lcd_caps()?;
        if caps.lines == 0 {
            return Err(DellError::Capability("LCD has no writable line"));
        }
        self.lcd_string(0xC1, caps.max_chars[0])
    }

    /// Set the LCD source, preserving extended qualifier/capability fields.
    /// Only explicit, known source values are accepted.
    pub fn set_lcd_mode(
        &mut self,
        _: WriteIntent,
        mode: LcdMode,
    ) -> Result<(), DellError<CON::Error>> {
        if !self.controller.extended() && mode.value() > 2 {
            return Err(DellError::UnsupportedGeneration(self.controller));
        }
        self.before_write()?;
        self.lcd_writable()?;
        let config = self.lcd_config()?;
        if self.controller.extended() {
            let mut data = config.raw;
            data[0] = 0xC2;
            data[1..5].copy_from_slice(&mode.value().to_le_bytes());
            self.send(Wire::setinfo(&data))
        } else {
            self.send(Wire::setinfo(&[0xC2, mode.value() as u8]))
        }
    }

    /// Set an extended LCD qualifier (bit 0: BTU/hr, bit 1: °F).
    pub fn set_lcd_qualifier(
        &mut self,
        _: WriteIntent,
        btu_per_hour: bool,
        fahrenheit: bool,
    ) -> Result<(), DellError<CON::Error>> {
        self.require(self.controller.extended())?;
        self.before_write()?;
        self.lcd_writable()?;
        let config = self.lcd_config()?;
        let mut data = config.raw;
        data[0] = 0xC2;
        data[5] = (data[5] & !3) | u8::from(btu_per_hour) | (u8::from(fahrenheit) << 1);
        self.send(Wire::setinfo(&data))
    }

    /// Select SEL (1) or simple (2) front-panel error display.
    pub fn set_lcd_error_display(
        &mut self,
        _: WriteIntent,
        sel: bool,
    ) -> Result<(), DellError<CON::Error>> {
        self.require(self.controller.extended())?;
        self.before_write()?;
        self.lcd_writable()?;
        let config = self.lcd_config()?;
        let mut data = config.raw;
        data[0] = 0xC2;
        data[11] = if sel { 1 } else { 2 };
        self.send(Wire::setinfo(&data))
    }

    /// Set the first LCD line to printable ASCII (up to 62 bytes).
    /// Each block is a distinct write; partial success must be recovered
    /// manually after a timeout, not replayed.
    pub fn set_lcd_text(
        &mut self,
        _: WriteIntent,
        text: &str,
    ) -> Result<(), DellError<CON::Error>> {
        if text.len() > 62 || !text.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(DellError::InvalidInput(
                "LCD requires 0–62 printable ASCII characters",
            ));
        }
        self.before_write()?;
        self.lcd_writable()?;
        let caps = self.lcd_caps()?;
        if caps.lines == 0 || text.len() > usize::from(caps.max_chars[0]) {
            return Err(DellError::Capability("LCD line absent or text too long"));
        }
        let bytes = text.as_bytes();
        let mut first = [0; 18];
        first[0] = 0xC1;
        first[3] = bytes.len() as u8;
        let size = bytes.len().min(14);
        first[4..4 + size].copy_from_slice(&bytes[..size]);
        self.send::<()>(Wire::setinfo(&first))?;
        for (index, chunk) in bytes[size..].chunks(16).enumerate() {
            let mut block = [0; 18];
            block[0] = 0xC1;
            block[1] = index as u8 + 1;
            block[2..2 + chunk.len()].copy_from_slice(chunk);
            self.send::<()>(Wire::setinfo(&block))?;
        }
        Ok(())
    }

    /// Set KVM indicator, preserving current lock state.
    pub fn set_lcd_kvm(&mut self, _: WriteIntent, value: Kvm) -> Result<(), DellError<CON::Error>> {
        self.before_write()?;
        let status = self.lcd_writable()?;
        let mut data = status.raw;
        data[0] = 0xE7;
        data[1] = u8::from(value == Kvm::Active);
        self.send(Wire::setinfo(&data))
    }

    /// Set LCD access, preserving current KVM indicator.
    pub fn set_lcd_lock(
        &mut self,
        _: WriteIntent,
        value: LcdLock,
    ) -> Result<(), DellError<CON::Error>> {
        self.before_write()?;
        let status = self.lcd_writable()?;
        let mut data = status.raw;
        data[0] = 0xE7;
        data[2] = match value {
            LcdLock::ViewAndModify => 0,
            LcdLock::ViewOnly => 1,
            LcdLock::Disabled => 2,
        };
        self.send(Wire::setinfo(&data))
    }
}

/// A six-octet hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

/// An embedded NIC described by Get System Info 0xDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lom {
    pub number: u8,
    pub mac: MacAddress,
    pub enabled: bool,
    pub ethernet: bool,
    pub blade_slot: u8,
}

struct Loms10(Vec<MacAddress>);
impl Decode for Loms10 {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 2)?;
        let count = usize::from(data[1]);
        if count > 8 {
            return Err(DecodeError::InvalidValue(data[1]));
        }
        len(data, 2 + count * 6)?;
        Ok(Self(
            data[2..2 + count * 6]
                .as_chunks::<6>()
                .0
                .iter()
                .map(|chunk| MacAddress(*chunk))
                .collect(),
        ))
    }
}

struct LomSize(u8);
impl Decode for LomSize {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 2)?;
        if data[1] > 64 || !data[1].is_multiple_of(8) {
            return Err(DecodeError::InvalidValue(data[1]));
        }
        Ok(Self(data[1]))
    }
}

struct LomBlock(Lom);
impl Decode for LomBlock {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 9)?;
        Ok(Self(Lom {
            blade_slot: data[1] & 0x0F,
            ethernet: (data[1] >> 4) & 3 == 0,
            enabled: (data[1] >> 6) & 3 == 0,
            number: data[2] & 0x1F,
            mac: MacAddress(data[3..9].try_into().expect("six bytes")),
        }))
    }
}

struct VirtualMac(Vec<u8>);
impl Decode for VirtualMac {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 7)?;
        Ok(Self(data.to_vec()))
    }
}

struct PhysicalMac(MacAddress);
impl Decode for PhysicalMac {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 7)?;
        Ok(Self(MacAddress(data[1..7].try_into().expect("six bytes"))))
    }
}

/// Legacy 10G/11G NIC selection modes (OEM 0x25/0x24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyNic {
    Shared,
    SharedFailoverLom2,
    Dedicated,
    SharedFailoverAll,
}

/// 12G/13G failover mode for a shared LOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failover {
    None,
    Lom(u8),
    AllLoms,
}

/// Current or proposed NIC configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicMode {
    Legacy(LegacyNic),
    Modern {
        /// None selects dedicated. Otherwise LOM 1–4.
        shared_lom: Option<u8>,
        failover: Failover,
    },
}

impl NicMode {
    fn modern_bytes(self) -> Result<[u8; 2], &'static str> {
        match self {
            Self::Modern {
                shared_lom: None,
                failover: Failover::None,
            } => Ok([1, 0]),
            Self::Modern {
                shared_lom: Some(lom @ 1..=4),
                failover,
            } => {
                let backup = match failover {
                    Failover::None => 0,
                    Failover::Lom(other @ 1..=4) if other != lom => other + 1,
                    Failover::AllLoms => 6,
                    _ => return Err("invalid or identical failover LOM"),
                };
                Ok([lom + 1, backup])
            }
            _ => Err("invalid shared LOM or failover for dedicated NIC"),
        }
    }
}

struct NicResponse(Vec<u8>);
impl Decode for NicResponse {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 1)?;
        Ok(Self(data.to_vec()))
    }
}

fn parse_nic(data: &[u8], modern: bool) -> Result<NicMode, DecodeError> {
    len(data, if modern { 2 } else { 1 })?;
    if modern {
        let failover = match data[1] {
            0 => Failover::None,
            2..=5 => Failover::Lom(data[1] - 1),
            6 => Failover::AllLoms,
            other => return Err(DecodeError::InvalidValue(other)),
        };
        match data[0] {
            1 if failover == Failover::None => Ok(NicMode::Modern {
                shared_lom: None,
                failover,
            }),
            2..=5 => {
                if failover == Failover::Lom(data[0] - 1) {
                    return Err(DecodeError::InvalidValue(data[1]));
                }
                Ok(NicMode::Modern {
                    shared_lom: Some(data[0] - 1),
                    failover,
                })
            }
            other => Err(DecodeError::InvalidValue(other)),
        }
    } else {
        Ok(NicMode::Legacy(match data[0] {
            0 => LegacyNic::Shared,
            1 => LegacyNic::SharedFailoverLom2,
            2 => LegacyNic::Dedicated,
            3 => LegacyNic::SharedFailoverAll,
            other => return Err(DecodeError::InvalidValue(other)),
        }))
    }
}

/// NIC currently providing the iDRAC link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveNic {
    None,
    Lom(u8),
    Dedicated,
}

impl<CON: IpmiConnection> Dell<'_, CON> {
    /// Get the BMC's virtual MAC, falling back to Transport Get LAN Parameter
    /// channel 1 / selector 5 if no virtual MAC was assigned.
    pub fn idrac_mac(&mut self) -> Result<MacAddress, DellError<CON::Error>> {
        let virtual_mac: Option<VirtualMac> = match self.send(Wire::oem(0xC9, &[1])) {
            Ok(mac) => Some(mac),
            Err(DellError::Dispatch(OemError::Command(
                crate::IpmiError::Failed { .. }
                | crate::IpmiError::Command {
                    error: DecodeError::Unsupported,
                    ..
                },
            ))) => None,
            Err(error) => return Err(error),
        };
        if let Some(virtual_mac) = virtual_mac {
            let start = if self.controller.modern_lan() {
                len(&virtual_mac.0, 13).map_err(|_| DellError::Capability("short virtual MAC"))?;
                if virtual_mac.0[1..7].iter().any(|&b| b != 0) {
                    1
                } else {
                    7
                }
            } else {
                1
            };
            let mac: [u8; 6] = virtual_mac.0[start..start + 6]
                .try_into()
                .expect("checked length");
            if mac.iter().any(|&b| b != 0) {
                return Ok(MacAddress(mac));
            }
        }
        let physical: PhysicalMac = self.send(Wire::new(NetFn::Transport, 0x02, &[1, 5, 0, 0]))?;
        Ok(physical.0)
    }

    /// List embedded LOMs. 10G uses App selector CB; 11G–13G/other
    /// supported iDRAC models use DA in up to eight bounded 8-byte blocks.
    pub fn loms(&mut self) -> Result<Vec<Lom>, DellError<CON::Error>> {
        if self.controller == Controller::Idrac10 {
            let addresses: Loms10 = self.send(Wire::sysinfo(0xCB, 0))?;
            Ok(addresses
                .0
                .into_iter()
                .enumerate()
                .map(|(index, mac)| Lom {
                    number: index as u8,
                    mac,
                    enabled: true,
                    ethernet: true,
                    blade_slot: 0,
                })
                .collect())
        } else {
            let count: LomSize = self.send(Wire::new(NetFn::App, 0x59, &[0, 0xDA, 0, 0, 0, 0]))?;
            let mut result = Vec::new();
            for offset in (0..count.0).step_by(8) {
                let block: LomBlock =
                    self.send(Wire::new(NetFn::App, 0x59, &[0, 0xDA, 0, 0, offset, 8]))?;
                if block.0.ethernet {
                    result.push(block.0);
                }
            }
            Ok(result)
        }
    }

    /// Read the current 10G/11G or 12G/13G NIC selection.
    pub fn nic_mode(&mut self) -> Result<NicMode, DellError<CON::Error>> {
        self.require(!matches!(
            self.controller,
            Controller::Idrac11 { modular: true }
        ))?;
        let modern = self.controller.modern_lan();
        let value: NicResponse = self.send(Wire::oem(if modern { 0x29 } else { 0x25 }, &[]))?;
        parse_nic(&value.0, modern).map_err(|_| DellError::Capability("invalid NIC selection"))
    }

    /// Read active NIC (OEM C1 subcommands 0 and 1).
    pub fn active_nic(&mut self) -> Result<ActiveNic, DellError<CON::Error>> {
        self.require(!matches!(
            self.controller,
            Controller::Idrac11 { modular: true }
        ))?;
        let current: NicResponse = self.send(Wire::oem(0xC1, &[0, 0, 0]))?;
        let link: NicResponse = self.send(Wire::oem(0xC1, &[1, 0, 0]))?;
        len(&link.0, 2).map_err(|_| DellError::Capability("short active NIC link"))?;
        Ok(match (current.0[0], link.0[1]) {
            (_, 0) | (0, _) => ActiveNic::None,
            (1..=4, _) => ActiveNic::Lom(current.0[0]),
            (5, _) => ActiveNic::Dedicated,
            _ => return Err(DellError::Capability("invalid active NIC")),
        })
    }

    /// Change NIC mode only after validating the current readable mode.
    /// A remote NIC change may disconnect this very IPMI session.
    pub fn set_nic_mode(
        &mut self,
        _: WriteIntent,
        mode: NicMode,
    ) -> Result<(), DellError<CON::Error>> {
        let modern = self.controller.modern_lan();
        let data = if modern {
            let bytes = mode.modern_bytes().map_err(DellError::InvalidInput)?;
            if self.controller.modular() && bytes != [1, 0] {
                return Err(DellError::UnsupportedGeneration(self.controller));
            }
            bytes.to_vec()
        } else {
            let NicMode::Legacy(legacy) = mode else {
                return Err(DellError::InvalidInput("legacy NIC mode required"));
            };
            vec![match legacy {
                LegacyNic::Shared => 0,
                LegacyNic::SharedFailoverLom2 => 1,
                LegacyNic::Dedicated => 2,
                LegacyNic::SharedFailoverAll => 3,
            }]
        };
        self.before_write()?;
        self.nic_mode()?;
        self.send(Wire::oem(if modern { 0x28 } else { 0x24 }, &data))
    }
}

/// Power monitor counters and timestamps (OEM 0x9C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerMonitor {
    pub cumulative_start: u32,
    /// Source counts watt-hours; divide by 1,000 for kWh.
    pub cumulative_watt_hours: u32,
    pub peak_start: u32,
    pub peak_amps_time: u32,
    pub peak_tenths_amps: u16,
    pub peak_watts_time: u32,
    pub peak_watts: u16,
}

impl Decode for PowerMonitor {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 24)?;
        Ok(Self {
            cumulative_start: u32_at(data, 0),
            cumulative_watt_hours: u32_at(data, 4),
            peak_start: u32_at(data, 8),
            peak_amps_time: u32_at(data, 12),
            peak_tenths_amps: u16_at(data, 16),
            peak_watts_time: u32_at(data, 18),
            peak_watts: u16_at(data, 22),
        })
    }
}

struct SelTime(u32);
impl Decode for SelTime {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 4)?;
        Ok(Self(u32_at(data, 0)))
    }
}

/// Instantaneous watts, tenths of an ampere, and unused bytes (OEM 0xB3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstantPower {
    pub watts: u16,
    pub tenths_amps: u16,
}

impl Decode for InstantPower {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 7)?;
        Ok(Self {
            watts: u16_at(data, 0),
            tenths_amps: u16_at(data, 2),
        })
    }
}

/// Power available above instantaneous/peak use (watts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerHeadroom {
    pub instant_watts: u16,
    pub peak_watts: u16,
}

impl Decode for PowerHeadroom {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 4)?;
        Ok(Self {
            instant_watts: u16_at(data, 0),
            peak_watts: u16_at(data, 2),
        })
    }
}

/// Four rolling consumption values (minute, hour, day, week) in watts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerPeriods {
    pub minute: u16,
    pub hour: u16,
    pub day: u16,
    pub week: u16,
}

fn periods(data: &[u8]) -> PowerPeriods {
    PowerPeriods {
        minute: u16_at(data, 1),
        hour: u16_at(data, 3),
        day: u16_at(data, 5),
        week: u16_at(data, 7),
    }
}

impl Decode for PowerPeriods {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 9)?;
        Ok(periods(data))
    }
}

/// Peak or minimum watts and their four SEL-clock timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerExtrema {
    pub watts: PowerPeriods,
    pub times: [u32; 4],
}

impl Decode for PowerExtrema {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 25)?;
        Ok(Self {
            watts: periods(data),
            times: [
                u32_at(data, 9),
                u32_at(data, 13),
                u32_at(data, 17),
                u32_at(data, 21),
            ],
        })
    }
}

/// Supported power budget and its currently configured cap in watts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerBudget {
    pub watts: u16,
    pub unit: u8,
    pub min_watts: u16,
    pub max_watts: u16,
    pub supplies: u16,
    pub available_watts: u16,
    pub throttling: u16,
}

impl Decode for PowerBudget {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 16)?;
        let result = Self {
            watts: u16_at(data, 1),
            unit: data[3],
            max_watts: u16_at(data, 4),
            min_watts: u16_at(data, 6),
            supplies: u16_at(data, 8),
            available_watts: u16_at(data, 10),
            throttling: u16_at(data, 12),
        };
        if result.min_watts > result.max_watts {
            return Err(DecodeError::InvalidValue(data[6]));
        }
        Ok(result)
    }
}

/// Which power monitor accumulator to clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearPower {
    Cumulative,
    Peak,
}

struct CapFlags(PowerCapStatus);
impl Decode for CapFlags {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 1)?;
        Ok(Self(PowerCapStatus {
            enabled: data[0] & 1 != 0,
            can_set: data[0] & 2 != 0,
        }))
    }
}

struct SensorReading(u8);
impl Decode for SensorReading {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 2)?;
        if data[1] & 0x20 != 0 || data[1] & 0xC0 == 0 {
            return Err(DecodeError::Unsupported);
        }
        Ok(Self(data[0]))
    }
}

struct SensorThresholds((u8, u8));
impl Decode for SensorThresholds {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 6)?;
        // GET_SENSOR_THRESHOLDS bits 3 and 4 indicate the upper thresholds.
        if data[0] & 0x18 != 0x18 {
            return Err(DecodeError::Unsupported);
        }
        Ok(Self((data[4], data[5])))
    }
}

/// Raw System Level sensor values; convert through the sensor's SDR record,
/// not by assuming that raw readings are measured in watts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerSensor {
    pub reading: u8,
    pub upper_noncritical: u8,
    pub upper_critical: u8,
}

impl<CON: IpmiConnection> Dell<'_, CON> {
    /// Get Storage NetFn SEL time (0x48) used with power timestamps.
    pub fn sel_time(&mut self) -> Result<u32, DellError<CON::Error>> {
        Ok(self
            .send::<SelTime>(Wire::new(NetFn::Storage, 0x48, &[]))?
            .0)
    }

    /// Read cumulative consumption and peak power/amperage.
    pub fn power_monitor(&mut self) -> Result<PowerMonitor, DellError<CON::Error>> {
        self.send(Wire::oem(0x9C, &[7, 1]))
    }

    /// Read OEM instantaneous power consumption.
    pub fn instant_power(&mut self) -> Result<InstantPower, DellError<CON::Error>> {
        self.send(Wire::oem(0xB3, &[0x0A, 0]))
    }

    /// Read OEM instantaneous/peak headroom.
    pub fn power_headroom(&mut self) -> Result<PowerHeadroom, DellError<CON::Error>> {
        self.send(Wire::oem(0xBB, &[]))
    }

    /// Read average watts per minute/hour/day/week (App 0x59/EB).
    pub fn average_power(&mut self) -> Result<PowerPeriods, DellError<CON::Error>> {
        self.send(Wire::sysinfo(0xEB, 0))
    }

    /// Read peak watts and timestamps (App 0x59/EC).
    pub fn peak_power(&mut self) -> Result<PowerExtrema, DellError<CON::Error>> {
        self.send(Wire::sysinfo(0xEC, 0))
    }

    /// Read minimum watts and timestamps (App 0x59/ED).
    pub fn minimum_power(&mut self) -> Result<PowerExtrema, DellError<CON::Error>> {
        self.send(Wire::sysinfo(0xED, 0))
    }

    /// Read a BMC-owned, LUN-0 System Level sensor identified by the caller's
    /// SDR traversal. Routes Sensor/Event 0x2D and 0x27; returned bytes are
    /// *not* watts. For sensors with a different owner/channel, use the raw
    /// SDR-directed IPMI command path instead.
    pub fn power_sensor(&mut self, sensor: u8) -> Result<PowerSensor, DellError<CON::Error>> {
        let reading: SensorReading = self.send(Wire::new(NetFn::SensorEvent, 0x2D, &[sensor]))?;
        let thresholds: SensorThresholds =
            self.send(Wire::new(NetFn::SensorEvent, 0x27, &[sensor]))?;
        Ok(PowerSensor {
            reading: reading.0,
            upper_noncritical: thresholds.0 .0,
            upper_critical: thresholds.0 .1,
        })
    }

    /// Read power-cap enable/settable flags (OEM BA [01 FF]).
    pub fn power_cap_status(&mut self) -> Result<PowerCapStatus, DellError<CON::Error>> {
        Ok(self.send::<CapFlags>(Wire::oem(0xBA, &[1, 0xFF]))?.0)
    }

    /// Read the current cap and the device's min/max limits (App 0x59/EA).
    pub fn power_budget(&mut self) -> Result<PowerBudget, DellError<CON::Error>> {
        self.send(Wire::sysinfo(0xEA, 0))
    }

    /// Enable or disable the cap after checking that it is settable.
    pub fn set_power_cap_enabled(
        &mut self,
        _: WriteIntent,
        enabled: bool,
    ) -> Result<(), DellError<CON::Error>> {
        self.before_write()?;
        if !self.power_cap_status()?.can_set {
            return Err(DellError::Capability("power cap is read-only"));
        }
        self.send(Wire::oem(0xBA, &[0, u8::from(enabled)]))
    }

    /// Change the power cap in watts only when enabled, settable and within
    /// the freshly read range. High unsupported fields are not truncated.
    pub fn set_power_budget(
        &mut self,
        _: WriteIntent,
        watts: u16,
    ) -> Result<(), DellError<CON::Error>> {
        self.before_write()?;
        let flags = self.power_cap_status()?;
        if !flags.enabled || !flags.can_set {
            return Err(DellError::Capability("power cap disabled or read-only"));
        }
        let budget = self.power_budget()?;
        if watts < budget.min_watts || watts > budget.max_watts {
            return Err(DellError::InvalidInput("watts outside device power budget"));
        }
        if budget.supplies > 255 || budget.throttling > 255 {
            return Err(DellError::Capability(
                "power budget has unsupported wide fields",
            ));
        }
        let mut data = [0; 13];
        data[0] = 0xEA;
        data[1..3].copy_from_slice(&watts.to_le_bytes());
        data[3] = 0; // source unit: watts
        data[4..6].copy_from_slice(&budget.max_watts.to_le_bytes());
        data[6..8].copy_from_slice(&budget.min_watts.to_le_bytes());
        data[8] = budget.supplies as u8;
        data[9..11].copy_from_slice(&budget.available_watts.to_le_bytes());
        data[11] = budget.throttling as u8;
        self.send(Wire::setinfo(&data))
    }

    /// Clear a named power accumulator after checking monitoring availability.
    pub fn clear_power(
        &mut self,
        _: WriteIntent,
        which: ClearPower,
    ) -> Result<(), DellError<CON::Error>> {
        self.before_write()?;
        self.power_monitor()?;
        self.send(Wire::oem(
            0x9D,
            &[
                7,
                1,
                if which == ClearPower::Cumulative {
                    1
                } else {
                    2
                },
            ],
        ))
    }
}

/// Valid PCI bus:device.function for Dell OEM storage mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveBdf {
    bus: u8,
    device: u8,
    function: u8,
}

impl DriveBdf {
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self, &'static str> {
        if device > 31 || function > 7 {
            return Err("PCI device must be <=31 and function <=7");
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }
}

/// Bay and slot returned by OEM D5 storage mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveLocation {
    pub bay: u8,
    pub slot: u8,
}

impl Decode for DriveLocation {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 9)?;
        if data[7] == 0xFF || data[8] == 0xFF {
            return Err(DecodeError::Unsupported);
        }
        Ok(Self {
            bay: data[7],
            slot: data[8],
        })
    }
}

/// SES drive status bit assigned by ipmitool's `setled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveLed {
    Present,
    Online,
    HotSpare,
    Identify,
    Rebuilding,
    Fault,
    PredictFailure,
    Critical,
    Failed,
}

impl DriveLed {
    fn mask(self) -> u16 {
        1 << match self {
            Self::Present => 0,
            Self::Online => 1,
            Self::HotSpare => 2,
            Self::Identify => 3,
            Self::Rebuilding => 4,
            Self::Fault => 5,
            Self::PredictFailure => 6,
            Self::Critical => 9,
            Self::Failed => 10,
        }
    }
}

/// vFlash card health, read via OEM A4 (only local Open/WMI routes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdHealth {
    Ok,
    Warning,
    Critical,
    Undefined,
}

/// Extended vFlash SD card information; returned only for an available card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdCard {
    pub size_mb: u32,
    pub available_mb: u32,
    pub initialized: bool,
    pub licensed: bool,
    pub attached: bool,
    pub enabled: bool,
    pub write_protected: bool,
    pub boot_partition: u8,
    pub health: SdHealth,
}

impl Decode for SdCard {
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        len(data, 12)?;
        match data[0] {
            0 => {}
            0x33 => return Err(DecodeError::Unlicensed),
            value => return Err(DecodeError::SdCardStatus(value)),
        }
        let status = data[1];
        if status & 4 == 0 {
            return Err(DecodeError::SdCardStatus(1));
        }
        Ok(Self {
            size_mb: u32_at(data, 2),
            available_mb: u32_at(data, 6),
            initialized: status & 0x80 != 0,
            licensed: status & 0x40 != 0,
            attached: status & 0x20 != 0,
            enabled: status & 0x10 != 0,
            write_protected: status & 8 != 0,
            boot_partition: data[10],
            health: match status & 3 {
                0 => SdHealth::Ok,
                1 => SdHealth::Warning,
                2 => SdHealth::Critical,
                _ => SdHealth::Undefined,
            },
        })
    }
}

impl<CON: IpmiConnection> Dell<'_, CON> {
    /// Probe OEM D5 storage firmware read command before drive status writes.
    pub fn drive_led_supported(&mut self) -> Result<(), DellError<CON::Error>> {
        self.send(Wire::oem(0xD5, &[1, 0, 8, 0, 0, 0, 0, 0, 0, 0]))
    }

    /// Map a PCI BDF to the current physical bay/slot.
    pub fn drive_location(
        &mut self,
        bdf: DriveBdf,
    ) -> Result<DriveLocation, DellError<CON::Error>> {
        self.drive_led_supported()?;
        self.send(Wire::oem(
            0xD5,
            &[1, 7, 6, 0, 0, 0, bdf.bus, (bdf.device << 3) | bdf.function],
        ))
    }

    /// Set a selected drive's SES LED state after storage support and mapping
    /// reads. This changes drive *status*, not merely a decorative indicator.
    pub fn set_drive_led(
        &mut self,
        _: WriteIntent,
        bdf: DriveBdf,
        states: &[DriveLed],
    ) -> Result<(), DellError<CON::Error>> {
        if states.is_empty() {
            return Err(DellError::InvalidInput("at least one SES state required"));
        }
        self.before_write()?;
        let location = self.drive_location(bdf)?;
        let mask = states.iter().fold(0u16, |mask, state| mask | state.mask());
        let mut data = [0; 20];
        data[..8].copy_from_slice(&[0, 4, 14, 0, 0, 0, 14, 0]);
        data[8] = location.bay;
        data[9] = location.slot;
        data[10..12].copy_from_slice(&mask.to_le_bytes());
        self.send(Wire::oem(0xD5, &data))
    }

    /// Read vFlash SD card information, available only through an explicitly
    /// local Open/WMI connection. Network callers must not assert local access.
    pub fn vflash_sd_card(&mut self, _: LocalVflash) -> Result<SdCard, DellError<CON::Error>> {
        self.require(matches!(
            self.controller,
            Controller::Idrac11 { .. } | Controller::Idrac12 { .. } | Controller::Idrac13 { .. }
        ))?;
        self.send(Wire::oem(0xA4, &[0, 0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_structs_reject_every_short_reply() {
        fn short<T: Decode>(size: usize) {
            assert!(T::decode(&vec![0; size - 1]).is_err());
        }
        short::<Controller>(11);
        short::<LcdConfig>(13);
        short::<LcdStatus>(5);
        short::<LcdCaps>(7);
        short::<LcdBlock>(2);
        short::<Loms10>(2);
        short::<LomSize>(2);
        short::<LomBlock>(9);
        short::<VirtualMac>(7);
        short::<PhysicalMac>(7);
        short::<NicResponse>(1);
        short::<PowerMonitor>(24);
        short::<SelTime>(4);
        short::<InstantPower>(7);
        short::<PowerHeadroom>(4);
        short::<PowerPeriods>(9);
        short::<PowerExtrema>(25);
        short::<PowerBudget>(16);
        short::<CapFlags>(1);
        short::<SensorReading>(2);
        short::<SensorThresholds>(6);
        short::<DriveLocation>(9);
        short::<SdCard>(12);
        assert!(parse_nic(&[1], true).is_err());
        assert!(parse_nic(&[], false).is_err());
    }

    #[test]
    fn negative_reply_values_are_not_accepted_as_device_state() {
        assert_eq!(
            Controller::from_imc(0x09),
            Err(DecodeError::UnsupportedModel(9))
        );
        assert!(LcdStatus::decode(&[0, 3, 0, 0, 0]).is_err());
        assert!(LcdCaps::decode(&[0, 1, 5, 62, 0, 0, 0]).is_err());
        assert!(Loms10::decode(&[0, 9]).is_err());
        assert!(LomSize::decode(&[0, 65]).is_err());
        assert!(parse_nic(&[2, 2], true).is_err());
        assert!(parse_nic(&[4], false).is_err());
        assert!(PowerBudget::decode(&[0, 1, 0, 0, 10, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(SensorReading::decode(&[10, 0x20]).is_err());
        assert!(SensorThresholds::decode(&[0, 0, 0, 0, 1, 2]).is_err());
        assert!(DriveLocation::decode(&[0, 0, 0, 0, 0, 0, 0, 0xFF, 2]).is_err());
        assert!(matches!(
            SdCard::decode(&[0x33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::Unlicensed)
        ));
        assert!(matches!(
            SdCard::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::SdCardStatus(1))
        ));
    }
}
