//! PICMG HPM.1 firmware inventory and status (PICMG netfn `0x2c`).
//!
//! No command in this module is sent by construction. The mutating commands
//! require the opt-in `hpm-update` feature and explicit `Ipmi::send_recv` calls.

use crate::connection::{IpmiCommand, Message, NetFn};

fn request(cmd: u8, data: Vec<u8>) -> Message {
    Message::new_request(NetFn::Picmg, cmd, data)
}

/// Invalid or unsupported HPM.1 response data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpmResponseError {
    /// The reply has an unexpected number of bytes.
    Length { expected: usize, actual: usize },
    /// The returned PICMG identifier was not zero.
    Identifier(u8),
    /// The requested component property selector is not supported here.
    Selector(u8),
    /// The controller explicitly reports a rollback failure for this mask.
    RollbackFailed(u8),
}

fn reply(data: &[u8], size: usize) -> Result<&[u8], HpmResponseError> {
    if data.len() != size {
        return Err(HpmResponseError::Length {
            expected: size,
            actual: data.len(),
        });
    }
    if data[0] != 0 {
        return Err(HpmResponseError::Identifier(data[0]));
    }
    Ok(&data[1..])
}

/// Component index, from zero to seven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComponentId(u8);

impl ComponentId {
    /// Create an ID only for a component addressable by HPM.1.
    pub const fn new(value: u8) -> Option<Self> {
        if value < 8 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Component number.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Bit corresponding to this component.
    pub const fn bit(self) -> u8 {
        1 << self.0
    }
}

/// Nonempty HPM.1 component mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentMask(u8);

impl ComponentMask {
    /// Construct a nonempty mask.
    pub const fn new(bits: u8) -> Option<Self> {
        if bits == 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// The raw component bits.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Capabilities reported by the target (timeouts are in five-second units).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCapabilities {
    /// Raw HPM.1 protocol version, as returned by the controller.
    pub version: u8,
    /// Whether firmware upgrade is currently undesirable.
    pub upgrade_undesirable: bool,
    /// Whether the target supports automatic rollback override.
    pub automatic_rollback_override: bool,
    /// Whether the controller degrades during upgrade.
    pub degraded_during_upgrade: bool,
    /// Whether deferred activation is supported.
    pub deferred_activation: bool,
    /// Whether services are affected during upgrade.
    pub services_affected: bool,
    /// Whether manual rollback is supported.
    pub manual_rollback: bool,
    /// Whether automatic rollback is supported.
    pub automatic_rollback: bool,
    /// Whether self-test results are available.
    pub self_test: bool,
    /// Upgrade timeout in five-second units.
    pub upgrade_timeout: u8,
    /// Self-test timeout in five-second units.
    pub self_test_timeout: u8,
    /// Rollback timeout in five-second units.
    pub rollback_timeout: u8,
    /// Inaccessibility timeout in five-second units.
    pub inaccessible_timeout: u8,
    /// Components reported as present.
    pub components: u8,
}

/// Get target upgrade capabilities (`0x2e`), without changing firmware.
pub struct GetTargetCapabilities;

impl From<GetTargetCapabilities> for Message {
    fn from(_: GetTargetCapabilities) -> Self {
        request(0x2e, vec![0])
    }
}

impl IpmiCommand for GetTargetCapabilities {
    type Output = TargetCapabilities;
    type Error = HpmResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let d = reply(data, 8)?;
        let caps = d[1];
        Ok(TargetCapabilities {
            version: d[0],
            upgrade_undesirable: caps & 0x80 != 0,
            automatic_rollback_override: caps & 0x40 != 0,
            degraded_during_upgrade: caps & 0x20 != 0,
            deferred_activation: caps & 0x10 != 0,
            services_affected: caps & 0x08 != 0,
            manual_rollback: caps & 0x04 != 0,
            automatic_rollback: caps & 0x02 != 0,
            self_test: caps & 0x01 != 0,
            upgrade_timeout: d[2],
            self_test_timeout: d[3],
            rollback_timeout: d[4],
            inaccessible_timeout: d[5],
            components: d[6],
        })
    }
}

/// General properties returned by selector zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralProperties {
    /// Raw rollback/backup support mode (two bits).
    pub rollback_backup: u8,
    /// Whether preparation is supported.
    pub preparation: bool,
    /// Whether comparison is supported.
    pub comparison: bool,
    /// Whether deferred activation is supported.
    pub deferred_activation: bool,
    /// Whether payload cold reset is required.
    pub payload_cold_reset: bool,
}

/// Six-byte firmware version (major, minor, four auxiliary bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareVersion(pub [u8; 6]);

/// Decoded component property for selectors `0..=4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentProperty {
    /// Selector zero.
    General(GeneralProperties),
    /// Selector one.
    Current(FirmwareVersion),
    /// Selector two; raw bytes may not be UTF-8 or NUL terminated.
    Description([u8; 12]),
    /// Selector three.
    Rollback(FirmwareVersion),
    /// Selector four.
    Deferred(FirmwareVersion),
}

/// Get a component's general properties, active/rollback/deferred version or
/// description (`0x2f`). Unsupported selectors fail before returning a value.
pub struct GetComponentProperty<const SELECTOR: u8> {
    component: ComponentId,
}

impl<const SELECTOR: u8> GetComponentProperty<SELECTOR> {
    /// Read the given component's selected property.
    pub const fn new(component: ComponentId) -> Self {
        Self { component }
    }
}

impl<const SELECTOR: u8> From<GetComponentProperty<SELECTOR>> for Message {
    fn from(cmd: GetComponentProperty<SELECTOR>) -> Self {
        request(0x2f, vec![0, cmd.component.value(), SELECTOR])
    }
}

impl<const SELECTOR: u8> IpmiCommand for GetComponentProperty<SELECTOR> {
    type Output = ComponentProperty;
    type Error = HpmResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if SELECTOR > 4 {
            return Err(HpmResponseError::Selector(SELECTOR));
        }
        let size = if SELECTOR == 0 {
            2
        } else if SELECTOR == 2 {
            13
        } else {
            7
        };
        let d = reply(data, size)?;
        Ok(match SELECTOR {
            0 => ComponentProperty::General(GeneralProperties {
                rollback_backup: d[0] & 0x03,
                preparation: d[0] & 0x04 != 0,
                comparison: d[0] & 0x08 != 0,
                deferred_activation: d[0] & 0x10 != 0,
                payload_cold_reset: d[0] & 0x20 != 0,
            }),
            1 | 3 | 4 => {
                let version = FirmwareVersion(d.try_into().expect("checked response size"));
                match SELECTOR {
                    1 => ComponentProperty::Current(version),
                    3 => ComponentProperty::Rollback(version),
                    _ => ComponentProperty::Deferred(version),
                }
            }
            2 => ComponentProperty::Description(d.try_into().expect("checked response size")),
            _ => unreachable!(),
        })
    }
}

/// The last long-running HPM.1 command and its raw completion code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeStatus {
    /// Command reported as in progress.
    pub command: u8,
    /// Last command completion code (`0x80` means in progress).
    pub completion_code: u8,
}

/// Read upgrade status (`0x34`); does not confirm an individual upload block.
pub struct GetUpgradeStatus;

impl From<GetUpgradeStatus> for Message {
    fn from(_: GetUpgradeStatus) -> Self {
        request(0x34, vec![0])
    }
}

impl IpmiCommand for GetUpgradeStatus {
    type Output = UpgradeStatus;
    type Error = HpmResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let d = reply(data, 3)?;
        Ok(UpgradeStatus {
            command: d[0],
            completion_code: d[1],
        })
    }
}

/// Components affected by a rollback, possibly zero if none occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackStatus {
    /// The bitmask reported by the target.
    pub components: u8,
}

/// Query rollback status (`0x37`).
pub struct QueryRollbackStatus;

impl From<QueryRollbackStatus> for Message {
    fn from(_: QueryRollbackStatus) -> Self {
        request(0x37, vec![0])
    }
}

impl IpmiCommand for QueryRollbackStatus {
    type Output = RollbackStatus;
    type Error = HpmResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        Ok(RollbackStatus {
            components: reply(data, 2)?[0],
        })
    }

    fn handle_completion_code(
        completion_code: crate::connection::CompletionErrorCode,
        data: &[u8],
    ) -> Option<Self::Error> {
        if completion_code == crate::connection::CompletionErrorCode::CommandSpecific(0x81) {
            Some(match reply(data, 2) {
                Ok(d) => HpmResponseError::RollbackFailed(d[0]),
                Err(error) => error,
            })
        } else {
            None
        }
    }
}

/// Self-test result bytes; `result1 == 0x55` denotes success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestResult {
    /// Self-test primary result.
    pub result1: u8,
    /// Self-test detail.
    pub result2: u8,
}

/// Read firmware self-test results (`0x36`).
pub struct QuerySelfTestResult;

impl From<QuerySelfTestResult> for Message {
    fn from(_: QuerySelfTestResult) -> Self {
        request(0x36, vec![0])
    }
}

impl IpmiCommand for QuerySelfTestResult {
    type Output = SelfTestResult;
    type Error = HpmResponseError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        let d = reply(data, 3)?;
        Ok(SelfTestResult {
            result1: d[0],
            result2: d[1],
        })
    }
}

#[cfg(feature = "hpm-update")]
mod update {
    use super::*;

    /// Firmware upgrade action (`0x31`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UpgradeAction {
        /// Preserve current firmware for a possible rollback.
        Backup,
        /// Prepare components before upload.
        Prepare,
        /// Upgrade a component with uploaded blocks.
        Upgrade,
    }

    /// Start an explicitly selected upgrade action.
    pub struct InitiateUpgradeAction {
        /// Components affected.
        pub components: ComponentMask,
        /// Upgrade action to initiate.
        pub action: UpgradeAction,
    }

    impl From<InitiateUpgradeAction> for Message {
        fn from(cmd: InitiateUpgradeAction) -> Self {
            let action = match cmd.action {
                UpgradeAction::Backup => 0,
                UpgradeAction::Prepare => 1,
                UpgradeAction::Upgrade => 2,
            };
            request(0x31, vec![0, cmd.components.bits(), action])
        }
    }

    macro_rules! simple_write {
        ($name:ident, $number:literal, $bytes:expr) => {
            impl From<$name> for Message {
                fn from(cmd: $name) -> Self {
                    request($number, $bytes(cmd))
                }
            }
            impl IpmiCommand for $name {
                type Output = ();
                type Error = HpmResponseError;
                fn parse_success_response(data: &[u8]) -> Result<(), Self::Error> {
                    reply(data, 1).map(|_| ())
                }
            }
        };
    }

    impl IpmiCommand for InitiateUpgradeAction {
        type Output = ();
        type Error = HpmResponseError;
        fn parse_success_response(data: &[u8]) -> Result<(), Self::Error> {
            reply(data, 1).map(|_| ())
        }
    }

    /// Single bounded HPM.1 block (`0x32`).
    pub struct UploadFirmwareBlock {
        /// Sequence number (wraps after block 255 per HPM.1).
        pub number: u8,
        data: Vec<u8>,
    }

    impl UploadFirmwareBlock {
        /// Build a block containing 1 to 23 bytes (25 bytes total, safe on LAN).
        pub fn new(number: u8, data: &[u8]) -> Option<Self> {
            if data.is_empty() || data.len() > 23 {
                return None;
            }
            Some(Self {
                number,
                data: data.to_vec(),
            })
        }
    }

    impl From<UploadFirmwareBlock> for Message {
        fn from(cmd: UploadFirmwareBlock) -> Self {
            let mut data = vec![0, cmd.number];
            data.extend_from_slice(&cmd.data);
            request(0x32, data)
        }
    }

    /// Optional controller-provided next section offset and length.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UploadAcknowledgement {
        /// An optional section directive that must be handled by the caller.
        pub next_section: Option<(u32, u32)>,
    }

    impl IpmiCommand for UploadFirmwareBlock {
        type Output = UploadAcknowledgement;
        type Error = HpmResponseError;

        fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
            if data.len() == 1 {
                reply(data, 1)?;
                Ok(UploadAcknowledgement { next_section: None })
            } else {
                let d = reply(data, 9)?;
                Ok(UploadAcknowledgement {
                    next_section: Some((
                        u32::from_le_bytes(d[0..4].try_into().expect("checked size")),
                        u32::from_le_bytes(d[4..8].try_into().expect("checked size")),
                    )),
                })
            }
        }
    }

    /// Confirm the length transferred for a component (`0x33`).
    pub struct FinishFirmwareUpload {
        /// The component uploaded.
        pub component: ComponentId,
        /// Number of image bytes transmitted.
        pub length: u32,
    }

    simple_write!(FinishFirmwareUpload, 0x33, |cmd: FinishFirmwareUpload| {
        let mut d = vec![0, cmd.component.value()];
        d.extend_from_slice(&cmd.length.to_le_bytes());
        d
    });

    /// Explicitly activate uploaded firmware (`0x35`), without rollback override.
    pub struct ActivateFirmware;
    simple_write!(ActivateFirmware, 0x35, |_: ActivateFirmware| vec![0]);

    /// Explicitly request a manual firmware rollback (`0x38`).
    pub struct ManualFirmwareRollback;
    simple_write!(
        ManualFirmwareRollback,
        0x38,
        |_: ManualFirmwareRollback| vec![0]
    );

    /// Explicitly abort an update (`0x30`); never sent on cancellation or drop.
    pub struct AbortUpgrade;
    simple_write!(AbortUpgrade, 0x30, |_: AbortUpgrade| vec![0]);
}

#[cfg(feature = "hpm-update")]
pub use update::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picmg_reads_parse_exact_bytes() {
        let cap_request: Message = GetTargetCapabilities.into();
        assert_eq!(cap_request.netfn(), NetFn::Picmg);
        assert_eq!(cap_request.cmd(), 0x2e);
        assert_eq!(cap_request.data(), [0]);
        let cap = GetTargetCapabilities::parse_success_response(&[0, 0x10, 0xff, 1, 2, 3, 4, 0x81])
            .unwrap();
        assert_eq!(cap.components, 0x81);
        assert!(cap.manual_rollback && cap.upgrade_undesirable && cap.self_test);
        assert_eq!(
            GetTargetCapabilities::parse_success_response(&[0, 1]),
            Err(HpmResponseError::Length {
                expected: 8,
                actual: 2
            })
        );
        let id = ComponentId::new(7).unwrap();
        assert!(ComponentId::new(8).is_none());
        assert!(ComponentMask::new(0).is_none());
        let request: Message = GetComponentProperty::<2>::new(id).into();
        assert_eq!(request.cmd(), 0x2f);
        assert_eq!(request.data(), [0, 7, 2]);
        assert_eq!(
            GetComponentProperty::<0>::parse_success_response(&[0, 0x35]),
            Ok(ComponentProperty::General(GeneralProperties {
                rollback_backup: 1,
                preparation: true,
                comparison: false,
                deferred_activation: true,
                payload_cold_reset: true
            }))
        );
        assert_eq!(
            GetComponentProperty::<4>::parse_success_response(&[0, 1, 2, 3, 4, 5, 6]),
            Ok(ComponentProperty::Deferred(FirmwareVersion([
                1, 2, 3, 4, 5, 6
            ])))
        );
        assert_eq!(
            GetComponentProperty::<192>::parse_success_response(&[]),
            Err(HpmResponseError::Selector(192))
        );
        assert_eq!(
            GetUpgradeStatus::parse_success_response(&[0, 0x35, 0x80]).unwrap(),
            UpgradeStatus {
                command: 0x35,
                completion_code: 0x80
            }
        );
        assert_eq!(
            QueryRollbackStatus::handle_completion_code(
                crate::connection::CompletionErrorCode::CommandSpecific(0x81),
                &[0, 0x80]
            ),
            Some(HpmResponseError::RollbackFailed(0x80))
        );
    }

    #[cfg(feature = "hpm-update")]
    #[test]
    fn picmg_writes_require_explicit_messages_and_bounded_blocks() {
        let mask = ComponentMask::new(0x80).unwrap();
        let command: Message = InitiateUpgradeAction {
            components: mask,
            action: UpgradeAction::Upgrade,
        }
        .into();
        assert_eq!(command.data(), [0, 0x80, 2]);
        assert_eq!(command.cmd(), 0x31);
        assert!(UploadFirmwareBlock::new(0, &[]).is_none());
        assert!(UploadFirmwareBlock::new(0, &[7; 24]).is_none());
        let block: Message = UploadFirmwareBlock::new(255, &[1; 23]).unwrap().into();
        assert_eq!(block.cmd(), 0x32);
        assert_eq!(&block.data()[..2], [0, 255]);
        assert_eq!(block.data().len(), 25);
        assert_eq!(
            UploadFirmwareBlock::parse_success_response(&[0, 2, 0, 0, 0, 3, 0, 0, 0]),
            Ok(UploadAcknowledgement {
                next_section: Some((2, 3))
            })
        );
        let finish: Message = FinishFirmwareUpload {
            component: ComponentId::new(7).unwrap(),
            length: 0x1234,
        }
        .into();
        assert_eq!(finish.data(), [0, 7, 0x34, 0x12, 0, 0]);
        let activate: Message = ActivateFirmware.into();
        assert_eq!(activate.data(), [0]);
        assert_eq!(activate.cmd(), 0x35);
        let rollback: Message = ManualFirmwareRollback.into();
        assert_eq!(rollback.data(), [0]);
        assert_eq!(rollback.cmd(), 0x38);
    }
}
