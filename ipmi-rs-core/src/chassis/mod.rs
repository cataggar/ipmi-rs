//! Host power control and boot-option commands.
//!
//! Chassis power control is separate from resetting the BMC. A missing or
//! ambiguous mutation response leaves the outcome unknown: never retry it
//! automatically.

mod chassis_control;
pub use chassis_control::{ChassisControl, PowerAction, UnexpectedControlResponseLength};

mod chassis_operations;
pub use chassis_operations::{
    ChassisIdentify, ChassisResponseLength, GetPowerOnHours, GetPowerRestorePolicySupport,
    GetSystemRestartCause, IdentifyMode, PowerOnHours, PowerRestorePolicySetting, RestartCause,
    RestartReason, SetPowerRestorePolicy, SupportedPowerRestorePolicies,
};

mod get_chassis_status;
pub use get_chassis_status::{
    ChassisStatus, ChassisStatusParseError, FrontPanelButtons, GetChassisStatus, LastPowerEvent,
    PowerRestorePolicy,
};

mod boot_options;
pub use boot_options::{
    BootDevice, BootFlags, BootInfoAcknowledge, BootInfoActors, BootInitiatorInfo,
    BootInitiatorInfoWrite, BootMailboxBlock, BootOptionError, BootOptionRejection,
    BootOptionSelector, BootOptionWrite, BootOverride, BootOverrideDuration, BootParameter,
    BootValidBitClearing, GetBootMailboxBlock, GetRawBootOption, GetSystemBootOptions,
    RawBootOption, ServicePartitionScan, ServicePartitionSelector, SetBootMailboxBlock,
    SetInProgress, SetSystemBootOptions,
};
