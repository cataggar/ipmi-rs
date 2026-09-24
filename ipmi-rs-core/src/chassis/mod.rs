//! Read-only chassis status and explicit host power control commands.
//!
//! Host chassis control is separate from resetting the BMC. A missing or
//! ambiguous control response leaves the outcome unknown: never retry a
//! control command automatically.

mod chassis_control;
pub use chassis_control::{ChassisControl, PowerAction};

mod get_chassis_status;
pub use get_chassis_status::{
    ChassisStatus, ChassisStatusParseError, FrontPanelButtons, GetChassisStatus, LastPowerEvent,
    PowerRestorePolicy,
};
