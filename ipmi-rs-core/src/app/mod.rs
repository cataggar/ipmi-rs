//! Definitions for IPMI app commands.

mod get_device_id;
pub use get_device_id::{DeviceId, GetDeviceId};

mod get_channel_info;
pub use get_channel_info::{
    AuxChannelInfo, ChannelInfo, ChannelMediumType, ChannelProtocolType, ChannelSessionSupport,
    GetChannelInfo,
};

mod get_channel_access;
pub use get_channel_access::{
    ChannelAccess, ChannelAccessMode, ChannelAccessSettings, ChannelAccessType,
    ChannelPrivilegeLevel, GetChannelAccess, SetChannelAccess, SetChannelAccessError,
    SetChannelAccessMode,
};

pub mod user;
pub use user::{
    GetUserAccess, GetUserName, GetUserSummary, PasswordLength, SetUserAccess, SetUserName,
    SetUserPassword, SetUserPrivilege, UserAccess, UserEnableStatus, UserId, UserList, UserName,
    UserPassword, UserPrivilege, UserRequestError, UserResponseError, UserSummary, UserTextError,
};

pub mod auth;
pub mod sol;

mod reset;
pub use reset::{ColdReset, UnexpectedResetResponseLength, WarmReset};
