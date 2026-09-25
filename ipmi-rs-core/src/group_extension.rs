//! Shared, bounded PICMG and VITA 46.11 group-extension wire types.

pub(crate) const PICMG_ID: u8 = 0;
pub(crate) const VITA_ID: u8 = 3;
const MAX_RESPONSE: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupError {
    InvalidLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    WrongExtension {
        expected: u8,
        actual: u8,
    },
    UnsupportedOperation,
    InvalidInput(&'static str),
}

pub(crate) fn check(data: &[u8], id: u8, min: usize, max: usize) -> Result<&[u8], GroupError> {
    let max = max.min(MAX_RESPONSE);
    if data.len() < min || data.len() > max {
        return Err(GroupError::InvalidLength {
            min,
            max,
            actual: data.len(),
        });
    }
    if data[0] != id {
        return Err(GroupError::WrongExtension {
            expected: id,
            actual: data[0],
        });
    }
    Ok(data)
}

pub(crate) fn ack(data: &[u8], id: u8) -> Result<(), GroupError> {
    check(data, id, 1, 1).map(|_| ())
}

macro_rules! group_command {
    ($name:ty => $output:ty, $id:expr, $cmd:expr,
     |$value:ident| $payload:expr, |$data:ident| $parse:expr) => {
        impl From<$name> for $crate::connection::Message {
            fn from($value: $name) -> Self {
                $crate::connection::Message::new_request(
                    $crate::connection::NetFn::GroupExtension,
                    $cmd,
                    $payload,
                )
            }
        }

        impl $crate::connection::IpmiCommand for $name {
            type Output = $output;
            type Error = $crate::group_extension::GroupError;

            fn handle_completion_code(
                code: $crate::connection::CompletionErrorCode,
                _: &[u8],
            ) -> Option<Self::Error> {
                matches!(
                    code,
                    $crate::connection::CompletionErrorCode::InvalidCommand
                        | $crate::connection::CompletionErrorCode::InvalidCommandForLun
                        | $crate::connection::CompletionErrorCode::SubFunctionDisabled
                )
                .then_some(Self::Error::UnsupportedOperation)
            }

            fn parse_success_response($data: &[u8]) -> Result<Self::Output, Self::Error> {
                $crate::group_extension::check($data, $id, 1, 255)?;
                $parse
            }
        }
    };
}
pub(crate) use group_command;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    Deactivate,
    Activate,
}
impl Activation {
    pub const fn value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FruControl {
    ColdReset,
    WarmReset,
    GracefulReboot,
    DiagnosticInterrupt,
    Quiesce,
}
impl FruControl {
    pub const fn value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressInfo {
    pub hardware_address: u8,
    pub ipmb_0_address: u8,
    pub reserved: u8,
    pub fru_id: u8,
    pub site_id: u8,
    pub site_type: u8,
    pub channel_7_address: Option<u8>,
    pub optional_bytes: Vec<u8>,
}

pub(crate) fn address(data: &[u8], id: u8, vita: bool) -> Result<AddressInfo, GroupError> {
    let b = check(data, id, 7, if vita { 9 } else { 7 })?;
    Ok(AddressInfo {
        hardware_address: b[1],
        ipmb_0_address: b[2],
        reserved: b[3],
        fru_id: b[4],
        site_id: b[5],
        site_type: b[6],
        channel_7_address: b.get(8).copied(),
        optional_bytes: b[7..].to_vec(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedProperties {
    pub general_status: u8,
    pub application_specific_count: u8,
}
pub(crate) fn led_properties(data: &[u8], id: u8) -> Result<LedProperties, GroupError> {
    let b = check(data, id, 3, 3)?;
    Ok(LedProperties {
        general_status: b[1],
        application_specific_count: b[2],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedCapabilities {
    pub colors: u8,
    pub local_color: u8,
    pub override_color: u8,
    pub flags: Option<u8>,
}
pub(crate) fn led_capabilities(
    data: &[u8],
    id: u8,
    vita: bool,
) -> Result<LedCapabilities, GroupError> {
    let b = check(data, id, 4, if vita { 5 } else { 4 })?;
    Ok(LedCapabilities {
        colors: b[1],
        local_color: b[2],
        override_color: b[3],
        flags: b.get(4).copied(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedSetting {
    pub function: u8,
    pub duration: u8,
    pub color: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedState {
    pub flags: u8,
    pub local: Option<LedSetting>,
    pub override_setting: Option<LedSetting>,
    pub lamp_test_duration: Option<u8>,
}
pub(crate) fn led_state(data: &[u8], id: u8) -> Result<LedState, GroupError> {
    let b = check(data, id, 5, 9)?;
    let flags = b[1];
    let local = if flags & 1 != 0 {
        Some(LedSetting {
            function: b[2],
            duration: b[3],
            color: b[4],
        })
    } else {
        None
    };
    let override_setting = if flags & 6 != 0 {
        if b.len() < 8 {
            return Err(GroupError::InvalidLength {
                min: 8,
                max: 9,
                actual: b.len(),
            });
        }
        Some(LedSetting {
            function: b[5],
            duration: b[6],
            color: b[7],
        })
    } else {
        None
    };
    let lamp_test_duration = if flags & 4 != 0 {
        if b.len() < 9 {
            return Err(GroupError::InvalidLength {
                min: 9,
                max: 9,
                actual: b.len(),
            });
        }
        Some(b[8])
    } else {
        None
    };
    let expected = if flags & 4 != 0 {
        9
    } else if flags & 2 != 0 {
        8
    } else {
        5
    };
    if b.len() != expected {
        return Err(GroupError::InvalidLength {
            min: expected,
            max: expected,
            actual: b.len(),
        });
    }
    Ok(LedState {
        flags,
        local,
        override_setting,
        lamp_test_duration,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedFunction {
    Off,
    Blink { off_duration: u8, on_duration: u8 },
    LampTest(u8),
    LocalControl,
    On,
}
impl LedFunction {
    pub(crate) fn bytes(self) -> Result<(u8, u8), GroupError> {
        match self {
            Self::Off => Ok((0, 0)),
            Self::Blink {
                off_duration: off_duration @ 1..=250,
                on_duration,
            } => Ok((off_duration, on_duration)),
            Self::Blink { .. } => Err(GroupError::InvalidInput(
                "blinking off duration must be 1..=250",
            )),
            Self::LampTest(duration @ 0..=127) => Ok((0xfb, duration)),
            Self::LampTest(_) => Err(GroupError::InvalidInput(
                "lamp test duration must be <= 127",
            )),
            Self::LocalControl => Ok((0xfc, 0)),
            Self::On => Ok((0xff, 0)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedOverride {
    function: u8,
    duration: u8,
    color: u8,
}
impl LedOverride {
    pub fn new(function: LedFunction, color: u8) -> Result<Self, GroupError> {
        if !matches!(color, 1..=6 | 0xe..=0xf) {
            return Err(GroupError::InvalidInput(
                "LED color must be 1..=6 or 0xe..=0xf",
            ));
        }
        let (function, duration) = function.bytes()?;
        Ok(Self {
            function,
            duration,
            color,
        })
    }
    pub const fn wire(self) -> [u8; 3] {
        [self.function, self.duration, self.color]
    }
}
