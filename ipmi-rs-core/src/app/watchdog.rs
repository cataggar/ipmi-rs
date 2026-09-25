//! Explicit BMC watchdog reads, configuration and countdown restart.

use bitflags::bitflags;

use crate::connection::{CompletionErrorCode, IpmiCommand, Message, NetFn};

/// The owner of a BMC watchdog timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogUse {
    /// Reserved/unspecified readback (`0`); cannot be written.
    Unspecified,
    /// BIOS FRB2.
    BiosFrb2,
    /// BIOS/POST.
    BiosPost,
    /// OS loader.
    OsLoad,
    /// SMS/OS.
    SmsOs,
    /// OEM use.
    Oem,
}

impl WatchdogUse {
    fn value(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::BiosFrb2 => 1,
            Self::BiosPost => 2,
            Self::OsLoad => 3,
            Self::SmsOs => 4,
            Self::Oem => 5,
        }
    }

    fn parse(value: u8) -> Result<Self, WatchdogError> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::BiosFrb2),
            2 => Ok(Self::BiosPost),
            3 => Ok(Self::OsLoad),
            4 => Ok(Self::SmsOs),
            5 => Ok(Self::Oem),
            _ => Err(WatchdogError::InvalidField("timer use", value)),
        }
    }
}

/// Action when a running watchdog expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogAction {
    /// No action (expiration may still be logged).
    None,
    /// Hard reset the host.
    HardReset,
    /// Power off the host.
    PowerDown,
    /// Power-cycle the host.
    PowerCycle,
}

impl WatchdogAction {
    fn value(self) -> u8 {
        match self {
            Self::None => 0,
            Self::HardReset => 1,
            Self::PowerDown => 2,
            Self::PowerCycle => 3,
        }
    }

    fn parse(value: u8) -> Result<Self, WatchdogError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::HardReset),
            2 => Ok(Self::PowerDown),
            3 => Ok(Self::PowerCycle),
            _ => Err(WatchdogError::InvalidField("timer action", value)),
        }
    }
}

/// Interrupt before watchdog expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogInterrupt {
    /// No pre-timeout interrupt.
    None,
    /// System management interrupt.
    Smi,
    /// NMI/diagnostic interrupt.
    Nmi,
    /// Messaging interrupt.
    Messaging,
}

impl WatchdogInterrupt {
    fn value(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Smi => 1,
            Self::Nmi => 2,
            Self::Messaging => 3,
        }
    }

    fn parse(value: u8) -> Result<Self, WatchdogError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Smi),
            2 => Ok(Self::Nmi),
            3 => Ok(Self::Messaging),
            _ => Err(WatchdogError::InvalidField("pre-timeout interrupt", value)),
        }
    }
}

bitflags! {
    /// Watchdog use flags, for both reported expirations and write-to-clear.
    pub struct WatchdogExpirationFlags: u8 {
        /// BIOS FRB2.
        const BIOS_FRB2 = 0x02;
        /// BIOS/POST.
        const BIOS_POST = 0x04;
        /// OS loader.
        const OS_LOAD = 0x08;
        /// SMS/OS.
        const SMS_OS = 0x10;
        /// OEM.
        const OEM = 0x20;
    }
}

/// Get Watchdog Timer (App `0x25`).
#[derive(Clone, Copy, Debug)]
pub struct GetWatchdogTimer;

impl From<GetWatchdogTimer> for Message {
    fn from(_: GetWatchdogTimer) -> Self {
        Message::new_request(NetFn::App, 0x25, vec![])
    }
}

/// The controller's watchdog state, with countdowns in 100 ms units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogTimer {
    /// Which component owns the timer.
    pub timer_use: WatchdogUse,
    /// Whether the timer is currently running (not the Set command's "do not stop" bit).
    pub running: bool,
    /// Whether events for this timer use are not logged.
    pub do_not_log: bool,
    /// Expiry action.
    pub action: WatchdogAction,
    /// Pre-timeout interrupt.
    pub interrupt: WatchdogInterrupt,
    /// Pre-timeout interval, in seconds.
    pub pretimeout_seconds: u8,
    /// Timer use flags for previous expirations.
    pub expiration_flags: WatchdogExpirationFlags,
    /// Configured initial countdown, in 100 ms units.
    pub initial_countdown_deciseconds: u16,
    /// Current countdown, in 100 ms units.
    pub present_countdown_deciseconds: u16,
}

impl IpmiCommand for GetWatchdogTimer {
    type Output = WatchdogTimer;
    type Error = WatchdogError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        if data.len() != 8 {
            return Err(WatchdogError::Length {
                expected: 8,
                actual: data.len(),
            });
        }
        if data[0] & 0x38 != 0 {
            return Err(WatchdogError::InvalidField(
                "timer use reserved bits",
                data[0],
            ));
        }
        if data[1] & 0x88 != 0 {
            return Err(WatchdogError::InvalidField("action reserved bits", data[1]));
        }
        Ok(WatchdogTimer {
            timer_use: WatchdogUse::parse(data[0] & 7)?,
            running: data[0] & 0x40 != 0,
            do_not_log: data[0] & 0x80 != 0,
            action: WatchdogAction::parse(data[1] & 7)?,
            interrupt: WatchdogInterrupt::parse((data[1] >> 4) & 7)?,
            pretimeout_seconds: data[2],
            expiration_flags: WatchdogExpirationFlags::from_bits(data[3])
                .ok_or(WatchdogError::InvalidField("expiration flags", data[3]))?,
            initial_countdown_deciseconds: u16::from_le_bytes([data[4], data[5]]),
            present_countdown_deciseconds: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

/// Configuration for an explicit Set Watchdog Timer command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogConfiguration {
    /// Component owning the timer; `Unspecified` is not valid on write.
    pub timer_use: WatchdogUse,
    /// Preserve the running/stopped state while changing the settings.
    pub do_not_stop: bool,
    /// Suppress watchdog-use logging.
    pub do_not_log: bool,
    /// Action on expiry, including potentially rebooting/powering down the host.
    pub action: WatchdogAction,
    /// Pre-timeout interrupt.
    pub interrupt: WatchdogInterrupt,
    /// Pre-timeout interval, in seconds.
    pub pretimeout_seconds: u8,
    /// Clear only the selected historical expiration flags.
    pub clear_expiration_flags: WatchdogExpirationFlags,
    /// Initial countdown, in 100 ms units.
    pub initial_countdown_deciseconds: u16,
}

/// Set Watchdog Timer (App `0x24`), without resetting/restarting it implicitly.
///
/// This may stop an already-running watchdog unless `do_not_stop` is set, and
/// can cause a host reboot/power event when a running timer expires. The BMC
/// may apply a write even if the acknowledgement is lost; do not retry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetWatchdogTimer(WatchdogConfiguration);

impl SetWatchdogTimer {
    /// Validate and construct a watchdog configuration write.
    pub fn new(config: WatchdogConfiguration) -> Result<Self, WatchdogError> {
        if config.timer_use == WatchdogUse::Unspecified {
            return Err(WatchdogError::InvalidField("timer use", 0));
        }
        if config.pretimeout_seconds != 0
            && config.initial_countdown_deciseconds <= u16::from(config.pretimeout_seconds) * 10
        {
            return Err(WatchdogError::InvalidPretimeout);
        }
        Ok(Self(config))
    }
}

impl From<SetWatchdogTimer> for Message {
    fn from(value: SetWatchdogTimer) -> Self {
        let c = value.0;
        let count = c.initial_countdown_deciseconds.to_le_bytes();
        Message::new_request(
            NetFn::App,
            0x24,
            vec![
                (u8::from(c.do_not_log) << 7)
                    | (u8::from(c.do_not_stop) << 6)
                    | c.timer_use.value(),
                (c.interrupt.value() << 4) | c.action.value(),
                c.pretimeout_seconds,
                c.clear_expiration_flags.bits(),
                count[0],
                count[1],
            ],
        )
    }
}

impl IpmiCommand for SetWatchdogTimer {
    type Output = ();
    type Error = WatchdogError;

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

/// Reset Watchdog Timer (App `0x22`): reload and start the timer.
///
/// This is a side-effecting write, not a read/keepalive; retry only after
/// explicitly deciding what to do with an ambiguous transport outcome.
#[derive(Clone, Copy, Debug)]
pub struct ResetWatchdogTimer;

impl From<ResetWatchdogTimer> for Message {
    fn from(_: ResetWatchdogTimer) -> Self {
        Message::new_request(NetFn::App, 0x22, vec![])
    }
}

impl IpmiCommand for ResetWatchdogTimer {
    type Output = ();
    type Error = WatchdogError;

    fn handle_completion_code(code: CompletionErrorCode, _: &[u8]) -> Option<Self::Error> {
        (code == CompletionErrorCode::CommandSpecific(0x80))
            .then_some(WatchdogError::NotInitialized)
    }

    fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
        empty_response(data)
    }
}

fn empty_response(data: &[u8]) -> Result<(), WatchdogError> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(WatchdogError::Length {
            expected: 0,
            actual: data.len(),
        })
    }
}

/// Invalid watchdog response or rejected configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogError {
    /// Response expected and actual lengths.
    Length { expected: usize, actual: usize },
    /// Unsupported field or reserved bit (field name, raw byte).
    InvalidField(&'static str, u8),
    /// Pre-timeout must be strictly less than the configured initial countdown.
    InvalidPretimeout,
    /// Reset rejected with command-specific completion code `0x80`.
    NotInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> WatchdogConfiguration {
        WatchdogConfiguration {
            timer_use: WatchdogUse::SmsOs,
            do_not_stop: true,
            do_not_log: true,
            action: WatchdogAction::PowerCycle,
            interrupt: WatchdogInterrupt::Nmi,
            pretimeout_seconds: 10,
            clear_expiration_flags: WatchdogExpirationFlags::SMS_OS
                | WatchdogExpirationFlags::BIOS_FRB2,
            initial_countdown_deciseconds: 3000,
        }
    }

    #[test]
    fn watchdog_request_and_response_fixtures() {
        let get: Message = GetWatchdogTimer.into();
        assert_eq!((get.netfn_raw(), get.cmd(), get.data()), (6, 0x25, &[][..]));
        let timer = GetWatchdogTimer::parse_success_response(&[
            0xc4, 0x23, 10, 0x12, 0xb8, 0x0b, 0x34, 0x12,
        ])
        .unwrap();
        assert_eq!(timer.timer_use, WatchdogUse::SmsOs);
        assert!(timer.do_not_log && timer.running);
        assert_eq!(timer.action, WatchdogAction::PowerCycle);
        assert_eq!(timer.interrupt, WatchdogInterrupt::Nmi);
        assert_eq!(timer.expiration_flags.bits(), 0x12);
        assert_eq!(
            (
                timer.initial_countdown_deciseconds,
                timer.present_countdown_deciseconds
            ),
            (3000, 0x1234)
        );

        let set: Message = SetWatchdogTimer::new(fixture()).unwrap().into();
        assert_eq!(
            (set.netfn_raw(), set.cmd(), set.data()),
            (6, 0x24, &[0xc4, 0x23, 10, 0x12, 0xb8, 0x0b][..])
        );
        let reset: Message = ResetWatchdogTimer.into();
        assert_eq!(
            (reset.netfn_raw(), reset.cmd(), reset.data()),
            (6, 0x22, &[][..])
        );
        assert_eq!(SetWatchdogTimer::parse_success_response(&[]), Ok(()));
        assert_eq!(ResetWatchdogTimer::parse_success_response(&[]), Ok(()));
        assert_eq!(
            ResetWatchdogTimer::handle_completion_code(
                CompletionErrorCode::CommandSpecific(0x80),
                &[]
            ),
            Some(WatchdogError::NotInitialized)
        );
    }

    #[test]
    fn reject_invalid_or_short_watchdog_data() {
        for len in [0, 7, 9] {
            assert_eq!(
                GetWatchdogTimer::parse_success_response(&vec![0; len]),
                Err(WatchdogError::Length {
                    expected: 8,
                    actual: len
                })
            );
        }
        for (index, byte) in [(0, 0x08), (0, 0x06), (1, 0x08), (1, 0x40), (3, 0x01)] {
            let mut response = [0; 8];
            response[index] = byte;
            assert!(matches!(
                GetWatchdogTimer::parse_success_response(&response),
                Err(WatchdogError::InvalidField(_, _))
            ));
        }
        let mut invalid = fixture();
        invalid.timer_use = WatchdogUse::Unspecified;
        assert!(matches!(
            SetWatchdogTimer::new(invalid),
            Err(WatchdogError::InvalidField("timer use", 0))
        ));
        invalid.timer_use = WatchdogUse::SmsOs;
        invalid.initial_countdown_deciseconds = 100;
        assert_eq!(
            SetWatchdogTimer::new(invalid),
            Err(WatchdogError::InvalidPretimeout)
        );
        assert_eq!(
            SetWatchdogTimer::parse_success_response(&[0]),
            Err(WatchdogError::Length {
                expected: 0,
                actual: 1
            })
        );
        assert_eq!(
            ResetWatchdogTimer::parse_success_response(&[0]),
            Err(WatchdogError::Length {
                expected: 0,
                actual: 1
            })
        );
    }
}
