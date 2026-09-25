//! Read host chassis status, or explicitly request a host power action over RMCP+.
//!
//! Set IPMI_USERNAME and IPMI_PASSWORD in the environment before running.
//! With no `--action`, this example only reads status. `--action` requires an
//! explicit host power action; do not use remote mutations until the session
//! and request validation work tracked in issue #6 is available.

use std::{
    env,
    io::{self, ErrorKind},
    time::Duration,
};

use clap::{Parser, ValueEnum};
use ipmi_rs::{
    chassis::{ChassisControl, GetChassisStatus, PowerAction},
    rmcp::Rmcp,
    Ipmi, IpmiError,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    Off,
    On,
    Cycle,
    Reset,
    Diag,
    Soft,
}

impl From<Action> for PowerAction {
    fn from(action: Action) -> Self {
        match action {
            Action::Off => Self::Off,
            Action::On => Self::On,
            Action::Cycle => Self::Cycle,
            Action::Reset => Self::HardReset,
            Action::Diag => Self::DiagnosticInterrupt,
            Action::Soft => Self::AcpiSoftShutdown,
        }
    }
}

#[derive(Parser)]
#[command(about = "Read host status (default) or explicitly control host power via RMCP+")]
struct Cli {
    /// BMC address and port, e.g. 192.0.2.10:623
    #[arg(long)]
    address: String,
    /// Milliseconds to wait for a response
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    /// Explicit host action: off, on, cycle, reset, diag, or soft (not a BMC reset)
    #[arg(long, value_enum)]
    action: Option<Action>,
}

fn error(kind: ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    if cli.timeout_ms == 0 {
        return Err(error(
            ErrorKind::InvalidInput,
            "--timeout-ms must be nonzero",
        ));
    }

    let username = env::var("IPMI_USERNAME")
        .map_err(|_| error(ErrorKind::InvalidInput, "IPMI_USERNAME is required"))?;
    let password = env::var("IPMI_PASSWORD")
        .map_err(|_| error(ErrorKind::InvalidInput, "IPMI_PASSWORD is required"))?;

    let mut rmcp = Rmcp::new(&cli.address[..], Duration::from_millis(cli.timeout_ms))?;
    rmcp.activate(true, Some(&username), Some(password.as_bytes()))
        .map_err(|_| error(ErrorKind::Other, "RMCP+ session activation failed"))?;
    if !rmcp.is_rmcp_plus() {
        return Err(error(
            ErrorKind::Other,
            "BMC did not negotiate RMCP+; refusing to send chassis commands over IPMI 1.5",
        ));
    }

    let mut ipmi = Ipmi::new(rmcp);
    if let Some(action) = cli.action {
        match ipmi.send_recv(ChassisControl::new(action.into())) {
            Ok(()) => {
                println!("BMC acknowledged host control request; completion is not guaranteed.")
            }
            Err(IpmiError::Failed {
                completion_code, ..
            }) => {
                eprintln!(
                    "Host control failed (completion code: {completion_code:?}); outcome may be unknown. Do not retry automatically."
                );
                return Err(error(
                    ErrorKind::Other,
                    "Host chassis control not confirmed",
                ));
            }
            Err(_) => {
                eprintln!(
                    "Host control response missing or invalid; outcome unknown. Do not retry automatically."
                );
                return Err(error(
                    ErrorKind::Other,
                    "Host chassis control not confirmed",
                ));
            }
        }
    } else {
        let status = ipmi
            .send_recv(GetChassisStatus)
            .map_err(|_| error(ErrorKind::Other, "Unable to read host chassis status"))?;
        println!("{status:#?}");
    }

    Ok(())
}
