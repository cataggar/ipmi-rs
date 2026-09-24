# `ipmi-rs-core`: IPMI specification definitions

This crate contains the definitions for IPMI commands, payloads, and other data structures used in the
IPMI protocol.

The goal of this library is to be a sans-IO wrapper that can be re-used by other implementations.

For higher-level details, such as a file-based or RMCP connection, check out the [`ipmi-rs`] crate, which is built
on top of `ipmi-rs-core`.

The [`chassis`] module provides read-only `GetChassisStatus` and explicit
`ChassisControl::new(PowerAction)` commands for **host** power (off, on, cycle, hard
reset), distinct from BMC controller reset. Status parsing reports a typed error
for short responses and preserves unknown power restore policies. Failed
commands retain their completion codes in the `ipmi-rs` connection error.
Never automatically resend a chassis control request after a lost or ambiguous
response; a subsequent status read cannot prove whether a cycle/reset happened.

[`chassis`]: https://docs.rs/ipmi-rs-core/latest/ipmi_rs_core/chassis/

`app::{WarmReset, ColdReset}` resets the BMC, not the host. The typed
`chassis::{GetSystemBootOptions, SetSystemBootOptions}` commands cover only
boot-option parameters 0, 3, 4, and 5. Setting boot flags explicitly replaces
all five bytes; optional EFI/clear-CMOS and persistence require explicit
selection. These commands never implicitly update other parameters, reset the
host, or retry when the outcome is unknown after a timeout. Unsupported
controllers or readback fields return errors.

SOL commands are in `app::sol` (`ActivateSol`, `DeactivateSol`,
`SolInstance`) and `transport` (`GetSolConfig`, `SetSolConfig`,
`SolParameterValue`, `sol_write_guarded`). Configuration writes are always
explicit and distinct from activation; a guarded write attempts a bounded
set-complete cleanup and returns cleanup errors instead of hiding them.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs