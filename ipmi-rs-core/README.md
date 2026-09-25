# `ipmi-rs-core`: IPMI specification definitions

This crate contains the definitions for IPMI commands, payloads, and other data structures used in the
IPMI protocol.

The goal of this library is to be a sans-IO wrapper that can be re-used by other implementations.

For higher-level details, such as a file-based or RMCP connection, check out the [`ipmi-rs`] crate, which is built
on top of `ipmi-rs-core`.

The [`chassis`] module provides read-only `GetChassisStatus` and explicit
`ChassisControl::new(PowerAction)` commands for **host** power (off, on, cycle, hard
reset, diagnostic interrupt, ACPI soft shutdown), distinct from BMC controller
reset. Explicit `ChassisIdentify`, policy-support query and restore-policy
write, `GetSystemRestartCause`, and `GetPowerOnHours` cover additional standard
chassis operations. The restore policy applies to a future AC power recovery,
not the current host state. Status parsing reports a typed error
for short responses and preserves unknown power restore policies. Failed
commands retain their completion codes in the `ipmi-rs` connection error.
Never automatically resend a chassis control request after a lost or ambiguous
response; a subsequent status read cannot prove whether a cycle/reset happened.

[`chassis`]: https://docs.rs/ipmi-rs-core/latest/ipmi_rs_core/chassis/

`app::{WarmReset, ColdReset}` resets the BMC, not the host. The typed
`chassis::{GetSystemBootOptions, SetSystemBootOptions}` commands cover
boot-option parameters 0 through 6 (including service partitions and boot
initiator info). Parameter 7 is handled one block at a time by
`GetBootMailboxBlock::<N>` and `SetBootMailboxBlock`, with strict bounds and
block-zero IANA validation. Raw reads retain unknown selectors and locked
values, but do not enable raw writes. Unknown boot flags are retained read-only.
Setting boot flags explicitly replaces
all five bytes; optional EFI/clear-CMOS and persistence require explicit
selection. These commands never implicitly update other parameters, reset the
host, or retry when the outcome is unknown after a timeout. Controllers/BIOS
may not support optional identify force-on, mailbox, service partitions or
individual policies; completion errors remain visible.

SOL commands are in `app::sol` (`ActivateSol`, `DeactivateSol`,
`SolInstance`) and `transport` (`GetSolConfig`, `SetSolConfig`,
`SolParameterValue`, `sol_write_guarded`). Configuration writes are always
explicit and distinct from activation; a guarded write attempts a bounded
set-complete cleanup and returns cleanup errors instead of hiding them.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs