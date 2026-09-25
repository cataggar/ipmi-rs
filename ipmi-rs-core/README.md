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

PEF commands are in `sensor_event::pef`. Read-only discovery uses
`GetPefCapabilities` (`0x10`), `GetPefLastProcessedEventId` (`0x15`) and
`GetPefConfig` (`0x13`) for control, actions, filter/policy table sizes and
entries, and the optional PET system GUID. `PefInfo` and `PefStatus` group
these typed readbacks. Decode a configuration result with
`raw.parse(request.parameter)` (or `request.parse_response(bytes)`) and check
the returned `PefConfigValue` variant. Parameter revision, exact lengths,
reserved bits and echoed table IDs are checked. A table size of zero means
unsupported; `PefFilterId::new(index, size)` and `PefPolicyId::new(index, size)`
reject ID zero and IDs above the discovered size. Read the size again before
mutating a table that may have changed.

Writes are separate and **never** performed by reads or discovery.
`SetPefConfig` (`0x12`) explicitly changes a filter's enabled bit or writes a
complete alert policy entry. To toggle a policy, read its entry, change only
`entry.policy.enabled`, then write it using `PefChange::PolicyEntry(entry)`;
this preserves its policy set, rule, channel, destination and alert string key.
`pef_write_guarded(|request| ipmi.send_recv(request), change)` attempts
set-in-progress, the write, commit and set-complete; it attempts cleanup even
when an earlier request fails, and returns every error. A failed response does
not prove a write did not take effect; do not blindly retry. If the BMC rejects
set-in-progress as unsupported (`0x80`), an unguarded `SetPefConfig` requires
an explicit caller decision. Other completion codes are retained by the
connection's `IpmiError`.

An alert policy selects a **channel** and four-bit **destination ID**; it does
not configure the destination's address, type, community or delivery behavior.
LAN alert destination parameters 16–19 belong to LAN configuration on that
channel (tracked separately in issue #23). Do not mistake a policy write for a
LAN destination write. The reference ipmitool PEF CLI implements info, status,
filter/policy listing and enable/disable, including LAN/serial destination
*display*. Its `capabilities`, `event`, `pet`, `timer` and filter/policy
`create`/`delete` CLI branches are explicitly **not implemented**. This module
does not claim those CLI workflows, destination setup, or full filter-entry
writes.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs