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

`sensor_event::GetSensorReading` continues to return `RawSensorReading`.
Its `flags()` reports availability, scanning and event-message enablement;
`state_bytes()` retains both optional discrete-state bytes. Call
`raw.discrete_for(&full_or_compact_sdr)` to decode asserted offsets using the
SDR's event/reading type, sensor type and supported-reading mask. Each
`DiscreteState` includes its offset even when it has no standard description
or was not advertised in the SDR. Unavailable readings report no asserted
states. A missing required state byte is an error.

`sensor_event::GetSensorThresholds::for_sensor_key` returns a six-position
`SensorThresholds` mask and raw values; absent mask bits are `None`, not zero.
Use `validate_for(&sdr)` to compare the reported mask with the SDR, and
`value(kind, &full_sdr)` for linear analog conversion to `Value` with the SDR's
units. `SetSensorThresholds::new(&full_sdr, &[(kind, setting)])` is an explicit,
validated write: supply `ThresholdSetting::Raw(byte)` or
`ThresholdSetting::Converted(Value::new(full_sdr.common().sensor_units, value))`
for each distinct, settable threshold. Converted values require matching
units and a linear analog SDR; non-finite/out-of-range values are rejected
instead of clamped. Thresholds supplied together must be ordered, but
**partial writes cannot validate omitted thresholds against current BMC
values**. Completion-code errors retain the code. Never retry a threshold
write automatically after a timeout or ambiguous response.

The sensor-key constructors carry the SDR owner address, channel and LUN.
**Remote sensors on satellite controllers additionally need bridged RMCP/IPMB
support** in the transport; using a sensor key does not provide that missing
bridging by itself.

`app::{GetDeviceGuid, GetSelfTestResults}` return the exact GUID bytes (with
explicit IPMI-order formatting) and typed self-test codes including unknown
values. `app::{GetBmcGlobalEnables, SetBmcGlobalEnables}` validate defined
bits; setting enables replaces the full byte and can disable event logging
or interrupts. `app::watchdog` models get/set/reset separately, with countdowns
in 100 ms units and host-power consequences on expiry. `app::system_info`
provides versioned Get, per-set Set, typed set-in-progress, bounded strings
and a guarded multi-set write with visible cleanup errors after a confirmed
begin. A failed begin is not cleaned up automatically, since the lock may
belong to another writer. Select `SystemInfoCommitMode::CompleteOnly` for
controllers that do not support optional Commit Write (`2`), or
`CommitThenComplete` when they do; unsupported commit is not used as a
capability probe, and both modes attempt Set Complete. Mutations may
require Operator or Administrator privilege and a lost reply means the
outcome is unknown: do not automatically retry.

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
set-in-progress, the write, commit and set-complete. A confirmed nonzero
completion code for Begin (including `0x81`, already in progress) skips
set-complete so another writer's transaction is not released. A timeout, lost
response, or malformed success is ambiguous: set-complete is still attempted
and both errors are retained. Once Begin succeeds, cleanup is attempted after
write/commit failures as well. Other error types supplied to the helper must
implement `PefBeginError`, returning `true` only for a confirmed rejection.
A failed response does not prove a write did not take effect; do not blindly
retry. If the BMC rejects set-in-progress as unsupported (`0x80`), an
unguarded `SetPefConfig` requires an explicit caller decision. Completion
codes are retained by the connection's `IpmiError`.

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

OEM typed commands live in the opt-in `oem::{dell,sun,kontron,quanta,ime}`
namespace, executed with `ipmi_rs::Ipmi::send_oem`. This checks Get Device ID
at the command's destination before sending (manufacturer and, for Kontron
CP6012 nextboot, product). It returns an unsupported-device error rather than
trying a vendor packet on a different BMC. The [OEM coverage matrix](../docs/oem-coverage.md)
tracks unimplemented families, supported hardware, required routes and
verification limits. Ordinary raw `Message`/`Request` use remains possible.
Intel ME reads additionally require device ID 0, revision 0, IANA 343,
product 0x0B00 and an explicit bridged IPMB target. Firmware mutations
are available only through the `ipmi-rs` checked IME workflow; see the
[IME safety plan](../docs/ime.md).

SDR retrieval uses separate `storage::sdr::GetSdr` (Storage `0x23`) and
`GetDeviceSdr` (Sensor/Event `0x21`) commands. The latter previously sent the
repository command; its existing constructor and full-record result are
retained, but callers relying on its old wire encoding should switch to
`GetSdr`. `ReserveSdrRepository` and `ReserveDeviceSdr` reserve the respective
sources. `ReadSdr` and `ReadDeviceSdr` return raw `SdrChunk`s for partial
requests (the caller must verify the byte count); use `ipmi-rs`'s
`Ipmi::sdrs_fallible()` for bounded, reservation-aware traversal and errors.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs