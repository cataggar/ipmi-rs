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

`sensor_event::PlatformEventMessage` encodes explicit, validated IPMI 2.0
events with the caller-selected system-interface or LAN/IPMB wire format.
Existing typed BMC Global Enables commands support opt-in OpenIPMI
event-buffer setup, preserving other defined bits. Neither a SEL read nor an
event command automatically injects events or retries a write with an
uncertain outcome.

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

## DCMI and Intel Node Manager

`dcmi` implements DCMI 1.0/1.1/1.5 group-extension commands: capabilities
(platform, mandatory/optional attributes and access), power reading/limit
and activation, thermal policy, temperature and sensor-ID paging, asset tag
and management-controller identifier, and configuration parameters 1–5.
Call `GetCapabilities(CapabilitySelector::Platform)` first; its
`CapabilityPage::decode(selector)` validates that selector's standard length
(platform 3, mandatory 4, optional 2, access 3 bytes after the common
four-byte header); `CapabilityPage::extension(selector)` exposes any
additional OEM bytes separately. Always decode with the selector originally
requested: a raw `Ipmi::send_recv(GetCapabilities(selector))` page alone
cannot determine which selector's bytes it contains. Nonstandard
conformance/revisions and malformed payloads are errors, not guesses.
Temperature readings are signed °C, power limits/readings are watts,
correction times are milliseconds, and sample/exception/configuration
intervals explicitly name their units. Enhanced power sampling codes remain
raw because the controller advertises available codes.

For the 16-byte chunked DCMI strings, `read_string` and `write_string`
enforce a **64-byte total** and a bounded number of requests. Similarly,
`read_temperatures` and `read_sensor_records` stop on missing progress or
inconsistent instance counts (at most 255 instances). These are callback
helpers: use `|request| ipmi.send_recv(request)` or send individual typed
requests. `write_string` reports how many previous chunks were acknowledged;
the failed chunk may have applied. An asset tag and controller ID are byte
strings; choose text encoding explicitly and supply a terminating zero byte
for controller-ID strings if the target expects a C string. The read helper
uses the reference's one-byte initial query for controller IDs and a
zero-byte length query for asset tags. A controller ID write may disrupt
the RMCP+ session, so treat missing acknowledgement as uncertain.

`node_manager::NodeManager` **never probes automatically**. Obtain a handle
via `NodeManager::from_device_id(&id)` only for Intel manufacturer ID
`0x000157`, or explicitly override that detection with `NodeManager::opt_in()`
when a non-Intel BMC proxies to Intel NM. Then call `discover()` and
`capabilities(domain, trigger)` before configuring policy limits. The module
provides NM version/capabilities, policy get/upsert/remove/control, power
range, alert destination, and up to three alert thresholds. `PolicySettings`
can be checked with `validate_against(&capabilities)` before sending; only
the controller knows its current policy ranges. NM policy trigger values are
watts, °C or tenths of seconds depending on trigger; correction intervals
are milliseconds and statistics periods seconds. Unknown OEM trigger and
correction codes are preserved on reads and rejected on standard writes.

**Not covered:** DCMI OOB UDP ping, selector 5's NM-enhanced DCMI sampling
metadata, and user-facing CLI; NM statistics, reset-statistics, policy
limiting, and suspend periods. These are not sent implicitly. Reads normally
require Operator access; provisioning limits,
thermal policies, asset/configuration data, alerts and NM policies normally
requires Administrator access and controller support. Check the actual
controller's advertised privileges. Mutations return `Acknowledged` only
after a successful completion code; a lost reply is an **unknown outcome**.
Do not automatically retry limits/policies/alerts or string chunks, and do
not assume a subsequent read conclusively proves that no mutation occurred.

`app::i2c::{I2cBus, I2cAddress, MasterWriteRead}` implements App command 52h.
Each transfer accepts up to 64 bytes written and 64 bytes read. Addresses are
**eight-bit even write addresses** (e.g. SPD 0xA0); use `from_7bit` for SDR
slave addresses. The successful response must contain exactly the requested
number of bytes. Arbitration loss (81h), bus error (82h), NAK on write (83h),
and truncated read (84h) have distinct error variants. Other completion codes
are retained by `IpmiError`. A zero-byte write/read is permitted for
address-only DDR4 SPD page selection.

`storage::sdr::record::GenericDeviceLocator` provides `read(offset, count)`
and `write(offset, bytes)`, plus `_at_address` forms for locators with an
address span. Devices without a one-byte register offset can use
`read_raw(prefix, count)` or explicit `write_raw(bytes)` instead. These
build validated I2C commands; merely discovering/parsing
the locator **never sends a command or mutates a device**. Writes must be
explicitly sent, and their outcomes can be unknown after a timeout. Never
automatically retry uncertain writes. Controller addresses and LUNs in SDRs
are honored; device-access address zero denotes a device directly on IPMB
and uses the local BMC for the Master Write-Read command. Remote satellite
controllers require bridged RMCP routing
(tracked in issue #13), not provided by this API alone.

`app::spd::{Spd, SpdPage}` decodes a complete 256-byte SPD image (or two
pages for DDR4), preserving every unknown byte and memory type. DDR3/DDR4
capacity (including DDR4 12Gb/24Gb densities), ECC width, raw manufacturer
ID, serial and part-number bytes are
decoded where available. A DDR4 header declaring 512 bytes needs both pages.
Decoder output never attempts EEPROM writes.

`app::tyan_tsol` separately models Tyan's IPMI 1.5 OEM NetFn 0x30
start (0x06), stop (0x02), and keystroke (0x03) commands. A `TsolEndpoint`
encodes an IPv4 callback address followed by a big-endian UDP port; a
`TsolKeystroke` holds 1–14 bytes with a one-byte sequence. These sans-IO
commands do **not** validate the target manufacturer or channel on their own.
`app::auth::SetSessionPrivilegeLevel` models App `0x3B` and returns the
echoed *active* privilege, distinct from Activate Session's maximum.
Use the opt-in, identity-checked `ipmi_rs::rmcp::Rmcp` TSOL lifecycle rather
than sending commands directly to unknown devices. TSOL is not RMCP+ SOL or
Intel ISOL.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs