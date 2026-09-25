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

SOL commands are in `app::sol` (`ActivateSol`, `DeactivateSol`,
`SolInstance`) and `transport` (`GetSolConfig`, `SetSolConfig`,
`SolParameterValue`, `sol_write_guarded`). Configuration writes are always
explicit and distinct from activation; a guarded write attempts a bounded
set-complete cleanup and returns cleanup errors instead of hiding them.

[`ipmi-rs`]: https://crates.io/crates/ipmi-rs