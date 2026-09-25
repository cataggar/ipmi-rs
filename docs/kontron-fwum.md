# Kontron FWUM: inspection and guarded updates

This is a library API, not ipmitool CLI progress formatting. Reference wire
layout: [`ipmi_fwum.c`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_fwum.c)
and [`ipmi_fwum.h`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/include/ipmitool/ipmi_fwum.h),
plus [`ipmi_kontronoem.c` 0x3E/0x82](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_kontronoem.c#L131-L204).
There are **no live matched FWUM/IPMC captures or tested devices**: hardware
support, firmware-specific checksum interpretation, negotiated buffer sizes
and actual activation/rollback timing remain **unverified**. The tests use
source-derived synthetic responses, not on-device update transcripts.

## Read-only inventory

`ipmi_rs::Ipmi::fwum_inventory`, `fwum_banks`, and `fwum_trace` are available
without an update feature. Supply `oem::fwum::FwumTarget::new(address,
known_board_product_id)`. `None` addresses the session BMC; a bridged
`Some((Address, Channel))` addresses a selected IPMB device. Reads verify
Get Device ID on **that** destination (Kontron IANA 15000 and exact product),
then read Firmware NetFn 0x08/0x00, 0x07, and seven chunks of 0x0F. Identity
is checked again before each OEM packet, including 0x3E buffer operations.
Bank count is capped at 16, trace at 49 entries, response sizes at 32 bytes,
and busy/transport read retries at three total attempts. No firmware mutation
is triggered. Product 5002 additionally reports SDR revision from Get Device
ID's first auxiliary revision byte when present; other products do not.

**Routed firmware updates over RMCP/RMCP+ are not implemented.**
The [parity milestone #31](https://github.com/cataggar/ipmi-rs/issues/31)
explicitly excludes routed writes; a hardware-verified reconnect/resume
workflow is tracked in [follow-up #65](https://github.com/cataggar/ipmi-rs/issues/65).
[FWUM issue #36](https://github.com/cataggar/ipmi-rs/issues/36) covers
read-only inspection and guarded local updates, not routed writes.
RMCP/RMCP+ supports read-only inspection but not this update workflow.
Its request correlator permanently retires all 64 six-bit IPMB sequences.
Even the smallest valid 1460-byte image requires 57 page-bounded Save Image
packets, each with a Get Device ID check, in addition to baseline reads,
Start/Finish Image and cleanup. Although `Rmcp::activate` can establish a
fresh session using caller-provided credentials, ipmitool does not show that
FWUM preserves an in-flight sequence-mode image across sessions. Firmware
Status exposes bank state/size/revision, **not** the last acknowledged byte
offset or sequence, and the declared Get Last Answer command is not used as
a resumption protocol by ipmitool. No live capture establishes that an IPMC
accepts session renewal during an upload. A reconnect hook would therefore
claim support not yet demonstrated by the protocol reference. Until a
confirmed-boundary reconnect/resume path is verified, `fwum_prepare_update`
rejects RMCP (direct or bridged) before any packet or 0x3E buffer setup,
regardless of the caller's transport label.
Do not change RMCP sequence retirement to work around this limit.
`IpmiConnection::supports_long_mutation_workflows` defaults to **false**:
unknown transports and delegating wrappers around RMCP cannot accidentally
bypass this preflight. Only explicitly audited local transports (Linux IPMI
device files and Linux AMI USB) opt in; `&mut T` forwards the inner transport's
choice. A custom wrapper must not opt in unless its *entire* transport chain
can safely complete long uploads. Serial transport is not opted in.

## On-device write prerequisites

Enable `kontron-fwum-update` explicitly when building both crates; read-only
features remain the default. **Before invoking** `fwum_prepare_update`:

1. Reserve an approved maintenance window with operator, power and service
   impact accounted for. Confirm the exact controller manufacturer, product,
   device ID, transport route, and current bank status on the actual unit.
2. Keep an *independent*, matching Kontron IANA/board/device alternative
   recovery image and out-of-band console/power access readily available.
   Provide nonempty maintenance-window, interruption and rollback procedures
   via `UpdateAuthorization::new`. This is an operator acknowledgement, not
   automatic recovery or hardware qualification.
3. Use a transport without a nonrenewable request sequence limit, and
   establish its real request-data limit. Use
   `TransportLimits::standard(Local | Network | Bridged)` for 32-byte
   packets without changing controller buffers, or explicitly request
   `TransportLimits::negotiated(kind, max_request_bytes, buffer_bytes)`.
   A `Network` or `Bridged` label cannot override the RMCP preflight gate.
   Negotiation requires Kontron identification at the gateway too. For a
   bridged target, the 0x3E/0x82 setup order is local 0x0E, local IPMB 0x00,
   remote 0x0E; successful/uncertain settings are cleared once in reverse
   order, including on handled errors. These channel settings can affect other
   operators: coordinate exclusive access in the maintenance window.
4. Supply a complete image no larger than 512 KiB. The header at 0x5A0 must
   have a big-endian size equal to the file length, a valid big-endian 16-bit
   negative byte-sum checksum excluding the two checksum bytes themselves,
   and a little-endian three-byte IANA. Both primary and recovery images
   must match Kontron IANA 15000, the selected board product and target
   controller device ID exactly; they must be distinct. Start Image's padding
   is the negative byte sum *including* the header checksum bytes. Obtain
   model-specific confirmation of the checksum interpretation before a real
   write; ipmitool reads the header checksum but does not validate it.
5. Only a baseline with exactly one known-good bank and a second bank free of
   pending/new firmware can be staged. A currently pending upload is **not**
   overwritten. `fwum_prepare_update` performs only reads and preflight.

`UpdateSession::stage` starts 0x0A, emits page-bounded 0x0B packets (addressed
mode for protocol ≤5 or short Info replies; sequence mode otherwise), then
finishes 0x0C. The callback receives **acknowledged** bytes and may stop
cleanly by returning `false`. The staged bank must report matching size and
revision as `NewFirmware` **and** the original Last Known Good bank must
retain its baseline length/revision before 0x09 may be sent. Call `activate`
explicitly; an ACK only requests activation after shutdown, and `verify_activation`
needs a fresh status showing the new bank as Last Known Good and the unchanged
old bank as Previous Good. Pending verification can be retried **read-only**.
Manual 0x0E `rollback` is separately explicit, available only after verified
activation and a fresh check that the original Previous Good bank still has
its baseline length/revision. `verify_rollback` must observe the original
good bank, version and length. It never assumes that a rollback ACK completed
the reboot.

## Interruption and recovery

No mutation is replayed, even on `NodeBusy`, 0x82/0xCF duplicate indications,
timeout, truncated success, lost ACK, or an uncertain buffer-clear response.
`MutationOutcome::Rejected` means an acknowledged completion-code rejection;
`Unknown` means the controller *may* have acted; `NotSent` means identity
preflight blocked dispatch. `UpdateError` carries the last confirmed byte
count and any one-shot buffer cleanup errors. A failed or cancelled stage
transitions permanently to `Interrupted`: **do not** continue uploading,
finish, activate or automatically roll back based on a guessed offset. Read
`session.inspect()` / `fwum_banks()` / `fwum_trace()`, restore out-of-band
connectivity, compare status with known baseline and alternate image, and
decide a *new* authorized recovery operation after verifying the actual
device. A process crash cannot guarantee buffer cleanup; inspect/reconcile
0x3E/0x82 channel settings as part of the interruption procedure. If a
Start Update / Manual Rollback reply is lost, avoid replay even when the
immediate status still looks old: BMC reboot may be delayed.

The API does not perform file I/O, progress-bar formatting, reset scheduling,
power orchestration, captures, or automatic image recovery. A successful
synthetic fixture is **not** permission to update hardware: acquire matching
IPMC/firmware revision captures and verify behavior in a qualified
maintenance window first.
