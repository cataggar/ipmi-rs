# Intel ME (IME) maintenance and recovery

Source: [`ipmitool/lib/ipmi_ime.c`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_ime.c).
`ipmi-rs-core::oem::ime` decodes the Get Device ID firmware/SPS version and
image selector, OEM 0x30/0xA6 status (10-byte wire form; also accepts the
13-byte packed-C-enum form **only** with zero high state bytes), and 0xA7
capabilities. Unknown states and malformed lengths fail closed. The core
module is read-only; mutations are private commands in `ipmi_rs::Ipmi`'s
`ime_update` / `ime_rollback` workflow.

## Preconditions: human approval, not just a matching identifier

1. Plan a **maintenance window** with no dependent production workload,
   stable power, a verified backup, an operator and an out-of-band recovery
   procedure. Sudden power loss during staging or activation can make ME
   firmware unbootable. Retain a tested **board-vendor recovery image** and
   the vendor's local recovery process. Do not assume automatic rollback.
2. Confirm the physical board, ME model and firmware, approved vendor image
   and cryptographic provenance **outside this library**. CRC-8 is **not**
   a signature or authentication. Provide independently trusted expected
   size and CRC-8 when creating `ValidatedImage::new(bytes, size, crc8)`.
   Empty, over-16-MiB, wrong-length and bad-CRC images are rejected before
   sending any packet. Only operational-code images are supported.
3. Explicitly select the ME's **bridged IPMB slave address and numbered
   channel** with `ImeTarget::new(Address(0x88), Channel::new(8).unwrap())`
   (values here are an example, never a default). No direct BMC target or
   implicit channel is permitted. Identity lookup runs on that address,
   channel and LUN 0 before **each** OEM command; require device ID 0,
   revision 0, Intel IANA 343 and product 0x0B00. This prevents accidental
   commands to generic Intel BMCs, but cannot prove hardware authenticity
   or prevent a device swap between lookup and request.
4. Inspect `ipmi.ime_info(target)` for the expected version/image and read
   the capability/status flags before authorizing a write. Update requires
   an available ME, operational image, idle state, operational area support,
   no already staged image, and free staging space at least the image size.
   Rollback requires advertised rollback support, a valid rollback image
   and an inactive update state. Do not force recovery-mode firmware through
   this operational-image workflow.

## Execution and uncertain outcomes

`ipmi.ime_update(target, &image)` sends A0 prepare, A1 open operational area,
up to 22 bytes per A2 packet (sequence wraps modulo 256), A3 close with
little-endian u32 size and u16 CRC-8 (high byte zero), then A4 register
normal update. It checks status after **each** transition, including every
write; A3 must report Requested and a valid staging image, A4 must report
Success. `ipmi.ime_rollback(target)` sends A4 with manual-rollback type 3
and verifies RolledBack. Neither method uses retries or an implicit abort.

On `OutcomeUnknown`, a mutation was dispatched but its outcome cannot be
trusted; **never replay** that prepare/open/chunk/close/activation/rollback.
`NotSent` proves only that *this step's* identity check prevented this
request, not that prior acknowledged steps were rolled back. A status read
failure or unexpected state after a successful mutation likewise leaves a
**partially changed device**. Stop, preserve logs and image metadata,
check on-device status/version from a fresh trusted session and follow the
board vendor's recovery plan; do not rerun this workflow as a blind retry.
On success, independently re-read ME version, image type, attempt indicators,
and service health after the device stabilizes. No power cycling is performed.

These tests use **synthetic source-derived fixtures**, not checked-in ME
captures or hardware tests. No matching live device captures exist yet;
obtain matching, consented ME captures before claiming hardware validation.
The current RMCP implementation does **not** route arbitrary IPMB destinations
([#13](https://github.com/cataggar/ipmi-rs/issues/13)); it rejects unsupported
routes rather than silently writing to the BMC. A connection with explicit,
correct IPMB bridging is necessary to execute against hardware.
