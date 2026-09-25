# ipmi-rs
A Rust IPMI library.

This library is based on the [IPMI v2.0 Revision 1.1][0] specification.

[0]: https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf

## Examples

This repository contains several (useful) examples, which can be found in [ipmi-rs/examples](./ipmi-rs/examples/).

They have a configurable target, using the `-c` option. It supports the formats `file://<path-to-ipmi-file>` and `rmcp://<user>:<password>@<host>:<port>`.

To see information produced by the examples, configure the log level using [`RUST_LOG`](https://docs.rs/env_logger/latest/env_logger/#enabling-logging). `info` is recommended.

### `get-info`
This example usually has to be run as root.

This example will:
1. Get SEL info
2. (If supported) get SEL allocation information
3. (If present) get the first SEL record
4. Get the Device ID
5. Get Device SDR info when supported
6. Get SDR repository info and allocation information when supported
7. Load SDR records from the advertised repository or Device SDR source
8. Attempt to read the value of the sensors described by those records

### SDR retrieval

`Ipmi::sdrs_fallible()` uses Get Device ID to select the SDR repository
(Storage netfn, command `0x23`) or, for a device-only controller, Device SDRs
(Sensor/Event netfn, command `0x21`). When both are advertised it prefers the
repository. Choose one explicitly with `ipmi.sdrs_from(SdrSource::Device)` or
`ipmi.sdrs_from(SdrSource::Repository)`; this also avoids Get Device ID when
capability flags are unreliable. Both iterators yield
`Result<storage::sdr::Record, SdrError<_>>`:

```rust,ignore
use ipmi_rs::{Ipmi, SdrSource};

let records = ipmi.sdrs_fallible().collect::<Result<Vec<_>, _>>()?;
// To select Device SDRs explicitly instead:
let device_records = ipmi.sdrs_from(SdrSource::Device)
    .collect::<Result<Vec<_>, _>>()?;
```

An empty advertised source or a next-record ID of `0xffff` ends normally.
Errors (including metadata, transport, parsing, inconsistent/short chunks,
and reservation failures) are returned once, not silently mistaken for end of
records. The iterator reserves a repository only when its Reserve operation is
advertised, or Device SDRs only when their population is dynamic; otherwise it
uses reservation ID zero without issuing `0x22`. It reads up to 32 record bytes
per request, reduces the chunk size on transfer-size completion errors, and
restarts a record from its header after a cancelled supported reservation (up
to three renewals). For non-first records with a mismatched header ID, it
returns the requested ID, which was used for subsequent reads. Unrecoverable
errors are not skipped. The older `ipmi.sdrs()` still returns plain records
from the **repository** and logs then stops on errors; prefer the fallible API
for complete inventories.

For individual commands, `storage::sdr::GetSdr` now names the repository
operation. `GetDeviceSdr::new(...)` retains its constructor and full-record
return type but now correctly sends the **Device** SDR command. Migrate
callers relying on its former (incorrect) Storage wire encoding to `GetSdr`.
Full-record `0xff` requests can exceed transport limits; use the high-level
iterator for bounded reads.

### `sel`

This example will read out and print the SEL (System Event Log) of your target. It can also be cleared by passing the `--clear` flag. Listing uses bounded, fallible SEL traversal; errors are reported rather than treated as end-of-log.

### SEL traversal and writes

`Ipmi::sel_entries(max_entries)` returns an iterator over `Result<SelEntryInfo, SelIterError<_>>`.
It reads Get SEL Info to recognize an empty log, reserves the SEL if supported, follows
the BMC's next-record pointers (IDs need not be consecutive), renews cancelled
reservations on *reads*, and rescans from FIRST up to twice if a next ID was
deleted. Previously emitted records are not emitted again. `None` means the
log ended; an `Err` means a read failed or a bounded traversal could not
complete (including the caller's `max_entries` limit). The iterator is fused
after an error. This is **not a snapshot**: a changing log can omit records;
restart a new scan if a stable view is needed. The read budget is at most
`min(max_entries * 4 + 4, 65536)` Get SEL Entry requests.

```rust
// ipmi: &mut Ipmi<impl IpmiConnection>
for result in ipmi.sel_entries(4096) {
    let record = result?; // handle error; do not treat it as end-of-log
    println!("SEL ID {:04X}: {:?}", record.entry.record_id().value(), record.entry);
    // record.raw contains the exact 16 bytes for every record, including OEM/unknown.
}
```

`GetSelTime` returns a `Timestamp`; `.seconds()` exposes the raw 32-bit
seconds value (0 means unspecified). The clock value is not adjusted for
timezone by the library. `SetSelTime(Timestamp::from(seconds))` sends an
explicit clock write. `AddSelEntry::new(&raw_record)` accepts exactly 16
bytes with a zero record ID (the BMC assigns the ID) and validates the
record; it returns the assigned `RecordId`. `DeleteSelEntry::new(reservation,
record_id)` accepts only actual record IDs and returns the deleted ID.
Use `ReserveSel` first when the BMC advertises reservation support; otherwise
pass `None`. OEM and unrecognized record types retain their uninterpreted
payload; `SelEntryInfo::raw` preserves all 16 bytes losslessly.

Send SEL mutations using `ipmi.sel_mutation(command)`, **not** a retry loop:
`SelMutationError::Rejected` contains a BMC completion-code failure;
`SelMutationError::OutcomeUnknown` means a transport failure, mismatched
response, or malformed successful response could follow an executed
mutation. Never automatically retry add, delete, or time writes in that
case. A reservation cancellation returned for a delete is a rejection,
not a reason to silently resend the write.

### Platform events and event consumers

`sensor_event::PlatformEventMessage::new(sensor_type, sensor_number, event_type,
direction, data, interface)` validates reserved sensor/event codes and sensor
number `0xff`, uses event revision 0x04, and requires an explicit
`EventInterface::{System,LanOrIpmb}` choice. The system interface adds the SMS
generator byte `0x41`; LAN/IPMB must **not** include it. Reading the SEL never
injects an event. To inject an event, call `Ipmi::inject_platform_event(event)`
once. `EventInjectionError::Rejected` means the BMC explicitly returned a
completion-code failure; `OutcomeUnknown` means an event *may* have been
recorded despite a lost, mismatched, or malformed response. Never automatically
retry an unknown outcome.

```rust
use ipmi_rs::{
    sensor_event::{EventInterface, PlatformEventMessage},
    storage::{sdr::SensorType, sel::EventDirection},
};
// With an authenticated, authorized Ipmi connection:
let event = PlatformEventMessage::new(
    SensorType::Temperature, 0x30, 1, EventDirection::Assert,
    [9, 0xff, 0xff], EventInterface::LanOrIpmb,
)?;
ipmi.inject_platform_event(event)?; // only explicit calls can send an event
```

There are **two distinct receive paths**:

* On a Linux OpenIPMI `File` connection, `file.open_event_receiver()?` explicitly
  enables the BMC event buffer (read/modify/write, preserving other bits) and
  subscribes that descriptor via `IPMICTL_SET_GETS_EVENTS_CMD`. Its
  `receiver.recv_until(deadline, &token)` returns a parsed 16-byte
  `OpenIpmiEvent`, or a setup/receive, unexpected-message, malformed-record,
  truncated-event, cancellation, or deadline error. This is **true local
  asynchronous notification** (not available over RMCP); it exclusively
  borrows the descriptor. Call `receiver.close()` to surface unsubscribe
  failures; Drop unsubscribes best-effort, but does not disable the BMC-wide
  enable bit. Prefer a dedicated OpenIPMI file descriptor: kernel events
  already queued on a reused descriptor may conflict with subsequent
  command/response reads.
  A failed global-enables write may have taken effect; do not blindly repeat it.
* `ipmi.sel_poller(max_entries, deadline, &token)?` works with any
  `IpmiConnection` (local or RMCP). It establishes a baseline without replaying
  old entries, then `poll_once(deadline, &token)` performs one scan or
  `wait_next(interval, deadline, &token)` waits for an entry or gap. This is
  **periodic polling**, not an asynchronous interrupt. It reuses the bounded,
  fallible `sel_entries` traversal; supply `max_entries` in `1..=65534`.
  `SelPollBatch` has new entries in BMC order, removed/missing IDs,
  `wrapped` (new ID decrease across scans), `overflow` (current BMC state),
  and `continuity_lost` for removals, deletion timestamps, or **any currently
  set overflow bit**, including overflow present at startup. Check
  `poller.overflow()` immediately after creating a baseline; a quiet scan
  while still overflowing returns a gap rather than an empty wait. The poller
  deduplicates by record ID and **raw contents**, not by arithmetic increments,
  so IDs may skip or wrap. If an
  identical record ID/content is reused between scans without detectable SEL
  metadata changes, continuity cannot be proven; poll more often or use the
  local asynchronous receiver. A failed/unstable scan never advances the
  baseline or masquerades as an empty batch.

Both receive APIs accept an absolute monotonic `Instant` and the cloneable
`rmcp::CancellationToken` (cancellation is sticky; reset only after an operation
has returned). The local receiver checks cancellation every 50 ms. SEL polling
checks **before and after every transport command**, including Get SEL Info,
reservations, reads, and internal rescans. Built-in RMCP, OpenIPMI file, serial
and AMI USB connections clamp each command to the remaining deadline and
observe the poller's token during I/O (kernel ioctls cannot be preempted
mid-call). Custom `IpmiConnection` implementations should override
`send_recv_deadline` for the same guarantee; the default delegates to
`send_recv`, so configure a bounded per-command timeout on custom transports.

### `ipmi-channels`
This example discovers available channels and prints channel information. For LAN channels, it also shows a small set of LAN configuration parameters (addressing and gateways).

### `ipmi-lan-config`
This example reads LAN configuration for all LAN channels and emits JSON. You can apply a JSON configuration with `--set` **and** `--confirm-network-change`, print the input schema with `--print-schema`, or emit an IPv6 example payload with `--print-v6-example`. The example validates writes before starting a transaction and stops on the first uncertain result; `--force-write-all` is additionally needed for MAC fields that may be read-only.

### LAN configuration and operational safety

`ipmi-rs-core::transport` provides typed Get/Set LAN parameters (including alert destinations, IPv4, IPv6 static/dynamic addressing, DHCPv6 DUID/timing blocks, router fields, VLAN, authentication and ARP), plus `GetLanStatistics` and `ClearLanStatistics`. The latter two use Transport command `0x04` with explicit channel and clear flag; clearing statistics is a **mutation** and must not be retried after an ambiguous response. Known Get parameter values require revision `0x11` and validated lengths. For entries with a set or block selector, pass them on `GetLanConfigParameters` and use `LanConfigParameterResponse::parse_selected(parameter, set, block)` to verify the returned entry. For unsupported/OEM selectors use `LanConfigParameter::Other(n)` and raw payloads; this also retains unsupported revisions.

Construct checked writes with `SetLanConfigParameters::checked(channel, typed_value)`; for unknown fields, `SetLanConfigParameters::new(channel, Other(n), raw_bytes)` is the explicit unchecked escape hatch. DUIDs use `Ipv6Duid::blocks()`/`from_blocks()`, DHCPv6 timing uses `Ipv6DhcpTiming::blocks()`/`from_blocks()` (both writes contain 16 data bytes; the second pads its six meaningful bytes with zeroes), and the two static routers have independent selectors (`ipv6_static_router_writes`). The bounded `lan_write_guarded(send, channel, writes, classify_begin)` helper validates **all** writes before beginning, issues set-in-progress, writes in order, and commits only after all writes succeed. Classify a definite non-execution response (such as `0x81` or `NodeBusy` / `0xC0`) as `LanBeginFailure::Rejected` to avoid releasing another writer's transaction; classify a lost acknowledgement, processing timeout, or otherwise ambiguous response as `Uncertain` so set-complete cleanup is attempted. After an acknowledged begin, cleanup is always attempted. It returns both the primary error and any cleanup error; it never retries writes or suppresses an unsupported commit.

**Operator confirmation is essential:** changing IPv4 address/source/subnet/gateways, MAC, RMCP port, VLAN, IPv6 enablement/addresses/routers/DHCP settings, channel access or authentication can sever the management session immediately, even before commit. An application should verify the target, have alternate access/recovery ready, request explicit operator approval, and reconnect or read back from a *new* session after an uncertain result. Neither a timeout nor a nonzero completion code proves a mutation did not take effect; do not blindly resend it.

### `chassis`
This RMCP+ example reads host chassis status by default. Provide the BMC address and port, and set
`IPMI_USERNAME` and `IPMI_PASSWORD` in the environment via a secure credential source. Credentials
are never accepted as command-line arguments or printed by the example.

```sh
cargo run -p ipmi-rs --example chassis -- --address 192.0.2.10:623
```

To request a **host** power action, explicitly supply `--action off`, `on`, `cycle`, or `reset`
(hard host reset, **not** BMC reset). For example, only after verifying the target, access controls,
and operational readiness:

```sh
cargo run -p ipmi-rs --example chassis -- --address 192.0.2.10:623 --action cycle
```

The example refuses to send commands if RMCP+ was requested but activation fell back to IPMI 1.5.
A lost, timed-out, or ambiguous control response means the **outcome is unknown**.
Never automatically resend a power command, even for a "node busy" response.
A later status read is useful for observation but cannot prove whether a cycle
or reset occurred.

## DCMI and Node Manager

`ipmi-rs` re-exports the typed `dcmi` and `node_manager` modules. For
example, `ipmi.send_recv(dcmi::GetPowerReading(dcmi::PowerSample::Standard))`
reads watts, and `dcmi::read_string(dcmi::StringKind::AssetTag,
|request| ipmi.send_recv(request))` reads a bounded asset tag. NM commands
require an explicit `node_manager::NodeManager::opt_in()` or matching Intel
`GetDeviceId` manufacturer ID; nothing probes the OEM NetFn on connection.
See the `ipmi-rs-core` README for supported subsets, units, privileges,
pagination and uncertain mutation outcomes.

## DCMI and Node Manager

The typed [`dcmi`](ipmi-rs-core/src/dcmi.rs) and
[`node_manager`](ipmi-rs-core/src/node_manager.rs) modules cover DCMI
capability discovery, power, thermal, asset/configuration data, and Intel
Node Manager policy, alert and threshold operations. NM requires explicit
Intel vendor detection or an explicit OEM opt-in; requests are not sent
until called. See the [`ipmi-rs-core` README](ipmi-rs-core/README.md) for
supported command subsets, units, privileges, bounds and safe handling of
unknown mutation outcomes.

# Project structure

This project contains three crates:

* `ipmi-rs-core`: core primitives, commands, and other application independent structures.
* `ipmi-rs`: implements IO for interacting with IPMI systems based on primitives from `ipmi-rs-core`.
* `ipmi-rs-log`: logging/formatting for items from `ipmi-rs-core` (deprecated).

# Supported commands

The following IPMI commands are currently supported in `ipmi-rs-core`:

| Command                                 | Specification section |
| :-------------------------------------- | :-------------------- |
| Get Chassis Status                      | 28.2                  |
| Chassis Control (host power)            | 28.3                  |
| Get Device ID                           | 20.1                  |
| Get Device GUID / Self Test Results      | App commands 0x37/0x04 |
| Get / Set BMC Global Enables             | App commands 0x2f/0x2e |
| Get / Set / Reset Watchdog Timer         | App commands 0x25/0x24/0x22 |
| Get / Set System Info Parameters         | App commands 0x59/0x58 |
| Cold Reset / Warm Reset (BMC)            | App commands 0x02/0x03 |
| Get Channel Authentication Capabilities | 22.13                 |
| Get Channel Cipher Suites               | 22.15                 |
| Get Session Challenge                   | 22.16                 |
| Activate Session                        | 22.17                 |
| Get Channel Access                      | 22.23                 |
| Get Channel Info                        | 22.24                 |
| Set Channel Access                      | App command 0x40      |
| Get User Summary / Access / Name        | App commands 0x44/0x46 |
| Set User Access / Privilege / Name      | App commands 0x43/0x45 |
| Enable / Disable / Set / Test User Password | App command 0x47  |
| I2C Master Write-Read                   | App command 0x52      |
| Set / Get System Boot Options            | Chassis commands 0x08/0x09 |
| Set LAN Configuration Parameters        | 23.1                  |
| Get LAN Configuration Parameters        | 23.2                  |
| Get / Clear LAN Statistics              | 23.3                  |
| Set SOL Configuration Parameters        | 26.2                  |
| Get SOL Configuration Parameters        | 26.3                  |
| Activate / Deactivate Payload (SOL)     | 24.1 / 24.2           |
| DCMI capabilities / power / thermal / asset / configuration | DCMI 1.0–1.5, NetFn 0x2c |
| Intel Node Manager policies / alerts / thresholds | Intel NM 1.0–3.0, OEM NetFn 0x2e |
| Get SEL Info                            | 31.2                  |
| Get SEL Allocation Info                 | 31.3                  |
| Reserve SEL                             | 31.4                  |
| Get SEL Entry                           | 31.5                  |
| Add SEL Entry                           | 31.6                  |
| Delete SEL Entry                        | 31.8                  |
| Clear SEL                               | 31.9                  |
| Get / Set SEL Time                      | 31.10 / 31.11         |
| Platform Event Message                  | 29.3                  |
| Get Sensor Reading                      | 35.14                 |
| Get PEF Capabilities                     | Sensor/Event 0x10     |
| Set / Get PEF Configuration Parameters  | Sensor/Event 0x12/0x13 |
| Get Last Processed Event ID (PEF status) | Sensor/Event 0x15     |
| Get Device SDR Info                     | 35.2                  |
| Get Device SDR                          | 35.3                  |
| Get SDR Repository Info                 | 33.9                  |
| Get SDR Repository Allocation Info      | 33.10                 |
| Get SDR                                 | 33.12                 |
| HPM.1 Target Upgrade Capabilities        | PICMG HPM.1 `0x2e`   |
| HPM.1 Component Properties               | PICMG HPM.1 `0x2f`   |
| HPM.1 Upgrade / Rollback / Self-test Status | PICMG HPM.1 `0x34` / `0x37` / `0x36` |
| Get FRU Inventory Area Info             | Storage command 0x10  |
| Read FRU Data                           | Storage command 0x11  |
| Write FRU Data                          | Storage command 0x12  |

## FRU inventory

`ipmi_rs::storage::fru` provides sans-IO FRU info, read and **explicit**
write commands and `FruInventory::parse` for a complete image. The parser
validates the common header, area layout, terminators and checksums, and
multirecord boundaries/checksums. Unknown/OEM fields retain their original
bytes. English 8-bit fields decode as ASCII/Latin-1; non-English 8-bit
fields retain raw bytes rather than guessing text.

With an existing `Ipmi` connection:

```rust,ignore
use ipmi_rs::storage::fru::FruDevice;

let candidates = ipmi.fru_devices(); // built-in ID 0 plus logical SDR locators
let inventory = ipmi.read_fru_inventory(FruDevice::BUILTIN)?;
let raw = ipmi.read_fru_image(FruDevice::BUILTIN)?;
// Writing is never implicit in a read. To replace a complete valid image:
let info = ipmi.fru_info(FruDevice::BUILTIN)?;
ipmi.write_fru_image(FruDevice::BUILTIN, info, &raw)?;
```

SDR FRU-device and FRU-capable management-controller locators identify
candidate devices and their address/channel/LUN routing, not inventory contents.
Remote targets need a transport supporting that address; the RMCP transport
currently only sends requests to its local controller (the device-file
transport supports routed IPMB requests).
The built-in candidate may not exist on all systems; query it before reading.
Reads use at most 16 bytes per command, shrinking on size-related completion
codes. Writes validate the entire image **before** the first command, then
send at most 16 bytes per command without automatic retry. On any write error,
including a timeout, completion code, or short acknowledgement, some bytes
may have been changed. The reported offset and confirmed prefix are *not* a
guarantee that the affected chunk was not written. Investigate the device
state before attempting another mutation.

## Opt-in OEM commands

The `ipmi_rs::oem::{dell,sun,kontron,quanta,ime}` modules provide typed
vendor operations. Use `Ipmi::send_oem` for the individual foundation
commands and `Ipmi::dell()` for the generation/capability-checked Dell
operations. The sender first reads the selected device's ID (at the BMC/bridged
IPMB destination on LUN 0), checks vendor and any required product ID, then
sends the command; an identity or unsupported-device error sends **no** OEM
command. For example:

```rust
use ipmi_rs::oem::{dell::GetPowerCapStatus, kontron::{BootDevice, SetNextBoot}};

let status = ipmi.send_oem(GetPowerCapStatus)?;
// Only when explicitly requested on a verified Kontron CP6012:
ipmi.send_oem(SetNextBoot(BootDevice::Network))?;
```

The Kontron boot setter uses OEM LUN 3 and is **not** the generic chassis
boot-flags command. The sender never automatically repeats an OEM write;
after a lost response its outcome is unknown. Manufacturer/product matching
does not establish that a particular firmware supports a command. Raw
`Message`/`Request` and custom `IpmiCommand` use are still available for other
hardware, but have no automatic identity guard. The [source-based OEM coverage
matrix](docs/oem-coverage.md) lists all families, limitations and linked
implementation issues; compilation and synthetic fixtures do not establish
full OEM or hardware parity.

### Intel ME firmware inventory and maintenance

`Ipmi::ime_info(target)` reads the selected Intel Manageability Engine's
version, image/status and update capabilities. `Ipmi::ime_update(target,
&validated_image)` and `Ipmi::ime_rollback(target)` are explicit, bounded
workflows, not CLI file handling. `ValidatedImage::new(bytes, expected_size,
expected_crc8)` requires independently trusted metadata **before** any
network operation. Each step rechecks the exact device ID 0 / revision 0 /
Intel IANA 343 / product 0x0B00 at the selected bridged IPMB destination.
Never resend a mutation after an uncertain outcome. The [maintenance and
recovery plan](../docs/ime.md) explains operational prerequisites, power-loss
risks, incomplete-update handling and the lack of hardware validation.
The current RMCP transport rejects arbitrary bridged IPMB routes ([#13](https://github.com/cataggar/ipmi-rs/issues/13));
there is no silent fallback to the session BMC.

## I2C devices and SPD

`app::i2c::MasterWriteRead` sends one bounded (64-byte-per-direction)
transaction with an explicit `I2cBus` (channel plus public/private bus) and
eight-bit, even `I2cAddress`. A device locator obtained from an SDR can build
an explicit `read(offset, size)` or `write(offset, bytes)` command:

```rust
use ipmi_rs::app::i2c::{I2cAddress, I2cBus, I2cBusKind};
use ipmi_rs::app::spd::{Spd, SpdPage};

let bus = I2cBus::new(0, I2cBusKind::Private(0))?;
let address = I2cAddress::new(0xa0)?;
let base = ipmi.read_spd_page(bus, address, SpdPage::LegacyBase, 32)?;
let spd = Spd::decode(base.to_vec())?; // DDR3 or earlier, one 256-byte page

// For DDR4, explicitly select/read BOTH pages instead:
let base = ipmi.read_spd_page(bus, address, SpdPage::ddr4(0)?, 32)?;
let upper = ipmi.read_spd_page(bus, address, SpdPage::ddr4(1)?, 32)?;
let spd = Spd::decode([base.as_slice(), upper.as_slice()].concat())?;
```

SPD page selection writes only to the **volatile DDR4 page-select device**
(0x6C/0x6E); it does not program the EEPROM. Register-pointer reads also
change the device's transient pointer. No SPD decoding, SDR enumeration, or
generic locator parsing implicitly writes to an EEPROM. Only an explicitly
sent generic locator `write` command writes device data. A lost response leaves
its outcome uncertain: do not automatically resend the write, even if a later
read appears unchanged. Invalid lengths/addresses and short or extra successful
responses fail instead of being silently padded or truncated. Remote devices
behind satellite controllers additionally require bridged RMCP routing
(issue #13); this work does not provide that routing.
## Dell iDRAC OEM commands

Dell's typed client checks manufacturer **674** and the iDRAC type reported by
App Get System Info selector `DD`, block 2. For example (inside a function
that already owns `&mut ipmi`):

```rust
use ipmi_rs::oem::dell::{WriteIntent, LcdMode};

let mut dell = ipmi.dell()?;
let previous = dell.lcd_config()?;
let headroom = dell.power_headroom()?;
// Only under an authorized maintenance window, with a documented rollback:
dell.set_lcd_mode(WriteIntent, LcdMode::Model)?;
// Re-read lcd_config() and compare with `previous` to verify the write.
```

Other reads cover LCD status/caps/text, DRAC/LOM MAC, NIC mode/active link,
power monitor/instant/headroom/history/budget, BMC-owned power sensors, drive
mapping and local-only vFlash card information. Explicit `WriteIntent` is
required for LCD text/config/KVM/lock, NIC selection, drive SES status and
power-cap enable/limit/clear. Writes recheck iDRAC type and relevant readable
capabilities. A timeout or partial multi-block LCD write **must not** be
automatically replayed. Changing the active NIC can disconnect this connection;
verify the management path and have a rollback plan before any write.
`PowerBudget::cap` is a `PowerCapValue::Watts(u16)` or
`PowerCapValue::BtuPerHour(u16)` matching the **unconverted wire value**;
`min_watts` and `max_watts` are always in watts. Unknown cap units are
rejected. `set_power_budget` takes watts and writes unit 0, rather than
silently interpreting a saved BTU/hr cap as watts.

## HPM.1 firmware inventory and upgrades

`ipmi_rs::hpm::read_inventory(&mut ipmi)` reads Device ID, HPM.1 capabilities,
and the general properties, description and current version of every present
component. It reads rollback and deferred versions only when a component
advertises those capabilities. A supported component can still have no image
in an optional slot: HPM.1 `0x81` (not supported), `0x83` (invalid property
selector) and IPMI `0xcb` (requested data absent) on only these two queries
yield `None` for that version. Other completion codes, lost responses and
malformed data fail inventory; required properties always remain mandatory.
Inventory and the typed status commands in
`ipmi_rs::hpm` / `ipmi_rs_core::hpm` do not require an update feature and never
write firmware. HPM.1 is **not** vendor-specific FWUM or IME.

Firmware mutation requires the opt-in `hpm-update` feature:

```sh
cargo add ipmi-rs --features hpm-update
```

An existing `Ipmi` connection can use the following **explicit** sequence.
Inspect the target inventory and obtain the update file from a trusted source;
parse it in memory *before* constructing an updater:

```rust,ignore
use ipmi_rs::hpm::{read_inventory, package::Package, update::{Updater, UpdateOptions}};

let package = Package::parse(&image_bytes)?;
let inventory = read_inventory(&mut ipmi)?;
let options = UpdateOptions::new(23, 100_000, false).expect("valid limits");
let mut updater = Updater::new(&mut ipmi, &package, &inventory, options)?;
updater.upload(|state| {
    println!("component {:?}: {} / {} confirmed bytes",
             state.component, state.confirmed_bytes, state.total_bytes);
    !cancel_requested
})?;
// Upload does not activate. Only if explicitly approved:
updater.activate()?;
// Observe status with caller-managed deadlines/pacing:
let status = updater.upgrade_status()?;
let self_test = updater.self_test_result()?;
```

`Package::parse` checks signature, version, header and action checksums,
entire-file MD5, OEM length, action types, nonempty and declared component
masks, exactly-one-component upload records, nonzero image lengths, image
bounds and full coverage. Package size is limited to 64 MiB and records to
256. The MD5 is **only a file-integrity check**, not a signature or
authentication: verify the trusted vendor/source independently. `Updater::new`
rejects device/manufacturer/product or earliest-compatible-revision mismatch,
unsupported components/actions, an undesirable update, unacknowledged
service interruption, or a package exceeding the configured block budget.
An image with `services_affected` (or a target advertising service disruption)
requires `allow_service_disruption: true` in the explicitly provided options.
No force-override for device identity is provided.

Each block carries at most 23 firmware bytes (25 PICMG request bytes); the
caller chooses a smaller size if required by the transport. The block number
wraps after 255 per HPM.1. `max_blocks` bounds **all** blocks before the first
write. Confirmed bytes advance only for successful, well-formed block replies.
The workflow does not guess at an offset/length directive that would require
skipping, overlapping or repeating image bytes.

**Recovery:** a timeout, lost response, malformed acknowledgement, `0x80`
in-progress completion or other ambiguous mutation error returns
`UpdateError::Uncertain { state, source }`. Inspect `state.uncertain` (the
attempted command/block/offset), `state.confirmed_bytes` and
`state.finished_images`. No mutation is ever retried automatically, including
initiate/finish/activate/rollback, and the updater refuses to continue an
unresolved upload. A read-only `upgrade_status`, `rollback_status`, or
`self_test_result` can aid manual investigation; upgrade status alone cannot
prove whether **a particular upload block** was committed. Do not restart
from a guessed offset. After checking the target and vendor recovery procedure,
choose explicitly whether to abort (`ipmi_rs::hpm::AbortUpgrade`, feature-gated),
roll back (`Updater::rollback()` if no operation is uncertain, or an explicit
manual rollback command after external reconciliation), or recover by a
device-specific procedure. Dropping or cancelling an updater never activates,
aborts, retries, or rolls back; cancellation is checked *between* commands.
After an acknowledged activation, check upgrade and self-test status yourself;
after an acknowledged rollback check rollback status (`0x81` reports failure).
Poll status at HPM.1-compliant intervals (at least 1 second for upgrade
status, at least 100 ms for self-test/rollback) with a caller-imposed deadline;
the library performs one read per call and never automatically reconnects or
polls indefinitely. An acknowledged command can still be processing.

## PICMG/ATCA and VITA 46.11 group extensions

Enable `ipmi-rs` with `--features group-extensions` to use the typed
`ipmi_rs::{picmg,vita}` command modules (or enable the feature on
`ipmi-rs-core` for sans-IO use). These commands are **not** auto-discovered
or issued during ordinary IPMI operations. Query `GetPicmgProperties` or
`GetVitaCapabilities` first, then call `require_supported()` on the result
before issuing other extension commands. Commands validate the returned
extension ID (`0x00` for PICMG, `0x03` for VITA), lengths, and unsupported
completion codes; raw site types, flags, and OEM descriptor values are
preserved.

For example, with an already established `Ipmi` connection addressed to
the correct management controller:

```rust
use ipmi_rs::{picmg, vita};

let properties = ipmi.send_recv(picmg::GetPicmgProperties)?;
properties.require_supported().expect("supported PICMG extension version");
let location = ipmi.send_recv(picmg::GetPicmgAddress { fru_id: 0 })?;
let fru_id = location.fru_id.expect("legacy address reply has no FRU ID");
let power = ipmi.send_recv(picmg::GetPicmgPower {
    fru_id,
    power_type: picmg::PowerType::SteadyState,
})?;
// Read-only above. To request a mutation, explicitly construct the command:
let activation = picmg::SetPicmgActivation {
    fru_id,
    action: picmg::Activation::Activate,
};
// ipmi.send_recv(activation)?; // Only after independently authorizing the target.
```

The VITA counterparts use `vita::{GetVitaCapabilities,GetVitaAddress,
SetVitaActivation}`. `Ipmi::send_recv` addresses the local BMC by default;
**reading an IPMB address does not redirect later commands**. Shelf-manager,
slot, AMC/carrier or VPX FRU commands addressed to a different controller
require explicit bridged IPMB routing, now available for RMCP/RMCP+ through
`RequestTargetAddress::Bridged` (see [IPMB bridging](#ipmb-bridging-over-rmcp--rmcp)).
Do not attempt a remote operation with these local-only typed command defaults.
Write commands do not retry
themselves, and applications must not resend them on a timeout or other
ambiguous outcome; observe state separately without assuming a readback
proves whether an activation/reset/cycle occurred.

See the [ipmitool entry-point coverage matrix](docs/group-extensions.md)
for every supported family, unsupported operations, and fixture coverage.

On a Quanta BMC, `ipmi.send_oem(quanta::GetPlatformId)` returns a typed
Grantley/Purley platform after checking IANA 7244. For a `SelEntryInfo`
returned by `GetSelEntry` on that same BMC,
`quanta::MemoryLocation::from_sel_entry(platform, &entry_info)` returns
structured CPU/channel/DIMM indices for Purley memory events. A
Grantley, non-memory or other event returns `None`. Do not use a platform
from one BMC to decode another BMC's SEL; there is no live hardware validation.

## BMC reset and boot overrides

`ipmi_rs::app::{WarmReset, ColdReset}` reset the **management controller**, not the host.
To control host power, use the separate Chassis Control command. A cold reset can
interrupt its own response. After a timeout or lost connection the outcome is
**unknown**: neither retry the mutation automatically nor assume that an offline
BMC proves success or failure.

The core `ipmi_rs::chassis` module also exposes explicit host diagnostic
interrupt (`PowerAction::DiagnosticInterrupt`) and ACPI soft shutdown
(`PowerAction::AcpiSoftShutdown`) actions, `ChassisIdentify` (default interval,
seconds/zero to stop, or optional force-on), restore-policy support query and
typed policy write, and read-only restart cause and power-on-hours counters.
Restore-policy writes affect the behavior after a future AC outage, not the
host's current power state. Unsupported controller features return their
completion code; force identify may be rejected by older controllers.

Typed boot-option reads cover parameters 0 through 6: set-in-progress, service
partition selector/scan, valid-bit clearing, boot-info acknowledgement, boot
flags, and boot initiator info. Typed writes are explicit per parameter;
service-partition scan writes only the request bit, never the BIOS-discovered
bit. For example, using an existing `Ipmi` connection:

```rust
use ipmi_rs::chassis::{
    BootDevice, BootFlags, BootOptionWrite, BootOverride, BootOverrideDuration,
    GetSystemBootOptions, SetSystemBootOptions,
};

let flags = ipmi.send_recv(GetSystemBootOptions::<BootFlags>::new())?;
// BootFlags::Invalid means there is no active override.

let next_pxe = BootOverride::new(BootDevice::Pxe, BootOverrideDuration::OneTime);
ipmi.send_recv(SetSystemBootOptions::new(BootOptionWrite::BootFlags(next_pxe)))?;
// Persistent CD-ROM is explicit:
let cd = BootOverride::new(BootDevice::CdRom, BootOverrideDuration::Persistent);
// Optional flags must be explicitly opted into, e.g. cd.with_clear_cmos(true).
```

Setting parameter 5 writes **all five boot-flag bytes**, replacing existing
flags rather than performing a get/merge/set. EFI and clear-CMOS default to off;
other boot-flag fields are sent as zero. It does not modify parameters 0, 3,
or 4 implicitly, and does **not** restart the host. If coordination is needed,
set those parameters explicitly. Get checks the parameter version, echoed
selector, valid/unlocked state and lengths. `BootFlags::Unknown` retains all
five unmodelled readback bytes without treating them as an active override;
unknown bits/devices cannot be written. `GetRawBootOption` can inspect unknown
selectors, versions and locked values without providing a corresponding raw
write.
Parameter 7 uses `GetBootMailboxBlock::<N>` and `SetBootMailboxBlock::new`
to read/write one specified block: block zero carries a 24-bit IANA PEN and
at most 13 payload bytes, other blocks carry at most 16. The caller chooses
each block explicitly; `0xc9` may signal end of mailbox. No bulk write,
implicit commit, acknowledgement clearing, or host restart is performed.
Boot-option support varies by controller and BIOS; completion codes (including
`0x80` unsupported, `0x81` already in progress, `0x82` read-only) are surfaced,
not worked around. Remote mutations should wait for the transport hardening
tracked in issue #6.

## BMC user and channel access management

`ipmi_rs::app::{GetUserSummary, GetUserAccess, GetUserName, UserList}` expose
read-only user counts, per-channel ACLs, and 16-byte names. After sending
`GetUserSummary::new(channel)` with an existing `Ipmi` connection, use
`UserList::new(channel, summary)` to enumerate bounded IDs (1–63); each item
contains a `GetUserAccess` and `GetUserName` command **to send separately**.
Some controllers reject Get User Name for unnamed slots: inspect the returned
completion code rather than mistaking that failure for an empty name. Raw
username bytes and unknown privilege nibbles are retained on readback.

Writes require explicit construction: `SetUserName`, `SetUserAccess` (replaces
all flags, privilege and session limit), `SetUserPrivilege` (changes only the
privilege), and `SetUserPassword::{enable, disable, set, test}`. A user ID must
be 1–63; use `Channel::new` for supported channels and `UserPrivilege::new`
for assignable privilege levels (1–5 or 15 = no access). Names and passwords
are validated as printable US-ASCII; names are at most 16 bytes, passwords
at most the explicitly selected `PasswordLength::Bytes16` or `Bytes20` and
NUL-padded. An empty name clears it; an empty password **removes** password
protection where supported. Never use an empty password unintentionally.
20-byte passwords require compatible IPMI 2.0 support; test returns completion
code `0x80` for mismatch and `0x81` for wrong length. No test/set/enable call
is inferred from any read or another write.

`SetChannelAccess::new(channel, access, privilege)` takes two **independent**
optional updates; each explicitly selects `ChannelAccessType::NonVolatile`
(persistent across reset) or `Volatile` (active settings). An omitted field is
not changed. Setting an access mode, disabling authentication, reducing a
channel's privilege limit, or changing your own administrative user can
immediately lock out all remote administrators. Verify your BMC/channel,
retain a local recovery path, and observe controller-specific behavior before
modifying a production interface.

User and channel configuration generally requires an **Administrator-level**
session and a controller that permits the operation; read permissions vary by
BMC, channel and firmware. Prefer a confidential RMCP+ session (cipher suite
3 or 17), or a trusted local interface: IPMI 1.5 does **not** encrypt passwords
on the wire. The command and message `Debug` implementations redact password
contents, and the local file transport omits password bytes from trace logs;
**raw wire data accessors are not redacted**, so do not log request/response
bytes or credentials yourself. Completion codes, including insufficient
privilege (`0xD4`) and command-specific rejections, remain available from
`IpmiError`; password-command error response bytes are suppressed in case a
controller echoes the secret. The library never retries these writes. On
timeout, disconnection, or any ambiguous send result, the outcome is
**unknown**: check status through an independent read or recovery access, but
never blindly repeat a mutation (even after `NodeBusy`).

## Management-controller status and configuration

`ipmi_rs::app::{GetDeviceGuid, GetSelfTestResults}` return a typed GUID and
two-byte self-test result. GUID `raw()` preserves the controller's exact 16
bytes; `ipmi_uuid()` interprets them in **IPMI order** (node, clock sequence,
time-high, time-mid, time-low, all least-significant-byte first). Some BMCs
incorrectly send SMBIOS or RFC 4122 order; there is deliberately no
guess-based conversion. Self-test unknown codes and their diagnostic byte are
preserved.

`GetBmcGlobalEnables` reads the seven defined enable bits;
`SetBmcGlobalEnables(flags)` **replaces the entire byte**, never silently
read-modify-writes it. Changing flags can suppress event logging, alerts or
interrupts. Reserved bit 4 is rejected. Inspect existing enables and obtain
adequate BMC privileges (typically **Administrator** for writes) before
changing them. Reads typically require User privilege; device policy varies.

`app::watchdog::{GetWatchdogTimer, SetWatchdogTimer, ResetWatchdogTimer}` expose
the 8-byte readback and explicit six-byte configuration. Construct a validated
write using `SetWatchdogTimer::new(WatchdogConfiguration { ... })`; countdowns
are in **100 ms units**, pre-timeout in **seconds**. Setting can stop an
existing timer unless `do_not_stop` is true; resetting reloads **and starts**
the timer. An expiry action can hard-reset, power down or cycle the **host**.
Changing or remotely "petting" a watchdog over an unreliable network can
cause unexpected host downtime. Obtain Operator/Administrator privileges as
required by your BMC and use an appropriate local service for periodic resets.
No watchdog write is implicit in a read.

`app::system_info::{GetSystemInfoParameter, SetSystemInfoParameter}` cover
standard parameters 0–7. Get returns a revision-checked response; use
`request.decode(&response)` to validate the echoed set and interpret its value.
`SystemInfoString::new` validates the encoding and 255-byte limit;
`to_writes()` splits into a 14-byte first set and subsequent 16-byte sets.
To update multiple sets, explicitly send parameter-0
`SetSystemInfoParameter::set_in_progress` values (`InProgress`,
`CommitWrite`, `Complete`), or invoke `system_info_write_guarded` with an
`Ipmi::send_recv` closure and a validated `SystemInfoString`. **Choose**
`SystemInfoCommitMode::CompleteOnly` when the controller accepts In Progress
and Set Complete but rejects the optional Commit Write (`2`), as on some
OpenBMC controllers. Use `CommitThenComplete` only if the target supports it:

```rust,ignore
use ipmi_rs::app::system_info::{
    system_info_write_guarded, SystemInfoCommitMode, SystemInfoEncoding,
    SystemInfoSelector, SystemInfoString,
};

let name = SystemInfoString::new(
    SystemInfoSelector::SystemName,
    SystemInfoEncoding::Utf8,
    b"host-1".to_vec(),
)?;
let outcome = system_info_write_guarded(
    |command| ipmi.send_recv(command),
    &name,
    SystemInfoCommitMode::CompleteOnly,
);
// Handle outcome (including any uncertain write or cleanup failure).
```

The helper does not probe for optional commit support by mutating the BMC.
After an acknowledged begin, it attempts set-complete cleanup even if a
block or optional commit fails, and reports begin, block, commit and cleanup
errors separately. If begin fails, it does not release a lock that may belong
to another writer; inspect an ambiguous outcome and decide how to recover.
Unsupported/read-only/already-in-progress completion codes are preserved;
other completion codes remain in `IpmiError`.
String and watchdog writes, including transaction-state writes, are sent
**once**, not retried after a possibly-applied request. A timeout or lost
acknowledgement leaves the outcome **unknown**; readback can show current
state but cannot prove a transient watchdog action did not occur. System-info
write privilege and multi-block support vary by BMC.

# Supported interfaces

## `ioctl`-based IPMI device file

The [Linux IPMI Driver][lipmid] is supported through the character device exposed by that driver, usually at `/dev/ipmi<N>`.

Access to this file generally requires root privileges.

[lipmid]: https://docs.kernel.org/driver-api/ipmi.html

## Serial basic and terminal modes (opt-in)

Enable `ipmi-rs/serial` to use `ipmi_rs::serial::{SerialConnection, SerialMode}`
with an explicitly selected port, baud rate, mode, and nonzero operation timeout:

```rust,no_run
use ipmi_rs::{chassis::GetChassisStatus, serial::{SerialConnection, SerialMode}, Ipmi};
use std::time::Duration;

let serial = SerialConnection::open(
    "/dev/ttyS0", 115200, SerialMode::Basic, Duration::from_secs(5),
).expect("open serial port");
let status = Ipmi::new(serial).send_recv(GetChassisStatus).expect("read chassis");
```

Use `SerialMode::Terminal` for a terminal-mode BMC instead. Supported rates are
2400, 9600, 19200, 38400, 57600, 115200, 230400 and (if supported by the
driver) 460800, with 8N1 and no flow control. Serial-port support depends on
the `serialport` crate and the OS driver (Linux, other Unix systems and Windows);
it is **not** required in default builds. Basic mode uses IPMB checksums and
escaped `A0`/`A5` frames; terminal mode uses `[hex]\r\n` frames. Direct BMC
requests and single-hop IPMB Send Message requests on primary/numbered channels
are supported; system-channel, double-bridge and larger-than-40-byte
transactions are rejected. Responses are correlated by sequence, netfn,
command, and (in basic mode) address and checksum. Both modes bound input size
and enforce a single deadline; neither automatically retries a request.

`cancellation_token().cancel()` interrupts I/O (checked at most every 50 ms
between serial-port reads/writes); call `reset()` **only after** the operation
has returned. If a send starts but a response is lost, timed out, or cancelled,
`send_recv` returns `SerialError::OutcomeUnknown` (or
`SerialError::Send(SerialSendError::OutcomeUnknown(_))` for an interrupted
write); standalone `recv` reports `SerialRecvError`. In all cases the command
**may have executed**. Never automatically retry a mutation; observe subsequent
status separately. Serial responses retain the IPMI completion code for typed
`Ipmi::send_recv` commands. After any ambiguous send/receive failure the
connection refuses further requests with
`SerialSendError::ConnectionUncertain`; resetting the cancellation token does
**not** make it safe to reuse the 6-bit sequence number. Reopen the serial
connection before any later operation.

## AMI USB virtual-CD via Linux SCSI generic (opt-in)

Enable `ipmi-rs/ami-usb` to use `ipmi_rs::ami_usb::AmiUsb`. On **Linux only**,
explicitly choose a SCSI generic device (such as `/dev/sg2`) and timeout:

```rust,no_run
use ipmi_rs::{ami_usb::AmiUsb, chassis::GetChassisStatus, Ipmi};
use std::time::Duration;

let usb = AmiUsb::open("/dev/sg2", Duration::from_secs(5)).expect("open AMI device");
let status = Ipmi::new(usb).send_recv(GetChassisStatus).expect("read chassis");
```

This backend follows the AMI virtual-CD `SG_IO` interface in ipmitool, **not**
generic USB HID/libusb; no libusb dependency, discovery, or USB hardware is
needed for default builds. There is no known universal USB vendor/product ID
pair: the selected device must respond to the AMI identify SCSI command `EEh`
with `$$$AMI$$$` and support `E2h`/`E3h` command/data sectors. Other devices
return `AmiUsbError::UnsupportedDevice` (or an I/O error if inaccessible).
On non-Linux targets the feature compiles but `AmiUsb::open` returns
`UnsupportedPlatform`. AMI USB only supports direct BMC commands; IPMB
bridging is rejected. Responses include the IPMI completion byte and use the
existing typed commands. The selected device is held with a nonblocking
advisory exclusive lock for the connection's lifetime; non-cooperating clients
must also avoid sending commands to the same device.

The SCSI transaction has a fixed response cap and deadline and never retries
requests. Cancellation is checked between SG_IO calls (a call can block for up
to 200 ms). After any post-dispatch failure, including timeout/cancellation,
`AmiUsbError::OutcomeUnknown` is returned and the connection refuses more
requests until it is reopened: AMI replies have no sequence field to safely
match a late response. Do not automatically resend a mutation. SCSI transport
status (`DeviceStatus`) is separate from an IPMI completion code.

## RMCP

RMCP with the following authentication types is supported:
* Unauthenticated
* MD5
* MD2

## RMCP+

RMCP+ supports cipher suites 3 (RAKP-HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128)
and 17 (RAKP-HMAC-SHA256 / HMAC-SHA256-128 / AES-CBC-128).
`Rmcp::activate(true, username, password)` keeps the suite-3 default.
To require suite 17, use
`Rmcp::activate_with_cipher_suite(CipherSuite::Id17, username, password)`.
This returns an activation error if the peer lacks RMCP+, rejects suite 17,
or selects any different authentication, integrity, or confidentiality algorithm;
it never falls back to suite 3 or IPMI 1.5. Suites other than 3 and 17
are rejected before activation.

### IPMB bridging over RMCP / RMCP+

Local-BMC requests are unchanged. `RequestTargetAddress::BmcOrIpmb` routes
non-local, even IPMB slave addresses through a **single** Send Message hop.
For an explicit one- or two-hop route, use `RequestTargetAddress::Bridged`:

```rust,no_run
use ipmi_rs::{
    connection::{
        Address, Channel, IpmbTarget, IpmiConnection, LogicalUnit, Message, NetFn,
        Request, RequestTargetAddress,
    },
    rmcp::Rmcp,
};
use std::time::Duration;

let mut connection = Rmcp::new("192.0.2.10:623", Duration::from_secs(3))?;
connection.require_rmcp_plus(true);
connection.activate(true, Some("operator"), Some(b"secret"))?;
let target = IpmbTarget::new(Address(0x52), Channel::Primary, LogicalUnit::Zero);
let transit = IpmbTarget::new(Address(0x30), Channel::Primary, LogicalUnit::Zero);
let mut request = Request::new(
    Message::new_request(NetFn::Chassis, 0x01, vec![]),
    RequestTargetAddress::Bridged { target, transit: Some(transit) },
);
let response = connection.send_recv(&mut request)?;
// For a single hop, specify `transit: None`.
```

The first channel is the BMC-to-transit (or BMC-to-target) IPMB channel;
the target's channel is the transit-to-target channel for two hops.
Only primary and numbered channels (1–11), even unicast slave addresses,
and one optional transit hop are supported. Transit must not be the local BMC
or the same target on the same channel. The BMC uses slave address `0x20`
and the remote software ID `0x81`. Controllers may use different IPMB
addresses or not support tracked Send Message, transit routing, embedded
responses, or Get Message receive queues; check the hardware's channel map
and privilege policy. The Linux device-file interface still uses its kernel
IPMB routing; explicit `Bridged` routes are RMCP-only.

The transport validates both IPMB checksums, responder/requester addresses
and LUNs, per-hop sequence, netfn and command, as well as the RMCP session
identity and replay sequence. It waits for each successful Send Message
acknowledgement before reporting the final response; the response may be
embedded, pushed over LAN, or retrieved with Get Message. Get Message is
requested only when Get Message Flags reports a receive-queue entry. If
the BMC reports either queue command as unsupported, the transport stops
querying the queue for that session and waits for a correlated pushed reply
until the original operation deadline. Transient queue failures (such as
Node Busy) only recheck the read-only queue, with backoff; unexpected
completion codes are returned as errors. The original bridged command is
never resent. If no correlated reply arrives, the outcome is unknown.
Queue backoff waits for pushed replies instead of sleeping, using the
original deadline and a 64-sequence-per-session budget
(including bridge hops and polls). When that budget is exhausted, the
current operation still waits for a pushed reply until its deadline;
open a **new session** for subsequent requests. Only one operation can
be pending. Cancellation and timeouts retire its sequences, so late
replies cannot satisfy the next request. A receive/poll failure is
`OutcomeUnknown`, and an ambiguous network send is
`SendOutcomeUnknown`: **never automatically resend a power or configuration
mutation**. RMCP 1.5 without authentication cannot guarantee peer
authenticity; prefer authenticated RMCP+ for remote changes.

To request a **non-administrator role**, supply a **separate Kg key**, or opt
into channel discovery, use `SessionConfig`:

```rust,no_run
use ipmi_rs::rmcp::{ActivationError, CipherSuitePolicy, PrivilegeLevel, Rmcp, SessionConfig};

fn activate(connection: &mut Rmcp, password: &[u8], kg: &[u8]) -> Result<(), ActivationError> {
    connection.activate_with_session_config(
        SessionConfig::new(Some("operator"), Some(password))
            .with_privilege(PrivilegeLevel::Operator)
            .with_kg(kg)
            .with_cipher_suite_policy(CipherSuitePolicy::BestAvailable),
    )
}
```

`BestAvailable` queries the current channel's IPMI cipher-suite records
before opening a session. It chooses suite 17 if advertised, otherwise suite 3
if advertised. A failed/incomplete query, an unsupported list, a malformed
record, or a peer-negotiated privilege/algorithm mismatch **fails activation**:
it never guesses suite 3 or falls back to IPMI 1.5. The advertisement is
unauthenticated, so an on-path attacker could suppress suite 17; use
`CipherSuitePolicy::Exact(CipherSuite::Id17)` to require SHA-256 instead.
Only suites 3 and 17 are implemented; weak MD5/xRC4/no-integrity suites
are never selected. `activate_with_cipher_suite` and `activate_with_provider`
still require the exact requested suite. The `SessionConfig` default requires
RMCP+ suite 3 and Administrator; `activate(true, ...)` is unchanged.

The password authenticates RAKP messages 2 and 3; Kg (or the password when
no separate Kg is supplied) derives the session keys used for RAKP4 and
encrypted/authenticated traffic. Internally copied secrets and handshake
authentication buffers are cleared, and debug output redacts both keys.
Callers remain responsible for protecting and clearing their own input buffers.

### Optional SymCrypt RMCP+ backend

The default build uses RustCrypto and does not need a native library. To
select SymCrypt for **all** RMCP+ HMAC and AES-128-CBC operations (including
RAKP authentication, SIK/K1/K2 and packet integrity), enable
`symcrypt-backend` and request it explicitly:

```rust,no_run
use ipmi_rs::rmcp::{CipherSuite, CryptoProvider, Rmcp};
use std::time::Duration;

let mut connection = Rmcp::new("192.0.2.1:623", Duration::from_secs(3)).unwrap();
let _result = connection.activate_with_provider(
    CipherSuite::Id17,
    CryptoProvider::SymCrypt,
    Some("ADMIN"),
    Some(b"password"),
);
// Handle `_result: Result<(), ActivationError>` as appropriate for your application.
```

Suites 3 (legacy SHA-1 interoperability) and 17 (SHA-256) are both supported.
If the feature is absent, a SymCrypt request returns
`ActivationError::CryptoBackend(CryptoBackendError::Unavailable)` **before
network I/O**. A rejected cipher suite or altered algorithms never select
another provider, a weaker suite, or IPMI 1.5. `activate()` retains its
existing suite-3/default-backend behavior and IPMI 1.5 compatibility.

The pinned `symcrypt` Rust wrapper **0.5.1** requires native
[Microsoft SymCrypt](https://github.com/microsoft/SymCrypt/releases)
**v103.4.2 or newer**. Its documented targets are Ubuntu and Azure Linux 3
(AMD64/ARM64) and Windows (AMD64/ARM64); other combinations are unverified.
For Linux, install the matching official SymCrypt release (or distro package)
and make `libsymcrypt.so*` available **both** to the build-time linker and
to the runtime loader. For an unpacked release with `lib/` at `<release>`:

```sh
export RUSTFLAGS="-L native=<release>/lib"
export LD_LIBRARY_PATH="<release>/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cargo test -p ipmi-rs --features symcrypt-backend
```

Alternatively install the library in a system linker path and refresh the
loader cache. On Windows, put `symcrypt.lib` in the directory named by
`SYMCRYPT_LIB_PATH` at build time and ensure the matching `symcrypt.dll` is
discoverable at runtime (for example beside the executable or in `PATH`).
The wrapper dynamically links SymCrypt: simply enabling the feature does not
bundle the native library. CI installs the SHA-256-verified official v103.4.2
AMD64 release for `--all-features` jobs. The 0.5.1 wrapper does **not** wipe
its AES expanded-key allocation on drop; our owned passwords and derived
key buffers are wiped, but this wrapper limitation remains. Selecting a
provider does **not** by itself make a deployment FIPS-compliant.

| Authentication algorithm | Supported      |
| :----------------------- | :------------- |
| RAKP-HMAC-SHA1           | Yes (suite 3)  |
| RAKP-None                | No             |
| RAKP-HMAC-MD5            | No             |
| RAKP-HMAC-SHA256         | Yes (suite 17) |

| Confidentiality algorithm | Supported           |
| :------------------------ | :------------------ |
| None                      | Supported primitive |
| AES-CBC-128               | Yes (suites 3, 17)  |
| xRC4-128                  | No                  |
| xRC4-40                   | No                  |

| Integrity algorithm | Supported           |
| :------------------ | :------------------ |
| None                | Supported primitive |
| HMAC-SHA1-96        | Yes (suite 3)       |
| HMAC-MD5-128        | No                  |
| MD5-128             | No                  |
| HMAC-SHA256-128     | Yes (suite 17)      |

### RMCP operational behavior

`Rmcp::new(remote, timeout)` uses the timeout as a monotonic deadline for the
entire activation handshake and for each request/response transaction (not as a
timeout that restarts after every packet). For operations that must not downgrade
to IPMI 1.5, call `connection.require_rmcp_plus(true)` before
`connection.activate(true, username, password)`.

`connection.cancellation_token()` returns a cloneable signal; call `cancel()` from
another thread to interrupt a receive (polled at most every 50 ms). The signal
is sticky. Call `reset()` **after** the cancelled operation has returned before
starting another one.

An RMCP connection supports one pending request at a time. Active RMCP+ traffic
requires the negotiated console session ID, the selected suite's SHA-1 or
SHA-256 integrity, and fresh, strictly increasing nonzero inbound session
sequences; reordered packets (including SOL) are rejected. Outbound requests
use the managed-system ID. IPMB replies must
match the request's address, LUN, six-bit sequence, netfn and command and have
both valid checksums. Bridged IPMB targets are not supported (explicit local BMC
addresses on the primary/current channel are accepted). Datagram payloads
over 4,096 bytes are rejected rather than silently truncated.

Late or unrelated, well-formed replies are drained while awaiting the current
request; valid SOL data is ACKed and retained for the capture/interactive reader.
Both RMCP+ IPMI receives and SOL polling share a cap of 32 unrelated datagrams
per operation and the original absolute deadline. If no correlated reply arrives,
the first mismatch is reported rather than silently accepted or replayed.
Malformed packets still fail explicitly.

There are no implicit retransmissions of ordinary IPMI commands. In particular,
`send_recv` can return `RmcpIpmiError::OutcomeUnknown` after a request was sent but its response was
lost, invalid, cancelled or timed out. Do **not** automatically retry a power,
reset, boot, or other potentially mutating request. A deliberate retry of a
safe read uses a new IPMB sequence. An ambiguous sequence is never reused within
the session; if all available correlation sequences are consumed, activate a
fresh session.

### Serial over LAN

`ipmi_rs_core::transport::{GetSolConfig, SetSolConfig}` provide typed SOL
parameters. `GetSolConfig` returns a revision-checked `SolConfigRaw`; call
`raw.parse(parameter)` to validate the selected parameter's length and decode
its value. Configuration is **never** changed by starting a capture or an
interactive session. Explicit multi-step writes can use `sol_write_guarded`,
which attempts set-complete cleanup even if writing or committing fails and
reports both the original and cleanup failures. A failed write's outcome can
still be uncertain; inspect `SolWriteError`.

SOL requires an already authenticated and encrypted RMCP+ connection using
suite 3 (AES-CBC-128/HMAC-SHA1-96) or suite 17
(AES-CBC-128/HMAC-SHA256-128), with either supported crypto backend.
Enable `require_rmcp_plus(true)` *before* activation, then call
`open_sol_capture(SolInstance::new(1).unwrap())` for a read-only capture or
`open_sol_interactive(...)` only when console input is explicitly authorized.
The activation request requires both SOL authentication and encryption; a BMC
that negotiates a different UDP port or a nonzero VLAN is rejected and
deactivation is attempted. No IPMI 1.5 fallback is allowed for SOL.

```rust,no_run
use ipmi_rs::{app::sol::SolInstance, rmcp::Rmcp};
use std::time::Duration;

let mut connection = Rmcp::new("127.0.0.1:623", Duration::from_secs(2))?;
connection.require_rmcp_plus(true);
let password = std::env::var("IPMI_PASSWORD")?;
connection.activate(true, Some("operator"), Some(password.as_bytes()))
    .map_err(|error| format!("{error:?}"))?;
let mut capture = connection.open_sol_capture(SolInstance::new(1).unwrap())
    .map_err(|error| format!("{error:?}"))?;
let mut output = [0u8; 1024];
let count = capture.read(&mut output).map_err(|error| format!("{error:?}"))?;
// Process output[..count] without logging console data or credentials.
let _ = count;
capture.close().map_err(|error| format!("{error:?}"))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Captures send only authenticated protocol ACKs and Deactivate Payload, never
console-input or control characters. Interactive input is explicitly supplied
to `SolInteractive::send_input` (up to 4096 bytes per call); break and flush
require separate methods. SOL characters are limited to 255 per packet and
queued output to 4096 bytes. Full queues send partial/NACK ACKs, not unbounded
allocations. Data, IPMI replies and ACK-only packets are dispatched on the
same identity-checked, replay-checked RMCP+ connection. A missing interactive
ACK can retransmit the *same* SOL sequence at most twice within that session;
the unacknowledged input is **never replayed across sessions**.

Each read or send has a monotonic deadline; a read timeout, cancelled operation,
frame gap, output overrun, or connection error interrupts the stream and makes
a bounded (250ms) deactivation attempt. Check `SolError::Interrupted` for
confirmed input bytes and uncertain input/output delivery or remote closure.
Already ACKed output buffered before cancellation is returned by subsequent
nonempty reads *before* the interruption is raised. If output is still buffered
when a send or cleanup fails, consume `interruption.buffered_output.as_bytes()`
or `into_bytes()` before discarding the error. Debug formatting reports only its
length, never console contents; the same applies to output attached to SOL
activation or routing errors. Reconnection of a live capture with unread
output returns `BufferedOutputPending` rather than discarding it.
Dropping the session also attempts deactivation but cannot report its outcome;
call `close()` explicitly. Even if deactivation succeeds, `close()` returns
`ClosedWithBufferedOutput` if it received ACKed output not yet read; consume
those bytes from the interruption. A quiet console times out rather than silently
waiting forever. To recover a capture, call `SolCapture::reconnect` with the
credentials and a 1–3 attempt bound; each attempt uses a fresh RMCP+ handshake,
resets per-session SOL sequence state and returns `CaptureGap`. Reset a cancelled
token **explicitly** before reconnection. Interactive sessions do not
automatically reconnect.

### Opt-in Tyan IPMI 1.5 TSOL (OEM)

Tyan TSOL is **not** the RMCP+ SOL implementation above, and is **not**
Intel ISOL (NetFn 0x34). Obtain authorization to attach to the remote console
before calling `open_tyan_tsol_capture` or `open_tyan_tsol_interactive`; neither
method is invoked during normal IPMI operations. Use `activate(false, ...)`
to request IPMI 1.5 LAN, with administrator credentials, then choose read-only
capture unless sending keystrokes is explicitly authorized:

```rust,no_run
use ipmi_rs::rmcp::{Rmcp, TYAN_TSOL_DEFAULT_PORT};
use std::time::Duration;

let mut connection = Rmcp::new("192.0.2.10:623", Duration::from_secs(2))?;
let password = std::env::var("IPMI_PASSWORD")?;
connection.activate(false, Some("operator"), Some(password.as_bytes()))
    .map_err(|error| format!("{error:?}"))?;
// Only after obtaining permission to attach to this specific Tyan BMC:
let mut capture = connection.open_tyan_tsol_capture(TYAN_TSOL_DEFAULT_PORT)
    .map_err(|error| format!("{error:?}"))?;
let mut output = [0; 1024];
let count = capture.read(&mut output).map_err(|error| format!("{error:?}"))?;
// Consume output[..count] without logging console data or credentials.
let _ = count;
capture.close().map_err(|error| format!("{error:?}"))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The preflight requires an active authenticated IPMI 1.5 session whose BMC
reported **administrator** as the *maximum* permitted privilege and MD2/MD5
session authentication,
Get Device ID manufacturer **6653**, IPv4 control route, IPMI 1.5 channel
capabilities with per-message/user authentication, and an available,
session-based 802.3 LAN/IPMB channel permitting administrator access.
It then sends App `0x3B` (Set Session Privilege Level) and requires the BMC
to echo **administrator** as the *active* privilege before Start; a rejection,
lower echo or lost reply stops without sending an OEM mutation. Activating
IPMI 1.5 alone does not elevate active privilege. The receiver binds the local
IPv4 address on that same control route before Start; nonlocal/NAT callback
addresses and IPv6 are not supported. Port `6230` matches ipmitool's default;
port `0` lets the OS assign a free port, inspectable through `receiver_addr()`.
Bind failures never send Start.

The typed Start/Stop payload is IPv4 octets followed by the **big-endian**
receiver port. Interactive `send_input` accepts 1–14 explicit bytes per call,
encodes their length plus one and a session-local sequence, and sends a
single IPMI command. It does **not** retry ambiguous sends, reconnect, or
replay input. A lost keystroke acknowledgment has uncertain delivery: do
not resend it automatically. Read-only capture has no input method.
Explicit `close()` reports Stop failure, including uncertain remote
deactivation; dropping a live session attempts a one-time 250 ms cleanup
but cannot report its outcome. Failed reads and sends stop the session and
return unread buffered output through `TsolInterruption::buffered_output`;
its Debug implementation does not print console bytes. Each read has a
monotonic deadline, cancellation is checked at most every 50 ms, and
received datagrams are limited to 4096 bytes and 32 unrelated/empty
datagrams per read. The four bytes of the legacy UDP header are skipped;
short and oversized datagrams interrupt the session. While the application
continues reading or sending input, the library sends an authenticated
Get Device ID keepalive after 30 seconds without control-session activity;
successful input and keepalive reset this monotonic timer. It shares the
call's absolute deadline and cancellation; failure interrupts TSOL and
attempts bounded Stop, without sending or replaying any keystrokes.
There is no background keepalive when an application stops polling. No
terminal raw mode, escape handling or CLI terminal presentation is provided. If an
application changes terminal state, it must restore it on *all* exits
(including errors and cancellation), e.g. with a scope guard.

**Security and verification limits:** The TSOL UDP stream has no known
cryptographic authentication or encryption. Incoming packets are accepted
only from the control BMC's IPv4 address, but their source port and opaque
four-byte header cannot authenticate the sender or prevent spoofing from
that address. Use only a trusted, isolated management network and do not
treat TSOL as a secure channel. Source-derived synthetic fixtures cover
the ipmitool payloads, framing, bounds and lost replies; no live TSOL
captures are checked in. A permissioned Tyan hardware transcript (with
credentials and console contents redacted) is needed to confirm source
port/header semantics and real-hardware interoperability.

## License

All source code (including code snippets) is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  [https://www.apache.org/licenses/LICENSE-2.0][L1])
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  [https://opensource.org/licenses/MIT][L2])

[L1]: https://www.apache.org/licenses/LICENSE-2.0
[L2]: https://opensource.org/licenses/MIT

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.

This project aims to conform to [Conventional Commits]. If you make contributions,
please be so kind to stick to that format :)

[Conventional Commits]: https://www.conventionalcommits.org/en/v1.0.0/#summary
