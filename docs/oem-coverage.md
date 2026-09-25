# OEM typed-command coverage (issue #29)

Source baseline: [cataggar/ipmitool `33f3a0a`](https://github.com/cataggar/ipmitool/tree/33f3a0a1b895e3effabb0ec8d180a0a2f1536128).
The [CLI command registry](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/src/ipmitool.c#L102-L125)
and the **implemented** command paths, not merely header constants or help text,
define the rows below. `ipmi-rs-core::oem` is opt-in, not a claim of full OEM
parity. All current command results are parsed from response data **after**
the completion code. BMC identity comes from App `Get Device ID` (0x06/0x01);
for a bridged destination it is read from that **same** IPMB address/channel
at LUN 0. Routing over RMCP is separately tracked in [#13](https://github.com/cataggar/ipmi-rs/issues/13).

| Family; source | Hardware/firmware indicated by source | Required routing, operations actually implemented in ipmitool | Typed here; remaining work |
| --- | --- | --- | --- |
| [Dell `delloem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_delloem.c#L266-L310) | IANA **674**; 10G DRAC, 11G iDRAC6, 12G iDRAC7, 13G iDRAC8; 11G modular forbids LAN selection; 12G/13G modular permits dedicated only; some 12G/13G responses require a license. **Generation mapping is from source, not tested on live hardware.** | Direct BMC LUN 0, OEM 0x30 plus App system-info, Transport, Sensor and Storage commands: `lcd` get/configure/text/KVM/lock, `mac` DRAC/LOM, `lan` NIC get/set/active, `setled` drive mapping, `powermonitor` status/consumption/history/headroom/cap/clear, `vFlash` card status (local Open/WMI only). | `Ipmi::dell()` provides typed reads and explicit guarded writes for all listed groups ([#33](https://github.com/cataggar/ipmi-rs/issues/33)); `dell::GetPowerCapStatus` remains a simple standalone read. Sensor reads require a BMC-owned LUN-0 sensor and SDR-based conversion to watts. Nonlocal sensor routing and hardware-verified firmware capabilities remain unverified; raw messages remain available. |
| [Sun/Oracle `sunoem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_sunoem.c#L2319-L2429) | Sun IANA **42**; ILOM `getfile` and `getbehavior` require **3.2.0.0+** (source checks version). No product-specific list in the command source. | OEM 0x2E: `version` (0x24), `nacname` (0x29), `ping` (0x23), `led get/set` (0x21/0x22, using SDR generic-device locators and LUN), `sshkey set/del` (0x01/0x02), `cli` (0x19), `getval` (0x2A), `setval` (0x2C, **local host only**), `getfile/getbehavior` via core tunnel (0x44). | `sun::GetVersion` plus checked `Ipmi::sun_*` typed and bounded read/write workflows, including firmware checks and local-only `sun_set_value`; see [Sun ILOM operational guide](sun-ilom.md). |
| [Kontron `kontronoem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_kontronoem.c#L70-L179) | IANA **15000**. Source explicitly describes `nextboot` for **CP6012** (product **6012**). Other FRU operations require board-specific verification. | OEM 0x3E LUN **3** `setsn` (0x0C read + Storage FRU writes), `setmfgdate` (0x0E read + Storage FRU writes), `nextboot` (0x02 write). `set_large_buffer` (0x3E/0x82) negotiates local and remote/IPMB channel lengths with failure restoration. | `kontron::{GetSerialNumber,GetManufacturingDate,SetNextBoot,SetLargeBuffer}`, plus guarded FRU prepare/apply and explicit recovery; maintenance and hardware limits in **[Kontron maintenance](kontron-maintenance.md)**. FWUM inspection and guarded local updates are covered by **[#36](https://github.com/cataggar/ipmi-rs/issues/36)**; routed writes are deferred to **[#65](https://github.com/cataggar/ipmi-rs/issues/65)**. |
| [Quanta QCT](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_quantaoem.c#L79-L174) | IANA **7244** (`4C 1C 00`); Get Platform ID enumerates **Grantley** (1) and **Purley** (2), with Purley-specific memory SEL location mapping. | Direct BMC LUN 0 OEM 0x36/0x65 `Get Platform ID` `[4C 1C 00 02]`, invoked from the SEL decoder. No Quanta CLI command or mutation is present. | `quanta::GetPlatformId` rejects empty/unknown replies; `quanta::MemoryLocation::from_sel_entry` maps Purley memory records to typed CPU/channel/DIMM values. Synthetic fixtures verified; live hardware remains unverified: **[#38](https://github.com/cataggar/ipmi-rs/issues/38)**. |
| [Kontron FWUM](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_fwum.c#L145-L218) | Kontron firmware-update manager; compatibility compares firmware **IANA and board product** with target. Board **5002** has special SDR reporting. Do not assume every device exposing Firmware NetFn supports it. | Firmware 0x08: `info` (0x00, plus App Get Device ID), `status` (0x07), `tracelog` (0x0F), `download` (0x0A/0x0B/0x0C), `upgrade` (0x09), `rollback` (0x0E); IPMB/local buffer negotiation via Kontron 0x3E/0x82. | Typed bounded reads; feature-gated one-shot image staging/activation/rollback on transports without a nonrenewable request sequence limit. **Routed RMCP updates remain unimplemented and are excluded from this milestone; follow-up [#65](https://github.com/cataggar/ipmi-rs/issues/65) requires hardware-verified safe resumption.** See the [FWUM maintenance guide](kontron-fwum.md). No live capture or hardware verification. |
| [Intel IME](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_ime.c#L184-L260) | Intel IANA **343**, **device ID 0 / rev 0 / product 0x0B00**; checked before each typed command. | Explicit bridged IPMB address/channel, LUN 0; App 0x06/0x01 for identity, OEM 0x30: A6 status, A7 capabilities, A0 prepare, A1 open, A2 write, A3 close, A4 activate/rollback. CLI file handling is excluded. | `ime::{GetStatus,GetCapabilities}` plus `Ipmi::{ime_info,ime_update,ime_rollback}`; size/CRC, image/status/capability gates, no automatic replay, synthetic transition/fault fixtures. Hardware verification and IPMB route support remain open: **[#34](https://github.com/cataggar/ipmi-rs/issues/34)**, [#13](https://github.com/cataggar/ipmi-rs/issues/13). See [IME safety plan](ime.md). |
| [Tyan TSOL](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_tsol.c#L65-L145) | Tyan IANA **6653**; ipmitool requires IPMIv1.5 **LAN** (not RMCP+ SOL). No product/firmware whitelist in source. | OEM 0x30 start (0x06), stop (0x02), send key (0x03); independent UDP receive on port **6230**. | No typed TSOL commands/session; **[#37](https://github.com/cataggar/ipmi-rs/issues/37)** covers gating, LAN routing and bounded lifecycle. |

## Boundaries and verification

- [Quanta SEL transcript](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_quanta.tr)
  supplies a synthetic IANA **7244** Device ID and Grantley/Purley platform-query
  responses. `ipmi-rs/tests/fixtures/quanta_sel.txt` pins its wire bytes and
  six SEL entries. Tests assert both platform IDs, Purley CPU/channel/DIMM
  locations (including raw byte `FF`, which generic event-data parsing treats
  as unspecified, via the existing `SelEntryInfo::raw` field without altering
  the `Entry::System` variant), Grantley's lack of a mapping, and no OEM send
  after non-Quanta, malformed or failed identity responses. Empty, zero, unknown and
  failed platform responses are rejected. System SEL records have **no**
  manufacturer ID: decode only after a platform query on the **same** Quanta
  device. The textual `CPU0_A0` formatter is CLI presentation, not a separate
  typed command; it remains out of scope. There are no Quanta writes in the
  source, and no live Grantley/Purley BMC request/reply captures are available,
  so firmware and real-device behavior remain unverified.
  The [Dell](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_dell.tr)
  and [Kontron](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_kontron.tr)
  fixtures exercise SEL records and manufacturer IDs, **not** OEM command
  request/response captures. `ipmi-rs/tests/oem.rs` uses source-derived
  synthetic wire examples. There are no matched live BMC captures for Dell,
  Sun, Kontron, Intel ME, FWUM or Tyan commands, and no hardware was tested.
  Model/firmware-specific behavior and mutation recovery remain unverified.
- [`ipmi_oem.c`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_oem.c#L44-L105)
  names Supermicro, IBM, Quanta and Intel OEM **session setup** profiles
  (including legacy LAN authentication and IBM SEL map loading). These are
  transport or formatting hooks, **not** independent typed command families
  to send via `send_oem`; they are explicitly excluded from this command
  matrix. Viking/Supermicro/IBM/Dell/Kontron/Quanta SEL prose decoders
  (in `ipmi_sel.c`) are excluded when they only print event descriptions;
  structured Quanta Purley location decoding is covered by #38.
- Generic IPMIv1.5 [ISOL](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_isol.c),
  DCMI, PICMG/VITA, HPM.1 and Node Manager are not *vendor-specific OEM*
  families here: ISOL is a generic legacy serial transport; the others are
  standards/extensions tracked by [#24](https://github.com/cataggar/ipmi-rs/issues/24),
  [#28](https://github.com/cataggar/ipmi-rs/issues/28) and
  [#30](https://github.com/cataggar/ipmi-rs/issues/30). CLI-only file
  handling, terminal formatting, SEL prose and declared but uncalled
  Sun health/fan header constants are excluded, not counted as coverage.
  Sun version/LED/CLI/core-tunnel fixtures are source-derived; no matched
  live hardware capture or real-device mutation verification is available.

`Ipmi::send_oem` checks manufacturer and, where specified, product immediately
before each command. Identity failures and mismatches send no OEM packet;
command completion codes and timeouts are distinct errors. Raw `Message` /
`Request` and custom `IpmiCommand` paths remain available without this
automatic check for applications intentionally implementing other commands.
Typed writes include Kontron CP6012 nextboot, checked board/product FRU updates,
approved Sun LED/key/CLI operations, and the explicitly requested Dell writes
in `Ipmi::dell()`.
Sun setval additionally requires the host-local device-file transport.
None automatically retries an uncertain write or resets the device. Dell's
iDRAC generation is read from App selector `DD` / block 2 before writes; the
individual operation probes status/capability before sending. Unknown models,
locked LCDs, unlicensed/unsupported responses, absent drives and read-only
power caps fail closed. See [Dell-specific recovery](#dell-generation-guards-and-recovery).
The Kontron FRU workflow validates both areas and requires retained backups
and explicit approval; see [maintenance/recovery](kontron-maintenance.md).
As elsewhere, a timeout **after** dispatch leaves the outcome unknown;
confirm on-device state before considering another write.
Do not mark #29 complete until each linked family is implemented or explicitly
excluded with a recorded rationale and verification limits.

## Dell generation guards and recovery

`Ipmi::dell()` requires IANA 674 and App 0x59/DD block 2 reporting known IMC
types: 10G `08`, 11G `0A/0B`, Master Lite `0D/0E`, 12G `10/11`, or 13G
`20/21/22`. Unknown/CMC types fail closed. Every request rechecks IANA.
Writes recheck IMC type and perform read-only prerequisites: LCD E7 status
(ViewAndModify required), C2 mode/CF text capacity, NIC 25/29 current
selection, drive D5 firmware support and BDF mapping, BA cap flags and EA
min/max budget, or power monitor 9C before clear. No mutation is performed
implicitly by a read. The 12G/13G dedicated-NIC license error `6F`,
unsupported `C1/CB` and vFlash embedded unlicensed `33` are surfaced, not
turned into zero-valued results. A generic connection cannot independently
prove that it is Open/WMI: callers must assert `LocalVflash::Open/Wmi` only
for genuinely local connections; ipmitool refuses vFlash over LAN/LAN+.

The power budget's current cap preserves the returned `Watts` or `BtuPerHour`
wire value without conversion; min/max bounds remain watts. Unknown units
are rejected, and guarded cap writes deliberately accept watts only.

Only the ipmitool C source and the local R630 *SDR* sample provide model
information. **No Dell OEM command capture, tested iDRAC firmware version,
or licensed live BMC run is available.** The `ipmi-rs/tests/oem.rs` fixtures
cover Dell synthetic command bytes and the decoder tests exercise malformed,
short, unsupported and unlicensed responses; they are not hardware captures.
Before deploying writes, schedule a maintenance window, save LCD/NIC/power
configuration and drive mapping, confirm out-of-band access and target drive,
and record rollback to the saved values. A NIC change may sever the current
IPMI connection. On a timeout or partial LCD block write, first re-read the
actual state via a fresh verified connection; **never blindly replay** a
mutation or presume a failed send left the device unchanged.
