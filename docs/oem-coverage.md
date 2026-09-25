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
| [Dell `delloem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_delloem.c#L266-L310) | IANA **674**; iDRAC 10G–13G capabilities vary; some 12G/13G features need a license. | Direct BMC LUN 0, OEM 0x30 plus App system-info, Transport, Sensor and Storage commands: `lcd` get/configure/text/KVM/lock, `mac` DRAC/LOM, `lan` NIC get/set/active, `setled` drive mapping, `powermonitor` status/consumption/history/headroom/cap/clear, `vFlash` card status. | `dell::GetPowerCapStatus` (0x30/0xBA read `[01 FF]`) only; remaining groups and capability gates: **[#32](https://github.com/cataggar/ipmi-rs/issues/32)**. |
| [Sun/Oracle `sunoem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_sunoem.c#L2319-L2429) | Sun IANA **42**; ILOM `getfile` and `getbehavior` require **3.2.0.0+** (source checks version). No product-specific list in the command source. | OEM 0x2E: `version` (0x24), `nacname` (0x29), `ping` (0x23), `led get/set` (0x21/0x22, using SDR generic-device locators and LUN), `sshkey set/del` (0x01/0x02), `cli` (0x19), `getval` (0x2A), `setval` (0x2C, **local host only**), `getfile/getbehavior` via core tunnel (0x44). | `sun::GetVersion` only; remaining reads, bounded multipacket handling, scoped writes and firmware gates: **[#33](https://github.com/cataggar/ipmi-rs/issues/33)**. |
| [Kontron `kontronoem`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_kontronoem.c#L70-L179) | IANA **15000**. Source explicitly describes `nextboot` for **CP6012** (product **6012**). Other FRU operations require board-specific verification. | OEM 0x3E LUN **3** `setsn` (0x0C read + Storage FRU writes), `setmfgdate` (0x0E read + Storage FRU writes), `nextboot` (0x02 write). `set_large_buffer` (0x3E/0x82) negotiates local and remote/IPMB channel lengths with rollback on failure. | `kontron::GetManufacturingDate` (read **only**) and product-gated `SetNextBoot` (CP6012); full FRU writes, channel buffer sequencing: **[#34](https://github.com/cataggar/ipmi-rs/issues/34)**. |
| [Quanta QCT](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_quantaoem.c#L79-L174) | IANA **7244**; Get Platform ID enumerates **Grantley** (1) and **Purley** (2), with Purley-specific memory SEL location mapping. | Direct BMC LUN 0 OEM 0x36/0x65 `Get Platform ID` `[4C 1C 00 02]`, invoked from the SEL decoder. No Quanta CLI command or mutation is present. | `quanta::GetPlatformId`, rejecting unknown IDs; confirm real hardware and assess typed SEL location (not CLI text): **[#35](https://github.com/cataggar/ipmi-rs/issues/35)**. |
| [Kontron FWUM](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_fwum.c#L145-L218) | Kontron firmware-update manager; compatibility compares firmware **IANA and board product** with target. Board **5002** has special SDR reporting. Do not assume every device exposing Firmware NetFn supports it. | Firmware 0x08: `info` (0x00, plus App Get Device ID), `status` (0x07), `tracelog` (0x0F), `download` (0x0A/0x0B/0x0C), `upgrade` (0x09), `rollback` (0x0E); IPMB/local buffer negotiation via Kontron 0x3E/0x82. | No typed FWUM commands yet; update state machine and device/image safety are separate **[#37](https://github.com/cataggar/ipmi-rs/issues/37)**. |
| [Intel IME](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_ime.c#L184-L260) | Intel IANA **343**, **device ID 0 / rev 0 / product 0x0B00**; these are checked in source before ME update commands. | Direct BMC LUN 0 App ID and OEM 0x30 A0/A1 status/capabilities, A2/A3/A4/A6/A7 update control, write and rollback; CLI `info`, `update`, `rollback`. | No typed Intel ME commands yet; **[#36](https://github.com/cataggar/ipmi-rs/issues/36)** covers exact hardware gate, safe firmware workflow and fixtures. |
| [Tyan TSOL](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_tsol.c#L65-L145) | Tyan IANA **6653**; ipmitool requires IPMIv1.5 **LAN** (not RMCP+ SOL). No product/firmware whitelist in source. | OEM 0x30 start (0x06), stop (0x02), send key (0x03); independent UDP receive on port **6230**. | No typed TSOL commands/session; **[#38](https://github.com/cataggar/ipmi-rs/issues/38)** covers gating, LAN routing and bounded lifecycle. |

## Boundaries and verification

- [Quanta SEL transcript](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_quanta.tr)
  supplies a synthetic IANA **7244** Device ID and Grantley/Purley platform-query
  responses. The [Dell](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_dell.tr)
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
  structured Quanta location decoding is separately assessed in #35.
- Generic IPMIv1.5 [ISOL](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_isol.c),
  DCMI, PICMG/VITA, HPM.1 and Node Manager are not *vendor-specific OEM*
  families here: ISOL is a generic legacy serial transport; the others are
  standards/extensions tracked by [#24](https://github.com/cataggar/ipmi-rs/issues/24),
  [#28](https://github.com/cataggar/ipmi-rs/issues/28) and
  [#30](https://github.com/cataggar/ipmi-rs/issues/30). CLI-only file
  handling, terminal formatting, SEL prose and declared but uncalled
  Sun health/fan header constants are excluded, not counted as coverage.

`Ipmi::send_oem` checks manufacturer and, where specified, product immediately
before each command. Identity failures and mismatches send no OEM packet;
command completion codes and timeouts are distinct errors. Raw `Message` /
`Request` and custom `IpmiCommand` paths remain available without this
automatic check for applications intentionally implementing other commands.
The initial typed writes are restricted to Kontron CP6012 nextboot; they do not
perform automatic retry or reset. A timeout **after** dispatch leaves the
outcome unknown; confirm on-device state before considering another write.
Do not mark #29 complete until each linked family is implemented or explicitly
excluded with a recorded rationale and verification limits.
