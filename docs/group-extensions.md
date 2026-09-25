# Group extension coverage against ipmitool

Reference: `lib/ipmi_picmg.c` (`ipmi_picmg_main`) and `lib/ipmi_vita.c`
(`ipmi_vita_main`) in ipmitool, at revision
`33f3a0a1b895e3effabb0ec8d180a0a2f1536128`. All commands below use
NetFn `0x2c` and put the group identifier in the first request **and**
successful response byte. `picmg` uses `0x00`; `vita` uses `0x03`.
`ipmi-rs-core/tests/fixtures/{picmg,vita}.txt` contains exact request,
success, rejection (incorrect identifier / unsupported completion), and
malformed-length fixtures for **every implemented command**.
PICMG Get Address Info recognizes the four-byte legacy, seven-byte ATCA,
and eight-byte MTCA carrier response forms; FRU/site fields absent from
legacy replies are `None`, while the carrier extension byte remains raw.
PICMG FRU Control acknowledges the group identifier and retains up to
254 additional opaque bytes in `FruControlAcknowledgement`, without
retrying the action.

| ipmitool `picmg` entry point | Command | Rust (`picmg` module) | Coverage |
| --- | --- | --- | --- |
| `properties` (also called before non-help commands) | 00 | `GetPicmgProperties`; explicit `require_supported` | Yes |
| `addrinfo` | 01 | `GetPicmgAddress` | Yes |
| `frucontrol` | 04 | `PicmgFruControl` | Yes |
| `activate`, `deactivate` | 0c | `SetPicmgActivation` with explicit action | Yes |
| `policy get`, `policy set` | 0b, 0a | `GetPicmgPolicy`, `SetPicmgPolicy` | Yes |
| `portstate get`, `portstate set` | 0f, 0e | `GetPicmgPortState`, `SetPicmgPortState` | Yes |
| `portstate getall/getgranted/getdenied` | repeated 0f | No automatic multi-port sweep; repeat `GetPicmgPortState` explicitly and filter raw state | Partial (no CLI sweep) |
| `amcportstate get`, `amcportstate set` | 1a, 19 | `GetAmcPortState`, `SetAmcPortState` | Yes |
| `amcportstate getall/getgranted/getdenied` | repeated 1a | No automatic sweep; repeat `GetAmcPortState` | Partial (no CLI sweep) |
| `led prop`, `led cap`, `led get`, `led set` | 05–08 | `GetPicmgLedProperties`, `GetPicmgLedCapabilities`, `GetPicmgLedState`, `SetPicmgLedState` | Yes |
| `power get`, `power set` | 12, 11 | `GetPicmgPower`, `SetPicmgPower` | Yes |
| `clk get`, `clk set` | 2d, 2c | `GetAmcClockState`, `SetAmcClockState` | Yes |
| `clk getall/getgranted/getdenied` | repeated 2d | No automatic sweep; repeat `GetAmcClockState` | Partial (no CLI sweep) |
| `busres summary` | repeated 17 | `GetPicmgBusResource` for each named resource | Yes (single resource per request) |
| `help` | — | Rust API documentation instead of CLI help | N/A |

| ipmitool `vita` entry point | Command | Rust (`vita` module) | Coverage |
| --- | --- | --- | --- |
| `properties` | 00 | `GetVitaCapabilities`; explicit `require_supported` | Yes |
| `addrinfo` | 40 | `GetVitaAddress` | Yes |
| `frucontrol` | 04 | `VitaFruControl` (quiesce explicitly unsupported) | Yes |
| `activate`, `deactivate` | 0c | `SetVitaActivation` with explicit action | Yes |
| `policy get`, `policy set` | 0b, 0a | `GetVitaPolicy`, `SetVitaPolicy` | Yes |
| `led prop`, `led cap`, `led get`, `led set` | 05–08 | `GetVitaLedProperties`, `GetVitaLedCapabilities`, `GetVitaLedState`, `SetVitaLedState` | Yes |
| `help` | — | Rust API documentation instead of CLI help | N/A |

These modules deliberately do **not** expose other PICMG wire codes that
are listed in `ipmi_picmg.h` but have no ipmitool `picmg` or `vita` dispatch
entry point: shelf-address changes, IPMB settings, device locator, fan
control, and additional power negotiation. Such operations remain
unsupported, not silently approximated. Unknown version/standard reports
remain inspectable but `require_supported()` returns
`GroupError::UnsupportedOperation`; IPMI unsupported-command completion
codes `0xc1`, `0xc2` and `0xd6` return the same error. Other nonzero
completion codes retain their original error and response bytes in
`IpmiError`, including `0xcc`.

## Addressing and writes

The default `Ipmi::send_recv` target is the BMC. Address-discovery reads
only report IPMB addresses; they do **not** change the target of later
requests. Operations on remotely addressed shelf/slot/FRU devices require
explicit bridged IPMB routing from #13. Until that routing is available
and selected, these typed commands address only the local controller.
All setters are explicit commands and are never retried by the modules.
If a mutation's acknowledgement is lost or times out, its outcome is
unknown. Do not automatically resend activation, FRU control, power,
policy, port, clock, or LED writes.
