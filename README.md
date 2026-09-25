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
5. Get SDR info
6. Get SDR repository info
7. (If supported) get SDR allocation information
8. Load all of the SDRs from the repository
9. Attempt to read the value of all of the sensors from the SDR repository

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

### `ipmi-channels`
This example discovers available channels and prints channel information. For LAN channels, it also shows a small set of LAN configuration parameters (addressing and gateways).

### `ipmi-lan-config`
This example reads LAN configuration for all LAN channels and emits JSON. You can apply a JSON configuration with `--set`, print the input schema with `--print-schema`, or emit an IPv6 example payload with `--print-v6-example`.

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
| Set / Get System Boot Options            | Chassis commands 0x08/0x09 |
| Set LAN Configuration Parameters        | 23.1                  |
| Get LAN Configuration Parameters        | 23.2                  |
| Set SOL Configuration Parameters        | 26.2                  |
| Get SOL Configuration Parameters        | 26.3                  |
| Activate / Deactivate Payload (SOL)     | 24.1 / 24.2           |
| Get SEL Info                            | 31.2                  |
| Get SEL Allocation Info                 | 31.3                  |
| Reserve SEL                             | 31.4                  |
| Get SEL Entry                           | 31.5                  |
| Add SEL Entry                           | 31.6                  |
| Delete SEL Entry                        | 31.8                  |
| Clear SEL                               | 31.9                  |
| Get / Set SEL Time                      | 31.10 / 31.11         |
| Get Sensor Reading                      | 35.14                 |
| Get Device SDR Info                     | 35.2                  |
| Get Device SDR                          | 35.3                  |
| Get SDR Repository Info                 | 33.9                  |
| Get SDR Repository Allocation Info      | 33.10                 |
| Get SDR                                 | 33.12                 |

## BMC reset and boot overrides

`ipmi_rs::app::{WarmReset, ColdReset}` reset the **management controller**, not the host.
To control host power, use the separate Chassis Control command. A cold reset can
interrupt its own response. After a timeout or lost connection the outcome is
**unknown**: neither retry the mutation automatically nor assume that an offline
BMC proves success or failure.

The core `ipmi_rs::chassis` boot-option commands support only parameters 0
(set-in-progress), 3 (valid-bit clearing), 4 (boot-info acknowledgement), and 5
(boot flags). For example, using an existing `Ipmi` connection:

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
selector, valid/unlocked state, lengths, and supported bits; unmodelled
readbacks and unsupported writes fail instead of silently changing meaning.
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

# Supported interfaces

## `ioctl`-based IPMI device file

The [Linux IPMI Driver][lipmid] is supported through the character device exposed by that driver, usually at `/dev/ipmi<N>`.

Access to this file generally requires root privileges.

[lipmid]: https://docs.kernel.org/driver-api/ipmi.html

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