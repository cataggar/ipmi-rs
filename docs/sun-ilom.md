# Sun/Oracle ILOM OEM commands (#35)

Reference: ipmitool [`lib/ipmi_sunoem.c`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_sunoem.c).
`Ipmi::send_oem(sun::GetVersion)` is the foundation representative (0x2e/0x24).
The additional `Ipmi::sun_*` methods are in `ipmi_rs::oem::sun`. Each OEM packet,
including each continuation or status poll, checks **Sun manufacturer IANA 42**
with Get Device ID at the same destination, LUN 0. A mismatch prevents the OEM
packet. The LED request's LUN and IPMB target/channel come from the current
physical generic-device SDR locator; both identity and OEM packet use the same
target. No board-product or model-specific capability is inferred.

| API | OEM command; wire body and typed output |
| --- | --- |
| `sun_nac_name(name)` | 0x29; 65 bytes (sequence + 64-byte short name); 65-byte replies, strictly increasing sequence until final NUL; returns a UTF-8 path ≤256 bytes. |
| `sun_ping(seq)` | 0x23; little-endian 16-bit sequence + bytes 0..63 (66 bytes); verifies exactly matching 66-byte echo. |
| `sun_led(id, kind)` / `sun_set_led(Approved, id, kind, mode)` | 0x21/0x22; physical generic locator selected by SDR ID, verified mode before setting. 7-byte get `[slave,kind,access,oem,entity,instance,0]` → one mode byte; 9-byte set `[slave,kind,access,oem,mode,entity,instance,0,0]` → empty success. Logical entity-group/all-LED mutation is deliberately excluded. |
| `sun_delete_ssh_key(Approved, uid)` / `sun_set_ssh_key(Approved, uid, public_key)` | 0x02 one UID byte / 0x01 `[uid,block index or FF for last,length,≤64 key bytes]`, empty success. UID 1..63, bounded single-line OpenSSH public key only, ≤16 KiB. No local file access. |
| `sun_cli(Approved, line, output_limit)` | 0x19; 8-byte header + NUL-terminated ≤72-byte chunk. Opens version 2 (version 1 fallback **only on explicit invalid-version reply**), polls bounded line chunks, ends with EOF; returns ≤4096 output bytes. No stdin/stdout, force-open, timeout retry or implicit replay. A server may keep the session open after abnormal termination; recover out of band. |
| `sun_get_value(path)` | 0x2a; `[1 or 2, 79-byte path]`, at most five polls; typed NUL-terminated property value or not-found/limit error. |
| `sun_set_value(Approved, path, value)` | 0x2c; `[3, kind (0 path/1 value), transaction ID, final marker, 56 bytes]`, followed by `[4,0,transaction ID,0..]` status polls. Paths ≤256 bytes, values ≤1024; only compiled for the sealed host-local `File` transport. Remote, USB and serial transports cannot call it. |
| `sun_get_file(id, max_bytes)` / `sun_get_behavior(id)` | 0x44, subcommands 11/15. First check typed ILOM version ≥**3.2.0.0**; file request `[11,16-byte ID, big-endian u32 block]` → big-endian block/size, EOF and ≤1024 bytes, returns caller-bounded bytes (≤1 MiB). Behavior request `[15,32-byte ID]` → typed boolean. No file saving/printing. |

All strings and multipacket flows have size/packet limits. Truncated replies,
bad sequences, status, invalid UTF-8, mismatched block numbers, unsupported
firmware, and excessive output produce errors instead of partial success.
The `WriteIntent::Approved` argument is mandatory for mutations and CLI;
**it does not authenticate the caller or prove that a model supports a command**.
Sun request and response data are redacted from Rust `Debug`, device-file trace
logs, and command errors, including key and LUAPI values. Never log raw
`Message::data()` or user-provided key strings in your application.

## Maintenance, rollback and recovery

During a maintenance window, inventory the BMC vendor/model/firmware,
capture current LED/key/property state with administrative tools, arrange an
out-of-band console and keep known-good public keys. Obtain change approval
before setting LEDs, replacing/deleting keys, invoking CLI or changing LUAPI
properties. Restore the prior LED/property value or re-install the previous
public key if confirmation shows the change was incorrect. CLI side effects
depend on the line executed: use its documented inverse or the BMC's recovery
procedure; there is **no generic automatic rollback**. If a write times out,
returns malformed data, or loses connection after dispatch, its outcome is
**unknown**; do not resend. Reconnect, re-read the state through an independent
management path, investigate, then decide whether a new approved mutation is
safe. An incomplete setval or CLI session may require BMC-side cleanup.

The tests under `ipmi-rs/src/oem/sun.rs` use **source-derived synthetic
fixtures**, not captured physical ILOM traffic. No matching live Sun hardware
or firmware captures were available. Version-format details, exact firmware
behavior, bridged LED targets, per-model capabilities, and rollback remain
**unverified on hardware**. Collect redacted request/response captures and
read-only confirmation first on an actual device; run any writes only under
the maintenance and recovery plan above.
