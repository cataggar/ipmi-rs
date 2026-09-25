# Kontron OEM FRU and CP6012 boot maintenance (#32)

Source baseline: [`ipmi_kontronoem.c` at `33f3a0a`](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/lib/ipmi_kontronoem.c).
The commands are opt-in library APIs, not automatic discovery or a CLI.

| Operation | Wire request and result (completion code excluded) | Guard |
| --- | --- | --- |
| Get serial for `setsn` | OEM netfn `0x3e`, cmd `0x0c`, LUN **3**, data `b4 90 91 8b`; returned serial bytes. | Same target's LUN-0 Get Device ID must report IANA **15000**. Accept only 1–63 printable ASCII bytes. |
| Get manufacturing date for `setmfgdate` | OEM `0x3e/0x0e`, LUN **3**, `b4 90 91 8b`; exactly three raw date bytes. | Same vendor gate. Date is copied as FRU minutes-since-1996 bytes, **without** local-time conversion. |
| CP6012 `nextboot` | OEM `0x3e/0x02`, LUN **3**, `b4 90 91 8b 9d <device> ff`; empty success reply. Device codes BIOS=0, FDD=1, HDD=2, CDROM=3, network=4. | Same target must report IANA **15000**, product **6012**. A lost response is **not replayed**; inspect the boot configuration before deciding on another operation. |
| Large buffer | OEM `0x3e/0x82`, LUN **0**, `[0e,size]` for current interface; `[00,size]` for local IPMB. Empty success reply. | Identity-check each target. For a remote target, negotiate **local current → local IPMB → remote current**. On failure restore all attempted channels in reverse order to size **0** (default), returning any cleanup errors. A prior nonzero buffer setting cannot be discovered by this command and is **not** recoverable automatically. |
| FRU info/read/write | Storage `0x0a/0x10` `[00]` → `[size_lo,size_hi,access]`; `0x0a/0x11` `[00,offset_lo,offset_hi,count]` → `[count,data…]`; `0x0a/0x12` `[00,offset_lo,offset_hi,data…]` → `[count]`. | FRU ID **0**, LUN **0**, **same destination** as the OEM request. Word-access FRUs divide the wire offset/count by two; reads and writes use ≤16-byte chunks. No write retries. |

Specify `FruDevice::BUILTIN` for the local controller, or
`FruDevice { id: 0, target: Some((address, channel)), lun: LogicalUnit::Zero }`
for an IPMB destination. The OEM query/CP6012 command uses LUN **3** on
that destination; its identity and all FRU transfers use LUN **0**. The
`target` is retained throughout a prepared update and routed by the RMCP
bridge implementation; it is never inferred from the local session address.
No other FRU IDs or LUNs are supported by this workflow.

## Maintenance window, backup, and recovery

1. Reserve a maintenance window and prevent other FRU writers, management
   automation, and device resets. Confirm board model/firmware independently.
   Obtain a fresh copy of the complete inventory before starting.
2. Call `Ipmi::prepare_kontron_serial(device)` or
   `Ipmi::prepare_kontron_mfg_date(device)`. Preparation sends only reads,
   checks manufacturer, reads the OEM value, and validates the **complete**
   FRU inventory. Both **complete board and product areas** must exist;
   their declared lengths, offsets, fields, and checksums (including the
   common header) must pass. Inspect `change.backup().board()`,
   `.product()`, and `change.proposed_image()`. **Persist
   `change.backup().image()` off-device** before any write, including a date
   change that writes only the board area. Existing serial fields must be
   eight-bit text with exactly the OEM serial's length; no relayout, type
   conversion, truncation, or use of ipmitool's unsafe inferred area lengths.
   The updated full image is checked again before use.
3. After inspecting the preview and saved backup, explicitly call
   `apply_kontron_fru_change(&change, KontronWriteApproval::acknowledge_risk())`.
   It rechecks the **full Get Device ID**, size/access, original full image,
   and identity again immediately before writes. It writes only changed
   complete areas, including their recalculated checksum bytes, and reads
   back the entire image, validating equality and checksum/layout.
4. If a chunk fails, **stop**: its error gives the area, byte offset,
   previously acknowledged bytes and best-effort raw observation (which may
   itself fail). Even a completion-code rejection or short acknowledgement
   cannot prove an earlier or in-flight chunk's resulting FRU state. There
   is **no automatic retry or rollback**. A mismatch/readback error also
   requires investigation. Keep the persisted backup, examine a fresh FRU
   dump and compare both complete areas; a partial area may be unparseable.
   Only after deliberate operator approval, call
   `restore_kontron_fru_backup(&change, KontronWriteApproval::acknowledge_risk())`.
   Recovery checks the original identity/size and **all other bytes**
   unchanged, rewrites only differing board/product areas from the saved
   image, and reads back the entire image. If recovery itself fails, **do
   not retry blindly**; stop and escalate to board-specific recovery.
5. To request nextboot, call
   `kontron_set_next_boot(target, BootDevice::Network,
   KontronWriteApproval::acknowledge_risk())` (choose the actual intended
   device). A timeout leaves the outcome unknown; it does not retry. For
   large-buffer setup use `kontron_set_large_buffer(target, size)`, and
   inspect restoration failures before continuing.

## Evidence and unsupported behavior

Tests use the literal request magic/device codes from `ipmi_kontronoem.c`,
the checked storage command layout, and the repository's **synthetic**
128-byte FRU fixture. In that fixture board bytes `32..72` and product
bytes `72..112` end in checksums `d3`/`2f`; changing both four-byte serials
to `Z123` produces `b6`/`23`, while setting the board date to `01 02 03`
produces `2d`. Unit/integration fault injection covers wrong IANA/product,
bad area checksums/lengths, short fields, IPMB targets, word access, changed
identity/image, lost/short/rejected partial writes, readback mismatch,
explicit recovery, ambiguous boot, and buffer failure/restoration.

The upstream [Kontron SEL transcript](https://github.com/cataggar/ipmitool/blob/33f3a0a1b895e3effabb0ec8d180a0a2f1536128/tests/transcripts/sel_kontron.tr)
identifies a manufacturer in SEL data; it **does not capture these commands
or verify CP6012 firmware/board behavior**. No CP6012 board captures or
live hardware validation are available. Non-CP6012 Kontron FRU operations
are vendor-gated but must be verified against the specific board/firmware
before use. FWUM, different field encodings/lengths, FRU ID ≠0, and
undocumented buffer sizes are unsupported. Readback is not a substitute
for a maintenance window or physical recovery if a controller changes state
while a write is in flight.
