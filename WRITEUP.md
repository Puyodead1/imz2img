# Reverse Engineering DFSee's `.IMZ` Compressed Image Format

## Goal

`dfsee` is a statically-linked 32-bit Linux ELF binary used for disk/partition
imaging and recovery. It can save a raw device or partition to a compressed
`.IMZ` image file (`RAW2IMZ` / `SAVE`) and restore it back (`IMZ2RAW` /
`RESTORE`). The task was to reverse engineer the `.IMZ` container and
compression format well enough to write an independent, standalone
decompressor with no dependency on `dfsee` itself, and to understand the
restore flow (including multi-volume image sets).

## Method

Static analysis alone (IDA decompilation of `dfsWriteImageFile_`,
`dfsLzwUncompress_`, `dfsLzwInputCode_`, `dfsUlInitialize_`, and
`dfsWriteImageTo_`) established the overall shape of the format, but a few
details — exact header field offsets, the precise LZW bit-width bump timing,
and the multi-volume naming scheme — were ambiguous or easy to get subtly
wrong from decompiled pseudocode alone. The approach that actually nailed the
format down was **dynamic verification**: run the real binary (under WSL) to
produce genuine `.IMZ` files and genuine restores, then write a decoder and
diff its output against dfsee's own output until they matched byte-for-byte.

This caught two real implementation bugs (see below) that pure disassembly
reading did not surface, and gave concrete ground truth for the header layout
across multiple sample files (different description-text lengths, single- and
multi-block images).

### Obstacle: evaluation period expired

The copy of `dfsee` used here refuses to run non-trivial commands once its
evaluation period is judged to have expired (checked against the system
clock). Since the environment's clock could not be altered (no root, and the
binary is statically linked so `LD_PRELOAD` interposition of libc time
functions isn't possible), the check itself was located in IDA:

```
0x80BE48E: cmp ebx, ebp
0x80BE490: jbe short loc_80BE4C8   ; branch taken -> "expired" path
```

The ELF file offset for the byte at VA `0x80BE490` was computed from the
`PT_LOAD` segment mapping (`VirtAddr 0x08048100` / file `Offset 0x100`, i.e.
`file_offset = VA - 0x8048000`), giving offset `0x76490`. A **single byte**
was flipped there, `0x76` (`jbe`) → `0xEB` (`jmp`), on a disposable copy of
the binary (`dfsee_patched`) used only to generate local test vectors — never
applied to the binary that ships in this repo.

## Container format

A `.IMZ` file is either:

1. A **DFSee image container**: starts with the 16-byte magic
   `"DFSeeImageFile #"`, followed by a fixed 512-byte header, optionally
   followed by a `Tpack#` compression sub-header and a stream of compressed
   blocks, **or**
2. Just **raw sector data** with no container at all (if the file doesn't
   start with that magic).

### Main header (512 bytes total, only present if magic matches)

| Offset | Size | Field |
|---|---|---|
| `0x000` | 16 | magic `"DFSeeImageFile #"` |
| `0x010` | 432 | human-readable description text, `0x1A`-terminated, zero-padded |
| `0x1C0` | 4 | file number (multi-volume sequence number) |
| `0x1C4` | 4 | start LSN |
| `0x1C8` | 4 | flags / unused by the decompressor |
| `0x1CC` | 4 | total sector count |
| `0x1D0` | 4 | chunk size in bytes (`sectorsPerBuffer * sectorSize`) |
| `0x1D4` | 4 | reserved, observed always 0 |
| `0x1D8` | 4 | total sector count (duplicate of the field at `0x1CC`) |
| `0x1DC` | 4 | sector size in bytes |
| `0x1E0` | 32 | zero padding |
| `0x200` | — | optional `Tpack#` compression sub-header follows here |

These offsets are **fixed regardless of how long the description text
actually is** — confirmed by generating a second sample with a much longer
source filename and diffing the header bytes. If the sector-count field at
`0x1CC` is zero, the duplicate at `0x1D8` is used instead (observed in
practice, not just theoretical).

### Compression sub-header (optional, 8 bytes at offset `0x200`)

```
6 bytes  "Tpack#"
uint16 LE  chunk size in bytes  (matches the header field at 0x1D0)
```

If those 6 bytes don't spell `Tpack#`, there's no compression: the rest of
the file is raw sector data, and — importantly — the 6 (or 8) bytes already
read need to be treated as the *start* of that raw data, not discarded.

### Block stream

When the `Tpack#` sub-header is present, the rest of the file is a sequence
of blocks, repeated until the declared sector count worth of bytes has been
produced (or a NEXTFILE marker ends the volume):

```
uint16 LE  type
uint16 LE  length
uint32 LE  crc32     -- present only if:
                          type == 0x0010, type == 0x001C, type == 0xEEFC,
                          or (type & 0xFF00) == 0xFC00
<payload>             -- present only if type < 0xEEEE, `length` bytes
```

Dispatch on `type`:

| type | meaning |
|---|---|
| `0x0000` / `0x0010` | literal bytes, stored verbatim |
| `(type & 0xFF00) == 0xFF00` or `0xFC00` | **RLE**: `length` bytes all equal to `type & 0xFF`. No payload bytes on disk at all — the fill value lives entirely in the type field. |
| `0xEEEE` / `0xEEFC` | "unused SMART area" — `length` zero bytes, no payload on disk |
| `0xEFEF` | **NEXTFILE** marker — end of this volume of a multi-volume set |
| anything else | LZW-compressed payload; `method = type & 0xEF` selects the max code width (observed in practice: always `0x0C` = 12) |

Every block that carries a CRC gets verified with a plain zlib/PKZIP CRC32
of the *decompressed* block data.

## The LZW variant

dfsee does **not** use classic Unix `ncompress`-style LZW. It's a home-grown
adaptive-width variant with two features that will silently corrupt output if
you assume standard conventions:

1. **MSB-first bit packing.** Codes are packed into a 32-bit accumulator
   left-justified from the top, not LSB-first like `compress(1)`.
2. **The bit-width bump happens one code early.** After adding a new table
   entry and incrementing `next_code`, the classic convention bumps `nbits`
   when `next_code == maxcode + 1`. dfsee's actual code (confirmed from
   `dfsLzwUncompress_`'s decompiled comparison) bumps when
   **`next_code == maxcode`** — one code sooner. Get this wrong and decoding
   silently diverges a few hundred codes in, with codes referencing table
   entries that don't exist yet.

Other properties:

- 9-bit codes to start, clear code `256`, EOF code `257`, first free code
  `258`.
- `method` (the low nibble of the block type, after masking off `0xEF`)
  selects `maxbits` and the code-table capacity:

  | maxbits | table capacity |
  |---|---|
  | 10 | 1193 |
  | 11 | 2399 |
  | 12 | 4799 |
  | 13 | 9587 |
  | other | 19183 |

- **Every compressed block is an independent LZW stream** — the code table
  is reset at the start of each block (`dfsUlInitialize_` is called fresh
  per block by `dfsLzwUncompress_`), so blocks can be decoded in isolation
  and don't depend on any cross-block state.

### Two real bugs found this way

Both were found by decoding a real 2-block sample, comparing against
dfsee's own restore output byte-for-byte, and bisecting where the two
diverged:

1. **Wrong EOF condition.** First attempt only treated "no more input bytes"
   as EOF when `curbits < nbits`. The actual behavior (per
   `dfsLzwInputCode_`) is unconditional: if the byte supplier has nothing
   left, return EOF code `257`, full stop.
2. **Off-by-one in the bit-width bump**, described above — writing
   `next_code == maxcode + 1` (the "textbook" condition) instead of the
   actual `next_code == maxcode` produced garbage a couple hundred codes
   into any block that grew past 9-bit codes. This was the one that actually
   mattered for correctness on realistic multi-KB blocks.

## Multi-volume images

`dfsee`'s restore driver, `dfsWriteImageTo_`, calls the per-file restore
routine `dfsWriteImageFile_` in a loop. When that routine hits a `0xEFEF`
NEXTFILE block, it returns a specific status code (217) back up to the
driver, which then:

1. Strips the extension off the **current** volume's path
   (`TxStripExtension_`).
2. Appends `.NNN` — `sprintf(".%3.3lu", part_number)` — zero-padded to 3
   digits, starting at `002` for the second volume (e.g.
   `image.imz` → `image.002` → `image.003` → ...).
3. Opens that file and re-probes it **exactly like the first file**: checks
   for the 16-byte magic, and if present, re-reads the 512-byte header and
   optional `Tpack#` sub-header before resuming block decoding.

Note this is driven *only* by an explicit NEXTFILE marker — a plain
truncated/EOF file does **not** trigger a search for a next volume.

This was confirmed from the decompiled restore-driver code directly (a
straightforward, unambiguous string-building loop), and then validated by
synthesizing a genuine split: an existing 2-block sample was cut after its
first block, a NEXTFILE marker (`0xEFEF`, length 0, no payload) was appended
to make volume 1, and the remaining block bytes (with no header at all) were
written out as volume `.002`. Running the decompressor against volume 1 alone
correctly picked up the `.002` continuation and reproduced the original data
exactly.

## Deliverable

[`imz2raw.c`](imz2raw.c) — a standalone, dependency-free C99 decompressor
(only libc; it includes its own small CRC32 table implementation) that:

- Parses the container/header/sub-header exactly as described above.
- Dispatches all five block types (literal, RLE, SMART-skip, NEXTFILE,
  LZW).
- Implements the MSB-first adaptive LZW decoder with both bug fixes applied.
- Transparently follows multi-volume `.NNN` chains.
- Verifies CRC32 per block when present (`--no-crc` to skip).

[`imz2raw.py`](imz2raw.py) is kept alongside it as the original reference
implementation / an executable form of this document — it was the first
thing validated against real samples, before being ported to C per request.

[`CMakeLists.txt`](CMakeLists.txt) builds the C tool:

```bash
cmake -S dfsee -B dfsee/build -DCMAKE_BUILD_TYPE=Release
cmake --build dfsee/build
```

```
./imz2raw input.imz output.img
```

### Validation performed

- A small single-block sample and a larger multi-block (235-sector) sample
  were generated with the real `dfsee` binary and decoded with both the
  Python and C implementations; output matched dfsee's own `IMZ2RAW` restore
  **byte-for-byte** in both cases.
- A synthetic multi-volume split (constructed from the multi-block sample)
  was decoded end-to-end through the volume-switching logic and matched the
  original source data exactly.
- The C build was reproduced from scratch via CMake directly in this
  directory (not just the scratch/test environment) and re-verified against
  the same ground truth.

### Known limitations

- Only the LZW method actually observed in practice (`0x0C`, maxbits 12) has
  been exercised against real data; other `maxbits` values are implemented
  per the disassembled table-capacity logic but untested against real
  samples, since dfsee's compressor was never observed emitting them.
- Header fields "flags/unused" (`0x1C8`) and "reserved" (`0x1D4`) are parsed
  but not used — they aren't needed for correct decompression and their full
  semantics were never pinned down (irrelevant unless a *re-compressor* is
  ever wanted, which was out of scope here).
