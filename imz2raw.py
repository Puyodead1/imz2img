#!/usr/bin/env python3
"""
imz2raw - standalone decompressor for DFSee ".IMZ" compressed disk images.

Reverse engineered from the dfsee Linux binary (dfsWriteImageFile_ / dfsLzwUncompress_ /
dfsLzwInputCode_ / dfsUlInitialize_) and cross-checked against real .IMZ files produced
by dfsee's own RAW2IMZ command.

File layout
-----------
Fixed 512-byte header (only present when the file starts with the 16-byte magic
"DFSeeImageFile #"; otherwise the file is a plain raw image and is copied as-is):

    offset 0x000  16 bytes   magic "DFSeeImageFile #"
    offset 0x010  432 bytes  human readable description, 0x1A-terminated, zero padded
    offset 0x1C0  8 x uint32 LE fields:
                     [0] file number (for multi-volume sets)
                     [1] start LSN
                     [2] flags / buffer-count related (unused by the decompressor)
                     [3] total sector count
                     [4] chunk size in bytes (sectorsPerBuffer * sectorSize)
                     [5] (unused / reserved, observed 0)
                     [6] total sector count (duplicate of [3])
                     [7] sector size in bytes
    offset 0x1E0  32 bytes   zero padding
    offset 0x200  compression sub-header (optional):
                     6 bytes   "Tpack#"
                     uint16 LE chunk size in bytes (matches field [4] above)
                 -> if the 6 bytes do NOT match "Tpack#", the file is uncompressed raw
                    sector data starting right after the main header; the 6 bytes just
                    read must be treated as the first 6 bytes of that raw data.

Per-block stream (only present when the Tpack# sub-header was found), repeated until
the declared number of sectors has been produced or a NEXTFILE marker is hit:

    uint16 LE type
    uint16 LE length
    uint32 LE crc32          -- present only if:
                                   type == 0x0010, type == 0x001C, type == 0xEEFC, or
                                   (type & 0xFF00) == 0xFC00
    payload                  -- present only if type < 0xEEEE, `length` bytes

    dispatch on type:
      0x0000 / 0x0010          -> literal payload bytes, verbatim (raw, [no|with] crc)
      (type & 0xFF00) in       -> RLE: `length` bytes of value (type & 0xFF); no payload
        (0xFF00, 0xFC00)          on disk at all - the fill byte lives in `type` itself
      0xEEEE / 0xEEFC           -> "unused SMART area": `length` bytes of 0x00, no payload
      0xEFEF                    -> NEXTFILE marker: end of this file of a split image set
      anything else             -> LZW-compressed payload, method = type & 0xEF
                                    (in practice always 0x0C -> maxbits 12)

LZW variant
-----------
Adaptive-width LZW, MSB-first bit packing (NOT the classic LSB-first `ncompress`
packing), starting at 9 bits/code, clear code 256, EOF code 257, first free code 258.
Each compressed block is its own independent stream (the code table is reset via
dfsUlInitialize_ at the start of every block). method (0..0xF, observed 0x0C=12)
selects the maximum code width, which also sets the code-table capacity:

      10 -> maxbits 10   11 -> maxbits 11   12 -> maxbits 12   13 -> maxbits 13
      (anything else observed as maxbits 15, per the switch's default case)

Bit reader (dfsLzwInputCode_): a 32-bit accumulator is kept left-justified; bytes are
OR'd in at the top as needed, and each code is extracted by reading `nbits` from the
top of the accumulator, then shifting them out.
"""

import argparse
import struct
import sys
import zlib

MAGIC = b"DFSeeImageFile #"
TPACK_MAGIC = b"Tpack#"
HEADER_SIZE = 0x200
HEADER_FIELDS_OFFSET = 0x1C0

CLEAR_CODE = 256
EOF_CODE = 257
FIRST_FREE_CODE = 258

_TABLE_CAPACITY = {10: 1193, 11: 2399, 12: 4799, 13: 9587}
_DEFAULT_TABLE_CAPACITY = 19183


class ImzFormatError(Exception):
    pass


class BlockLzwDecoder:
    """Decodes one independent dfsee LZW-compressed block."""

    __slots__ = ("data", "pos", "nbits", "maxcode", "maxbits", "table_capacity",
                 "prefix", "suffix", "next_code", "accum", "curbits")

    def __init__(self, data, maxbits):
        self.data = data
        self.pos = 0
        self.maxbits = maxbits
        self.table_capacity = _TABLE_CAPACITY.get(maxbits, _DEFAULT_TABLE_CAPACITY)
        self.accum = 0
        self.curbits = 0
        self._reset_table()

    def _reset_table(self):
        self.nbits = 9
        self.maxcode = (1 << self.nbits) - 1
        self.next_code = FIRST_FREE_CODE
        self.prefix = [0] * self.table_capacity
        self.suffix = [0] * self.table_capacity

    def _get_byte(self):
        if self.pos >= len(self.data):
            return -1
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _get_code(self):
        # MSB-first bit unpacking out of a 32-bit, left-justified accumulator.
        i = 0
        while self.curbits <= 0x18:
            i = self._get_byte()
            if i == -1:
                break
            shift = 24 - self.curbits
            self.curbits += 8
            self.accum |= (i << shift) & 0xFFFFFFFF
        if i == -1:
            return EOF_CODE
        shift = 32 - self.nbits
        code = (self.accum & 0xFFFFFFFF) >> shift
        self.curbits -= self.nbits
        self.accum = (self.accum << self.nbits) & 0xFFFFFFFF
        return code

    def _decode_string(self, code):
        stack = []
        while code > 0xFF:
            if code >= self.next_code:
                raise ImzFormatError(
                    f"LZW code {code} exceeds current table limit {self.next_code}")
            stack.append(self.suffix[code])
            code = self.prefix[code]
        stack.append(code)
        stack.reverse()
        return bytes(stack)

    def decode(self, out_limit=None):
        out = bytearray()
        oldcode = None
        oldchar = 0
        first = True

        while True:
            code = self._get_code()
            if code == EOF_CODE:
                break
            if code == CLEAR_CODE:
                self._reset_table()
                first = True
                continue
            if first:
                if code > 0xFF:
                    raise ImzFormatError(f"first code {code} is not a literal byte")
                out.append(code)
                oldcode = code
                oldchar = code
                first = False
                continue

            if code >= self.next_code:
                entry = self._decode_string(oldcode) + bytes([oldchar])
            else:
                entry = self._decode_string(code)

            out += entry
            oldchar = entry[0]

            if self.next_code <= self.maxcode:
                self.prefix[self.next_code] = oldcode
                self.suffix[self.next_code] = oldchar
                self.next_code += 1
                if self.next_code == self.maxcode and self.nbits < self.maxbits:
                    self.nbits += 1
                    self.maxcode = (1 << self.nbits) - 1

            oldcode = code

            if out_limit is not None and len(out) >= out_limit:
                break

        return bytes(out)


def lzw_decompress_block(payload, method, out_limit):
    maxbits = method & 0xF
    return BlockLzwDecoder(payload, maxbits).decode(out_limit)


def _crc_present(type_field):
    if type_field in (0x0010, 0x001C, 0xEEFC):
        return True
    return (type_field & 0xFF00) == 0xFC00


def convert(in_path, out_path, verify_crc=True, quiet=False):
    def log(msg):
        if not quiet:
            print(msg, file=sys.stderr)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        head = fin.read(HEADER_SIZE)
        if len(head) >= 16 and head[:16] == MAGIC:
            fields = struct.unpack_from("<8I", head, HEADER_FIELDS_OFFSET)
            file_no, start_lsn, _flags, total_sectors, chunk_size, _rsvd, \
                total_sectors2, sector_size = fields
            if total_sectors == 0:
                total_sectors = total_sectors2
            total_bytes = total_sectors * sector_size
            log(f"DFSee image header: file#{file_no} start_lsn=0x{start_lsn:x} "
                f"sectors={total_sectors} sector_size={sector_size} "
                f"chunk_size={chunk_size}")

            tpack = fin.read(8)
            if len(tpack) == 8 and tpack[:6] == TPACK_MAGIC:
                block_size = struct.unpack_from("<H", tpack, 6)[0]
                log(f"Compression header found, block size = {block_size} bytes")
                _decode_block_stream(fin, fout, total_bytes, verify_crc, log)
            else:
                # No compression sub-header: remaining data is raw sectors, and the
                # 8 bytes just read are already part of that raw payload.
                log("No compression header, copying raw sector data")
                remaining = total_bytes
                if tpack:
                    take = tpack[:remaining] if remaining else b""
                    fout.write(take)
                    remaining -= len(take)
                while remaining > 0:
                    chunk = fin.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    fout.write(chunk)
                    remaining -= len(chunk)
        else:
            # Not a DFSee image container at all: treat as already-raw data.
            log("No DFSeeImageFile# magic found, copying input verbatim")
            fout.write(head)
            while True:
                chunk = fin.read(1 << 20)
                if not chunk:
                    break
                fout.write(chunk)

    log(f"Wrote {out_path}")


def _decode_block_stream(fin, fout, total_bytes, verify_crc, log):
    written = 0
    block_no = 0
    while total_bytes is None or written < total_bytes:
        hdr = fin.read(4)
        if len(hdr) < 4:
            break
        type_field, length = struct.unpack("<HH", hdr)
        block_no += 1

        crc = None
        if _crc_present(type_field):
            crc_bytes = fin.read(4)
            if len(crc_bytes) < 4:
                raise ImzFormatError("truncated file: missing crc32 field")
            crc = struct.unpack("<I", crc_bytes)[0]

        if type_field >= 0xEEEE:
            if type_field in (0xEEEE, 0xEEFC):
                data = bytes(length)  # unused/SMART-skipped area -> zero fill
            elif type_field == 0xEFEF:
                log(f"block {block_no}: NEXTFILE marker, stopping "
                    f"(multi-volume images are not supported)")
                break
            elif (type_field & 0xFF00) in (0xFF00, 0xFC00):
                data = bytes([type_field & 0xFF]) * length  # RLE, no payload on disk
            else:
                raise ImzFormatError(f"unknown marker type 0x{type_field:04x}")
        else:
            payload = fin.read(length)
            if len(payload) < length:
                raise ImzFormatError("truncated file: short block payload")
            if type_field in (0x0000, 0x0010):
                data = payload
            else:
                method = type_field & 0xEF
                data = lzw_decompress_block(payload, method, out_limit=None)

        if crc is not None and verify_crc:
            actual = zlib.crc32(data) & 0xFFFFFFFF
            if actual != crc:
                log(f"block {block_no}: CRC32 mismatch (stored 0x{crc:08x}, "
                    f"computed 0x{actual:08x})")

        fout.write(data)
        written += len(data)

    if total_bytes is not None and written < total_bytes:
        log(f"warning: only {written} of {total_bytes} expected bytes were produced "
            f"(truncated or multi-volume image)")


def main():
    ap = argparse.ArgumentParser(
        description="Decompress a DFSee .IMZ compressed disk image to a raw .img file")
    ap.add_argument("input", help="input .IMZ file")
    ap.add_argument("output", help="output raw .img file")
    ap.add_argument("--no-crc", action="store_true",
                     help="skip CRC32 verification of decompressed blocks")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    args = ap.parse_args()

    try:
        convert(args.input, args.output, verify_crc=not args.no_crc, quiet=args.quiet)
    except (ImzFormatError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
