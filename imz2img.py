#!/usr/bin/env python3
"""Standalone DFSee IMZ to raw IMG converter.

Reverse engineered from DFSee 11.5.  Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import os
import re
import struct
import sys
from pathlib import Path


MAGIC = b"DFSeeImageFile #"
PACK_MAGIC = b"Tpack#"
NEXT_FILE = 0xEFEF
SMART_ZERO = {0xEEEE, 0xEEFC}
RAW_TYPES = {0x0000, 0x0010}
LZW_TYPES = {0x000C, 0x001C}


class ImzError(Exception):
    pass


def read_exact(stream, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ImzError(f"short read for {what}: wanted {size}, got {len(data)}")
    return data


def has_crc(record_type: int) -> bool:
    return record_type in (0x0010, 0x001C, 0xEEFC) or (
        record_type & 0xFF00
    ) == 0xFC00


def is_rle(record_type: int) -> bool:
    return (record_type & 0xFF00) in (0xFC00, 0xFF00)


def human_size(size: int) -> str:
    value = float(size)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = 0
    while value >= 1024 and unit + 1 < len(units):
        value /= 1024
        unit += 1
    if unit == 0:
        return f"{size} B"
    precision = 2 if value < 10 else 1
    return f"{value:.{precision}f} {units[unit]}"


def lzw_decode(data: bytes, max_bits: int, expected_size: int) -> bytes:
    """Decode DFSee's MSB-first Unix-compress-style LZW stream."""
    if not 9 <= max_bits <= 15:
        raise ImzError(f"unsupported LZW width {max_bits}")

    input_pos = 0
    bit_buffer = 0
    valid_bits = 0
    width = 9
    max_code = (1 << width) - 1
    prefixes = [0] * (1 << max_bits)
    suffixes = bytearray(1 << max_bits)
    next_code = 258
    old_code = None
    first_char = 0
    output = bytearray()

    def get_code() -> int | None:
        nonlocal input_pos, bit_buffer, valid_bits
        # DFSee prefetches to >24 valid bits before every code.  If the
        # payload ends during that prefetch it emits END immediately, even
        # when a few buffered bits remain; this also ignores byte padding.
        while valid_bits <= 24:
            if input_pos >= len(data):
                return None
            bit_buffer |= data[input_pos] << (24 - valid_bits)
            input_pos += 1
            valid_bits += 8
        value = bit_buffer >> (32 - width)
        valid_bits -= width
        bit_buffer = (bit_buffer << width) & 0xFFFFFFFF
        return value

    while True:
        code = get_code()
        if code is None or code == 257:
            break
        if old_code is None:
            if code == 256:
                width, max_code, next_code = 9, 511, 258
                continue
            if code > 255:
                raise ImzError(f"invalid first LZW code {code}")
            output.append(code)
            old_code = code
            first_char = code
            continue
        if code == 256:
            width, max_code, next_code = 9, 511, 258
            old_code = None
            continue

        in_code = code
        stack = bytearray()
        if code >= next_code:
            if code != next_code:
                raise ImzError(f"LZW code {code} exceeds table limit {next_code}")
            stack.append(first_char)
            code = old_code
        while code > 255:
            if code >= next_code:
                raise ImzError(f"LZW prefix {code} exceeds table limit {next_code}")
            stack.append(suffixes[code])
            code = prefixes[code]
            if len(stack) >= 16000:
                raise ImzError("LZW decode stack overflow")
        first_char = code
        stack.append(code)
        output.extend(reversed(stack))

        if next_code <= max_code:
            prefixes[next_code] = old_code
            suffixes[next_code] = first_char
            next_code += 1
            if next_code == max_code and width < max_bits:
                width += 1
                max_code = (1 << width) - 1
        old_code = in_code

    if len(output) < expected_size:
        raise ImzError(f"LZW output is {len(output)} bytes, expected {expected_size}")
    # Some DFSee streams omit an explicit END code and leave decodable pad
    # bits in the payload.  The original bounded output callback discards
    # bytes beyond the advertised block buffer.
    return bytes(output[:expected_size])


def multipart_paths(first: Path) -> list[Path]:
    """Find part0/part1 sets and classic .imz/.002/.003 DFSee sets."""
    name = first.name
    match = re.match(r"^(.*?)(\d+)(\.[^.]+)$", name)
    if match:
        prefix, digits, suffix = match.groups()
        candidates = []
        for item in first.parent.glob(prefix + "*" + suffix):
            found = re.match(
                rf"^{re.escape(prefix)}(\d+){re.escape(suffix)}$", item.name
            )
            if found:
                candidates.append((int(found.group(1)), item))
        candidates.sort()
        start = int(digits)
        selected = [(number, path) for number, path in candidates if number >= start]
        for expected, (number, _path) in enumerate(selected, start):
            if number != expected:
                selected = selected[: expected - start]
                break
        return [path for _number, path in selected]

    paths = [first]
    number = 2
    while True:
        candidate = first.with_suffix(f".{number:03d}")
        if not candidate.exists():
            break
        paths.append(candidate)
        number += 1
    return paths


def parse_header(header: bytes) -> dict[str, int | str]:
    if len(header) != 512 or not header.startswith(MAGIC):
        raise ImzError("not a DFSee IMZ header")
    file_number, start, _unknown, sectors, buffer_size, base, total, bps = \
        struct.unpack_from("<8I", header, 0x1C0)
    text = header[:0x1C0].split(b"\x1a", 1)[0].decode("latin-1", "replace")
    if not bps:
        bps = 512
    return {
        "file_number": file_number,
        "start_sector": start,
        "sectors": sectors,
        "buffer_size": buffer_size,
        "base_sector": base,
        "total_sectors": total,
        "sector_size": bps,
        "text": text,
    }


def open_stream(src, path: Path) -> tuple[dict[str, int | str] | None, int]:
    """Position a modern or legacy/headerless stream at its first record."""
    prefix = read_exact(src, 16, f"format signature in {path}")
    src.seek(0)
    header = None
    if prefix.startswith(MAGIC):
        header = parse_header(read_exact(src, 512, f"header in {path}"))
    elif not prefix.startswith(PACK_MAGIC):
        raise ImzError(f"{path} is not a DFSee IMZ file")
    signature = read_exact(src, len(PACK_MAGIC), "compression signature")
    if signature != PACK_MAGIC:
        raise ImzError(f"bad compression signature in {path}")
    block_size = struct.unpack("<H", read_exact(src, 2, "block size"))[0]
    if not block_size:
        raise ImzError("zero block size")
    return header, block_size


def convert(inputs: list[Path], output: Path, verify_crc: bool, verbose: bool) -> None:
    total_written = 0
    expected_total = None
    block_size = None
    records = 0
    part_index = 0
    digest = hashlib.sha256()

    with output.open("wb") as dst:
        while part_index < len(inputs):
            path = inputs[part_index]
            with path.open("rb") as src:
                header, this_block_size = open_stream(src, path)
                if expected_total is None and header is not None:
                    logical_sectors = int(header["total_sectors"]) or int(header["sectors"])
                    if logical_sectors:
                        expected_total = logical_sectors * int(header["sector_size"])
                if block_size is None:
                    block_size = this_block_size
                elif this_block_size != block_size:
                    raise ImzError("block size changed between parts")
                if verbose:
                    print(f"{path.name}: block size {human_size(block_size)}", file=sys.stderr)

                continue_part = False
                while expected_total is None or total_written < expected_total:
                    raw_type = src.read(2)
                    if not raw_type:
                        break
                    if len(raw_type) != 2:
                        raise ImzError(f"truncated record type in {path}")
                    record_type = struct.unpack("<H", raw_type)[0]
                    payload_size = struct.unpack("<H", read_exact(src, 2, "payload size"))[0]
                    expected_crc = None
                    if has_crc(record_type):
                        expected_crc = struct.unpack("<I", read_exact(src, 4, "CRC32"))[0]

                    if record_type == NEXT_FILE:
                        continue_part = True
                        break
                    if payload_size > block_size:
                        raise ImzError(
                            f"payload {payload_size} exceeds block size {block_size} "
                            f"at record {records + 1}, output 0x{total_written:x}, "
                            f"type 0x{record_type:04x}"
                        )

                    decoded_size = block_size
                    if expected_total is not None:
                        decoded_size = min(block_size, expected_total - total_written)
                    if record_type in SMART_ZERO:
                        chunk = bytes(payload_size)
                    elif is_rle(record_type):
                        chunk = bytes([record_type & 0xFF]) * payload_size
                    else:
                        payload = read_exact(src, payload_size, "record payload")
                        if record_type in RAW_TYPES or record_type == block_size:
                            chunk = payload
                        elif record_type in LZW_TYPES:
                            try:
                                chunk = lzw_decode(payload, record_type & 0x0F, decoded_size)
                            except ImzError as error:
                                raise ImzError(
                                    f"{error} (record {records + 1}, output "
                                    f"0x{total_written:x}, payload {payload_size})"
                                ) from error
                        else:
                            raise ImzError(f"unknown record type 0x{record_type:04x}")

                    # DEAFFACE is DFSee's explicit "no data CRC" marker for
                    # discarded SMART/free-space records.
                    if expected_crc is not None and expected_crc != 0xDEAFFACE and verify_crc:
                        actual_crc = binascii.crc32(chunk) & 0xFFFFFFFF
                        if actual_crc != expected_crc:
                            raise ImzError(
                                f"CRC mismatch at output 0x{total_written:x}: "
                                f"got {actual_crc:08x}, expected {expected_crc:08x}"
                            )
                    if expected_total is not None:
                        remaining = expected_total - total_written
                        if len(chunk) > remaining:
                            chunk = chunk[:remaining]
                    dst.write(chunk)
                    digest.update(chunk)
                    total_written += len(chunk)
                    records += 1
                    if verbose and records % 10000 == 0:
                        suffix = (
                            f" / {human_size(expected_total)}"
                            if expected_total is not None else ""
                        )
                        print(f"Processed {human_size(total_written)}{suffix}", file=sys.stderr)

            if expected_total is not None and total_written >= expected_total:
                break
            if expected_total is None and not continue_part:
                break
            part_index += 1
            if part_index >= len(inputs):
                if expected_total is not None:
                    raise ImzError(
                        f"image ended at {total_written} of {expected_total} bytes; next part missing"
                    )
                if continue_part:
                    raise ImzError("next-part marker found but next part is missing")
            if verbose:
                print(f"Continuing with {inputs[part_index].name}", file=sys.stderr)

    if expected_total is not None and total_written != expected_total:
        raise ImzError(f"wrote {total_written}, expected {expected_total} bytes")
    print(f"Converted {records} records, {human_size(total_written)} -> {output.name}")
    print(f"SHA256: {digest.hexdigest()}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert DFSee IMZ images to raw IMG")
    parser.add_argument("input", type=Path, help="first IMZ part (e.g. part0.imz)")
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        help="raw output image (default: input filename with .img extension)",
    )
    parser.add_argument("--no-crc", action="store_true", help="skip CRC32 validation")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    try:
        if not args.input.is_file():
            raise ImzError(f"input not found: {args.input}")
        parts = multipart_paths(args.input)
        output = args.output if args.output is not None else args.input.with_suffix(".img")
        convert(parts, output, not args.no_crc, args.verbose)
        return 0
    except (ImzError, OSError) as error:
        print(f"imz2img: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
