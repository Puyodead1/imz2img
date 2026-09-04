# DFSee IMZ converter

`imz2img.py` converts DFSee compressed IMZ images to raw disk/partition images.
It is standalone and uses only Python 3's standard library.

`imz2img.cpp` is the faster C++17 implementation. Build it on Linux with:

```text
g++ -O2 -std=c++17 -Wall -Wextra -pedantic imz2img.cpp -o imz2img
./imz2img part0.imz output.img
```

Or build with CMake:

```text
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

A statically linked x86-64 Linux build is included as `imz2img`; it has no
runtime dependency on DFSee, its license key, Python, or shared C++ libraries.

```text
python imz2img.py part0.imz output.img
```

Multipart `part0.imz`, `part1.imz`, ... sets are discovered automatically when
the first part is supplied. Classic DFSee `.imz`, `.002`, `.003`, ... sets are
also supported. CRC32 fields are checked by default; use `--no-crc` only for
recovery from a damaged image.

Modern streams consist of a 512-byte `DFSeeImageFile #` header, `Tpack#`, a
16-bit block size, and typed records. Older DFSee streams that begin directly
with `Tpack#` are also accepted. Records may contain raw, repeated-byte (RLE),
LZW, or sparse/unused blocks, including legacy no-CRC variants. LZW codes are
MSB-first, start at 9 bits, use clear code 256 and end code 257, and grow up to
the width encoded in the record type.
