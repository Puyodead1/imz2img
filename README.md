# DFSee IMZ converter

`imz2img.py` converts DFSee compressed IMZ images to raw disk/partition images.
It is standalone and uses only Python 3's standard library.

`imz2img.cpp` is the faster C++17 implementation. Build it on Linux with:

```text
g++ -O2 -std=c++17 -Wall -Wextra -pedantic imz2img.cpp -o imz2img
./imz2img part0.imz output.img
```

The output argument is optional. When omitted, the converter writes beside the
input using the same base name and an `.img` extension:

```text
./imz2img part0.imz
# writes part0.img
```

Or build with CMake:

```text
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

On Windows, run the same commands from a Visual Studio Developer PowerShell or
Developer Command Prompt. The executable will normally be at
`build\Release\imz2img.exe` for the Visual Studio generator. A native x64
Windows build is included as `imz2img.exe`.

A statically linked x86-64 Linux build is included as `imz2img`. Neither
included executable requires DFSee, its license key, or Python.

```text
python imz2img.py part0.imz output.img
```

Multipart `part0.imz`, `part1.imz`, ... sets are discovered automatically when
the first part is supplied. Classic DFSee `.imz`, `.002`, `.003`, ... sets are
also supported. When both naming patterns are present, a same-stem `.002` file
takes precedence (for example, `part1.imz`, `part1.002`) so an unrelated
`part2.imz` is not consumed. CRC32 fields are checked by default; use `--no-crc`
only for recovery from a damaged image.

Similarly named files are consumed only when the image itself requires a
continuation. Modern headers provide the total image size; legacy streams use
DFSee's next-file marker. Separate `part0`, `part1`, etc. partition images
therefore remain separate.

Early `DFSeeImageFile #0001` headers that leave the newer total-sector field
zero are supported using their original sector-count field.

Modern streams consist of a 512-byte `DFSeeImageFile #` header, `Tpack#`, a
16-bit block size, and typed records. Older DFSee streams that begin directly
with `Tpack#` are also accepted. Records may contain raw, repeated-byte (RLE),
LZW, or sparse/unused blocks, including legacy no-CRC variants. LZW codes are
MSB-first, start at 9 bits, use clear code 256 and end code 257, and grow up to
the width encoded in the record type.
