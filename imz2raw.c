/*
 * imz2raw - standalone decompressor for DFSee ".IMZ" compressed disk images.
 *
 * Reverse engineered from the dfsee Linux binary (dfsWriteImageFile_ /
 * dfsLzwUncompress_ / dfsLzwInputCode_ / dfsUlInitialize_) and cross-checked
 * byte-for-byte against real .IMZ files produced by dfsee's own RAW2IMZ
 * command (both single-block and multi-block images).
 *
 * ---------------------------------------------------------------------------
 * File layout
 * ---------------------------------------------------------------------------
 * Fixed 512-byte header, present only when the file starts with the 16-byte
 * magic "DFSeeImageFile #" (otherwise the file is a plain raw image and is
 * copied through as-is):
 *
 *   offset 0x000  16 bytes   magic "DFSeeImageFile #"
 *   offset 0x010  432 bytes  human readable description, 0x1A-terminated,
 *                            zero padded (offsets/lengths below are fixed
 *                            regardless of how long the text actually is)
 *   offset 0x1C0  8 x uint32 LE fields:
 *                    [0] file number (for multi-volume sets)
 *                    [1] start LSN
 *                    [2] flags / buffer-count related (unused here)
 *                    [3] total sector count
 *                    [4] chunk size in bytes (sectorsPerBuffer * sectorSize)
 *                    [5] unused / reserved, observed 0
 *                    [6] total sector count (duplicate of [3])
 *                    [7] sector size in bytes
 *   offset 0x1E0  32 bytes   zero padding
 *   offset 0x200  compression sub-header (optional):
 *                    6 bytes   "Tpack#"
 *                    uint16 LE block/chunk size in bytes (matches field [4])
 *                  -> if the 6 bytes do NOT match "Tpack#", the file is
 *                     uncompressed raw sector data starting right after the
 *                     main header; the 8 bytes just read are already part of
 *                     that raw payload and must be written out too.
 *
 * Per-block stream (only when the Tpack# sub-header was found), repeated
 * until the declared number of sectors has been produced or a NEXTFILE
 * marker is hit:
 *
 *   uint16 LE type
 *   uint16 LE length
 *   uint32 LE crc32     -- present only if:
 *                            type == 0x0010, type == 0x001C, type == 0xEEFC,
 *                            or (type & 0xFF00) == 0xFC00
 *   payload             -- present only if type < 0xEEEE, `length` bytes
 *
 *   dispatch on type:
 *     0x0000 / 0x0010        -> literal payload bytes, verbatim
 *     (type & 0xFF00) in     -> RLE: `length` bytes of value (type & 0xFF);
 *       {0xFF00, 0xFC00}        no payload on disk - the fill byte lives in
 *                                the type field itself
 *     0xEEEE / 0xEEFC         -> "unused SMART area": `length` zero bytes,
 *                                no payload on disk
 *     0xEFEF                  -> NEXTFILE marker: end of this volume of a
 *                                split image set. dfsee's restore driver
 *                                (dfsWriteImageTo_) handles this by
 *                                stripping the extension off the current
 *                                volume's path and appending ".NNN"
 *                                (sprintf "%3.3lu", zero padded, starting
 *                                at 002) to get the next volume's filename,
 *                                then reopening and re-probing it exactly
 *                                like the first file (magic + optional
 *                                Tpack# sub-header). We do the same; if the
 *                                next volume can't be opened, decoding
 *                                stops there.
 *     anything else            -> LZW-compressed payload,
 *                                 method = type & 0xEF (observed: always
 *                                 0x0C -> maxbits 12)
 *
 * ---------------------------------------------------------------------------
 * LZW variant
 * ---------------------------------------------------------------------------
 * Adaptive-width LZW, MSB-first bit packing (not the classic LSB-first
 * `ncompress` packing). Starts at 9 bits/code, clear code 256, EOF code 257,
 * first free code 258. Every compressed block is its own independent stream
 * (the code table is reset at the start of each block, matching
 * dfsUlInitialize_ being called fresh by dfsLzwUncompress_ every time).
 * `method` (low nibble = maxbits, observed 0x0C = 12) selects the maximum
 * code width and the code-table capacity:
 *
 *     10 -> maxbits 10, capacity 1193      11 -> maxbits 11, capacity 2399
 *     12 -> maxbits 12, capacity 4799      13 -> maxbits 13, capacity 9587
 *     other -> maxbits taken as-is, capacity 19183
 *
 * Table growth: after adding a new entry at `next_code` and incrementing it,
 * if next_code == maxcode (NOT maxcode+1 - this is a real off-by-one quirk
 * of dfsee's implementation, confirmed against dfsLzwUncompress_'s
 * disassembly and empirically) and nbits < maxbits, nbits is incremented and
 * maxcode = (1 << nbits) - 1 is recomputed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define IMZ_MAGIC "DFSeeImageFile #"
#define IMZ_MAGIC_LEN 16
#define TPACK_MAGIC "Tpack#"
#define TPACK_MAGIC_LEN 6
#define HEADER_SIZE 0x200
#define HEADER_FIELDS_OFFSET 0x1C0

#define CLEAR_CODE 256
#define EOF_CODE   257
#define FIRST_FREE_CODE 258

static int table_capacity(int maxbits) {
    switch (maxbits) {
        case 10: return 1193;
        case 11: return 2399;
        case 12: return 4799;
        case 13: return 9587;
        default: return 19183;
    }
}

/* ---------------------------------------------------------------------- */
/* CRC32 (zlib/PKZIP polynomial), self-contained, no external dependency. */
/* ---------------------------------------------------------------------- */

static uint32_t crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init(void) {
    uint32_t c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = (uint32_t)n;
        for (k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[n] = c;
    }
    crc32_table_ready = 1;
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    size_t i;
    if (!crc32_table_ready) crc32_init();
    for (i = 0; i < len; i++)
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---------------------------------------------------------------------- */
/* LZW block decoder                                                      */
/* ---------------------------------------------------------------------- */

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;

    int maxbits;
    int capacity;

    int nbits;
    int maxcode;
    int next_code;

    uint32_t accum;
    int curbits;

    uint16_t *prefix; /* [capacity] */
    uint8_t  *suffix;  /* [capacity] */
} lzw_dec_t;

static int lzw_get_byte(lzw_dec_t *d) {
    if (d->pos >= d->len) return -1;
    return d->data[d->pos++];
}

static void lzw_reset_table(lzw_dec_t *d) {
    d->nbits = 9;
    d->maxcode = (1 << d->nbits) - 1;
    d->next_code = FIRST_FREE_CODE;
    /* prefix/suffix contents for codes < next_code are never read before
     * being written, so no need to clear them on reset. */
}

static int lzw_dec_init(lzw_dec_t *d, const uint8_t *data, size_t len, int maxbits) {
    d->data = data;
    d->len = len;
    d->pos = 0;
    d->maxbits = maxbits;
    d->capacity = table_capacity(maxbits);
    d->accum = 0;
    d->curbits = 0;
    d->prefix = (uint16_t *)malloc(sizeof(uint16_t) * (size_t)d->capacity);
    d->suffix = (uint8_t *)malloc(sizeof(uint8_t) * (size_t)d->capacity);
    if (!d->prefix || !d->suffix) return -1;
    lzw_reset_table(d);
    return 0;
}

static void lzw_dec_free(lzw_dec_t *d) {
    free(d->prefix);
    free(d->suffix);
    d->prefix = NULL;
    d->suffix = NULL;
}

/* MSB-first bit unpacking out of a 32-bit, left-justified accumulator -
 * mirrors dfsLzwInputCode_ exactly, including its use of a plain 32-bit
 * wraparound shift. */
static int lzw_get_code(lzw_dec_t *d) {
    int i = 0;
    int shift, code;

    while (d->curbits <= 0x18) {
        i = lzw_get_byte(d);
        if (i == -1) break;
        shift = 24 - d->curbits;
        d->curbits += 8;
        d->accum |= ((uint32_t)i << shift);
    }
    if (i == -1) return EOF_CODE;

    shift = 32 - d->nbits;
    code = (int)(d->accum >> shift);
    d->curbits -= d->nbits;
    d->accum <<= d->nbits;
    return code;
}

/* Walks the prefix chain for `code`, writing the decoded bytes into `out`
 * in reverse (last-added byte first). Returns the number of bytes written,
 * or -1 on a corrupt/out-of-range code. */
static int lzw_decode_string(lzw_dec_t *d, int code, uint8_t *out, int out_cap) {
    int n = 0;
    /* build in reverse into a temp area at the tail of `out`, then shift */
    uint8_t stack[16000];
    while (code > 0xFF) {
        if (code >= d->next_code || n >= (int)sizeof(stack)) return -1;
        stack[n++] = d->suffix[code];
        code = d->prefix[code];
    }
    if (n >= (int)sizeof(stack)) return -1;
    stack[n++] = (uint8_t)code;

    if (n > out_cap) return -1;
    for (int i = 0; i < n; i++)
        out[i] = stack[n - 1 - i];
    return n;
}

/* Decodes one whole LZW block into a growable output buffer.
 * *out_data / *out_len receive a malloc'd buffer the caller must free. */
static int lzw_decode_block(const uint8_t *payload, size_t payload_len,
                             int method, uint8_t **out_data, size_t *out_len) {
    lzw_dec_t d;
    int maxbits = method & 0xF;
    int oldcode = -1;
    int oldchar = 0;
    int first = 1;
    int rc = 0;

    size_t cap = 65536;
    size_t len = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return -1;

    if (lzw_dec_init(&d, payload, payload_len, maxbits) != 0) {
        free(buf);
        return -1;
    }

    for (;;) {
        int code = lzw_get_code(&d);
        if (code == EOF_CODE) break;
        if (code == CLEAR_CODE) {
            lzw_reset_table(&d);
            first = 1;
            continue;
        }

        if (first) {
            if (code > 0xFF) { rc = -1; break; }
            if (len + 1 > cap) { cap *= 2; buf = (uint8_t *)realloc(buf, cap); if (!buf) { rc = -1; break; } }
            buf[len++] = (uint8_t)code;
            oldcode = code;
            oldchar = code;
            first = 0;
            continue;
        }

        {
            uint8_t entry[16000];
            int entry_len;

            if (code >= d.next_code) {
                entry_len = lzw_decode_string(&d, oldcode, entry, (int)sizeof(entry));
                if (entry_len < 0 || entry_len + 1 > (int)sizeof(entry)) { rc = -1; break; }
                entry[entry_len++] = (uint8_t)oldchar;
            } else {
                entry_len = lzw_decode_string(&d, code, entry, (int)sizeof(entry));
                if (entry_len < 0) { rc = -1; break; }
            }

            if (len + (size_t)entry_len > cap) {
                while (len + (size_t)entry_len > cap) cap *= 2;
                buf = (uint8_t *)realloc(buf, cap);
                if (!buf) { rc = -1; break; }
            }
            memcpy(buf + len, entry, (size_t)entry_len);
            len += (size_t)entry_len;
            oldchar = entry[0];

            if (d.next_code <= d.maxcode && d.next_code < d.capacity) {
                d.prefix[d.next_code] = (uint16_t)oldcode;
                d.suffix[d.next_code] = (uint8_t)oldchar;
                d.next_code++;
                if (d.next_code == d.maxcode && d.nbits < d.maxbits) {
                    d.nbits++;
                    d.maxcode = (1 << d.nbits) - 1;
                }
            }
            oldcode = code;
        }
    }

    lzw_dec_free(&d);
    if (rc != 0) {
        free(buf);
        return -1;
    }
    *out_data = buf;
    *out_len = len;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* IMZ container parsing                                                  */
/* ---------------------------------------------------------------------- */

static int crc_present(uint16_t type) {
    if (type == 0x0010 || type == 0x001C || type == 0xEEFC) return 1;
    return (type & 0xFF00) == 0xFC00;
}

static uint16_t rd_u16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---------------------------------------------------------------------- */
/* Multi-volume support                                                   */
/* ---------------------------------------------------------------------- */

/*
 * Confirmed from dfsWriteImageTo_'s restore-driver loop: when the block
 * whose type is decoded as 0xEFEF (NEXTFILE) is hit, dfsee strips the
 * extension off the *current* image path (TxStripExtension_) and appends
 * ".NNN" (sprintf "%3.3lu", zero padded, starting at 002 for the second
 * volume) to get the next volume's filename, e.g. "image.imz" -> "image.002"
 * -> "image.003" ... Each subsequent volume is opened independently and is
 * re-probed the same way the first file was: for the 16-byte
 * "DFSeeImageFile #" magic and, if present, the 512-byte header followed by
 * an optional "Tpack#" compression sub-header. Only an explicit NEXTFILE
 * marker triggers this; a plain truncated/EOF file does not.
 */

typedef struct {
    FILE *f;
    char path[4096];
    int part;
} imz_stream_t;

/* Mirrors TxStripExtension_: drop everything from the last '.' found after
 * the last path separator, then append ".NNN". */
static int next_volume_path(const char *cur_path, int part, char *out, size_t out_sz) {
    char tmp[4096];
    size_t n = strlen(cur_path);
    if (n >= sizeof(tmp)) return 0;
    memcpy(tmp, cur_path, n + 1);

    char *slash = strrchr(tmp, '/');
    char *bslash = strrchr(tmp, '\\');
    char *last_sep = slash;
    if (bslash && (!last_sep || bslash > last_sep)) last_sep = bslash;
    char *dot = strrchr(last_sep ? last_sep : tmp, '.');
    if (dot) *dot = 0;

    int written = snprintf(out, out_sz, "%s.%03d", tmp, part);
    return written > 0 && (size_t)written < out_sz;
}

/* Opens the next volume and, if it carries its own header, consumes it
 * (same probing convert() does for the first file) so the caller's next
 * read lands right at the start of that volume's block stream. Returns 1
 * on success, 0 if there is no further volume to open. */
static int imz_stream_advance(imz_stream_t *s, int quiet) {
    char next_path[4096];
    if (!next_volume_path(s->path, s->part + 1, next_path, sizeof(next_path)))
        return 0;

    FILE *nf = fopen(next_path, "rb");
    if (!nf) {
        if (!quiet)
            fprintf(stderr, "next volume '%s' not found, stopping "
                            "(multi-volume set incomplete or this was the last one)\n",
                    next_path);
        return 0;
    }
    if (!quiet)
        fprintf(stderr, "Continuing with next volume: %s\n", next_path);

    fclose(s->f);
    s->f = nf;
    s->part += 1;
    strncpy(s->path, next_path, sizeof(s->path) - 1);
    s->path[sizeof(s->path) - 1] = 0;

    uint8_t head[HEADER_SIZE];
    size_t head_len = fread(head, 1, HEADER_SIZE, s->f);
    if (head_len >= IMZ_MAGIC_LEN && memcmp(head, IMZ_MAGIC, IMZ_MAGIC_LEN) == 0) {
        uint8_t tpack[8];
        size_t tpack_len = fread(tpack, 1, 8, s->f);
        if (!(tpack_len == 8 && memcmp(tpack, TPACK_MAGIC, TPACK_MAGIC_LEN) == 0)) {
            /* No compression sub-header on this volume: not expected for a
             * compressed multi-volume set, but rewind so those bytes are
             * reprocessed as block-stream data rather than dropped. */
            fseek(s->f, (long)head_len, SEEK_SET);
        }
    } else {
        /* No per-volume magic: the whole file is a raw block-stream
         * continuation starting at offset 0. */
        fseek(s->f, 0, SEEK_SET);
    }
    return 1;
}

static int decode_block_stream(imz_stream_t *s, FILE *fout, uint64_t total_bytes,
                                int verify_crc, int quiet) {
    uint64_t written = 0;
    long block_no = 0;

    while (total_bytes == 0 || written < total_bytes) {
        uint8_t hdr[4];
        uint16_t type_field, length;
        uint32_t crc = 0;
        int have_crc = 0;

        if (fread(hdr, 1, 4, s->f) != 4) break;
        type_field = rd_u16le(hdr);
        length = rd_u16le(hdr + 2);
        block_no++;

        if (crc_present(type_field)) {
            uint8_t cb[4];
            if (fread(cb, 1, 4, s->f) != 4) {
                fprintf(stderr, "error: truncated file: missing crc32 field\n");
                return -1;
            }
            crc = rd_u32le(cb);
            have_crc = 1;
        }

        uint8_t *data = NULL;
        size_t data_len = 0;
        int free_data = 0;

        if (type_field >= 0xEEEE) {
            if (type_field == 0xEEEE || type_field == 0xEEFC) {
                data = (uint8_t *)calloc(1, length ? length : 1);
                data_len = length;
                free_data = 1;
            } else if (type_field == 0xEFEF) {
                if (!quiet)
                    fprintf(stderr, "block %ld: NEXTFILE marker\n", block_no);
                if (!imz_stream_advance(s, quiet))
                    break;
                continue;
            } else if ((type_field & 0xFF00) == 0xFF00 || (type_field & 0xFF00) == 0xFC00) {
                data = (uint8_t *)malloc(length ? length : 1);
                memset(data, type_field & 0xFF, length);
                data_len = length;
                free_data = 1;
            } else {
                fprintf(stderr, "error: unknown marker type 0x%04x\n", type_field);
                return -1;
            }
        } else {
            uint8_t *payload = (uint8_t *)malloc(length ? length : 1);
            if (fread(payload, 1, length, s->f) != length) {
                fprintf(stderr, "error: truncated file: short block payload\n");
                free(payload);
                return -1;
            }
            if (type_field == 0x0000 || type_field == 0x0010) {
                data = payload;
                data_len = length;
                free_data = 1;
            } else {
                int method = type_field & 0xEF;
                if (lzw_decode_block(payload, length, method, &data, &data_len) != 0) {
                    fprintf(stderr, "error: LZW decode failed in block %ld (type 0x%04x)\n",
                            block_no, type_field);
                    free(payload);
                    return -1;
                }
                free(payload);
                free_data = 1;
            }
        }

        if (have_crc && verify_crc) {
            uint32_t actual = crc32_buf(data, data_len);
            if (actual != crc && !quiet) {
                fprintf(stderr, "block %ld: CRC32 mismatch (stored 0x%08x, computed 0x%08x)\n",
                        block_no, crc, actual);
            }
        }

        fwrite(data, 1, data_len, fout);
        written += data_len;
        if (free_data) free(data);
    }

    if (total_bytes != 0 && written < total_bytes && !quiet) {
        fprintf(stderr, "warning: only %llu of %llu expected bytes were produced "
                        "(truncated image, or a later volume in the set is missing)\n",
                (unsigned long long)written, (unsigned long long)total_bytes);
    }
    return 0;
}

static int convert(const char *in_path, const char *out_path, int verify_crc, int quiet) {
    imz_stream_t s;
    s.f = fopen(in_path, "rb");
    if (!s.f) { fprintf(stderr, "error: cannot open '%s'\n", in_path); return -1; }
    strncpy(s.path, in_path, sizeof(s.path) - 1);
    s.path[sizeof(s.path) - 1] = 0;
    s.part = 1;

    FILE *fout = fopen(out_path, "wb");
    if (!fout) { fprintf(stderr, "error: cannot create '%s'\n", out_path); fclose(s.f); return -1; }

    uint8_t head[HEADER_SIZE];
    size_t head_len = fread(head, 1, HEADER_SIZE, s.f);
    int rc = 0;

    if (head_len >= IMZ_MAGIC_LEN && memcmp(head, IMZ_MAGIC, IMZ_MAGIC_LEN) == 0) {
        const uint8_t *f = head + HEADER_FIELDS_OFFSET;
        uint32_t file_no      = rd_u32le(f + 0);
        uint32_t start_lsn    = rd_u32le(f + 4);
        uint32_t total_sectors  = rd_u32le(f + 12);
        uint32_t chunk_size     = rd_u32le(f + 16);
        uint32_t total_sectors2 = rd_u32le(f + 24);
        uint32_t sector_size    = rd_u32le(f + 28);
        uint64_t total_bytes;

        if (total_sectors == 0) total_sectors = total_sectors2;
        total_bytes = (uint64_t)total_sectors * (uint64_t)sector_size;

        if (!quiet) {
            fprintf(stderr, "DFSee image header: file#%u start_lsn=0x%x sectors=%u "
                            "sector_size=%u chunk_size=%u\n",
                    file_no, start_lsn, total_sectors, sector_size, chunk_size);
        }

        uint8_t tpack[8];
        size_t tpack_len = fread(tpack, 1, 8, s.f);
        if (tpack_len == 8 && memcmp(tpack, TPACK_MAGIC, TPACK_MAGIC_LEN) == 0) {
            uint16_t block_size = rd_u16le(tpack + 6);
            if (!quiet)
                fprintf(stderr, "Compression header found, block size = %u bytes\n", block_size);
            rc = decode_block_stream(&s, fout, total_bytes, verify_crc, quiet);
        } else {
            if (!quiet) fprintf(stderr, "No compression header, copying raw sector data\n");
            uint64_t remaining = total_bytes;
            if (tpack_len > 0) {
                size_t take = tpack_len;
                if ((uint64_t)take > remaining) take = (size_t)remaining;
                fwrite(tpack, 1, take, fout);
                remaining -= take;
            }
            uint8_t buf[1 << 16];
            while (remaining > 0) {
                size_t want = sizeof(buf);
                if ((uint64_t)want > remaining) want = (size_t)remaining;
                size_t got = fread(buf, 1, want, s.f);
                if (got == 0) break;
                fwrite(buf, 1, got, fout);
                remaining -= got;
            }
        }
    } else {
        if (!quiet) fprintf(stderr, "No DFSeeImageFile# magic found, copying input verbatim\n");
        fwrite(head, 1, head_len, fout);
        uint8_t buf[1 << 16];
        size_t got;
        while ((got = fread(buf, 1, sizeof(buf), s.f)) > 0)
            fwrite(buf, 1, got, fout);
    }

    fclose(s.f);
    fclose(fout);
    if (rc == 0 && !quiet) fprintf(stderr, "Wrote %s\n", out_path);
    return rc;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <input.imz> <output.img>\n"
        "  --no-crc   skip CRC32 verification of decompressed blocks\n"
        "  -q         suppress progress output\n",
        prog);
}

int main(int argc, char **argv) {
    const char *in_path = NULL, *out_path = NULL;
    int verify_crc = 1, quiet = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-crc") == 0) verify_crc = 0;
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) quiet = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else if (!in_path) in_path = argv[i];
        else if (!out_path) out_path = argv[i];
        else { usage(argv[0]); return 1; }
    }
    if (!in_path || !out_path) { usage(argv[0]); return 1; }

    return convert(in_path, out_path, verify_crc, quiet) == 0 ? 0 : 1;
}
