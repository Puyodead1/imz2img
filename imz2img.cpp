#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

class ImzError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

static uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

static uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static void read_exact(std::istream& in, void* destination, size_t size,
                       const std::string& description) {
    in.read(static_cast<char*>(destination), static_cast<std::streamsize>(size));
    if (static_cast<size_t>(in.gcount()) != size)
        throw ImzError("short read for " + description);
}

static uint16_t read_u16(std::istream& in, const std::string& description) {
    uint8_t bytes[2];
    read_exact(in, bytes, sizeof(bytes), description);
    return le16(bytes);
}

static uint32_t read_u32(std::istream& in, const std::string& description) {
    uint8_t bytes[4];
    read_exact(in, bytes, sizeof(bytes), description);
    return le32(bytes);
}

static uint32_t crc32(const uint8_t* data, size_t size) {
    static const auto table = [] {
        std::array<uint32_t, 256> values{};
        for (uint32_t n = 0; n < 256; ++n) {
            uint32_t value = n;
            for (int bit = 0; bit < 8; ++bit)
                value = (value & 1) ? (value >> 1) ^ 0xEDB88320u : value >> 1;
            values[n] = value;
        }
        return values;
    }();
    uint32_t value = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i)
        value = table[(value ^ data[i]) & 0xFF] ^ (value >> 8);
    return value ^ 0xFFFFFFFFu;
}

static bool has_crc(uint16_t type) {
    return type == 0x0010 || type == 0x001C || type == 0xEEFC ||
           (type & 0xFF00) == 0xFC00;
}

static bool is_rle(uint16_t type) {
    return (type & 0xFF00) == 0xFC00 || (type & 0xFF00) == 0xFF00;
}

static std::string human_size(uint64_t bytes) {
    static constexpr const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream text;
    if (unit == 0) text << bytes;
    else text << std::fixed << std::setprecision(value < 10.0 ? 2 : 1) << value;
    return text.str() + ' ' + units[unit];
}

class BitReader {
public:
    explicit BitReader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

    std::optional<uint16_t> code(unsigned width) {
        // This deliberately matches DFSee's >24-bit prefetch and EOF behavior.
        while (valid_bits_ <= 24) {
            if (position_ == bytes_.size()) return std::nullopt;
            buffer_ |= static_cast<uint32_t>(bytes_[position_++]) << (24 - valid_bits_);
            valid_bits_ += 8;
        }
        const auto result = static_cast<uint16_t>(buffer_ >> (32 - width));
        valid_bits_ -= width;
        buffer_ <<= width;
        return result;
    }

private:
    const std::vector<uint8_t>& bytes_;
    size_t position_ = 0;
    uint32_t buffer_ = 0;
    unsigned valid_bits_ = 0;
};

static std::vector<uint8_t> lzw_decode(const std::vector<uint8_t>& input,
                                       unsigned max_bits, size_t output_limit) {
    if (max_bits < 9 || max_bits > 15)
        throw ImzError("unsupported LZW width " + std::to_string(max_bits));

    BitReader reader(input);
    std::vector<uint16_t> prefix(size_t{1} << max_bits);
    std::vector<uint8_t> suffix(size_t{1} << max_bits);
    std::vector<uint8_t> stack;
    std::vector<uint8_t> output;
    stack.reserve(16000);
    output.reserve(output_limit);
    unsigned width = 9;
    uint16_t max_code = 511;
    uint16_t next_code = 258;
    std::optional<uint16_t> old_code;
    uint8_t first_char = 0;

    auto emit = [&](uint8_t byte) {
        // DFSee uses a bounded callback; valid padding may decode past this.
        if (output.size() < output_limit) output.push_back(byte);
    };

    for (;;) {
        auto maybe_code = reader.code(width);
        if (!maybe_code || *maybe_code == 257) break;
        uint16_t code = *maybe_code;
        if (!old_code) {
            if (code == 256) {
                width = 9; max_code = 511; next_code = 258;
                continue;
            }
            if (code > 255) throw ImzError("invalid first LZW code");
            emit(static_cast<uint8_t>(code));
            old_code = code;
            first_char = static_cast<uint8_t>(code);
            continue;
        }
        if (code == 256) {
            width = 9; max_code = 511; next_code = 258; old_code.reset();
            continue;
        }

        const uint16_t input_code = code;
        stack.clear();
        if (code >= next_code) {
            if (code != next_code)
                throw ImzError("LZW code exceeds current table limit");
            stack.push_back(first_char);
            code = *old_code;
        }
        while (code > 255) {
            if (code >= next_code) throw ImzError("invalid LZW prefix");
            if (stack.size() >= 16000) throw ImzError("LZW decode stack overflow");
            stack.push_back(suffix[code]);
            code = prefix[code];
        }
        first_char = static_cast<uint8_t>(code);
        stack.push_back(first_char);
        for (auto it = stack.rbegin(); it != stack.rend(); ++it) emit(*it);

        if (next_code <= max_code) {
            prefix[next_code] = *old_code;
            suffix[next_code] = first_char;
            ++next_code;
            if (next_code == max_code && width < max_bits) {
                ++width;
                max_code = static_cast<uint16_t>((1u << width) - 1);
            }
        }
        old_code = input_code;
    }
    if (output.size() != output_limit)
        throw ImzError("LZW output is " + std::to_string(output.size()) +
                       " bytes, expected " + std::to_string(output_limit));
    return output;
}

struct Header {
    uint32_t file_number;
    uint32_t start_sector;
    uint32_t sectors;
    uint32_t buffer_size;
    uint32_t total_sectors;
    uint32_t sector_size;
};

static std::optional<Header> read_header(std::istream& in, const fs::path& path) {
    std::array<uint8_t, 16> prefix{};
    read_exact(in, prefix.data(), prefix.size(), "format signature in " + path.string());
    in.seekg(0);
    if (!in) throw ImzError("cannot rewind " + path.string());
    if (std::memcmp(prefix.data(), "Tpack#", 6) == 0) return std::nullopt;

    std::array<uint8_t, 512> bytes{};
    read_exact(in, bytes.data(), bytes.size(), "header in " + path.string());
    constexpr char magic[] = "DFSeeImageFile #";
    if (std::memcmp(bytes.data(), magic, sizeof(magic) - 1) != 0)
        throw ImzError(path.string() + " is not a DFSee IMZ file");
    const uint8_t* fields = bytes.data() + 0x1C0;
    Header header{le32(fields), le32(fields + 4), le32(fields + 12),
                  le32(fields + 16), le32(fields + 24), le32(fields + 28)};
    if (!header.sector_size) header.sector_size = 512;
    return header;
}

static std::vector<fs::path> multipart_paths(const fs::path& first) {
    const std::string name = first.filename().string();

    // A numbered basename can still use DFSee's classic extension sequence,
    // for example part1.imz, part1.002.  Prefer that unambiguous same-stem
    // continuation over treating part2.imz as the next file.
    fs::path classic_second = first;
    classic_second.replace_extension(".002");
    if (first.extension() == ".imz" && fs::exists(classic_second)) {
        std::vector<fs::path> result{first};
        for (unsigned number = 2;; ++number) {
            std::ostringstream extension;
            extension << '.' << std::setw(3) << std::setfill('0') << number;
            fs::path candidate = first;
            candidate.replace_extension(extension.str());
            if (!fs::exists(candidate)) break;
            result.push_back(candidate);
        }
        return result;
    }

    struct NumberedName { std::string prefix, suffix; unsigned number; };
    const auto parse_numbered = [](const std::string& value) -> std::optional<NumberedName> {
        const size_t dot = value.rfind('.');
        if (dot == std::string::npos || dot == 0) return std::nullopt;
        size_t digit_start = dot;
        while (digit_start && value[digit_start - 1] >= '0' &&
               value[digit_start - 1] <= '9')
            --digit_start;
        if (digit_start == dot) return std::nullopt;
        return NumberedName{value.substr(0, digit_start), value.substr(dot),
                            static_cast<unsigned>(std::stoul(
                                value.substr(digit_start, dot - digit_start)))};
    };
    if (const auto parsed = parse_numbered(name)) {
        const std::string& prefix = parsed->prefix;
        const unsigned start = parsed->number;
        const std::string& suffix = parsed->suffix;
        std::vector<std::pair<unsigned, fs::path>> found;
        for (const auto& entry : fs::directory_iterator(first.parent_path().empty()
                                                        ? fs::path(".") : first.parent_path())) {
            const std::string item = entry.path().filename().string();
            if (const auto candidate = parse_numbered(item);
                candidate && candidate->prefix == prefix && candidate->suffix == suffix) {
                if (candidate->number >= start)
                    found.emplace_back(candidate->number, entry.path());
            }
        }
        std::sort(found.begin(), found.end());
        std::vector<fs::path> result;
        unsigned expected = start;
        for (const auto& [number, path] : found) {
            if (number != expected) break;
            result.push_back(path);
            ++expected;
        }
        return result;
    }

    std::vector<fs::path> result{first};
    for (unsigned number = 2;; ++number) {
        std::ostringstream extension;
        extension << '.' << std::setw(3) << std::setfill('0') << number;
        fs::path candidate = first;
        candidate.replace_extension(extension.str());
        if (!fs::exists(candidate)) break;
        result.push_back(candidate);
    }
    return result;
}

static void convert(const std::vector<fs::path>& parts, const fs::path& output_path,
                    bool verify_crc, bool verbose) {
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) throw ImzError("cannot open output " + output_path.string());

    uint64_t total_written = 0, records = 0;
    std::optional<uint64_t> expected_total;
    uint16_t block_size = 0;
    for (size_t part_index = 0; part_index < parts.size(); ++part_index) {
        const fs::path& path = parts[part_index];
        std::ifstream input(path, std::ios::binary);
        if (!input) throw ImzError("cannot open input " + path.string());
        const auto header = read_header(input, path);
        if (header) {
            if (!expected_total) {
                const uint32_t logical_sectors =
                    header->total_sectors ? header->total_sectors : header->sectors;
                if (logical_sectors)
                    expected_total = static_cast<uint64_t>(logical_sectors) *
                                     header->sector_size;
            }
        }

        char signature[6];
        read_exact(input, signature, sizeof(signature), "compression signature");
        if (std::memcmp(signature, "Tpack#", 6) != 0)
            throw ImzError("bad compression signature in " + path.string());
        const uint16_t current_block_size = read_u16(input, "block size");
        if (!current_block_size) throw ImzError("zero block size");
        if (!block_size) block_size = current_block_size;
        else if (block_size != current_block_size)
            throw ImzError("block size changed between parts");
        if (verbose)
            std::cerr << path.filename().string() << ": block size "
                      << human_size(block_size) << '\n';

        bool next_marker = false;
        while (!expected_total || total_written < *expected_total) {
            const auto record_offset = static_cast<uint64_t>(input.tellg());
            uint8_t type_bytes[2];
            input.read(reinterpret_cast<char*>(type_bytes), 2);
            if (input.gcount() == 0) break;
            if (input.gcount() != 2) throw ImzError("truncated record type");
            const uint16_t type = le16(type_bytes);
            const uint16_t payload_size = read_u16(input, "payload size");
            std::optional<uint32_t> expected_crc;
            if (has_crc(type)) expected_crc = read_u32(input, "CRC32");
            if (type == 0xEFEF) { next_marker = true; break; }
            if (payload_size > block_size) {
                std::ostringstream message;
                message << "payload " << payload_size << " exceeds block size "
                        << block_size << " at record " << (records + 1)
                        << ", output 0x" << std::hex << total_written
                        << ", input 0x" << record_offset
                        << ", type 0x" << type;
                throw ImzError(message.str());
            }

            std::vector<uint8_t> chunk;
            size_t decoded_size = block_size;
            if (expected_total)
                decoded_size = static_cast<size_t>(std::min<uint64_t>(
                    block_size, *expected_total - total_written));
            if (type == 0xEEEE || type == 0xEEFC) {
                chunk.assign(payload_size, 0);
            } else if (is_rle(type)) {
                chunk.assign(payload_size, static_cast<uint8_t>(type));
            } else {
                std::vector<uint8_t> payload(payload_size);
                read_exact(input, payload.data(), payload.size(), "record payload");
                if (type == 0 || type == 0x10 || type == block_size)
                    chunk = std::move(payload);
                else if (type == 0x0C || type == 0x1C)
                    chunk = lzw_decode(payload, type & 0x0F, decoded_size);
                else {
                    std::ostringstream message;
                    message << "unknown record type 0x" << std::hex << type;
                    throw ImzError(message.str());
                }
            }

            if (expected_crc && *expected_crc != 0xDEAFFACE && verify_crc) {
                const uint32_t actual = crc32(chunk.data(), chunk.size());
                if (actual != *expected_crc) {
                    std::ostringstream message;
                    message << "CRC mismatch at output 0x" << std::hex << total_written
                            << ": got " << std::setw(8) << std::setfill('0') << actual
                            << ", expected " << std::setw(8) << *expected_crc;
                    throw ImzError(message.str());
                }
            }
            size_t to_write = chunk.size();
            if (expected_total)
                to_write = static_cast<size_t>(std::min<uint64_t>(
                    chunk.size(), *expected_total - total_written));
            output.write(reinterpret_cast<const char*>(chunk.data()),
                         static_cast<std::streamsize>(to_write));
            if (!output) throw ImzError("write failed for " + output_path.string());
            total_written += to_write;
            ++records;
            if (verbose && records % 10000 == 0) {
                std::cerr << "Processed " << human_size(total_written);
                if (expected_total) std::cerr << " / " << human_size(*expected_total);
                std::cerr << '\n';
            }
        }
        if (expected_total && total_written >= *expected_total) break;
        if (!expected_total && !next_marker) break;
        if (part_index + 1 == parts.size()) {
            if (expected_total)
                throw ImzError("image ended at " + std::to_string(total_written) + " of " +
                               std::to_string(*expected_total) + " bytes; next part missing");
            if (next_marker) throw ImzError("next-part marker found but next part is missing");
        }
        if (verbose)
            std::cerr << "Continuing with "
                      << parts[part_index + 1].filename().string() << '\n';
    }
    if (expected_total && total_written != *expected_total)
        throw ImzError("output size does not match image header");
    std::cout << "Converted " << records << " records, " << human_size(total_written)
              << " -> " << output_path.filename().string() << '\n';
}

static void usage(const char* program) {
    std::cerr << "Usage: " << program
              << " [--no-crc] [-v|--verbose] FIRST_PART.imz [OUTPUT.img]\n";
}

int main(int argc, char** argv) {
    bool verify_crc = true, verbose = false;
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--no-crc") verify_crc = false;
        else if (argument == "-v" || argument == "--verbose") verbose = true;
        else if (argument == "-h" || argument == "--help") { usage(argv[0]); return 0; }
        else if (!argument.empty() && argument[0] == '-') {
            std::cerr << "Unknown option: " << argument << '\n'; usage(argv[0]); return 2;
        } else positional.push_back(argument);
    }
    if (positional.size() < 1 || positional.size() > 2) { usage(argv[0]); return 2; }
    try {
        const fs::path input = positional[0];
        if (!fs::is_regular_file(input)) throw ImzError("input not found: " + input.string());
        fs::path output = positional.size() == 2 ? fs::path(positional[1]) : input;
        if (positional.size() == 1) output.replace_extension(".img");
        convert(multipart_paths(input), output, verify_crc, verbose);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "imz2img: error: " << error.what() << '\n';
        return 1;
    }
}
