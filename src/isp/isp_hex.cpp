#include "stcisp/isp.hpp"
#include "utf8_path.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace stcisp {
namespace {

uint8_t hex_byte(const std::string& text, size_t offset) {
    if (offset + 2 > text.size()) throw std::invalid_argument("truncated Intel HEX byte");
    unsigned value = 0;
    for (size_t index = offset; index < offset + 2; ++index) {
        const char ch = text[index];
        value <<= 4;
        if (ch >= '0' && ch <= '9') value |= static_cast<unsigned>(ch - '0');
        else if (ch >= 'A' && ch <= 'F') value |= static_cast<unsigned>(ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f') value |= static_cast<unsigned>(ch - 'a' + 10);
        else throw std::invalid_argument("invalid Intel HEX digit");
    }
    return static_cast<uint8_t>(value);
}

std::vector<uint8_t> dense(const std::map<uint32_t, uint8_t>& bytes,
                           uint32_t base, uint32_t end, uint8_t fill_value, bool pad_to_block = true) {
    if (bytes.empty()) return {};
    uint32_t last = base;
    bool found = false;
    for (const auto& [address, value] : bytes) {
        (void)value;
        if (address >= base && address < end) {
            last = found ? std::max(last, address) : address;
            found = true;
        }
    }
    if (!found) return {};
    std::vector<uint8_t> result(last - base + 1, fill_value);
    for (const auto& [address, value] : bytes) {
        if (address >= base && address <= last) result[address - base] = value;
    }
    if (pad_to_block) result.resize((result.size() + 127) / 128 * 128, fill_value);
    return result;
}

}  // namespace

HexImage read_hex_file(const std::string& path) {
    std::ifstream input(utf8_path(path));
    if (!input) throw std::runtime_error("cannot open Intel HEX: " + path);
    HexImage image;
    uint32_t linear_base = 0;
    std::string line;
    size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (image.has_eof) throw std::invalid_argument("Intel HEX data after EOF at line " +
                                                       std::to_string(line_number));
        if (line.front() != ':') {
            throw std::invalid_argument("Intel HEX line " + std::to_string(line_number) +
                                        " does not start with ':'");
        }
        const size_t byte_count = hex_byte(line, 1);
        if (line.size() != 11 + byte_count * 2) {
            throw std::invalid_argument("invalid Intel HEX line length at line " +
                                        std::to_string(line_number));
        }
        uint8_t checksum = 0;
        for (size_t index = 1; index < line.size(); index += 2) checksum += hex_byte(line, index);
        if (checksum != 0) {
            throw std::invalid_argument("Intel HEX checksum failure at line " +
                                        std::to_string(line_number));
        }
        const uint16_t address = static_cast<uint16_t>(hex_byte(line, 3) << 8 | hex_byte(line, 5));
        const uint8_t type = hex_byte(line, 7);
        std::vector<uint8_t> data(byte_count);
        for (size_t index = 0; index < byte_count; ++index) data[index] = hex_byte(line, 9 + index * 2);
        if (type == 0x00) {
            if (static_cast<uint32_t>(address) + byte_count > 0x10000)
                throw std::invalid_argument("Intel HEX data record crosses a 64 KiB boundary");
            for (size_t index = 0; index < data.size(); ++index) {
                const uint32_t absolute = linear_base + address + static_cast<uint32_t>(index);
                auto [it, inserted] = image.bytes.emplace(absolute, data[index]);
                if (!inserted && it->second != data[index]) {
                    throw std::invalid_argument("conflicting Intel HEX data at 0x" +
                                                [&] { std::ostringstream out; out << std::hex << absolute; return out.str(); }());
                }
            }
        } else if (type == 0x01 && byte_count == 0 && address == 0) {
            image.has_eof = true;
        } else if (type == 0x02 && byte_count == 2 && address == 0) {
            linear_base = static_cast<uint32_t>(data[0] << 8 | data[1]) << 4;
        } else if (type == 0x04 && byte_count == 2 && address == 0) {
            linear_base = static_cast<uint32_t>(data[0] << 8 | data[1]) << 16;
        } else if ((type == 0x03 || type == 0x05) && byte_count == 4 && address == 0) {
            continue;
        } else {
            throw std::invalid_argument("unsupported Intel HEX record at line " +
                                        std::to_string(line_number));
        }
    }
    if (!image.has_eof) throw std::invalid_argument("Intel HEX has no EOF record");
    return image;
}

HexImage read_binary_file(const std::string& path, uint32_t max_size) {
    std::ifstream input(utf8_path(path), std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open binary image: " + path);
    const auto size = input.tellg();
    if (size <= 0 || size > max_size)
        throw std::invalid_argument("binary image is empty or exceeds the supported capacity");
    input.seekg(0);
    std::vector<char> bytes(static_cast<size_t>(size));
    if (!input.read(bytes.data(), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("cannot read binary image: " + path);
    HexImage image;
    for (uint32_t address = 0; address < bytes.size(); ++address)
        image.bytes.emplace_hint(image.bytes.end(), address, static_cast<uint8_t>(bytes[address]));
    return image;
}

Stc32Image split_stc32_image(const HexImage& image, uint32_t eeprom_end,
                             uint8_t fill_value) {
    constexpr uint32_t eeprom_base = 0xFC2800;
    constexpr uint32_t code_base = 0xFF0000;
    constexpr uint32_t code_end = 0x1000000;
    for (const auto& [address, value] : image.bytes) {
        (void)value;
        const bool in_eeprom = address >= eeprom_base && address < eeprom_end;
        const bool in_code = address >= code_base && address < code_end;
        if (!in_eeprom && !in_code) {
            std::ostringstream message;
            message << "HEX address 0x" << std::hex << std::uppercase << address
                    << " is outside FC2800..EEPROM and FF0000..FFFFFF";
            throw std::invalid_argument(message.str());
        }
    }
    return {dense(image.bytes, code_base, code_end, fill_value),
            dense(image.bytes, eeprom_base, eeprom_end, fill_value)};
}

Stc8Image split_stc8_image(const HexImage& image, uint32_t code_size,
                           uint8_t fill_value, bool pad_to_block) {
    if (code_size > 0x10000) throw std::invalid_argument("8-bit code size is outside 16-bit address space");
    std::map<uint32_t, uint8_t> code;
    std::map<uint32_t, uint8_t> eeprom;
    for (const auto& [address, value] : image.bytes) {
        if (address < code_size) code[address] = value;
        else if (address < 0x10000) eeprom[address] = value;
        else throw std::invalid_argument("8-bit HEX address is outside 0000..FFFF");
    }
    return {dense(code, 0, code_size, fill_value, pad_to_block),
            dense(eeprom, code_size, 0x10000, fill_value, pad_to_block)};
}

}  // namespace stcisp
