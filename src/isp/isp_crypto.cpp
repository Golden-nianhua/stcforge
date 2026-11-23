#include "stcisp/crypto.hpp"
#include "utf8_path.hpp"

#include <algorithm>
#include <bitset>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace stcisp {
namespace {

// AiCube 6.97C, inverse wrapper table at 5374C8 (used by 4E7FC0).
constexpr auto wrapper_inverse = [] {
    constexpr std::string_view hex =
        "535443b2d1ce3d7046a16a393b145cb60534c4696cb84be410d51a5aa0b1c1f8"
        "8f38e1284596b9bf4cf9647c1eaa21151c9006ddc749985979a4743f9b034a56"
        "180493b31df0f55debd2c9e8ac729aa52b7d2507622e4f9f88529da7898c19be"
        "6016f70ba6c5990c9ea2c0b4718aa8fb80767ae7e685ef6f130a0d295ff3bbfd"
        "d68d2c7720ff847e24e536580fea816861e397cc1109b7270195f13a9cdacb12"
        "63f4f24123d486aeb01b0e82c62d87db1755bc3102442a2fec91ab48ede9dcd7"
        "cf83c830420851374ee032fa4d00d36540f6af75479457d9df5b8eeebd3e67c"
        "ade229233add05e358b6da9b5786b263c666e73a3c2fed8fcba1f507f7bcde2c3";
    static_assert(hex.size() == 512);
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    UserKey table{};
    for (size_t i = 0; i < table.size(); ++i)
        table[i] = static_cast<uint8_t>((digit(hex[2 * i]) << 4) | digit(hex[2 * i + 1]));
    return table;
}();

UserKey inverse_key(const UserKey& key) {
    UserKey inverse{};
    std::bitset<256> seen;
    for (size_t index = 0; index < key.size(); ++index) {
        if (seen.test(key[index]))
            throw std::invalid_argument("user key table must contain each byte value exactly once");
        seen.set(key[index]);
        inverse[key[index]] = static_cast<uint8_t>(index);
    }
    return inverse;
}

uint32_t image_crc32(std::span<const uint8_t> data) {
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        crc ^= byte;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
    }
    return ~crc;
}

void unwrap_tool_image(std::span<uint8_t> wrapped) {
    uint8_t state = 0x4C;
    for (size_t i = 0; i < wrapped.size(); ++i) {
        const auto mixed = wrapper_inverse[wrapped[i]] ^ wrapper_inverse[state];
        const auto index = static_cast<uint8_t>(mixed + wrapper_inverse[static_cast<uint8_t>(state + 1)]);
        wrapped[i] = wrapper_inverse[index];
        state = static_cast<uint8_t>((wrapped[i] ^ state) + i);
    }
}

}  // namespace

UserKey decode_aicube_key(const UserKey& wrapped) {
    // 45BB7B passes step 2; the file contains the inverse of the user table.
    UserKey inverse{};
    uint8_t state = 0x4C;
    uint8_t counter = 0;
    for (size_t i = 0; i < inverse.size(); ++i) {
        const auto mixed = wrapper_inverse[wrapped[i]] ^ wrapper_inverse[state];
        const auto index = static_cast<uint8_t>(mixed + wrapper_inverse[static_cast<uint8_t>(state + 1)]);
        inverse[i] = wrapper_inverse[index];
        state = static_cast<uint8_t>((inverse[i] ^ state) + counter);
        counter += 2;
    }
    return inverse_key(inverse);
}

void configure_aicube_tool_image(std::span<uint8_t> wrapped, uint8_t pin_modes) {
    // 4C21D4 selects the stock 6.97C res65 before changing its port profile.
    if (wrapped.size() != 14864 || image_crc32(wrapped) != 0xBAFA93F3)
        throw std::invalid_argument("tool firmware requires the unmodified AiCube 6.97C res65.bin");
    if (pin_modes & 3) throw std::invalid_argument("invalid tool pin modes");
    unwrap_tool_image(wrapped);
    auto profile = wrapped.subspan(0x1000, 16);
    std::ranges::fill(profile, 0);
    profile[0] = 0x5A;
    profile[1] = 0xA5;
    profile[2] = pin_modes;
    encrypt_firmware(wrapped, inverse_key(wrapper_inverse));
}

void configure_aicube_uart_tool_image(std::span<uint8_t> wrapped, uint16_t magic, bool legacy_tag_bit) {
    if (wrapped.size() != 8192 || image_crc32(wrapped) != 0xF766AC30)
        throw std::invalid_argument("tool firmware requires the unmodified AiCube 6.97C res11.bin");
    uint8_t tag{};
    switch (magic) {
    case 0xF44B: tag = 0x22; break;
    case 0xF4CB: tag = 0x21; break;
    case 0xF44C: tag = 0x42; break;
    case 0xF4CC: tag = 0x41; break;
    case 0xF56C: tag = 0x40; break;
    default: throw std::invalid_argument("unknown UART tool controller");
    }
    // 44F130 changes the last plaintext byte, then rewraps the entire image.
    unwrap_tool_image(wrapped);
    wrapped.back() = tag | (legacy_tag_bit ? 0x10 : 0);
    encrypt_firmware(wrapped, inverse_key(wrapper_inverse));
}

std::vector<uint8_t> build_aicube_iap15_monitor(const std::string& directory, uint16_t magic) {
    unsigned resource;
    size_t address = 0xE000;
    uint32_t crc;
    switch (magic) {
    case 0xF449: case 0xF4C9: resource = 6; crc = 0xE414DFA1; break;
    case 0xF569: case 0xF56D: resource = 30; crc = 0xEBCDE359; address = 0xD400; break;
    case 0xF56A: resource = 31; crc = 0x75968815; break;
    default: throw std::invalid_argument("unknown IAP15 simulation controller");
    }
    const auto load = [&](unsigned id, std::span<uint8_t> destination, uint32_t expected) {
        const auto name = "res" + std::to_string(id) + ".bin";
        std::ifstream input(utf8_path(directory) / name, std::ios::binary);
        if (!input.read(reinterpret_cast<char*>(destination.data()), destination.size()) ||
            input.peek() != std::char_traits<char>::eof() || input.bad() ||
            image_crc32(destination) != expected)
            throw std::invalid_argument("IAP15 simulation requires unmodified AiCube 6.97C " + name);
        unwrap_tool_image(destination);
    };
    // 4C2477: random padding, independent resource unwrapping, then one wrapper for the image.
    std::vector<uint8_t> image(address + 0x1000);
    std::mt19937 random{std::random_device{}()};
    std::generate(image.begin(), image.end(), [&] { return static_cast<uint8_t>(random()); });
    load(2, std::span(image).first(0x200), 0xAF07BCAA);
    load(resource, std::span(image).subspan(address), crc);
    encrypt_firmware(image, inverse_key(wrapper_inverse));
    return image;
}

UserKey read_user_key(const std::string& path) {
    std::ifstream input(utf8_path(path), std::ios::binary);
    if (!input) throw std::invalid_argument("cannot open user key file");
    UserKey key{};
    if (!input.read(reinterpret_cast<char*>(key.data()), key.size()) ||
        input.peek() != std::char_traits<char>::eof() || input.bad())
        throw std::invalid_argument("user key file must contain exactly 256 bytes");
    auto extension = utf8_path(path).extension().u8string();
    if (extension == u8".k" || extension == u8".K") return decode_aicube_key(key);
    (void)inverse_key(key);
    return key;
}

void encrypt_firmware(std::span<uint8_t> data, const UserKey& key) {
    // AiCube 6.97C 45C190: state advances with the plaintext and byte index.
    const auto inverse = inverse_key(key);
    uint8_t state = 0x4C;
    for (size_t i = 0; i < data.size(); ++i) {
        const auto plain = data[i];
        const auto mixed = static_cast<uint8_t>(key[plain] - inverse[static_cast<uint8_t>(state + 1)]);
        data[i] = key[mixed ^ inverse[state]];
        state = static_cast<uint8_t>((plain ^ state) + i);
    }
}

void encrypt_binary_file(const std::string& input, const std::string& output, const std::string& key_file) {
    std::ifstream source(utf8_path(input), std::ios::binary | std::ios::ate);
    if (!source) throw std::invalid_argument("cannot open input binary");
    const auto length = source.tellg();
    if (length <= 0 || length > 0x40000)
        throw std::invalid_argument("input binary must contain 1 to 262144 bytes");
    std::vector<uint8_t> data(static_cast<size_t>(length));
    if (!source.seekg(0) || !source.read(reinterpret_cast<char*>(data.data()), data.size()))
        throw std::runtime_error("cannot read input binary");
    encrypt_firmware(data, read_user_key(key_file));
    const auto output_path = utf8_path(output);
    if (std::filesystem::symlink_status(output_path).type() != std::filesystem::file_type::not_found)
        throw std::invalid_argument("encrypted output must be a new file");
    std::ofstream target(output_path, std::ios::binary | std::ios::out);
    target.write(reinterpret_cast<const char*>(data.data()), data.size());
    target.close();
    if (!target) throw std::runtime_error("cannot write encrypted binary");
}

}  // namespace stcisp
