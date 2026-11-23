#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace stcisp {

using UserKey = std::array<uint8_t, 256>;

UserKey read_user_key(const std::string& path);
UserKey decode_aicube_key(const UserKey& wrapped);
void configure_aicube_tool_image(std::span<uint8_t> wrapped, uint8_t pin_modes);
void configure_aicube_uart_tool_image(std::span<uint8_t> wrapped, uint16_t magic, bool legacy_tag_bit);
std::vector<uint8_t> build_aicube_iap15_monitor(const std::string& directory, uint16_t magic);
void encrypt_firmware(std::span<uint8_t> data, const UserKey& key);
void encrypt_binary_file(const std::string& input, const std::string& output, const std::string& key_file);

}  // namespace stcisp
