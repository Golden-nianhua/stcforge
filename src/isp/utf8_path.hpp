#pragma once

#include <filesystem>
#include <string>

namespace stcisp {
inline std::filesystem::path utf8_path(const std::string& text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}
}
