#pragma once

#include "stcisp/isp.hpp"

#include <vector>

namespace stcisp {

const std::vector<ModelInfo>& model_database();
const ModelInfo* find_model_by_name(const std::string& name);
const ModelInfo* find_model_by_magic(uint16_t magic, uint8_t status_variant = 0);
enum class IspRoute {
    unavailable, stc89, legacy_stc12, stc15e_uart, irc15_uart, h8u_usb,
    modern_8bit_uart, stc8u_usb, ai8051u_usb, ai8051u_uart, ai16, ai32, f8d1
};

constexpr bool has_stc8u_status(uint8_t family) {
    return family == 61 || family == 86 || family == 87 || family == 90;
}

// AiCube 6.97C 0x43E300: UART wire selector, independent of configuration family.
constexpr uint8_t uart_selector(const ModelInfo& model) {
    return static_cast<uint8_t>((model.flags >> 6) & 7);
}
IspRoute isp_route(const ModelInfo& model, bool uart);
bool supports_isp_write(const ModelInfo& model, bool uart);
constexpr bool supports_usb_tool_make(const ModelInfo& model) {
    const auto magic = model.magic & 0x7FFF;
    return magic == 0x77EE || magic == 0x77EF;
}
constexpr bool supports_uart_tool_make(const ModelInfo& model) {
    switch (model.magic) {
    case 0xF44B: case 0xF4CB: case 0xF44C: case 0xF4CC: case 0xF56C:
        return true;
    default:
        return false;
    }
}

enum class SimulationMode : uint8_t { uart = 1, usb = 2, swd = 4 };
uint8_t simulation_modes(const ModelInfo& model);
bool supports_simulation(const ModelInfo& model, SimulationMode mode, bool uart_isp);

struct HardwareOptionInfo {
    uint8_t family = 0;
    uint16_t control = 0;
    const char* label = nullptr;
    int raw_offset = -1;
    uint8_t mask = 0;
    uint8_t default_value = 0;
    uint8_t flags = 0;
};

const std::vector<HardwareOptionInfo>& hardware_options();

}  // namespace stcisp
