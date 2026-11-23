#include "stcisp/database.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

namespace stcisp {

const std::vector<ModelInfo>& model_database() {
    static const std::vector<ModelInfo> models = {
#include "isp_database_generated.inc"
    };
    return models;
}

static bool equal_name(const std::string& left, const std::string& right) {
    if (left.size() != right.size()) {
        return false;
    }
    for (size_t i = 0; i < left.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(left[i])) !=
            std::tolower(static_cast<unsigned char>(right[i]))) {
            return false;
        }
    }
    return true;
}

const ModelInfo* find_model_by_name(const std::string& name) {
    for (const auto& model : model_database()) {
        if (equal_name(model.name, name)) {
            return &model;
        }
    }
    for (const auto& model : model_database()) {
        const auto delimiter = model.name.find('/');
        if (delimiter == std::string::npos) continue;
        if (equal_name(model.name.substr(0, delimiter), name))
            return &model;
    }
    return nullptr;
}

const ModelInfo* find_model_by_magic(uint16_t magic, uint8_t status_variant) {
    if (magic == 0) return nullptr;
    for (const auto& model : model_database()) {
        if (model.status_variant == status_variant &&
            (model.magic == magic || model.alternate_magic == magic)) {
            return &model;
        }
    }
    return nullptr;
}

IspRoute isp_route(const ModelInfo& model, bool uart) {
    if (!uart && !(model.flags & 0x4000)) return IspRoute::unavailable;
    if (model.magic == 0xF8D1 && model.family == 89 && uart_selector(model) == 3)
        return IspRoute::f8d1;
    if ((model.family == 76 || model.family == 79 || model.family == 84) &&
        (model.flags & 1) && uart_selector(model) == 3 && (uart || (model.flags & 0x4000)))
        return IspRoute::ai32;
    if (model.family == 70 && (model.flags & 1) &&
        uart_selector(model) == 3 && (uart || (model.flags & 0x4000)))
        return IspRoute::ai16;
    if (uart) {
        const auto timer = (model.flags >> 9) & 7;
        if (timer == 3 && ((model.family >= 1 && model.family <= 6 && uart_selector(model) == 0) ||
                           ((model.family == 15 || model.family == 16) && uart_selector(model) == 1)))
            return IspRoute::stc89;
        if (timer == 2 && ((model.family >= 7 && model.family <= 14) ||
                          (model.family >= 19 && model.family <= 24)) && uart_selector(model) <= 1)
            return IspRoute::legacy_stc12;
        if (uart_selector(model) == 2 && timer == 0 && (model.family == 25 || model.family == 28))
            return IspRoute::stc15e_uart;
        if (uart_selector(model) == 4 && timer <= 1 &&
            (model.family == 27 || model.family == 28 || model.family == 29 ||
             model.family == 31 || model.family == 32 || (model.family >= 34 && model.family <= 38)))
            return IspRoute::irc15_uart;
        if (model.family == 88 && uart_selector(model) == 3)
            return IspRoute::ai8051u_uart;
        if (uart_selector(model) == 3 && timer <= 1 && model.family >= 27 &&
            model.family <= 44 && (model.flags & 0x1000) == 0)
            return IspRoute::modern_8bit_uart;
        if (uart_selector(model) == 3 && timer == 1 && model.magic != 0xF78F) {
            if (has_stc8u_status(model.family))
                return IspRoute::modern_8bit_uart;
            // Exclude extended-address records from the 16-bit block sender.
            if (model.family >= 45 && model.family <= 85 && (model.flags & 0x1000) == 0 &&
                model.code_size > 0 && model.code_size <= 0xFE00)
                return IspRoute::modern_8bit_uart;
        }
    } else {
        if (model.family == 61 && uart_selector(model) == 3) return IspRoute::h8u_usb;
        if (model.family == 88 && uart_selector(model) == 3) return IspRoute::ai8051u_usb;
        if (has_stc8u_status(model.family) && uart_selector(model) == 3)
            return IspRoute::stc8u_usb;
    }
    return IspRoute::unavailable;
}

bool supports_isp_write(const ModelInfo& model, bool uart) {
    return isp_route(model, uart) != IspRoute::unavailable;
}

uint8_t simulation_modes(const ModelInfo& model) {
    // AiCube 6.97C: 47E920 filters the list; 47F0D0 gates the mode controls.
    if ((model.flags & 0x11) != 0x11) return 0;
    uint8_t modes = 0;
    if (model.family != 89)
        modes |= static_cast<uint8_t>(SimulationMode::uart);
    if (model.flags & 0x4000)
        modes |= static_cast<uint8_t>(SimulationMode::usb);
    if (model.family != 88 && (model.flags & 0x3000) == 0x1000)
        modes |= static_cast<uint8_t>(SimulationMode::swd);
    return modes;
}

bool supports_simulation(const ModelInfo& model, SimulationMode mode, bool uart_isp) {
    if (!(simulation_modes(model) & static_cast<uint8_t>(mode))) return false;
    if (uart_isp) return model.magic != 0xF78F && uart_selector(model) == 3 && ((model.flags >> 9) & 7) == 1;
    if (mode == SimulationMode::swd) return false;
    return supports_isp_write(model, false);
}

const std::vector<HardwareOptionInfo>& hardware_options() {
    static const std::vector<HardwareOptionInfo> options = {
#include "isp_hardware_options_generated.inc"
    };
    return options;
}

void print_models() {
    for (const auto& model : model_database()) {
        std::cout << model.name << " magic=0x" << std::hex << std::uppercase
                  << model.magic << std::dec << " code=" << model.code_size
                  << " total=" << model.total_size << " family=0x"
                  << std::hex << static_cast<unsigned>(model.family) << std::dec
                  << " uart-protocol=" << static_cast<unsigned>(uart_selector(model))
                  << " uart-write=" << (supports_isp_write(model, true) ? "yes" : "no")
                  << " usb-write=" << (supports_isp_write(model, false) ? "yes" : "no");
        if (supports_usb_tool_make(model)) std::cout << " tool-make=usb";
        if (supports_uart_tool_make(model)) std::cout << " tool-make=serial";
        std::cout << " simulation-make=";
        const char* separator = "";
        for (const auto& [mode, name] : {std::pair{SimulationMode::uart, "uart"},
                                        std::pair{SimulationMode::usb, "usb"},
                                        std::pair{SimulationMode::swd, "swd"}}) {
            if (!supports_simulation(model, mode, true) && !supports_simulation(model, mode, false))
                continue;
            std::cout << separator << name;
            separator = ",";
        }
        if (!*separator) std::cout << "no";
        std::cout << "\n";
    }
}

}  // namespace stcisp
