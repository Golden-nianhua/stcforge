#include "stcisp/isp.hpp"
#include "stcisp/softusb.hpp"

#include "stcisp/crypto.hpp"
#include "stcisp/database.hpp"
#include "stcisp/link1d.hpp"
#include "utf8_path.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <tuple>

namespace stcisp {
namespace {

constexpr uint32_t kEepromBase = 0xFC2800;
constexpr uint32_t kCodeBase = 0xFF0000;
constexpr size_t kBlockSize = 128;

const std::array<unsigned, 32>& stc15_core_voltages(unsigned family) {
    static constexpr std::array<unsigned, 32> voltages[]{
#include "isp_core_voltage_generated.inc"
    };
    const auto row = family == 32 ? 5 : family <= 34 ? 0 : std::min(family - 34, 4u);
    return voltages[row];
}

uint8_t legacy_iap_wait(uint64_t clock) {
    return clock < 1'000'000 ? 0x87 : clock < 2'000'000 ? 0x86 :
           clock < 3'000'000 ? 0x85 : clock < 6'000'000 ? 0x84 : clock < 12'000'000 ? 0x83 :
           clock < 20'000'000 ? 0x82 : clock < 24'000'000 ? 0x81 : 0x80;
}

int select_measured_uart_baud(uint64_t clock, int requested, bool timer1, bool link1d) {
    // 441F42/4420C5/4421FB: the 1T and Link1D paths use the short table.
    constexpr std::array short_rates{921600, 460800, 230400, 115200, 57600, 38400, 28800,
                                     19200, 14400, 9600, 4800, 2400, 1200};
    constexpr std::array long_rates{2000000, 1500000, 1000000, 921600, 500000, 460800,
                                    250000, 230400, 200000, 115200, 100000, 57600, 38400,
                                    28800, 19200, 14400, 9600, 4800, 2400, 1200};
    const auto rates = !timer1 || link1d ? std::span<const int>(short_rates) :
        std::span<const int>(long_rates);
    const double timer_hz = static_cast<double>(clock) / (timer1 ? 4.0 : 1.0);
    const double maximum_ticks = timer1 ? 65535.0 : static_cast<double>(43690.0f);
    const auto valid = [&](int rate) {
        const double ticks = timer_hz / rate;
        if (ticks < (timer1 ? 1.5 : 200.0) || ticks >= maximum_ticks) return false;
        const auto reload = std::lround(ticks);
        return std::abs(ticks / reload - 1) < 0.01;
    };
    const auto max_rate = std::find_if(rates.begin(), rates.end(), valid);
    const auto min_rate = std::find_if(rates.rbegin(), rates.rend(), [=](int rate) {
        return timer_hz / rate < maximum_ticks;
    });
    if (max_rate == rates.end() || min_rate == rates.rend() || *max_rate < *min_rate)
        throw std::invalid_argument("target clock cannot use a supported UART transfer baud");
    int baud = std::clamp(requested, *min_rate, *max_rate);
    if (!timer1) baud = std::min(baud, 38400);
    if (valid(baud)) return baud;
    // A user-specified rate can fall in a hole between two representable rates.
    const auto safe_rate = std::find_if(rates.begin(), rates.end(), [&](int rate) {
        return rate <= baud && valid(rate);
    });
    if (safe_rate != rates.end()) return *safe_rate;
    throw std::invalid_argument("target clock cannot use a supported UART transfer baud");
}

uint8_t simulation_pin_bits(const std::string& value) {
    const std::array<std::string, 4> pairs{"p3.0-p3.1", "p3.6-p3.7", "p1.6-p1.7", "p4.3-p4.4"};
    const auto pair = std::find(pairs.begin(), pairs.end(), value);
    if (pair != pairs.end()) return static_cast<uint8_t>((pair - pairs.begin()) << 6);
    if (value.size() == 1 && value.front() >= '0' && value.front() <= '3')
        return static_cast<uint8_t>((value.front() - '0') << 6);
    throw std::invalid_argument("invalid simulation pin pair: " + value);
}

SimulationMode parse_simulation_mode(const std::string& value) {
    if (value == "uart") return SimulationMode::uart;
    if (value == "usb") return SimulationMode::usb;
    if (value == "swd") return SimulationMode::swd;
    throw std::invalid_argument("--make-simulation requires simulation_mode=uart, usb or swd");
}

bool bool_value(const std::string& value) {
    if (value == "true" || value == "1" || value == "yes") return true;
    if (value == "false" || value == "0" || value == "no") return false;
    throw std::invalid_argument("option value must be true or false: " + value);
}

void set_bit(uint8_t& value, uint8_t mask, bool enabled) {
    value = static_cast<uint8_t>((value & static_cast<uint8_t>(~mask)) |
                                 (enabled ? mask : 0));
}

uint32_t number_value(const std::string& value) {
    return parse_unsigned(value, UINT32_MAX);
}

uint8_t rs485_pin(std::string_view value) {
    constexpr std::array<uint8_t, 8> port_codes{0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xC8, 0xE8, 0xF8};
    if (value.size() != 4 || (value[0] != 'p' && value[0] != 'P') ||
        value[1] < '0' || value[1] > '7' || value[2] != '.' ||
        value[3] < '0' || value[3] > '7' || (value[1] == '3' && value[3] < '2'))
        throw std::invalid_argument("invalid ISP RS485 pin: " + std::string(value));
    return static_cast<uint8_t>(port_codes[value[1] - '0'] + (value[3] - '0'));
}

bool is_rs485_option(std::string_view name) {
    return name == "rs485_enabled" || name == "rs485_rx_pin" || name == "rs485_tx_pin" ||
           name == "rs485_rx_active_high" || name == "rs485_tx_active_high";
}

std::vector<uint8_t> irc_value(uint32_t hz) {
    static const std::map<uint32_t, std::array<uint8_t, 3>> values = {
        {5529600, {0x08, 0x10, 0x04}}, {6000000, {0x26, 0x10, 0x04}},
        {11059200, {0x08, 0x10, 0x02}}, {12000000, {0x26, 0x10, 0x02}},
        {20000000, {0x1C, 0x20, 0x02}}, {22118400, {0x08, 0x10, 0x01}},
        {24000000, {0x26, 0x10, 0x01}}, {30000000, {0xD6, 0x20, 0x02}},
        {32000000, {0xFC, 0x20, 0x02}}, {40000000, {0x1C, 0x20, 0x01}},
        {45158400, {0x47, 0x20, 0x01}}, {48000000, {0x65, 0x20, 0x01}},
        {50803200, {0x6F, 0x20, 0x01}}, {60000000, {0xD6, 0x20, 0x01}},
    };
    const auto it = values.find(hz);
    if (it == values.end()) {
        throw std::invalid_argument("unsupported USB IRC preset: " + std::to_string(hz));
    }
    return {static_cast<uint8_t>(hz >> 24), static_cast<uint8_t>(hz >> 16),
            static_cast<uint8_t>(hz >> 8), static_cast<uint8_t>(hz),
            it->second[0], it->second[1], it->second[2]};
}

std::string format_transfer_size(double bytes) {
    const char* units[] = {"B", "KiB", "MiB", "GiB"};
    size_t unit = 0;
    while (bytes >= 1024.0 && unit < 3) {
        bytes /= 1024.0;
        ++unit;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(bytes >= 10.0 ? 1 : 2)
           << bytes << ' ' << units[unit];
    return output.str();
}

std::string format_transfer_time(double seconds) {
    if (!std::isfinite(seconds) || seconds < 0.0) return "--:--";
    const auto rounded = static_cast<int64_t>(std::ceil(seconds));
    const int64_t hours = rounded / 3600;
    const int64_t minutes = (rounded % 3600) / 60;
    const int64_t remaining = rounded % 60;
    std::ostringstream output;
    output << std::setfill('0');
    if (hours > 0) output << hours << ':' << std::setw(2) << minutes << ':';
    else output << std::setw(2) << minutes << ':';
    output << std::setw(2) << remaining;
    return output.str();
}

class TransferProgress {
public:
    explicit TransferProgress(uint64_t total)
        : total_(total), start_(std::chrono::steady_clock::now()), last_render_(start_) {}

    void update(uint64_t completed) {
        if (total_ == 0 || complete_) return;
        const auto now = std::chrono::steady_clock::now();
        if (completed < total_ && now - last_render_ < std::chrono::milliseconds(100)) return;
        last_render_ = now;
        complete_ = completed >= total_;

        const double elapsed = std::max(
            0.001, std::chrono::duration<double>(now - start_).count());
        const double rate = static_cast<double>(completed) / elapsed;
        const double remaining = rate > 0.0
            ? static_cast<double>(total_ - std::min(completed, total_)) / rate
            : 0.0;
        const int width = 28;
        const int filled = static_cast<int>(
            (static_cast<double>(std::min(completed, total_)) / total_) * width);
        const double percent = (static_cast<double>(std::min(completed, total_)) / total_) * 100.0;

        std::ostringstream line;
        line << '\r' << '[' << std::string(filled, '#')
             << std::string(width - filled, '-') << "] "
             << std::fixed << std::setprecision(1) << std::setw(6) << percent << "% "
             << format_transfer_size(static_cast<double>(completed)) << " / "
             << format_transfer_size(static_cast<double>(total_)) << "  "
             << format_transfer_size(rate) << "/s  ETA "
             << format_transfer_time(remaining) << std::flush;
        std::cout << line.str() << std::flush;
    }

    void finish() {
        if (total_ == 0) return;
        update(total_);
        std::cout << '\n';
    }

private:
    uint64_t total_;
    bool complete_ = false;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point last_render_;
};

std::array<uint8_t, 7> usb_irc_value(const ModelInfo& model, uint32_t requested,
                                    const std::array<uint8_t, 54>& status, size_t status_size) {
    if (!requested || requested > 128'000'000)
        throw std::invalid_argument("invalid USB IRC target frequency");
    // 43EB30: select the first table entry whose integer divider fits.
    static constexpr uint32_t common[]{22'118'400, 24'000'000, 27'000'000, 30'000'000, 33'177'600,
        35'000'000, 36'864'000, 40'000'000, 44'236'800, 45'158'400};
    static constexpr uint32_t wide[]{22'118'400, 24'000'000, 40'000'000, 45'158'400, 48'000'000,
        50'803'200, 52'000'000, 56'000'000, 60'000'000, 64'000'000};
    const bool wide_table = model.family == 84 || model.family == 89;
    // 43F098 predates the 7.4 band encoding in 43EFF3.
    const bool legacy_band = status_size && status[17] == 0x73 && status_size > 22 && status[22] >= 12;
    const auto& table = wide_table ? wide : common;
    for (size_t i = 0; i < std::size(table); ++i) {
        const double ratio = static_cast<double>(table[i]) / requested;
        const auto divider = std::lround(ratio);
        if (divider <= 0 || divider > 255 || std::abs(ratio - divider) >= 0.005)
            continue;
        if (status_size && status[17] < 0x74 && (!legacy_band || wide_table))
            throw std::invalid_argument("this USB BSL does not support the selected IRC preset");
        const auto trim_offset = i < 2 ? 0x19 + i : 0x2A + i - 2;
        if (status_size && trim_offset >= status_size)
            throw std::invalid_argument("target status is missing the USB IRC preset trim");
        auto band = legacy_band ? (table[i] >= 27'000'000 ? 0x80u : 0u) :
            wide_table ? (table[i] >= 33'000'000 ? 0x20u : 0x10u) :
            (table[i] >= 35'000'000 ? 0x30u : 0x20u);
        // 43F043: from patch 8, status[50] identifies the band for entries 2..9.
        if (!legacy_band && !wide_table && i >= 2 && status[22] >= 8) {
            if (status_size <= 50)
                throw std::invalid_argument("target status is missing the USB IRC band selector");
            band = status[50] & (1u << (i - 2)) ? 0x30u : 0x20u;
        }
        const auto hz = static_cast<uint32_t>(table[i] / divider);
        return {static_cast<uint8_t>(hz >> 24), static_cast<uint8_t>(hz >> 16),
            static_cast<uint8_t>(hz >> 8), static_cast<uint8_t>(hz),
            status[trim_offset], static_cast<uint8_t>(band), static_cast<uint8_t>(divider)};
    }
    throw std::invalid_argument(model.name + " does not have a USB IRC preset for " +
                                std::to_string(requested) + " Hz");
}

std::string hex_bytes(const std::vector<uint8_t>& data) {
    std::ostringstream result;
    for (size_t index = 0; index < data.size(); ++index) {
        if (index) result << ' ';
        result << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(data[index]);
    }
    return result.str();
}

enum class OptionLayout { stc89, stc12a, stc12, stc15a, stc15, stc8, stc32 };

bool compact_stc12_options(uint8_t family) {
    return family == 7 || family == 8 || family == 9 ||
           family == 10 || family == 19 || family == 20;
}

size_t stc89_option_offset(const ModelInfo& model, uint8_t bsl) {
    // AiCube 444340: these chips move the option byte in the 7.2 status packet.
    // The STC89C516 family has its own parser (444280).
    return bsl >= 0x72 && model.family != 6 ? 1 : 19;
}

bool bsl_reports_code_end(uint8_t version, uint8_t patch) {
    return version >= 0x75 || (version == 0x74 && patch >= 3) ||
           (version == 0x73 && patch >= 13);
}

int stc12_option_status_offset(bool compact, int raw_offset, uint8_t bsl) {
    if (bsl >= 0x72) {
        // 44459D/44485D (compact) and 444B27 (extended) rearrange
        // the same four status bytes into their respective option layouts.
        switch (raw_offset) {
        case 0: return compact ? 7 : 8;
        case 1: return compact ? 6 : 7;
        case 2: return compact ? -1 : 6;
        case 4: return compact ? 8 : -1;
        case 14: return 5;
        default: return -1;
        }
    }
    switch (raw_offset) {
    case 0: return 23;
    case 1: return 24;
    case 2: return compact ? -1 : 25;
    case 4: return compact ? 29 : -1;
    case 14: return compact ? 25 : 27;
    default: return -1;
    }
}

std::optional<std::string> decode_stc12_option(
    bool compact, const std::array<uint8_t, 54>& status, size_t status_size,
    const HardwareOptionInfo& option) {
    const auto offset = stc12_option_status_offset(compact, option.raw_offset, status[17]);
    if (offset < 0 || static_cast<size_t>(offset) >= status_size || !option.mask) return std::nullopt;
    const auto mask = option.mask;
    const unsigned bits = status[offset] & mask;
    if (option.control == 0x041B) return bits ? "高门槛电压" : "低门槛电压";
    if (option.control == 0x041D || option.control == 0x041F) {
        unsigned code = bits;
        for (unsigned m = mask; !(m & 1); m >>= 1) code >>= 1;
        return std::to_string((option.control == 0x041D ? 2u : 4096u) << code);
    }
    if ((option.flags & ~1u) != 4) return std::nullopt;
    return (bits != 0) != ((option.flags & 1) != 0) ? "是" : "否";
}

std::optional<OptionLayout> option_layout(const ModelInfo& model) {
    const auto& name = model.name;
    if (model.magic == 0xF8D1 && model.family == 89) return OptionLayout::stc32;
    if (model.family == 61) return OptionLayout::stc8;
    if (model.family > 45) return std::nullopt;
    if (name.rfind("STC89", 0) == 0 || name.rfind("STC90", 0) == 0) {
        return OptionLayout::stc89;
    }
    if (name.find("STC12C1052") != std::string::npos ||
        name.find("STC12C52") != std::string::npos ||
        name.find("STC12C56") != std::string::npos) {
        return OptionLayout::stc12a;
    }
    if (name.rfind("STC10", 0) == 0 || name.rfind("STC11", 0) == 0 ||
        name.rfind("STC12", 0) == 0 || name.rfind("IAP10", 0) == 0 ||
        name.rfind("IAP11", 0) == 0 || name.rfind("IAP12", 0) == 0) {
        return OptionLayout::stc12;
    }
    if ((name.find("STC15") != std::string::npos ||
         name.find("IAP15") != std::string::npos) &&
        (name.find("E") != std::string::npos || name.find("EA") != std::string::npos)) {
        return OptionLayout::stc15a;
    }
    if (name.find("STC15") != std::string::npos ||
        name.find("IAP15") != std::string::npos ||
        name.find("IRC15") != std::string::npos) {
        return OptionLayout::stc15;
    }
    return std::nullopt;
}

std::array<uint8_t, 13> option_registers(const OptionLayout layout,
                                          const std::array<uint8_t, 54>& status) {
    std::array<uint8_t, 13> msr{};
    switch (layout) {
    case OptionLayout::stc89: msr[0] = status[19]; break;
    case OptionLayout::stc12a:
        msr = {status[23], status[24], status[25], status[29]};
        break;
    case OptionLayout::stc12:
        msr = {status[23], status[24], status[25], status[27]};
        break;
    case OptionLayout::stc15a:
        for (size_t i = 0; i < 13; ++i) msr[i] = status[23 + i];
        break;
    case OptionLayout::stc15:
        msr = {status[5], status[6], status[7], status[12], status[37]};
        break;
    case OptionLayout::stc32:
        msr = {status[9], status[13], status[14], status[15], status[16]};
        break;
    case OptionLayout::stc8:
        msr = {status[9], status[10], status[11], status[15], status[16]};
        break;
    }
    return msr;
}

std::optional<std::string> decode_hardware_option(const ModelInfo& model,
                                                  const std::array<uint8_t, 54>& status,
                                                  uint16_t control) {
    if (has_stc8u_status(model.family)) {
        // AiCube 446870: status offsets in this family's live response are not
        // the offsets in the 04 write packet.
        const auto yes_no = [](bool value) { return value ? "是" : "否"; };
        switch (control) {
        case 0x0423: {
            const auto start = unsigned{status[16]} << 8;
            if (!(model.flags & 8) || start > model.total_size) return std::nullopt;
            const auto quarters = (model.total_size - start) / 256;
            static constexpr const char* suffix[] = {"", ".25", ".5", ".75"};
            return std::to_string(quarters / 4) + suffix[quarters % 4] + " KiB";
        }
        case 0x0418: {
            if ((status[15] & 0x80) || !(status[12] & 0x20)) return std::nullopt;
            static constexpr const char* pins[] = {"P3.0/P3.1", "P3.6/P3.7", "P1.6/P1.7", "P4.3/P4.4"};
            return pins[status[12] >> 6];
        }
        case 0x041B: {
            static constexpr const char* voltages[] = {"3.00 V", "2.70 V", "2.40 V", "2.00 V"};
            return voltages[status[11] & 3];
        }
        case 0x041D: return std::to_string(2u << (status[15] & 7));
        case 0x0606: return yes_no(status[9] & 0x02);
        case 0x0607: return yes_no(!(status[9] & 0x01));
        case 0x0609: return (status[10] & 0x02) ? "已启用" : "未启用";
        case 0x0611: return yes_no(status[10] & 0x80);
        case 0x0616: return yes_no(!(status[11] & 0x10));
        case 0x0617: return yes_no(!(status[11] & 0x40));
        case 0x0619: return yes_no(!(status[15] & 0x20));
        case 0x061A: return yes_no(!(status[15] & 0x08));
        case 0x06F3: return yes_no(!(status[10] & 0x20));
        case 0x06F4: return yes_no(!(status[10] & 0x10));
        case 0x0625: return (status[15] & 0x80) || (status[12] & 0x20) ? "未启用" : "已启用";
        default: return std::nullopt;
        }
    }
    if (model.family == 88 && control == 0x0423 && status[16] < 64)
        return std::to_string(static_cast<unsigned>(status[16]) + 1) + " KiB";
    const auto selected_layout = option_layout(model);
    if (!selected_layout) return std::nullopt;
    const auto layout = *selected_layout;
    auto msr = option_registers(layout, status);
    if (layout == OptionLayout::stc89) msr[0] = status[stc89_option_offset(model, status[17])];
    const bool stc32 = layout == OptionLayout::stc32;
    const auto yes_no = [](bool value) { return value ? "是" : "否"; };
    const auto enabled_disabled = [](bool value) { return value ? "已启用" : "未启用"; };
    const uint32_t irc_hz = (static_cast<uint32_t>(status[1]) << 24) |
                            (static_cast<uint32_t>(status[2]) << 16) |
                            (static_cast<uint32_t>(status[3]) << 8) |
                            status[4];

    switch (control) {
    case 0x0415:
        return std::to_string(irc_hz) + " Hz";
    case 0x0418:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8) {
            static constexpr const char* pins[] = {"P3.0/P3.1", "P3.6/P3.7",
                                                    "P1.6/P1.7", "P4.3/P4.4"};
            return pins[(status[12] >> 6) & 0x03];
        }
        return std::nullopt;
    case 0x0419:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8) {
            static constexpr const char* pins[] = {"P3.0/P3.1", "P3.6/P3.7",
                                                    "P1.6/P1.7", "P4.3/P4.4"};
            return pins[(status[11] >> 6) & 0x03];
        }
        return std::nullopt;
    case 0x041B:
        if (layout == OptionLayout::stc12a) return yes_no((msr[3] & 0x40) == 0);
        if (layout == OptionLayout::stc12) return yes_no((msr[0] & 0x40) == 0);
        if (layout == OptionLayout::stc15a) return std::to_string(msr[1] & 0x07);
        if (layout == OptionLayout::stc15) return std::to_string(msr[1] & 0x07);
        return std::to_string(3 - (msr[2] & 0x03));
    case 0x041D:
        if (layout == OptionLayout::stc12) return std::to_string(2u << (msr[2] & 0x07));
        if (layout == OptionLayout::stc12a) return std::to_string(2u << (msr[1] & 0x07));
        if (layout == OptionLayout::stc15a) return std::to_string(2u << (msr[2] & 0x07));
        if (layout == OptionLayout::stc15) return std::to_string(2u << (msr[0] & 0x07));
        return std::to_string(2u << (msr[3] & 0x07));
    case 0x041F:
        if (layout == OptionLayout::stc12) return std::to_string(4096u << ((msr[0] >> 4) & 0x03));
        return std::nullopt;
    case 0x0421:
        if (layout == OptionLayout::stc15) {
            const auto offset = uart_selector(model) == 4 ? (status[17] >= 0x72 ? 41 : 0) : 37;
            if (offset) return std::to_string(stc15_core_voltages(model.family)[status[offset] & 0x1F]) + " mV";
        }
        return std::nullopt;
    case 0x0423:
        if (model.family == 88)
            return std::to_string(static_cast<unsigned>(msr[4]) + 1) + " KiB";
        if (model.magic == 0xF8D1)
            return std::to_string((static_cast<unsigned>(msr[4]) + 1) * 2) + " KiB";
        return std::nullopt;
    case 0x0453:
        if (layout != OptionLayout::stc32 && layout != OptionLayout::stc8) return std::nullopt;
        switch (msr[3] & 0x60) {
        case 0x20: return "上一次调节频率";
        case 0x40: return "内部预置频率";
        default: return "动态调节";
        }
    case 0x0454:
        return (msr[3] & 0x40) ? "32 位模式" : "8 位模式";
    case 0x0455:
        if (stc32) {
            if (status[51] == 0xFF) return "禁用";
            return std::to_string((static_cast<unsigned>(status[51]) + 1) * 2) + " KiB";
        }
        return std::nullopt;
    case 0x0606:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x08) == 0);
        if (layout == OptionLayout::stc12a) return yes_no((msr[2] & 0x02) == 0);
        if (layout == OptionLayout::stc12) return yes_no((msr[3] & 0x02) == 0);
        if (layout == OptionLayout::stc15a) return yes_no((msr[12] & 0x02) == 0);
        if (layout == OptionLayout::stc15) return yes_no((msr[3] & 0x02) != 0);
        return yes_no((msr[0] & 0x02) != 0);
    case 0x0607:
        return yes_no((msr[0] & 0x01) == 0);
    case 0x0608:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x04) == 0);
        if (stc32) return yes_no((msr[3] & 0x01) != 0);
        return std::nullopt;
    case 0x060D:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x01) == 0);
        return std::nullopt;
    case 0x060E:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x08) == 0);
        return std::nullopt;
    case 0x0609:
        if (layout == OptionLayout::stc89) return enabled_disabled((msr[0] & 0x10) != 0);
        if (layout == OptionLayout::stc12) return enabled_disabled((msr[1] & 0x40) != 0);
        if (layout == OptionLayout::stc15) return enabled_disabled((msr[2] & 0x02) != 0);
        return enabled_disabled((msr[1] & 0x02) != 0);
    case 0x060F:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x10) == 0);
        if (layout == OptionLayout::stc12) return yes_no((msr[1] & 0x40) == 0);
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x02) == 0);
        return yes_no((msr[1] & 0x02) == 0);
    case 0x0610:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x40) != 0);
        return std::nullopt;
    case 0x060B:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x20) == 0);
        return std::nullopt;
    case 0x060C:
    case 0x0619:
        if (layout == OptionLayout::stc89) return yes_no((msr[0] & 0x80) == 0);
        if (layout == OptionLayout::stc12a) return yes_no((msr[1] & 0x20) == 0);
        if (layout == OptionLayout::stc12)
            return yes_no((msr[2] & 0x20) == 0);
        if (layout == OptionLayout::stc15a) return yes_no((msr[2] & 0x20) == 0);
        if (layout == OptionLayout::stc15) return yes_no((msr[0] & 0x20) == 0);
        return yes_no((msr[3] & 0x20) == 0);
    case 0x0611:
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x80) != 0);
        return yes_no((msr[1] & 0x80) != 0);
    case 0x0612:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8)
            return enabled_disabled((status[11] & 0x01) == 0);
        return std::nullopt;
    case 0x0614:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8) {
            switch (msr[3] & 0x60) {
            case 0x20: return "上一次调节频率";
            case 0x40: return "内部预置频率";
            default: return "动态调节";
            }
        }
        return std::nullopt;
    case 0x061D:
        if (stc32) return yes_no((msr[0] & 0x40) != 0);
        return std::nullopt;
    case 0x061F:
        return "芯片状态包不返回 ID 写入状态";
    case 0x0616:
        if (layout == OptionLayout::stc89) return std::nullopt;
        if (layout == OptionLayout::stc12 || layout == OptionLayout::stc12a)
            return yes_no((msr[0] & 0x02) == 0);
        if (layout == OptionLayout::stc15a) return yes_no((msr[0] & 0x10) == 0);
        return yes_no((msr[2] & 0x10) == 0);
    case 0x0617:
        if (layout == OptionLayout::stc15a) return yes_no((msr[1] & 0x40) != 0);
        if (layout == OptionLayout::stc12 || layout == OptionLayout::stc12a)
            return yes_no((msr[0] & 0x40) == 0);
        return yes_no((msr[2] & 0x40) == 0);
    case 0x0618:
        if (layout == OptionLayout::stc15a || layout == OptionLayout::stc15)
            return yes_no((msr[1] & 0x80) != 0);
        return std::nullopt;
    case 0x061A:
        if (layout == OptionLayout::stc15) return yes_no((msr[0] & 0x08) == 0);
        if (layout == OptionLayout::stc12a) return yes_no((msr[1] & 0x08) == 0);
        if (layout == OptionLayout::stc12 || layout == OptionLayout::stc15a)
            return yes_no((msr[2] & 0x08) == 0);
        return yes_no((msr[3] & 0x08) == 0);
    case 0x0623:
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x40) != 0);
        return yes_no((msr[1] & 0x40) != 0);
    case 0x0621:
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x20) != 0);
        return yes_no((msr[1] & 0x20) != 0);
    case 0x0620:
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x40) != 0);
        if (layout == OptionLayout::stc8) return yes_no((msr[1] & 0x10) != 0);
        return std::nullopt;
    case 0x0624:
        if (layout == OptionLayout::stc8) return yes_no((msr[1] & 0x04) != 0);
        return std::nullopt;
    case 0x0628:
        if (layout == OptionLayout::stc15) return (msr[2] & 0x08) ? "高电平" : "低电平";
        if (layout == OptionLayout::stc8) return (msr[1] & 0x08) ? "高电平" : "低电平";
        return std::nullopt;
    case 0x06F3:
        if (layout == OptionLayout::stc8) return yes_no((msr[1] & 0x20) != 0);
        return std::nullopt;
    case 0x06F4:
        if (layout == OptionLayout::stc8) return yes_no((msr[1] & 0x10) != 0);
        return std::nullopt;
    case 0x0638:
        if (layout == OptionLayout::stc15) return yes_no((msr[2] & 0x01) != 0);
        if (layout == OptionLayout::stc12a) return yes_no((msr[0] & 0x02) == 0);
        if (layout == OptionLayout::stc12)
            return yes_no((msr[1] & 0x02) == 0);
        return std::nullopt;
    case 0x06F5:
        if (stc32) return yes_no((msr[2] & 0x80) == 0);
        return std::nullopt;
    case 0x06F6:
        if (stc32) return yes_no((msr[0] & 0x40) != 0);
        return std::nullopt;
    case 0x06F7:
        if (stc32) return yes_no((msr[0] & 0x20) == 0);
        return std::nullopt;
    case 0x0625:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8)
            return enabled_disabled((status[12] & 0x20) == 0);
        return std::nullopt;
    case 0x0626:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8)
            return enabled_disabled((status[11] & 0x20) == 0);
        return std::nullopt;
    case 0x0678:
        if (layout == OptionLayout::stc32 || layout == OptionLayout::stc8)
            return enabled_disabled((msr[0] & 0x10) != 0);
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

}  // namespace

Programmer::Programmer(Config config, std::unique_ptr<Transport> io)
    : config_(std::move(config)), transport_(std::move(io)) {}

void Programmer::connect() {
    const auto* selected = config_.model.empty() ? nullptr : find_model_by_name(config_.model);
    legacy_checksum_ = uses_uart() && selected && uart_selector(*selected) == 0;
    if (config_.transport == "usb") {
        if (!transport_) transport_ = make_usb_transport(config_.device_path);
    } else if (config_.transport == "link1d" && config_.link1d_auto_power) {
        if (!transport_) transport_ = make_link1d_hid_transport(config_.device_path);
        auto hid = std::make_unique<Link1dTransport>(std::move(transport_));
        link1d_ = hid.get();
        transport_ = std::move(hid);
    } else {
        if (config_.port.empty()) throw std::invalid_argument("serial transport requires port");
        if (!transport_) transport_ = make_serial_transport(config_.port, config_.handshake_baud,
                                                           config_.timeout_ms,
                                                           !selected || uart_selector(*selected) != 0);
    }
    transport_->open();
    opened_ = true;
    std::vector<uint8_t> status;
    if (link1d_) {
        status = link1d_->start(config_.handshake_baud, config_.timeout_ms,
                              !selected || uart_selector(*selected) != 0,
                              selected && (selected->flags & 4) != 0);
    } else if (uses_uart()) {
        std::cout << "等待 UART ISP，请为目标板重新上电。\n" << std::flush;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(config_.timeout_ms);
        while (true) {
            const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) throw TransportTimeout("等待目标板重新上电超时");
            transport_->write({0x7F});
            try {
                status = read_frame(std::min(250, static_cast<int>(remaining)));
                break;
            } catch (const TransportTimeout&) {}
        }
    } else {
        status = request({0x00}, {0x00}, "read status");
    }
    if (uses_uart() && !link1d_ && status == std::vector<uint8_t>{0x80}) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        send_frame({0x80});
        status = read_frame(config_.timeout_ms);
    }
    if (status.size() < 22 || (uses_uart() && status[0] != 0x50 &&
        status[0] != 0x00 && status[0] != 0x8F)) {
        throw std::runtime_error("unexpected ISP status packet");
    }
    const uint16_t magic = static_cast<uint16_t>(status[20] << 8 | status[21]);
    const uint8_t variant = status[17] >= 0x71 && status[18] >= 0x51 ? status[19] : 0;
    const ModelInfo* found = find_model_by_magic(magic, variant);
    if (!found) {
        std::ostringstream message;
        message << "unsupported model magic 0x" << std::hex << std::uppercase << magic
                << " in current built-in database";
        throw std::runtime_error(message.str());
    }
    model_ = *found;
    legacy_checksum_ = uses_uart() && uart_selector(model_) == 0 && status[17] < 0x72;
    if ((model_.magic == 0xF8D1 || model_.family == 61 || model_.family == 88) &&
        status.size() != 54)
        throw std::runtime_error("unexpected status length for model " + model_.name);
    status_.emplace();
    status_size_ = status.size();
    std::copy_n(status.begin(), std::min(status.size(), status_->size()), status_->begin());
    if ((model_.family == 25 || model_.family == 28) && status.size() > 51)
        std::copy_n(status.begin() + 51, std::min(status.size() - 51, stc15e_irc_seed_.size()),
                    stc15e_irc_seed_.begin());
    uart_clock_count_ = static_cast<uint16_t>((uint16_t{status[13]} << 8) | status[14]);
    original_option_byte_ = (*status_)[stc89_option_offset(model_, status[17])];
    if (selected && selected->name != model_.name) {
        throw std::runtime_error("configured model does not match the target status");
    }
    config_.model = model_.name;
    if (!config_.info_only) print_status();
}

void Programmer::disconnect(bool success) {
    if (!opened_) return;
    try {
        if (link1d_) link1d_->finish(success, config_.link1d_keep_power);
        else if (success && (config_.make_simulation || supports_isp_write(model_, uses_uart()))) {
            send_frame({0xFF});
            if (uses_uart() && uart_selector(model_) < 3 && (*status_)[17] < 0x72)
                send_frame({0x82});
        }
    } catch (...) {
        transport_->close();
        opened_ = false;
        throw;
    }
    transport_->close();
    opened_ = false;
}

void Programmer::send_frame(const std::vector<uint8_t>& payload) {
    const bool secret = !payload.empty() &&
        ((payload.front() == 5 && payload.size() > 5) ||
         payload.front() == 7 || payload.front() == 0x26 ||
         (payload.front() == 6 && !user_key_.empty()));
    if (link1d_) {
        if (config_.verbose)
            std::cerr << "-> Link1D " << (secret ? "[credential payload]" : hex_bytes(payload)) << "\n";
        return link1d_->write(payload);
    }
    const uint16_t length = static_cast<uint16_t>(payload.size() + (legacy_checksum_ ? 5 : 6));
    std::vector<uint8_t> frame = {0x46, 0xB9, 0x6A,
                                  static_cast<uint8_t>(length >> 8),
                                  static_cast<uint8_t>(length)};
    frame.insert(frame.end(), payload.begin(), payload.end());
    uint16_t checksum = 0;
    for (size_t index = 2; index < frame.size(); ++index) checksum += frame[index];
    if (!legacy_checksum_) frame.push_back(static_cast<uint8_t>(checksum >> 8));
    frame.push_back(static_cast<uint8_t>(checksum));
    frame.push_back(0x16);
    if (config_.verbose)
        std::cerr << "-> " << (secret ? "[credential payload]" : hex_bytes(frame)) << "\n";
    if (config_.transport == "usb") {
        for (size_t offset = 0; offset < frame.size(); offset += 64) {
            std::vector<uint8_t> report(64, 0);
            const size_t count = std::min<size_t>(64, frame.size() - offset);
            std::copy_n(frame.begin() + static_cast<std::ptrdiff_t>(offset),
                        static_cast<std::ptrdiff_t>(count), report.begin());
            transport_->write(report);
        }
    } else {
        transport_->write(frame);
    }
}

std::vector<uint8_t> Programmer::read_frame(int timeout_ms) {
    if (link1d_) {
        auto payload = link1d_->read(timeout_ms);
        if (config_.verbose) std::cerr << "<- Link1D " << hex_bytes(payload) << "\n";
        return payload;
    }
    std::vector<uint8_t> usb_raw;
    auto& raw = uses_uart() ? uart_pending_ : usb_raw;
    const std::array<uint8_t, 2> sync{0x46, 0xB9};
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (true) {
        if (raw.size() >= 2) {
            auto header = std::search(raw.begin(), raw.end(), sync.begin(), sync.end());
            if (header == raw.end() && raw.back() == sync.front()) --header;
            raw.erase(raw.begin(), header);
        }
        size_t frame_size = 0;
        if (raw.size() >= 5) {
            if (raw[2] != 0x68) throw std::runtime_error("ISP reply has invalid direction");
            frame_size = static_cast<size_t>((raw[3] << 8) | raw[4]) + 2;
            if (frame_size < (uses_uart() ? 8u : 9u))
                throw std::runtime_error("ISP reply length is invalid");
        }
        if (!frame_size || raw.size() < frame_size) {
            const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) throw TransportTimeout("ISP frame read timeout");
            const auto part = transport_->read(static_cast<int>(remaining));
            raw.insert(raw.end(), part.begin(), part.end());
            continue;
        }
        std::vector<uint8_t> frame(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(frame_size));
        raw.erase(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(frame_size));
        if (frame.back() != 0x16) throw std::runtime_error("ISP reply has invalid terminator");
        unsigned tail = legacy_checksum_ ? 2 : 3;
        if (legacy_checksum_ && (!config_.offline_image.empty() || config_.erase_offline) &&
            frame[5] == 0x51 && frame.size() >= 9) {
            // The initial identity can use either checksum width. After the
            // baud switch the writer always uses the full 16-bit checksum.
            uint16_t sum = 0;
            for (size_t index = 2; index + 3 < frame.size(); ++index) sum += frame[index];
            if (sum == static_cast<uint16_t>(frame[frame.size() - 3] << 8 | frame[frame.size() - 2]))
                tail = 3;
        }
        if (!status_ && uses_uart() && frame.size() >= 29 && (frame[5] == 0 || frame[5] == 0x50)) {
            const auto* candidate = find_model_by_magic(static_cast<uint16_t>(frame[25] << 8 | frame[26]));
            if (candidate) tail = uart_selector(*candidate) == 0 && frame[22] < 0x72 ? 2 : 3;
        }
        if (frame.size() <= 5 + tail) throw std::runtime_error("ISP reply contains no payload");
        uint16_t checksum = 0;
        for (size_t index = 2; index + tail < frame.size(); ++index) checksum += frame[index];
        const auto expected = tail == 3
            ? static_cast<uint16_t>(frame[frame.size() - 3] << 8 | frame[frame.size() - 2])
            : frame[frame.size() - 2];
        if ((tail == 3 ? checksum : checksum & 0xFF) != expected)
            throw std::runtime_error("ISP reply checksum mismatch");
        std::vector<uint8_t> payload(frame.begin() + 5, frame.end() - tail);
        if (config_.verbose) std::cerr << "<- " << hex_bytes(frame) << "\n";
        return payload;
    }
}

std::vector<uint8_t> Programmer::request(const std::vector<uint8_t>& payload,
                                         const std::vector<uint8_t>& expected,
                                         const std::string& stage,
                                         int timeout_ms) {
    send_frame(payload);
    const auto response = read_frame(timeout_ms < 0 ? config_.timeout_ms : timeout_ms);
    if (response.size() < expected.size() ||
        !std::equal(expected.begin(), expected.end(), response.begin())) {
        std::ostringstream message;
        message << stage << " returned an unexpected response";
        throw std::runtime_error(message.str());
    }
    return response;
}

void Programmer::print_status() const {
    const auto& status = *status_;
    const unsigned major = status[17] >> 4;
    const unsigned minor = status[17] & 0x0F;
    std::cout << "Target: " << model_.name << " ("
              << (link1d_ ? "Link1D HID-UART" : uses_uart() ? "UART" :
                  config_.transport == "usb-soft" ? "软件 USB" : "USB HID")
              << ", BSL " << major << "." << minor << static_cast<char>(status[18]) << ")\n";
    if (model_.magic == 0xF8D1)
        std::cout << "EEPROM: " << (static_cast<unsigned>(status[16]) + 1) * 2 << " KiB\n";
    else if (model_.family == 88)
        std::cout << "EEPROM: " << static_cast<unsigned>(status[16]) + 1 << " KiB\n";
}

void Programmer::print_device_info() const {
    const auto& status = *status_;
    std::cout << "单片机型号: " << model_.name << "\n\n";
    std::cout << "当前芯片的硬件选项为:\n";
    bool found = false;
    const bool stc12 = isp_route(model_, true) == IspRoute::legacy_stc12;
    for (const auto& option : hardware_options()) {
        if (option.family != model_.family) continue;
        if (option.raw_offset < 0 || option.mask == 0 || option.control == 0x0453 ||
            option.control == 0x0614 || option.control == 0x061F) continue;
        const auto value = stc12 ? decode_stc12_option(compact_stc12_options(model_.family),
                                                      status, status_size_, option) :
                                   decode_hardware_option(model_, status, option.control);
        if (!value) continue;
        found = true;
        std::string label = option.control == 0x0423 ? "用户 EEPROM 容量" :
            option.label ? option.label : "未命名选项";
        if (model_.family == 90 && option.control != 0x0423) {
            const auto& table = hardware_options();
            const auto named = std::find_if(table.begin(), table.end(), [&](const auto& item) {
                return item.family == 86 && item.control == option.control;
            });
            if (named != table.end() && named->label) label = named->label;
        }
        for (size_t position = 0; (position = label.find("·", position)) != std::string::npos; ) {
            label.replace(position, std::string("·").size(), "/");
            ++position;
        }
        std::cout << " . " << label << ": " << *value << "\n";
    }
    if (!found) std::cout << " . 尚未实现这个型号的硬件状态解码\n";
}

bool Programmer::has_fixed_63k_partition() const {
    // 43E77A--43E838: affected lot has a fixed 63 KiB program / 1 KiB EEPROM split.
    constexpr std::array<uint16_t, 18> affected{
        0xF814, 0xF824, 0xF7CC, 0xF7C4, 0xF744, 0xF74C, 0xF784, 0xF764, 0xF76C,
        0xF7D4, 0xF7DC, 0xF648, 0xF638, 0xF618, 0xF7F4, 0xF804, 0xF658, 0xF628,
    };
    if (status_size_ < 40 || std::ranges::find(affected, model_.magic) == affected.end()) return false;
    const auto& status = *status_;
    const auto date = uint32_t{status[37]} << 16 | uint32_t{status[38]} << 8 | status[39];
    return date >= 0x220224 && date <= 0x220322;
}

void Programmer::enforce_fixed_63k_partition() {
    if (!has_fixed_63k_partition()) return;
    auto& partition = (*status_)[16];
    if (modify_hardware_options_ && config_.options.contains("eeprom_kib") && partition != 0xFC)
        throw std::invalid_argument("这批 " + model_.name + " 的 EEPROM 固定为 1 KiB，不能修改分区");
    partition = 0xFC;
}

void Programmer::apply_options(IspRoute route) {
    hardware_options_write_required_ = false;
    uart_irc_target_.reset();
    legacy_irc_result_.reset();
    legacy_clock_uses_measured_ = false;
    const auto is_eeprom_fill = [](std::string_view name) {
        return name == "eeprom_fill_zero" || name == "eeprom_fill_ff";
    };
    if (const auto it = config_.options.find("append_test_parameters"); it != config_.options.end()) {
        if (!model_.test_parameter_reserve)
            throw std::invalid_argument(model_.name + " does not support appending test parameters");
        (void)bool_value(it->second);
    }
    if (const auto it = config_.options.find("flash_blank_value"); it != config_.options.end()) {
        const auto value = number_value(it->second);
        if (value != 0 && value != 0xFF)
            throw std::invalid_argument("flash_blank_value must be 0x00 or 0xFF");
        image_fill_value_ = static_cast<uint8_t>(value);
    }
    if (const auto it = config_.options.find("modify_hardware_options"); it != config_.options.end())
        modify_hardware_options_ = bool_value(it->second);
    const auto irc_mode = config_.options.find("irc_adjust_mode");
    const auto irc_enabled = config_.options.find("irc_adjust_enabled");
    const auto irc_hz = config_.options.find("irc_hz");
    const auto configure_dynamic_uart_irc = [&] {
        if (!uses_uart() || !modify_hardware_options_) return;
        if (irc_mode != config_.options.end() && irc_enabled != config_.options.end())
            throw std::invalid_argument("set only one of irc_adjust_mode and irc_adjust_enabled");
        const bool dynamic = irc_enabled != config_.options.end() ? bool_value(irc_enabled->second) :
            irc_mode == config_.options.end() ? irc_hz != config_.options.end() :
            irc_mode->second == "dynamic";
        if (!dynamic) return;
        const auto hz = irc_hz == config_.options.end() ? 24'000'000u : number_value(irc_hz->second);
        if (hz == 0 || hz > 128'000'000)
            throw std::invalid_argument("invalid UART IRC target frequency");
        uart_irc_target_ = hz;
        hardware_options_write_required_ = true;
    };
    const bool stc15e_layout = (model_.family == 25 || model_.family == 28) &&
        (route == IspRoute::stc15e_uart || route == IspRoute::irc15_uart);
    const bool legacy_stc15_options = stc15e_layout || (model_.family >= 27 && model_.family <= 43 &&
        model_.family != 28 && (route == IspRoute::irc15_uart || route == IspRoute::modern_8bit_uart));
    if (legacy_stc15_options) {
        if (config_.options.contains("simulation_mode") && config_.options.at("simulation_mode") != "none")
            throw std::invalid_argument("simulation settings require a separate task");
        if (!modify_hardware_options_) return;
        if (irc_mode != config_.options.end() && irc_enabled != config_.options.end())
            throw std::invalid_argument("set only one of irc_adjust_mode and irc_adjust_enabled");
        const auto& status = *status_;
        const unsigned pin_base = route != IspRoute::irc15_uart || (stc15e_layout && status[17] < 0x71)
            ? 5 : status[17] >= 0x72 ? 47 : 39;
        const auto original = [&] {
            std::array<uint8_t, 15> raw;
            raw.fill(0xFF);
            raw[0] = status[pin_base + 2];
            raw[1] = status[pin_base + 1];
            raw[2] = status[pin_base];
            raw[8] = route != IspRoute::irc15_uart ? status[37] : status[17] >= 0x72 ? status[41] : 0xF8;
            raw[14] = status[12] ^ 0x02;
            if (stc15e_layout) {
                raw[0] ^= 0x10;
                raw[1] ^= 0x07;
                raw[8] = 0xFF;
                raw[14] = status[12];
            }
            return raw;
        }();
        legacy_options_ = original;
        static const std::map<std::string_view, uint16_t> controls{
            {"oscillator_gain_high", 0x0609}, {"por_reset_delay_long", 0x0611},
            {"reset_pin_as_io", 0x0616}, {"low_voltage_reset_enabled", 0x0617},
            {"low_voltage_threshold", 0x041B}, {"eeprom_disabled_at_low_voltage", 0x0618},
            {"watchdog_por_enabled", 0x0619}, {"watchdog_prescale", 0x041D},
            {"watchdog_stop_idle", 0x061A}, {"eeprom_erase_enabled", 0x0606},
            {"cold_start_p32_p33_required", 0x0607}, {"reset_pin_level", 0x0628},
            {"uart1_remap_p37_level", 0x0620}, {"uart1_p37_push_pull", 0x0621},
            {"internal_irc_clock", 0x0638}, {"core_voltage", 0x0421},
        };
        configure_dynamic_uart_irc();
        const bool soft_usb = config_.transport == "usb-soft";
        if (soft_usb && irc_mode != config_.options.end() && irc_mode->second != "last_trim" &&
            irc_mode->second != "internal_preset" && irc_mode->second != "dynamic")
            throw std::invalid_argument("invalid software USB IRC adjustment mode");
        // 43EFC0 falls back to 43E9E0 for these families on software USB.
        const bool keep_irc = soft_usb ||
            (irc_mode != config_.options.end() && irc_mode->second == "last_trim") ||
            (irc_enabled != config_.options.end() && !bool_value(irc_enabled->second));
        if (soft_usb && irc_enabled != config_.options.end()) (void)bool_value(irc_enabled->second);
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options" || name == "append_test_parameters" ||
                name == "simulation_mode") continue;
            if ((keep_irc || uart_irc_target_) &&
                (name == "irc_adjust_mode" || name == "irc_adjust_enabled" || name == "irc_hz"))
                continue;
            if (is_eeprom_fill(name)) continue;
            if (name == "fast_download_enabled") {
                (void)bool_value(value);
                continue;
            }
            if (name == "isp_rs485_wait_time" && number_value(value) == 0) continue;
            const auto control = controls.find(name);
            const auto& table = hardware_options();
            const auto field = control == controls.end() ? table.end() :
                std::find_if(table.begin(), table.end(), [&](const auto& item) {
                    return item.family == model_.family && item.control == control->second &&
                           item.flags != 0 && item.mask != 0 && item.raw_offset >= 0 &&
                           item.raw_offset < static_cast<int>(legacy_options_.size());
                });
            if (field == table.end())
                throw std::invalid_argument(model_.name + " option is not implemented: " + name);
            auto& target = legacy_options_[field->raw_offset];
            const bool invert = (field->flags & 1) != 0;
            if (field->control == 0x0421) {
                auto& voltages = stc15_core_voltages(model_.family);
                const auto requested = parse_unsigned(value, 5000);
                const auto selection = std::find(voltages.begin(), voltages.end(), requested);
                if (selection == voltages.end())
                    throw std::invalid_argument(model_.name + " does not support core_voltage=" + value + " mV");
                target = static_cast<uint8_t>((target & ~field->mask) | (selection - voltages.begin()));
            } else if (field->control == 0x041B || field->control == 0x041D) {
                const auto shift = std::countr_zero(static_cast<unsigned>(field->mask));
                const unsigned max = field->mask >> shift;
                unsigned code;
                if (field->control == 0x041B) code = parse_unsigned(value, max);
                else {
                    const auto divisor = parse_unsigned(value, 2u << max);
                    if (divisor < 2 || !std::has_single_bit(divisor))
                        throw std::invalid_argument("watchdog_prescale must be a supported power of two");
                    code = std::countr_zero(divisor) - 1;
                }
                if (invert) code ^= max;
                target = static_cast<uint8_t>((target & ~field->mask) | (code << shift));
            } else {
                const bool selected = field->control == 0x0628 ? parse_unsigned(value, 1) == 0 :
                    field->control == 0x0620 ? parse_unsigned(value, 1) != 0 : bool_value(value);
                set_bit(target, field->mask, selected != invert);
            }
        }
        if (config_.options.contains("internal_irc_clock") &&
            (!(original[0] & 1) || !(legacy_options_[0] & 1))) {
            // 44EFC6: when either side uses the external clock, keep the
            // handshake clock instead of running the internal IRC sweep.
            uart_irc_target_.reset();
            legacy_clock_uses_measured_ = true;
        }
        hardware_options_write_required_ |= legacy_options_ != original;
        if (hardware_options_write_required_ && status_size_) {
            if (stc15e_layout) {
                if (model_.family == 28 && status[17] >= 0x71)
                    throw std::invalid_argument("this IRC15 BSL does not send a hardware configuration packet");
                if (!uart_irc_target_ || status_size_ <= 27)
                    throw std::invalid_argument("this STC15E/EA option write requires IRC calibration and trim status");
                if (status[17] >= 0x71 && (status[12] & 0x0C) != 0x0C)
                    throw std::invalid_argument("cannot preserve active STC15E/EA download password or RS485 settings");
                return;
            }
            if (status[17] < 0x71 || status_size_ <= std::max(39u, pin_base + 2))
                throw std::invalid_argument("STC15 BSL did not return the fields needed to preserve hardware options");
            if (!soft_usb && !(status[12] & 0x04))
                throw std::invalid_argument("cannot preserve the configured STC15 ISP RS485 direction pins");
            if (!soft_usb && status[17] >= 0x72 && !(status[12] & 0x08))
                throw std::invalid_argument("cannot preserve the configured STC15 ISP password");
            if (uart_irc_target_ && !(original[0] & 1))
                throw std::invalid_argument("this STC15 IRC sweep requires the target to already use its internal clock");
        }
        return;
    }
    if (route == IspRoute::irc15_uart || route == IspRoute::stc15e_uart) {
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options" || is_eeprom_fill(name)) continue;
            if (name == "simulation_mode" && value == "none") continue;
            if (name == "irc_adjust_mode" && value == "last_trim") continue;
            if (modify_hardware_options_ || name == "simulation_mode")
                throw std::invalid_argument("option is not available for this download protocol: " + name);
        }
        return;
    }
    if (route == IspRoute::legacy_stc12) {
        if (!modify_hardware_options_) {
            if (config_.options.contains("simulation_mode") && config_.options.at("simulation_mode") != "none")
                throw std::invalid_argument("this model does not support simulation creation");
            return;
        }
        const auto& status = *status_;
        const bool compact = compact_stc12_options(model_.family);
        legacy_options_.fill(0xFF);
        for (size_t i = 0; i < legacy_options_.size(); ++i) {
            const auto offset = stc12_option_status_offset(compact, static_cast<int>(i), status[17]);
            if (offset >= 0 && (status_size_ == 0 || static_cast<size_t>(offset) < status_size_))
                legacy_options_[i] = status[offset];
        }
        const auto original = legacy_options_;
        const std::map<std::string, uint16_t> controls{
            {"internal_irc_clock", 0x0638}, {"low_voltage_threshold", 0x041B},
            {"watchdog_por_enabled", 0x0619}, {"watchdog_prescale", 0x041D},
            {"watchdog_stop_idle", 0x061A}, {"eeprom_erase_enabled", 0x0606},
            {"cold_start_p10_p11_required", 0x0608}, {"oscillator_gain_high", 0x0609},
            {"reset2_voltage_reset_enabled", 0x060A}, {"por_reset_delay_long", 0x0611},
            {"reset_pin_as_io", 0x0616}, {"oscillator_stable_delay", 0x041F},
        };
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options" || is_eeprom_fill(name)) continue;
            if (name == "simulation_mode" && value == "none") continue;
            if (status_size_ != 0 && status_size_ <= (status[17] >= 0x72 ? 8u : compact ? 29u : 27u))
                throw std::invalid_argument("target status is missing the legacy hardware option bytes");
            const auto control = controls.find(name);
            const auto& table = hardware_options();
            const auto option = control == controls.end() ? table.end() :
                std::find_if(table.begin(), table.end(), [&](const auto& item) {
                    return item.family == model_.family && item.control == control->second;
                });
            if (option == table.end() || option->raw_offset < 0 || option->raw_offset >= 15 || !option->mask)
                throw std::invalid_argument("hardware option write is not implemented for " + model_.name + ": " + name);
            if (stc12_option_status_offset(compact, option->raw_offset, status[17]) < 0)
                throw std::invalid_argument("unsupported STC12 hardware option: " + name);
            auto& byte = legacy_options_[option->raw_offset];
            const auto mask = option->mask;
            if (option->control == 0x041B) {
                const auto level = number_value(value);
                if (level > 1) throw std::invalid_argument("low_voltage_threshold must be 0 (low) or 1 (high)");
                set_bit(byte, mask, level != 0);
            } else if (option->control == 0x041D || option->control == 0x041F) {
                const unsigned first = option->control == 0x041D ? 2 : 4096;
                const unsigned limit = option->control == 0x041D ? 256 : 32768;
                const auto numeric = number_value(value);
                if (numeric < first || numeric > limit || (numeric & (numeric - 1)))
                    throw std::invalid_argument(name + " is not a supported power of two");
                unsigned shift = 0, code = 0;
                while (!(mask & (1u << shift))) ++shift;
                for (uint64_t v = numeric; v > first; v >>= 1) ++code;
                byte = static_cast<uint8_t>((byte & ~mask) | (code << shift));
            } else {
                const bool active_low = (option->flags & 1) != 0;
                set_bit(byte, mask, bool_value(value) != active_low);
            }
        }
        if (config_.transport == "usb-soft" && legacy_options_[4] != original[4])
            throw std::invalid_argument("the legacy software USB configuration packet does not carry low_voltage_threshold");
        hardware_options_write_required_ = status_size_ != 0 && original != legacy_options_;
        return;
    }
    if (route == IspRoute::stc89) {
        if (!modify_hardware_options_) return;
        auto& option = (*status_)[stc89_option_offset(model_, (*status_)[17])];
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options") continue;
            if (model_.family == 6) {
                if (name != "cpu_6t_enabled")
                    throw std::invalid_argument("unsupported STC89C516RD option: " + name);
                set_bit(option, 0x08, !bool_value(value));
            } else if (name == "clock_gain") {
                if (value != "high" && value != "low") throw std::invalid_argument("clock_gain must be high or low");
                set_bit(option, 0x10, value == "high");
            } else if (name == "cpu_6t_enabled") set_bit(option, 0x01, !bool_value(value));
            else if (name == "bsl_pindetect_enabled" || name == "cold_start_p10_p11_required")
                set_bit(option, 0x04, !bool_value(value));
            else if (name == "eeprom_erase_enabled") set_bit(option, 0x08, !bool_value(value));
            else if (name == "oscillator_gain_reduced") set_bit(option, 0x10, !bool_value(value));
            else if (name == "xram_enabled") set_bit(option, 0x40, bool_value(value));
            else if (name == "ale_as_p45") set_bit(option, 0x20, !bool_value(value));
            else if (name == "ale_enabled") set_bit(option, 0x20, bool_value(value));
            else if (name == "watchdog_poweroff_only" || name == "watchdog_por_enabled")
                set_bit(option, 0x80, !bool_value(value));
            else throw std::invalid_argument("unknown STC89 option: " + name);
        }
        return;
    }
    const bool ai8051 = route == IspRoute::ai8051u_uart || route == IspRoute::ai8051u_usb;
    const bool ai32 = route == IspRoute::ai32;
    const bool stc8u = has_stc8u_status(model_.family) &&
        (route == IspRoute::h8u_usb || route == IspRoute::stc8u_usb ||
         route == IspRoute::modern_8bit_uart);
    const bool generic_8bit = route == IspRoute::ai16 ||
        (route == IspRoute::modern_8bit_uart && model_.family >= 45 && !stc8u);
    const bool rs485_supported = ai8051 || ai32 || stc8u || generic_8bit || route == IspRoute::f8d1;
    if (modify_hardware_options_) {
        const auto enable = config_.options.find("rs485_enabled");
        const auto rx = config_.options.find("rs485_rx_pin");
        const auto tx = config_.options.find("rs485_tx_pin");
        const auto rx_high = config_.options.find("rs485_rx_active_high");
        const auto tx_high = config_.options.find("rs485_tx_active_high");
        if (rx != config_.options.end() || tx != config_.options.end() ||
            rx_high != config_.options.end() || tx_high != config_.options.end() ||
            enable != config_.options.end()) {
            if (!rs485_supported)
                throw std::invalid_argument("RS485 configuration is not implemented for " + model_.name);
            if (enable == config_.options.end())
                throw std::invalid_argument("RS485 pin and polarity settings require rs485_enabled");
            if (bool_value(enable->second)) {
                if (rx == config_.options.end() || tx == config_.options.end() ||
                    rx_high == config_.options.end() || tx_high == config_.options.end())
                    throw std::invalid_argument("RS485 requires both direction pins and both polarities");
                (void)rs485_pin(rx->second);
                (void)rs485_pin(tx->second);
                (void)bool_value(rx_high->second);
                (void)bool_value(tx_high->second);
            }
            hardware_options_write_required_ = true;
        }
    }
    if (ai8051 || ai32 || stc8u || generic_8bit) {
        auto& status = *status_;
        if (!modify_hardware_options_) {
            if (config_.options.contains("simulation_mode") && config_.options.at("simulation_mode") != "none")
                throw std::invalid_argument(model_.name + " simulation settings require --make-simulation");
            return;
        }
        const bool wide_status = ai8051 || ai32;
        auto& pins0 = status[wide_status && !uses_uart() ? 13 : 10];
        auto& pins1 = status[wide_status ? (uses_uart() ? 8 : 14) : 11];
        std::optional<bool> ai8051_system_enabled;
        std::optional<unsigned> ai8051_system_half_kib;
        const auto mode = config_.options.find("irc_adjust_mode");
        const bool compact_partition = generic_8bit && model_.family <= 52 &&
            (uses_uart() || config_.transport == "usb-soft");
        const bool keep_irc = (mode != config_.options.end() &&
            (mode->second == "last_trim" || mode->second == "internal_preset")) ||
            (irc_enabled != config_.options.end() && !bool_value(irc_enabled->second));
        if (!uses_uart() && irc_enabled != config_.options.end() && mode != config_.options.end())
            throw std::invalid_argument("set only one of irc_adjust_mode and irc_adjust_enabled");
        const auto apply_usb_irc = [&] {
            if (uses_uart() || keep_irc) return;
            if (mode == config_.options.end() && irc_enabled == config_.options.end() &&
                irc_hz == config_.options.end()) return;
            if (mode != config_.options.end() && mode->second != "dynamic")
                throw std::invalid_argument("irc_adjust_mode must be dynamic, internal_preset, or last_trim");
            const auto hz = irc_hz == config_.options.end() ? 24'000'000u : number_value(irc_hz->second);
            const auto bytes = usb_irc_value(model_, hz, status, status_size_);
            std::copy(bytes.begin(), bytes.end(), status.begin() + 1);
            hardware_options_write_required_ = true;
        };
        configure_dynamic_uart_irc();
        apply_usb_irc();
        if (generic_8bit) {
            // 48D238 collects these controls into the same raw slots used by
            // 44B760/44BBA7. Use the family descriptor for masks and polarity.
            static const std::map<std::string_view, uint16_t> controls{
                {"oscillator_gain_high", 0x0609}, {"por_reset_delay_long", 0x0611},
                {"reset_pin_as_io", 0x0616}, {"low_voltage_reset_enabled", 0x0617},
                {"low_voltage_threshold", 0x041B}, {"watchdog_por_enabled", 0x0619},
                {"watchdog_prescale", 0x041D}, {"watchdog_stop_idle", 0x061A},
                {"eeprom_disabled_at_low_voltage", 0x0618}, {"eeprom_erase_enabled", 0x0606},
                {"cold_start_p32_p33_required", 0x0607}, {"verify_system_code", 0x06F6},
                {"checksum_user_code", 0x06F7}, {"uart1_p37_push_pull", 0x0621},
                {"uart1_remap", 0x0623}, {"uart1_remap_p37_level", 0x0620},
                {"reset_pwm_port_open_drain", 0x0624}, {"reset_pin_level", 0x0628},
                {"usb_isp_enabled", 0x0678},
            };
            for (const auto& [name, value] : config_.options) {
                if (name == "flash_blank_value" || name == "modify_hardware_options" || name == "append_test_parameters" ||
                    is_rs485_option(name) || (name == "simulation_mode" && value == "none") ||
                    name == "swd_pins" || name == "uart_simulation_pins") continue;
                if ((name == "irc_adjust_mode" || name == "irc_hz") &&
                    (keep_irc || uart_irc_target_ || !uses_uart()))
                    continue;
                if (name == "irc_adjust_enabled") continue;
                if (name == "usb_isp_clock_source" && route == IspRoute::ai16) {
                    // 44B8E4 copies raw option 13 into configuration body 1F.
                    (void)parse_unsigned(value, 3);
                    hardware_options_write_required_ = true;
                    continue;
                }
                if (name == "eeprom_kib" && (compact_partition || has_fixed_63k_partition())) {
                    if (!(model_.flags & 8))
                        throw std::invalid_argument(model_.name + " has a fixed EEPROM partition");
                    // 4BE2A5 derives the program end from the combo index in 256-byte pages.
                    const auto separator = value.find('.');
                    const auto whole = parse_unsigned(value.substr(0, separator), 63);
                    const auto fraction = separator == std::string::npos ? "" : value.substr(separator + 1);
                    const int quarters = fraction.empty() || fraction == "0" ? 0 :
                        fraction == "25" ? 1 : fraction == "5" || fraction == "50" ? 2 :
                        fraction == "75" ? 3 : -1;
                    if (quarters < 0)
                        throw std::invalid_argument("eeprom_kib must be a multiple of 0.25");
                    const auto eeprom_bytes = whole * 1024 + static_cast<unsigned>(quarters) * 256;
                    const auto program_max = model_.total_size > eeprom_bytes ?
                        model_.total_size - eeprom_bytes : 0;
                    if (!program_max || program_max / 256 > 255 || program_max % 256)
                        throw std::invalid_argument("eeprom_kib must leave a representable program boundary");
                    status[16] = static_cast<uint8_t>(program_max / 256);
                    hardware_options_write_required_ = true;
                    continue;
                }
                const auto id = controls.find(name);
                const auto& table = hardware_options();
                const auto field = id == controls.end() ? table.end() :
                    std::find_if(table.begin(), table.end(), [&](const auto& item) {
                        return item.family == model_.family && item.control == id->second &&
                               item.flags != 0 && item.mask != 0;
                    });
                if (field == table.end())
                    throw std::invalid_argument(model_.name + " option is not implemented: " + name);
                uint8_t* target = nullptr;
                const bool ai16_usb = route == IspRoute::ai16 && !uses_uart();
                switch (field->raw_offset) {
                case 0: target = &status[ai16_usb ? 13 : 10]; break;
                case 1: target = &status[ai16_usb ? 14 : 11]; break;
                case 2: target = &status[15]; break;
                case 14: target = &status[9]; break;
                default:
                    throw std::invalid_argument(model_.name + " option has an unsupported layout: " + name);
                }
                if (field->control == 0x041B || field->control == 0x041D) {
                    const auto range = std::countr_zero(static_cast<unsigned>(field->mask));
                    const auto max = field->mask >> range;
                    unsigned code = 0;
                    if (field->control == 0x041B) {
                        code = parse_unsigned(value, max);
                        if (field->flags & 1) code = max - code;
                    } else {
                        const auto divisor = parse_unsigned(value, 2u << max);
                        if (divisor < 2 || !std::has_single_bit(divisor))
                            throw std::invalid_argument("watchdog_prescale must be a supported power of two");
                        code = std::countr_zero(divisor) - 1;
                    }
                    *target = static_cast<uint8_t>((*target & ~field->mask) | (code << range));
                } else if (field->control == 0x0628 || field->control == 0x0620) {
                    // 0628 is a checkbox for LOW; normalize to the actual
                    // level before applying the descriptor polarity.
                    const bool selected = (parse_unsigned(value, 1) != 0) ^ (field->control == 0x0628);
                    set_bit(*target, field->mask, selected != ((field->flags & 1) != 0));
                } else {
                    // 44B760/44BBA7 invert raw option 14 bit 1 on the way out.
                    const bool inverse = ((field->flags & 1) != 0) ^
                        (field->raw_offset == 14 && field->mask == 2);
                    set_bit(*target, field->mask, bool_value(value) != inverse);
                }
                hardware_options_write_required_ = true;
            }
            return;
        }
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options" ||
                is_rs485_option(name)) continue;
            if (name == "irc_adjust_enabled") continue;
            if (name == "irc_adjust_mode") {
                if (keep_irc || uart_irc_target_ || !uses_uart()) continue;
                throw std::invalid_argument(model_.name + " IRC adjustment mode is not implemented: " + value);
            }
            if (name == "irc_hz") {
                if (keep_irc || uart_irc_target_ || !uses_uart()) continue;
                throw std::invalid_argument(model_.name + " IRC frequency adjustment is not implemented");
            } else if (name == "eeprom_kib") {
                if (!(model_.flags & 8))
                    throw std::invalid_argument(model_.name + " has a fixed EEPROM partition");
                if (ai8051) {
                    const auto kib = number_value(value);
                    if (kib == 0 || kib > 32 || (kib & (kib - 1)))
                        throw std::invalid_argument("AI8051U eeprom_kib must be 1, 2, 4, 8, 16, or 32 for a program download");
                    status[16] = static_cast<uint8_t>(kib - 1);
                } else if (model_.family == 76) {
                    const auto kib = number_value(value);
                    if (kib == 0 || kib >= model_.total_size / 1024)
                        throw std::invalid_argument("AI32G12 EEPROM must leave room for the program");
                    status[16] = static_cast<uint8_t>(kib - 1);
                } else {
                    // H8U stores the remaining program boundary in 256-byte pages.
                    const auto separator = value.find('.');
                    const auto whole = parse_unsigned(value.substr(0, separator), 63);
                    const auto fraction = separator == std::string::npos ? "" : value.substr(separator + 1);
                    const auto quarters = fraction.empty() || fraction == "0" ? 0 :
                        fraction == "25" ? 1 : fraction == "5" || fraction == "50" ? 2 :
                        fraction == "75" ? 3 : -1;
                    if (quarters < 0)
                        throw std::invalid_argument("eeprom_kib must be a multiple of 0.25");
                    const auto bytes = whole * 1024 + quarters * 256;
                    if (bytes < 512 || bytes >= model_.total_size)
                        throw std::invalid_argument("eeprom_kib must leave room for the program");
                    status[16] = static_cast<uint8_t>((model_.total_size - bytes) / 256);
                }
            } else if (name == "clock_gain") {
                if (value != "high" && value != "low")
                    throw std::invalid_argument("clock_gain must be high or low");
                set_bit(pins0, 0x02, value == "high");
            } else if (name == "oscillator_gain_high") set_bit(pins0, 0x02, bool_value(value));
            else if (name == "oscillator_gain_reduced") set_bit(pins0, 0x02, !bool_value(value));
            else if (name == "por_reset_delay_long") set_bit(pins0, 0x80, bool_value(value));
            else if (name == "reset_pin_as_io") set_bit(pins1, 0x10, !bool_value(value));
            else if (name == "reset_pin_enabled") set_bit(pins1, 0x10, bool_value(value));
            else if (name == "low_voltage_reset" || name == "low_voltage_reset_enabled")
                set_bit(pins1, 0x40, !bool_value(value));
            else if (name == "low_voltage_threshold") {
                const auto threshold = parse_unsigned(value, 3);
                pins1 = static_cast<uint8_t>((pins1 & 0xFC) | (3 - threshold));
            } else if (name == "watchdog_por_enabled") set_bit(status[15], 0x20, !bool_value(value));
            else if (name == "watchdog_stop_idle") set_bit(status[15], 0x08, !bool_value(value));
            else if (name == "watchdog_prescale") {
                const auto divisor = parse_unsigned(value, 256);
                if (divisor < 2 || (divisor & (divisor - 1)))
                    throw std::invalid_argument("watchdog_prescale must be a power of two from 2 to 256");
                unsigned bits = 0;
                for (auto n = divisor; n > 2; n >>= 1) ++bits;
                status[15] = static_cast<uint8_t>((status[15] & 0xF8) | bits);
            } else if (name == "eeprom_erase_enabled") set_bit(status[9], 0x02, bool_value(value));
            else if (name == "cold_start_p32_p33_required" || name == "bsl_pindetect_enabled")
                set_bit(status[9], 0x01, !bool_value(value));
            else if (name == "verify_system_code") set_bit(status[9], 0x40, bool_value(value));
            else if (name == "checksum_user_code") set_bit(status[9], 0x20, !bool_value(value));
            else if (name == "cpu_mode" && ai8051) {
                if (value != "8" && value != "32") throw std::invalid_argument("cpu_mode must be 8 or 32");
                set_bit(status[15], 0x40, value == "32");
            } else if (name == "user_system_enabled" && ai8051) {
                ai8051_system_enabled = bool_value(value);
            } else if (name == "user_system_kib" && ai8051) {
                const auto dot = value.find('.');
                const auto whole = parse_unsigned(value.substr(0, dot), 64);
                const auto fraction = dot == std::string::npos ? "0" : value.substr(dot + 1);
                const bool half = fraction == "5" || fraction == "50";
                if ((!half && fraction != "0" && fraction != "00") || (whole == 64 && half))
                    throw std::invalid_argument("AI8051U user_system_kib must be 0..64 in 0.5 KiB steps");
                ai8051_system_half_kib = whole * 2 + half;
            } else if (name == "wtst_initial_value" && model_.family == 84) {
                (void)parse_unsigned(value, 4);
            } else if ((model_.family == 86 || model_.family == 87 || model_.family == 90) &&
                       (name == "p54_as_p12" || name == "swap_p10_p11")) {
                set_bit(pins0, name == "p54_as_p12" ? 0x20 : 0x10, !bool_value(value));
            } else if (name == "user_system_enabled" && model_.family == 90) {
                set_bit(pins1, 0x80, !bool_value(value));
            } else if ((name == "simulation_mode" && value == "none") ||
                       name == "swd_pins" || name == "uart_simulation_pins") {
                continue;
            } else {
                throw std::invalid_argument(model_.name + " option is not implemented: " + name);
            }
            hardware_options_write_required_ = true;
        }
        if (ai8051_system_enabled || ai8051_system_half_kib) {
            const bool enabled = ai8051_system_enabled.value_or(ai8051_system_half_kib.value_or(0) != 0);
            set_bit(pins1, 0x80, !enabled);
            if (enabled) {
                // 48C6CB counts 512-byte sizes down from 64 KiB and stores the starting page.
                if (ai8051_system_half_kib && *ai8051_system_half_kib > 0)
                    status[51] = static_cast<uint8_t>(256 - 2 * *ai8051_system_half_kib);
                else if (ai8051_system_half_kib || (status[51] & 1))
                    throw std::invalid_argument("enabling the AI8051U system area requires user_system_kib");
            }
        }
        return;
    }
    if (route == IspRoute::modern_8bit_uart || route == IspRoute::stc8u_usb ||
        route == IspRoute::ai16) {
        for (const auto& [name, value] : config_.options) {
            if (name == "flash_blank_value" || name == "modify_hardware_options") continue;
            if (name == "irc_adjust_mode" && value == "last_trim") continue;
            if (name == "simulation_mode" && value == "none") continue;
            if (!modify_hardware_options_ && name != "simulation_mode") continue;
            throw std::invalid_argument("hardware option write is not implemented for " + model_.name + ": " + name);
        }
        return;
    }
    if (route != IspRoute::f8d1)
        throw std::logic_error("hardware options requested without an ISP route");
    auto& status = *status_;
    std::array<uint8_t, 5> msr{status[9], status[13], status[14], status[15], status[16]};
    if (!modify_hardware_options_) {
        for (const auto& [name, value] : config_.options) {
            if (name == "usb_ice_enabled") {
                const bool enabled = bool_value(value);
                const bool current_enabled = (msr[3] & 0x80) == 0;
                if (current_enabled != enabled) {
                    set_bit(msr[3], 0x80, !enabled);
                    hardware_options_write_required_ = true;
                }
            } else if (name == "simulation_mode") {
                if (value != "none" && value != "usb" && value != "swd") {
                    throw std::invalid_argument(
                        "STC32G144K246 simulation_mode must be none, usb, or swd");
                }
                const bool current_usb = (status[12] & 0x20) == 0;
                const bool current_swd = (status[11] & 0x20) == 0;
                const bool requested_usb = value == "usb";
                const bool requested_swd = value == "swd";
                if (current_usb != requested_usb || current_swd != requested_swd) {
                    set_bit(status[12], 0x20, !requested_usb);
                    set_bit(status[11], 0x20, !requested_swd);
                    hardware_options_write_required_ = true;
                }
                if (config_.transport == "link1d") {
                    const auto previous = msr[3];
                    set_bit(msr[3], 0x80, !requested_usb);
                    hardware_options_write_required_ |= previous != msr[3];
                }
                if (requested_swd) {
                    if (const auto pins = config_.options.find("swd_pins"); pins != config_.options.end()) {
                        const auto previous = status[11];
                        status[11] = (status[11] & 0x3F) | simulation_pin_bits(pins->second);
                        hardware_options_write_required_ |= previous != status[11];
                    }
                }
            }
        }
        status[15] = msr[3];
        return;
    }
    bool irc_frequency_is_active = true;
    configure_dynamic_uart_irc();
    if (const auto it = config_.options.find("irc_adjust_mode"); it != config_.options.end()) {
        if (it->second == "internal_preset" || it->second == "last_trim") {
            irc_frequency_is_active = false;
        } else if (it->second != "dynamic") {
            throw std::invalid_argument(
                "irc_adjust_mode must be dynamic, internal_preset, or last_trim");
        }
    }
    std::optional<bool> user_system_enabled_override;
    std::optional<uint32_t> user_system_kib_override;
    for (const auto& [name, value] : config_.options) {
        if (name == "flash_blank_value" || name == "modify_hardware_options" ||
            is_rs485_option(name)) {
            continue;
        } else if (name == "cpu_mode") {
            const auto mode = number_value(value);
            if (mode != 8 && mode != 32) throw std::invalid_argument("cpu_mode must be 8 or 32");
            set_bit(msr[3], 0x40, mode == 32);
        }
        else if (name == "clock_gain" || name == "oscillator_gain_high") {
            set_bit(msr[1], 0x02, value == "high" ||
                                     (value != "low" && bool_value(value)));
        } else if (name == "oscillator_gain_reduced") {
            set_bit(msr[1], 0x02, !bool_value(value));
        } else if (name == "reset_pin_enabled") {
            set_bit(msr[2], 0x10, bool_value(value));
        } else if (name == "reset_pin_as_io") {
            set_bit(msr[2], 0x10, !bool_value(value));
        }
        else if (name == "watchdog_por_enabled") set_bit(msr[3], 0x20, !bool_value(value));
        else if (name == "watchdog_stop_idle") set_bit(msr[3], 0x08, !bool_value(value));
        else if (name == "watchdog_prescale") {
            const uint32_t prescale = number_value(value);
            if (prescale < 2 || prescale > 256 || (prescale & (prescale - 1)) != 0)
                throw std::invalid_argument("watchdog_prescale must be a power of two from 2 to 256");
            unsigned shift = 0;
            for (uint32_t current = prescale; current > 2; current >>= 1) ++shift;
            msr[3] = static_cast<uint8_t>((msr[3] & 0xF8) | shift);
        } else if (name == "low_voltage_reset" || name == "low_voltage_reset_enabled") {
            set_bit(msr[2], 0x40, !bool_value(value));
        }
        else if (name == "low_voltage_threshold") {
            const auto threshold = number_value(value);
            if (threshold > 3) throw std::invalid_argument("low_voltage_threshold must be 0..3");
            msr[2] = static_cast<uint8_t>((msr[2] & 0xFC) | (3 - threshold));
        } else if (name == "eeprom_erase_enabled") set_bit(msr[0], 0x02, bool_value(value));
        else if (name == "bsl_pindetect_enabled" || name == "cold_start_p32_p33_required")
            set_bit(msr[0], 0x01, !bool_value(value));
        else if (name == "por_reset_delay") set_bit(msr[1], 0x80, value == "long");
        else if (name == "por_reset_delay_long") set_bit(msr[1], 0x80, bool_value(value));
        else if (name == "uart1_remap") set_bit(msr[1], 0x40, bool_value(value));
        else if (name == "download_password_enabled") set_bit(msr[0], 0x08, !bool_value(value));
        else if (name == "usb_isp_enabled") set_bit(msr[0], 0x10, bool_value(value));
        else if (name == "verify_system_code") set_bit(msr[0], 0x40, bool_value(value));
        else if (name == "checksum_user_code") set_bit(msr[0], 0x20, !bool_value(value));
        else if (name == "eeprom_enabled") set_bit(status[11], 0x01, !bool_value(value));
        else if (name == "eeprom_disabled") set_bit(status[11], 0x01, bool_value(value));
        else if (name == "usb_simulation_enabled") set_bit(status[12], 0x20, !bool_value(value));
        else if (name == "swd_enabled") set_bit(status[11], 0x20, !bool_value(value));
        else if (name == "usb_ice_enabled") set_bit(msr[3], 0x80, !bool_value(value));
        else if (name == "cold_start_pin_check" || name == "cold_start_p10_p11_required") {
            set_bit(msr[3], 0x01, bool_value(value));
        }
        else if (name == "eeprom_kib") {
            const auto kib = number_value(value);
            if (kib < 2 || kib > 246 || kib % 2) throw std::invalid_argument("eeprom_kib must be 2..246 in 2 KiB steps");
            msr[4] = static_cast<uint8_t>(kib / 2 - 1);
        } else if (name == "user_system_enabled") {
            user_system_enabled_override = bool_value(value);
        } else if (name == "user_system_kib") {
            user_system_kib_override = number_value(value);
        } else if (name == "irc_adjust_mode") {
            // AiCube opt[15] is host policy, not the on-chip status[15] byte.
            continue;
        } else if (name == "irc_hz") {
            const auto hz = number_value(value);
            if (hz != 0 && irc_frequency_is_active && !uses_uart()) {
                const auto bytes = irc_value(hz);
                std::copy(bytes.begin(), bytes.end(), status.begin() + 1);
            }
        } else if (name == "simulation_mode") {
            if (value != "none" && value != "usb" && value != "swd") {
                throw std::invalid_argument(
                    "STC32G144K246 simulation_mode must be none, usb, or swd");
            }
            // Both bits are active-low in the F8D1 status/configuration block.
            // USB and SWD are mutually exclusive; none disables both.
            set_bit(status[12], 0x20, value != "usb");
            set_bit(status[11], 0x20, value != "swd");
            if (config_.transport == "link1d") set_bit(msr[3], 0x80, value != "usb");
        } else if (name == "uart_ice_pins" || name == "uart_simulation_pins") {
            throw std::invalid_argument(
                "STC32G144K246 does not support serial simulation; use SWD or USB simulation");
        } else if (name == "swd_pins") {
            const std::map<std::string, uint8_t> pairs = {
                {"p3.0-p3.1", 0}, {"p3.6-p3.7", 1},
                {"p1.6-p1.7", 2}, {"p4.3-p4.4", 3}};
            uint8_t pair_value = 0;
            const auto pair = pairs.find(value);
            if (pair != pairs.end()) {
                pair_value = pair->second;
            } else {
                const auto numeric = number_value(value);
                if (numeric > 3) throw std::invalid_argument("simulation pin pair must be 0..3");
                pair_value = static_cast<uint8_t>(numeric);
            }
            uint8_t& target = name == "swd_pins" ? status[11] : status[12];
            target = static_cast<uint8_t>((target & 0x3F) | (pair_value << 6));
        } else if (name.rfind("raw_msr", 0) == 0) {
            const size_t index = static_cast<size_t>(number_value(name.substr(7)));
            if (index >= msr.size()) throw std::invalid_argument("raw_msr index out of range");
            msr[index] = static_cast<uint8_t>(parse_unsigned(value, UINT8_MAX));
        } else {
            throw std::invalid_argument("unknown STC32G144K246 option: " + name);
        }
    }
    if (user_system_enabled_override.has_value() || user_system_kib_override.has_value()) {
        const bool enabled = user_system_enabled_override.value_or(
            user_system_kib_override.value_or(0) != 0);
        if (!enabled) {
            set_bit(msr[2], 0x80, true);
            status[51] = 0xFF;
        } else if (user_system_kib_override.has_value()) {
            const auto kib = *user_system_kib_override;
            if (kib == 0 || kib > 246 || kib % 2)
                throw std::invalid_argument("user_system_kib must be 0 or an even size");
            set_bit(msr[2], 0x80, false);
            status[51] = static_cast<uint8_t>(kib / 2 - 1);
        } else {
            set_bit(msr[2], 0x80, false);
        }
    }
    status[9] = msr[0];
    status[13] = msr[1];
    status[14] = msr[2];
    status[15] = msr[3];
    status[16] = msr[4];
}

std::vector<uint8_t> Programmer::build_f8d1_options() const {
    const auto& status = *status_;
    std::vector<uint8_t> packet(46, 0xFF);
    packet[0] = 0x04; packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x5A; packet[4] = 0xA5;
    packet[8] = 0; packet[11] = 0; packet[27] = 0;
    std::copy(status.begin() + 1, status.begin() + 17, packet.begin() + 29);
    packet[37] = status[9];
    std::copy(status.begin() + 13, status.begin() + 17, packet.begin() + 41);
    packet[45] = status[51];
    return packet;
}

std::vector<uint8_t> Programmer::build_stc8u_options() const {
    const auto& status = *status_;

    std::vector<uint8_t> packet{4, 0, 0, 0x5A, 0xA5};
    packet.resize(45, 0xFF);
    packet[8] = packet[11] = packet[27] = 0;
    std::copy_n(status.begin() + 1, 7, packet.begin() + 29);
    packet[37] = status[9];
    packet[40] = status[12];
    packet[41] = status[10];
    // 44B94A: H8U BSL before 7.4 inverts the corresponding pin bit.
    packet[42] = model_.family == 61 && status[17] < 0x74 ? status[11] ^ 0x10 : status[11];
    packet[43] = status[15] | 0x80;
    if (model_.flags & 8) packet[44] = status[16];
    set_download_rs485(packet);
    return packet;
}

std::vector<uint8_t> Programmer::build_ai8051_options() const {
    const auto& status = *status_;

    // Family 88 adds a system-area byte and returns the port options at
    // different status offsets on UART and native USB.
    std::vector<uint8_t> packet{4, 0, 0, 0x5A, 0xA5};
    packet.resize(46, 0xFF);
    packet[8] = packet[11] = packet[27] = 0;
    std::copy_n(status.begin() + 1, 7, packet.begin() + 29);
    packet[37] = status[9];
    packet[39] = status[11] | 0x20;
    packet[40] = status[12];
    packet[41] = status[uses_uart() ? 10 : 13];
    packet[42] = status[uses_uart() ? 8 : 14];
    packet[43] = status[15] | 0x80;
    if (model_.flags & 8) packet[44] = status[16];
    packet[45] = status[51];
    set_download_rs485(packet);
    return packet;
}

std::vector<uint8_t> Programmer::build_ai32_options() const {
    const auto& status = *status_;
    std::vector<uint8_t> packet{4, 0, 0, 0x5A, 0xA5};
    packet.resize(45, 0xFF);
    packet[8] = packet[11] = packet[27] = 0;
    std::copy_n(status.begin() + 1, 7, packet.begin() + 29);
    if (model_.family == 84) {
        const auto hz = (uint32_t{status[1]} << 24) | (uint32_t{status[2]} << 16) |
                        (uint32_t{status[3]} << 8) | status[4];
        const auto requested = config_.options.find("wtst_initial_value");
        packet[28] = requested != config_.options.end() && modify_hardware_options_ ?
            static_cast<uint8_t>(parse_unsigned(requested->second, 4)) :
            static_cast<uint8_t>(hz > 52'520'000 ? 2 : 1);
    }
    packet[37] = status[9];
    packet[39] = status[11] | 0x20;
    packet[40] = status[12];
    packet[41] = status[uses_uart() ? 10 : 13];
    packet[42] = status[uses_uart() ? 8 : 14];
    packet[43] = status[15] | 0x80;
    if (model_.flags & 8) packet[44] = status[16];
    set_download_rs485(packet);
    return packet;
}

std::vector<uint8_t> Programmer::build_generic_8bit_options() const {
    const auto& status = *status_;
    // 44BBA7 (families 45–52) and 44B82D share this body size.
    std::vector<uint8_t> packet{4, 0, 0, 0x5A, 0xA5};
    packet.resize(45, 0xFF);
    packet[8] = packet[11] = packet[27] = 0;
    std::copy_n(status.begin() + 1, 7, packet.begin() + 29);
    if (model_.family == 70) {
        if (const auto it = config_.options.find("usb_isp_clock_source");
            modify_hardware_options_ && it != config_.options.end())
            packet[36] = static_cast<uint8_t>(parse_unsigned(it->second, 3) | 0xFC);
    }
    packet[37] = status[9];
    const bool ai16_usb = model_.family == 70 && !uses_uart();
    packet[41] = status[ai16_usb ? 13 : 10];
    packet[42] = status[ai16_usb ? 14 : 11];
    packet[43] = model_.family <= 52 ? status[15] : status[15] | 0x80;
    if (model_.flags & 8) packet[44] = status[16];
    set_download_rs485(packet);
    return packet;
}

std::vector<uint8_t> Programmer::build_stc15_options() const {
    const auto& status = *status_;
    const bool stc15e_layout = model_.family == 25 || model_.family == 28;
    if (stc15e_layout && !legacy_irc_result_)
        throw std::logic_error("STC15E options require measured trim values");
    if (stc15e_layout && status[17] < 0x71) {
        std::vector<uint8_t> packet(20, 0xFF);
        packet[0] = 0x8D;
        packet[1] = (legacy_options_[0] | 0x80) ^ 0x10;
        packet[2] = legacy_options_[1] ^ 0x07;
        packet[3] = legacy_options_[2];
        packet[4] = legacy_irc_result_->program_band;
        packet[5] = legacy_irc_result_->program_trim;
        packet[13] = legacy_options_[14];
        return packet;
    }
    const auto raw_selector = uart_selector(model_);
    const bool selector4 = raw_selector == 4;
    const bool soft_usb = config_.transport == "usb-soft";
    const auto io_status = selector4 ? status[status[17] >= 0x72 ? 49 : 41] : status[7];
    const bool no_live_trim = legacy_clock_uses_measured_ || (io_status & 1) == 0;
    const auto measured = (uint32_t{status[13]} << 8) | status[14];
    const uint32_t saved_freq = (uint32_t{status[8]} << 24) | (uint32_t{status[9]} << 16) |
        (uint32_t{status[10]} << 8) | status[11];
    const uint32_t freq = soft_usb ? saved_freq : legacy_irc_result_ ? legacy_irc_result_->program_hz :
        selector4 ? (65536u - measured) * 4u * config_.handshake_baud :
        no_live_trim ? measured * config_.handshake_baud : saved_freq;
    std::vector<uint8_t> packet{4, 0, 0};
    if (soft_usb || status[17] >= 0x72) packet.insert(packet.end(), {0x5A, 0xA5});
    const auto header = packet.size();
    packet.resize(header + 64, 0xFF);
    auto body = std::span(packet).subspan(header);
    // 44BA6A: 64-byte legacy body with interleaved frequency.
    body[3] = body[6] = body[22] = 0;
    for (unsigned i = 0; i < 4; ++i)
        body[23 + 2 * i] = static_cast<uint8_t>(freq >> (24 - 8 * i));
    body[31] = static_cast<uint8_t>((legacy_options_[14] | 0x0C) ^ 0x02);
    body[32] = 1;
    body[55] = legacy_options_[8];
    body[59] = soft_usb ? status[38] : legacy_irc_result_ ? legacy_irc_result_->program_trim :
        no_live_trim ? (selector4 ? status[26] : status[4]) : status[38];
    body[60] = (soft_usb ? status[39] : legacy_irc_result_ ? legacy_irc_result_->program_band :
        no_live_trim ? 0x40 : status[39]) | 0x3F;
    body[61] = legacy_options_[2];
    body[62] = legacy_options_[1];
    body[63] = legacy_options_[0];
    if (stc15e_layout) {
        body[31] = legacy_options_[14] | 0x0C;
        body[32] = 0xFF;
        body[62] ^= 0x07;
        body[63] = (body[63] | 0x80) ^ 0x10;
    }
    return packet;
}

void Programmer::set_download_rs485(std::vector<uint8_t>& packet) const {
    // 44B77D packs the direction levels and pin codes independently of
    // the target's active-low enable bit in the normal 04 request.
    const auto enable = config_.options.find("rs485_enabled");
    if (!modify_hardware_options_ || enable == config_.options.end()) {
        if (!(packet[37] & 4))
            throw std::invalid_argument("supply the existing ISP RS485 pins and polarities before rewriting hardware options");
        return;
    }
    const auto enabled = bool_value(enable->second);
    set_bit(packet[37], 0x04, !enabled);
    if (!enabled) return;
    packet[8] = bool_value(config_.options.at("rs485_rx_active_high")) ? 0x10 : 0;
    packet[9] = rs485_pin(config_.options.at("rs485_rx_pin"));
    packet[11] = bool_value(config_.options.at("rs485_tx_active_high")) ? 0x10 : 0;
    packet[12] = rs485_pin(config_.options.at("rs485_tx_pin"));
}

void Programmer::write_download_options(std::vector<uint8_t> packet) {
    if (packet.empty()) return;
    const auto next = password_bytes(config_.next_password);
    if (!next.empty()) {
        // 44B760 writes the next password length and clears the active-low
        // password flag before the separate 07 request carries the bytes.
        packet[27] = static_cast<uint8_t>(next.size());
        packet[37] &= 0xF7;
    }
    const auto& status = *status_;
    const bool password_first = uses_uart() && !next.empty() &&
        (status[17] == 0x72 || status[17] == 0x73) && status[22] < 2;
    const auto send_password = [&](bool intermediate) {
        std::vector<uint8_t> command{7, 0, 0, 0x5A, 0xA5};
        command.insert(command.end(), next.begin(), next.end());
        request(command, intermediate ? std::vector<uint8_t>{7} : std::vector<uint8_t>{7, 0x54},
                "next download password");
    };
    if (password_first) {
        // 443E16: early 7.2/7.3 sends 07 first and checks only the opcode.
        send_password(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    request(packet, uses_uart() && !password_first ? std::vector<uint8_t>{4} :
            std::vector<uint8_t>{4, 0x54}, "hardware options");
    if (!next.empty() && !password_first) send_password(false);
}

void Programmer::prepare_test_parameters(const HexImage& image, uint32_t code_end) {
    const auto& status = *status_;
    const auto version = status[17];
    const bool software_usb = config_.transport == "usb-soft";
    if (version >= 0x74 && model_.family >= 45 && status[22] >= 4)
        return;  // AiCube 44B015 leaves the program unchanged for this BSL.
    if (status_size_ <= 36 || (version >= 0x73 && model_.family >= 45 &&
        ((version == 0x73 && status[22] >= 12) || version >= 0x74) && status_size_ <= 49))
        throw std::invalid_argument("target status is missing the fields needed to append test parameters");
    if (config_.encrypted_image && version < 0x72)
        throw std::invalid_argument("cannot append test parameters to a legacy encrypted program image");

    // 44AA08/44AEDE choose the footer layout; the values are live BSL test data.
    std::vector<uint8_t> bytes{0, 0, 0x75, 0xC7, 0x20};
    if (version < 0x72 || model_.family < 45) {
        const unsigned rc = !software_usb && uart_selector(model_) == 4 ? 23 : 1;
        bytes.insert(bytes.end(), {status[rc + 3], status[28], 0x40, status[rc + 2],
                                   status[29], 0x80, status[rc], status[rc + 1]});
    } else {
        if (version >= 0x74) bytes.insert(bytes.end(), {status[30], status[29], status[28], status[27]});
        else if (version == 0x73 && status[22] >= 12)
            bytes.insert(bytes.end(), {status[29], status[28]});
        if (version >= 0x74 || (version == 0x73 && status[22] >= 12)) {
            for (size_t i = 49; i >= 42; --i) bytes.push_back(status[i]);
        }
        bytes.insert(bytes.end(), {status[26], status[25], status[23], status[24]});
    }
    bytes.insert(bytes.end(), {status[35], status[36]});
    const auto reserved = *model_.test_parameter_reserve;
    if (reserved > model_.code_size)
        throw std::invalid_argument("test parameters do not fit within the current program partition");
    const auto end = model_.code_size - reserved;
    if (end < bytes.size() || end > code_end)
        throw std::invalid_argument("test parameters do not fit within the current program partition");
    const auto address = end - static_cast<uint32_t>(bytes.size());
    const auto occupied = image.bytes.lower_bound(address);
    if (occupied != image.bytes.end() && occupied->first < end)
        throw std::invalid_argument("test parameters overlap the supplied image or UID binding");
    test_parameter_patch_ = TestParameterPatch{address, std::move(bytes)};
}

void Programmer::write_test_parameters() {
    if (!test_parameter_patch_ || (*status_)[17] < 0x72) return;
    const auto& [address, bytes] = *test_parameter_patch_;
    const bool banked_header = (*status_)[17] >= 0x75;
    std::vector<uint8_t> packet{2, static_cast<uint8_t>(address >> 8), static_cast<uint8_t>(address),
        static_cast<uint8_t>(banked_header ? address >> 24 : 0x5A),
        static_cast<uint8_t>(banked_header ? address >> 16 : 0xA5)};
    packet.insert(packet.end(), bytes.begin(), bytes.end());
    request(packet, {2, 0x54}, "write test parameters");
}

void Programmer::write_user_key() {
    if (user_key_.empty()) return;
    // 443030 and 44CBB6 send four 64-byte blocks after erase and before code.
    for (size_t offset = 0; offset < user_key_.size(); offset += 64) {
        std::vector<uint8_t> command{static_cast<uint8_t>(offset ? 0x06 : 0x26),
                                     0, static_cast<uint8_t>(offset), 0x5A, 0xA5};
        command.insert(command.end(), user_key_.begin() + offset, user_key_.begin() + offset + 64);
        request(command, {0x06, 0x54}, "write user key");
    }
}

void Programmer::validate_uid_regions(std::initializer_list<FlashRegion> regions) const {
    for (const auto& binding : uid_bindings_) {
        if (std::none_of(regions.begin(), regions.end(), [&](const auto& region) {
            return binding.address >= region.base &&
                uint64_t{binding.address - region.base} + 7 <= region.data.size();
        })) throw std::invalid_argument("UID address is outside the writable image regions");
    }
}

void Programmer::reserve_uid_destinations(HexImage& image, uint32_t reset) const {
    for (const auto& binding : uid_bindings_) {
        if (binding.address < reset + 3 && binding.address + 7 > reset)
            throw std::invalid_argument("UID binding overlaps the reset entry");
        for (uint32_t offset = 0; offset < 7; ++offset) image.bytes[binding.address + offset] = 0;
    }
}

void Programmer::apply_erase_uid(const std::vector<uint8_t>& reply,
                                 std::initializer_list<FlashRegion> regions) const {
    if (allowed_uids_.empty() && uid_bindings_.empty()) return;
    // AiCube 4425D0 compares the seven bytes following the erase ACK.
    std::array<uint8_t, 7> uid{};
    if (reply.size() < uid.size() + 1)
        throw std::runtime_error("擦除应答不含完整 UID，已停止写入");
    std::copy_n(reply.begin() + 1, uid.size(), uid.begin());
    if (!allowed_uids_.empty() && !std::binary_search(allowed_uids_.begin(), allowed_uids_.end(), uid))
        throw std::runtime_error("芯片 UID 不在名单中，已停止写入（程序区可能已擦除）");
    // 442630 transforms each original UID byte independently for each configured address.
    for (const auto& binding : uid_bindings_) {
        const auto region = std::find_if(regions.begin(), regions.end(), [&](const auto& candidate) {
            return binding.address >= candidate.base &&
                uint64_t{binding.address - candidate.base} + uid.size() <= candidate.data.size();
        });
        if (region == regions.end()) throw std::logic_error("UID image region was not validated");
        auto data = region->data.subspan(binding.address - region->base, uid.size());
        for (size_t i = 0; i < uid.size(); ++i) {
            auto byte = uid[i];
            for (const auto& [op, operand] : binding.operations) {
                switch (op) {
                case UidOperation::add: byte = static_cast<uint8_t>(byte + operand); break;
                case UidOperation::multiply: byte = static_cast<uint8_t>(byte * operand); break;
                case UidOperation::divide: byte = static_cast<uint8_t>(byte / operand); break;
                case UidOperation::xor_byte: byte ^= operand; break;
                }
            }
            data[i] = byte;
        }
    }
}

void Programmer::apply_short_uart_erase_uid(const std::vector<uint8_t>& reply,
                                            std::initializer_list<FlashRegion> regions) const {
    if (allowed_uids_.empty() && uid_bindings_.empty()) return;
    if ((*status_)[17] > 0x62) return apply_erase_uid(reply, regions);
    // 442ED4: the short erase response on these BSLs has no UID.
    const auto& status = *status_;
    std::vector<uint8_t> uid_reply{reply.front()};
    uid_reply.insert(uid_reply.end(), status.begin() + 31, status.begin() + 38);
    apply_erase_uid(uid_reply, regions);
}

Stc32Image Programmer::load_stc32_image(const HexImage& hex, uint32_t eeprom_end) const {
    for (uint32_t address = kCodeBase; address < kCodeBase + 3; ++address) {
        if (!hex.bytes.contains(address)) {
            throw std::invalid_argument("HEX does not contain the FF0000 reset entry");
        }
    }
    auto image = split_stc32_image(hex, eeprom_end, image_fill_value_);
    if (image.program.size() < 128) throw std::invalid_argument("HEX does not contain a complete first code block");
    return image;
}

void Programmer::write_region(uint32_t physical_base, const std::vector<uint8_t>& data,
                              uint8_t first_command, uint8_t continuation_command,
                              uint32_t relative_base,
                              uint64_t& written,
                              const std::function<void(uint64_t)>& report_progress) {
    for (size_t offset = 0; offset < data.size(); offset += kBlockSize) {
        const uint32_t address = physical_base + static_cast<uint32_t>(offset);
        const uint32_t relative = address - relative_base;
        const auto command = static_cast<uint8_t>((offset == 0 ? first_command : continuation_command) |
                                                  (config_.encrypted_image ? 0x80 : 0));
        std::vector<uint8_t> payload = {command, static_cast<uint8_t>(relative >> 8),
                                        static_cast<uint8_t>(relative),
                                        0x00, static_cast<uint8_t>(relative >> 16)};
        payload.insert(payload.end(), data.begin() + static_cast<std::ptrdiff_t>(offset),
                       data.begin() + static_cast<std::ptrdiff_t>(std::min(offset + kBlockSize, data.size())));
        payload.resize(5 + kBlockSize, 0xFF);
        request(payload, {0x02, 0x54}, "write block", config_.timeout_ms);
        written += kBlockSize;
        report_progress(written);
    }
}

std::vector<uint8_t> Programmer::password_bytes(const std::string& value) {
    if (value.size() > 63) throw std::invalid_argument("password is limited to 63 bytes");
    return {value.begin(), value.end()};
}

void Programmer::initialize_measured_uart() {
    const auto& status = *status_;
    // 44F079 preserves trim. 441F42 chooses the 1T or 4T reload layout.
    const uint64_t clock = legacy_irc_result_ ? legacy_irc_result_->transfer_hz :
        uint64_t{uart_clock_count_} * static_cast<unsigned>(config_.handshake_baud);
    const bool timer1 = ((model_.flags >> 9) & 7) == 1;
    const int baud = config_.make_simulation ? config_.baud :
        select_measured_uart_baud(clock, config_.baud, timer1, link1d_ != nullptr);
    const auto ticks = static_cast<double>(clock) / ((timer1 ? 4.0 : 1.0) * baud);
    if (ticks < (config_.make_simulation ? 2.0 : 1.5) ||
        ticks > (config_.make_simulation ? 32767.5 : 65535.0))
        throw std::invalid_argument("target clock cannot use requested transfer baud");
    const auto divisor = std::lround(ticks);
    if (std::abs(ticks / divisor - 1) >= 0.01)
        throw std::invalid_argument("transfer baud would exceed the target's 1% tolerance");
    const auto reload = static_cast<uint16_t>(65536 - divisor);
    const auto secondary = timer1 ? uint16_t{} : static_cast<uint16_t>(0 - std::lround(1.5 * ticks));
    const auto iap = model_.family < 53 ? legacy_iap_wait(clock) :
        static_cast<uint8_t>(0x80 | std::min<uint64_t>(63, (clock + 500000) / 1000000));
    request({0x01, legacy_irc_result_ ? legacy_irc_result_->transfer_trim : status[4],
             legacy_irc_result_ ? legacy_irc_result_->transfer_band : uint8_t{0x40},
             static_cast<uint8_t>(reload >> 8),
             static_cast<uint8_t>(reload), static_cast<uint8_t>(secondary >> 8),
             static_cast<uint8_t>(secondary), iap},
            {0x01}, "set UART baud");
    transport_->set_baud(baud);
    if (baud != config_.baud) std::cout << "串口实际传输波特率：" << baud << '\n';
}

std::vector<uint8_t> Programmer::request_uart_irc(const std::vector<uint8_t>& probe, uint8_t trigger) {
    send_frame(probe);
    if (link1d_) return read_frame(5000);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (true) {
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TransportTimeout("UART IRC measurement timeout");
        transport_->write({trigger});
        try {
            return read_frame(std::min<int>(static_cast<int>(remaining),
                config_.handshake_baud == 1200 ? 150 : 25));
        } catch (const TransportTimeout&) {}
    }
}

std::vector<int64_t> Programmer::measure_uart_irc(const std::vector<uint8_t>& probe, uint8_t trigger,
                                                 unsigned multiplier, unsigned divisor) {
    const auto response = request_uart_irc(probe, trigger);
    if (response.size() != probe.size() || response.front() != (probe.front() & 0x0F))
        throw std::runtime_error("unexpected UART IRC measurement response");
    std::vector<int64_t> frequencies;
    for (size_t i = 2; i < response.size(); i += 2) {
        const auto count = (unsigned{response[i]} << 8) | response[i + 1];
        if (!count) throw std::runtime_error("empty UART IRC measurement");
        frequencies.push_back(int64_t{count} * config_.handshake_baud * multiplier / divisor);
    }
    return frequencies;
}

uint64_t Programmer::stc15_isp_clock_target(uint64_t measured) const {
    const auto fast = config_.options.find("fast_download_enabled");
    // 4C1862 supplies the desired ISP clock to the legacy trim routine.
    return fast == config_.options.end() ? measured :
        bool_value(fast->second) ? 22'118'400u : 11'059'200u;
}

void Programmer::calibrate_stc15e_irc(uint64_t initial_clock) {
    if (!uart_irc_target_) return;
    const auto baud = config_.handshake_baud;
    const auto wanted = int64_t{*uart_irc_target_};
    const std::array<int, 6> timing_cutoffs{6'000'000, 8'400'000, 12'000'000, 17'000'000,
                                            24'000'000, 34'000'000};
    constexpr std::array<std::array<uint8_t, 7>, 5> timing{{
        {16, 16, 20, 14, 12, 18, 12}, {6, 6, 8, 6, 6, 6, 6}, {6, 6, 6, 8, 6, 6, 6},
        {6, 6, 6, 12, 12, 12, 255}, {255, 255, 255, 255, 255, 255, 255},
    }};
    const auto row = baud == 1200 ? 0 : baud == 2400 ? 1 : baud == 4800 ? 2 : baud == 9600 ? 3 : 4;
    const auto column = std::lower_bound(timing_cutoffs.begin(), timing_cutoffs.end(), wanted) -
        timing_cutoffs.begin();
    const uint8_t lo = wanted <= 10'000'000 ? 0 : wanted <= 21'000'000 ? 1 : wanted <= 31'000'000 ? 2 : 3;
    const bool spans_bands = (wanted > 7'500'000 && wanted <= 10'000'000) ||
        (wanted > 15'000'000 && wanted <= 21'000'000);
    const auto hi = static_cast<uint8_t>(lo + spans_bands);
    const auto band = [](uint8_t index) { return static_cast<uint8_t>((index << 6) | 0x18); };
    const uint8_t second_trim = spans_bands ? 0x80 : 0;
    const uint8_t third_trim = spans_bands ? 0xFF : 0x80;
    const uint8_t fourth_trim = spans_bands ? 0 : 0x80;
    const uint8_t fifth_trim = spans_bands ? 0x80 : lo == 3 ? 0xB4 : 0xFF;
    const uint8_t transfer_band = stc15_isp_clock_target(initial_clock) >= 20'000'000 ? 0x98 : 0x58;
    std::vector<uint8_t> probe{0x65};
    probe.insert(probe.end(), stc15e_irc_seed_.begin(), stc15e_irc_seed_.end());
    probe.insert(probe.end(), {0xFF, 0xFF, timing[row][column], 6,
        band(lo), second_trim, 2, 0, band(lo), third_trim, 2, 0,
        band(hi), fourth_trim, 2, 0, band(hi), fifth_trim, 2, 0,
        transfer_band, 0, 2, 0, transfer_band, 0x80, 2, 0});
    const auto coarse = request_uart_irc(probe, 0x7F);
    if (coarse.size() < 36 || coarse[0] != 0x65)
        throw std::runtime_error("unexpected STC15E coarse IRC response");
    const unsigned multiplier = baud == 115200 ? 0x835 : baud == 57600 ? 0x820 :
        baud == 38400 ? 0x81B : baud == 28800 ? 0x818 : baud == 19200 ? 0x816 :
        baud == 14400 || baud == 9600 ? 0x814 : baud == 4800 ? 0x812 : baud == 2400 ? 0x80F : 0x80D;
    const auto frequency = [&](const std::vector<uint8_t>& reply, size_t offset) -> int64_t {
        const auto count = (unsigned{reply[offset]} << 8) | reply[offset + 1];
        if (!count) throw std::runtime_error("empty STC15E IRC measurement");
        return (int64_t{count} * baud / 1200 + 6) * multiplier;
    };
    const auto transfer_hz = frequency(coarse, 34);
    std::array<int64_t, 4> coarse_hz{};
    for (size_t i = 0; i < coarse_hz.size(); ++i) coarse_hz[i] = frequency(coarse, 14 + i * 4);
    const auto nearest = [&](int64_t a, int64_t b) { return std::abs(a - wanted) < std::abs(b - wanted); };
    const auto base = std::min_element(coarse_hz.begin(), coarse_hz.end(), nearest) - coarse_hz.begin() < 2 ? 0 : 2;
    const auto trim_delta = int{coarse[17 + base * 4]} - coarse[13 + base * 4];
    const auto hz_delta = coarse_hz[base + 1] - coarse_hz[base];
    if (!trim_delta || !hz_delta) throw std::runtime_error("invalid STC15E IRC range");
    const auto slope = static_cast<long double>(hz_delta) / trim_delta;
    const auto origin = static_cast<int64_t>(slope * coarse[13 + base * 4]);
    const auto first = std::clamp<int64_t>(
        static_cast<int64_t>((origin + wanted - coarse_hz[base]) / slope) - 5, 0, 244);
    probe.resize(12);
    probe[11] = 11;
    for (unsigned i = 0; i < 11; ++i)
        probe.insert(probe.end(), {coarse[12 + base * 4], static_cast<uint8_t>(first + i), 2, 0});
    const auto fine = request_uart_irc(probe, 0x7F);
    if (fine.size() < 56 || fine[0] != 0x65)
        throw std::runtime_error("unexpected STC15E fine IRC response");
    auto program_hz = frequency(fine, 14);
    size_t best = 0;
    for (size_t i = 1; i < 11; ++i) {
        const auto hz = frequency(fine, 14 + i * 4);
        if (nearest(hz, program_hz)) {
            program_hz = hz;
            best = i;
        }
    }
    legacy_irc_result_ = LegacyIrcResult{
        static_cast<uint32_t>(transfer_hz), static_cast<uint32_t>(program_hz), coarse[33],
        static_cast<uint8_t>(uart_selector(model_) == 4 ? 0 : 0x40),
        fine[13 + best * 4], fine[12]};
}

void Programmer::calibrate_stc15_irc() {
    if (!uart_irc_target_) return;
    const auto& status = *status_;
    const bool selector4 = uart_selector(model_) == 4;
    const auto measured = (uint32_t{status[13]} << 8) | status[14];
    const auto measured_clock = uint64_t{selector4 ? (65536u - measured) * 4 : measured} * config_.handshake_baud;
    if (!measured_clock) throw std::invalid_argument("STC15 returned no ISP clock measurement");
    const auto isp_target = static_cast<int64_t>(stc15_isp_clock_target(measured_clock));
    const int64_t target = *uart_irc_target_;
    // 43F920 samples four ranges, then uses six points each for the
    // program clock and the clock used during the ISP transfer.
    std::vector<uint8_t> probe{0, 11};
    for (uint8_t band : {0xC0, 0x80, 0x40, 0}) {
        for (uint8_t trim : {0, 0x80, 0xFF}) probe.insert(probe.end(), {trim, band});
    }
    probe[24] = 0;  // 43F9D0 replaces the final trim byte.
    const auto coarse = measure_uart_irc(probe, 0x66, 1, 2);
    if (std::adjacent_find(coarse.begin(), coarse.end()) != coarse.end())
        return;  // 43FB47 falls back to the current trim.
    if ((2 * coarse[10] - coarse[9] - coarse[0]) / coarse[0] < 2)
        throw std::runtime_error("invalid STC15 IRC coarse measurements");
    const auto seed = [&](int64_t wanted) {
        size_t base = 9;
        for (size_t i : {0, 1, 3, 4, 6, 7, 9}) {
            if (wanted <= coarse[i + 1]) { base = i; break; }
            if (i == 9) base = 10;
        }
        const auto width = coarse[base + 1] - coarse[base];
        if (width <= 0) throw std::runtime_error("invalid STC15 IRC range");
        const auto position = (wanted - coarse[base]) * (base % 3 ? 127 : 128) / width;
        const auto center = std::clamp<int64_t>(position + (base % 3 ? 128 : 0), 3, 253);
        return std::pair{static_cast<int>(center) - 3, probe[2 * base + 3]};
    };
    const auto [program_start, program_band] = seed(target);
    const auto [transfer_start, transfer_band] = seed(isp_target);
    probe = {0, 12};
    for (auto [first, band] : {std::pair{program_start, program_band}, std::pair{transfer_start, transfer_band}})
        for (int j = 0; j < 6; ++j) probe.insert(probe.end(), {static_cast<uint8_t>(first + j), band});
    for (unsigned attempt = 0; attempt < 6; ++attempt) {
        const auto fine = measure_uart_irc(probe, 0x66, 1, 2);
        const auto advance = [&](size_t base, int64_t desired) {
            const int delta = desired < fine[base] && probe[2 + 2 * base] ? -5 :
                desired > fine[base + 5] && probe[2 + 2 * (base + 5)] < 255 ? 5 : 0;
            for (auto i = base; i < base + 6; ++i)
                probe[2 + 2 * i] = static_cast<uint8_t>(
                    std::clamp(static_cast<int>(probe[2 + 2 * i]) + delta, 0, 255));
            return delta != 0;
        };
        if (attempt != 5) {
            const bool retry_program = advance(0, target);
            const bool retry_transfer = advance(6, isp_target);
            if (retry_program || retry_transfer) continue;
        }
        const auto nearest = [&](size_t base, int64_t desired) {
            return std::min_element(fine.begin() + base, fine.begin() + base + 6, [&](auto a, auto b) {
                return std::abs(a - desired) < std::abs(b - desired);
            }) - fine.begin();
        };
        const auto program_index = nearest(0, target), transfer_index = nearest(6, isp_target);
        legacy_irc_result_ = LegacyIrcResult{
            static_cast<uint32_t>(fine[transfer_index]), static_cast<uint32_t>(fine[program_index]),
            probe[2 + 2 * transfer_index], transfer_band, probe[2 + 2 * program_index], program_band};
        return;
    }
}

void Programmer::calibrate_uart_irc(std::vector<uint8_t>& options) {
    if (!uart_irc_target_) return;
    const auto version = (*status_)[17];
    if (options.size() < 36 || model_.family < 45 ||
        (version < 0x72 && model_.family > 52))
        throw std::invalid_argument("this UART BSL does not support the selected IRC calibration path");

    // 4413D0 switches from the two-band 4407C0 to 440CE0 in BSL 7.4.
    // 4402F0 is the separate single-band path for families 45–52.
    const bool older = version < 0x74;
    const bool compact = model_.family <= 52;
    const uint8_t command = !older && model_.family == 84 ? 0x10 : 0;
    const auto measure = [&](const std::vector<uint8_t>& probe) {
        return measure_uart_irc(probe, command ? 0xF8 : 0x66,
                                !older && (model_.family == 85 || model_.family == 89) ? 2 : 1,
                                compact ? 2 : 1);
    };

    const auto commit = [&](uint32_t hz, uint8_t trim, uint8_t band, uint8_t divider) {
        options[29] = static_cast<uint8_t>(hz >> 24);
        options[30] = static_cast<uint8_t>(hz >> 16);
        options[31] = static_cast<uint8_t>(hz >> 8);
        options[32] = static_cast<uint8_t>(hz);
        options[33] = trim;
        options[34] = band;
        options[35] = divider;
        if (model_.family == 84 && (!config_.options.contains("wtst_initial_value") ||
                                    !modify_hardware_options_))
            options[28] = hz > 52'520'000 ? 2 : 1;
    };
    const auto requested = int64_t{*uart_irc_target_};
    if (older || compact) {
        auto coarse = compact ? measure({0, 2, 0, 0, 0x80, 0}) :
            measure({0, 5, 0, 0, 0x80, 0, 0, 0x80, 0x80, 0x80, 0xFF, 0});
        const bool double_counts = compact && model_.family >= 51 && coarse[1] < 18'000'000;
        if (double_counts)
            for (auto& value : coarse) value *= 2;
        const unsigned band = !compact && (requested > coarse[4] ||
            (requested < coarse[0] && requested * 2 > coarse[4])) ? 1 : 0;
        const auto lower = coarse[2 * band];
        const auto slope = (coarse[2 * band + 1] - lower) / 128;
        if (slope <= 0) throw std::runtime_error("invalid two-band UART IRC measurements");
        const auto initial_divider = (lower + requested - 1) / requested;
        const auto divider = std::clamp<int64_t>(initial_divider, 1, compact ? 63 : 15);
        const auto desired = requested * divider;
        int trim = initial_divider >= 64 ? 1 : static_cast<int>(
            std::clamp((requested * initial_divider - lower) / slope, int64_t{1}, int64_t{254}));
        for (unsigned attempt = 0; attempt < 6; ++attempt) {
            std::vector<uint8_t> probe{0, 12};
            for (int delta = -1; delta <= 1; ++delta)
                for (unsigned sub = 0; sub < 4; ++sub)
                    probe.insert(probe.end(), {static_cast<uint8_t>(trim + delta),
                                               static_cast<uint8_t>((band << 7) | sub)});
            auto fine = measure(probe);
            if (double_counts)
                for (auto& value : fine) value *= 2;
            if (attempt < 5 && desired > fine.back() && trim < 254) {
                trim = std::min(254, trim + 2);
                continue;
            }
            if (attempt < 5 && desired < fine.front() && trim > 1) {
                trim = std::max(1, trim - 2);
                continue;
            }
            const auto closest = std::min_element(fine.begin(), fine.end(), [&](int64_t a, int64_t b) {
                return std::abs(a - desired) < std::abs(b - desired);
            });
            const auto index = 2 + 2 * (closest - fine.begin());
            const auto committed_divider = double_counts ? std::max<int64_t>(2, divider) : divider;
            commit(static_cast<uint32_t>(*closest / committed_divider), probe[index], probe[index + 1],
                   static_cast<uint8_t>(committed_divider));
            return;
        }
    }

    const auto last_band = model_.family == 89 ? 0x20 : 0x30;
    const auto coarse = measure({command, 8, 0, 0, 0xFF, 0, 0, 0x10, 0xFF, 0x10,
                                 0, 0x20, 0xFF, 0x20, 0, static_cast<uint8_t>(last_band),
                                 0xFF, static_cast<uint8_t>(last_band)});
    unsigned band = 0;
    unsigned divider = 1;
    int trim = 0;
    for (; divider < 64; ++divider) {
        const auto target = requested * divider;
        bool covered = false;
        for (unsigned candidate = 0; candidate < 4; ++candidate) {
            const auto lower = coarse[2 * candidate], upper = coarse[2 * candidate + 1];
            if (target < lower || target > upper) continue;
            if (upper - lower < 256) throw std::runtime_error("invalid UART IRC band measurements");
            band = candidate;
            trim = static_cast<int>((target - lower) / ((upper - lower) / 256));
            covered = true;
            break;
        }
        if (covered) break;
        if (target >= coarse[6]) {
            band = 3;
            if (coarse[7] - coarse[6] < 256)
                throw std::runtime_error("invalid highest UART IRC band");
            trim = target >= coarse[7] ? 255 :
                static_cast<int>((target - coarse[6]) / ((coarse[7] - coarse[6]) / 256));
            break;
        }
        if (divider > 1 && coarse[5] < target && target < coarse[6] &&
            requested > coarse[7] / (divider + 1)) {
            band = target - coarse[5] <= coarse[6] - target ? 2 : 3;
            trim = band == 2 ? 255 : 0;
            break;
        }
    }
    divider = std::min(divider, 15u);
    const auto desired = requested * divider;
    const auto band_byte = static_cast<uint8_t>(band << 4);
    for (unsigned attempt = 0; attempt < 6; ++attempt) {
        trim = std::clamp(trim, 7, 251);
        std::vector<uint8_t> probe{command, 12};
        for (int offset = -7; offset <= 4; ++offset)
            probe.insert(probe.end(), {static_cast<uint8_t>(trim + offset), band_byte});
        const auto fine = measure(probe);
        if (attempt < 5 && desired > fine.back() && trim < 251) {
            trim += 5;
            continue;
        }
        if (attempt < 5 && desired < fine.front() && trim > 7) {
            trim -= 8;
            continue;
        }
        const auto closest = std::min_element(fine.begin(), fine.end(), [&](int64_t a, int64_t b) {
            return std::abs(a - desired) < std::abs(b - desired);
        });
        commit(static_cast<uint32_t>(*closest / divider),
               static_cast<uint8_t>(trim - 7 + (closest - fine.begin())), band_byte,
               static_cast<uint8_t>(divider));
        return;
    }
}

void Programmer::program_modern_8bit_uart(std::vector<uint8_t> program, uint8_t extra_erase_sectors) {
    const auto version = (*status_)[17];
    const bool legacy_layout = model_.family < 45;
    const int minimum = legacy_layout ? 0x60 : 0x62;
    if (version < minimum)
        throw std::invalid_argument("this 8-bit UART route requires a newer BSL");
    if ((!allowed_uids_.empty() || !uid_bindings_.empty()) && version <= 0x62 && status_size_ < 38)
        throw std::invalid_argument("this UART BSL did not report a complete UID in the status response");
    validate_uid_regions({{0, program}});
    const bool has_password = model_.family >= 45 && !config_.password.empty();
    const bool compact = model_.family >= 45 && model_.family <= 52;
    if ((hardware_options_write_required_ && version < 0x72 && !compact && !legacy_layout) ||
        (has_password && version < 0x74))
        throw std::invalid_argument(model_.name + " requires BSL 7.2 for options or 7.4 for a current password");
    if (!config_.next_password.empty() &&
        (version < 0x72 || ((version == 0x72 || version == 0x73) && status_size_ <= 22)))
        throw std::invalid_argument("next download password requires BSL 7.2 or later with a known patch version");
    if (legacy_layout) calibrate_stc15_irc();
    std::vector<uint8_t> options;
    if (hardware_options_write_required_ || !config_.next_password.empty()) {
        options = legacy_layout ? build_stc15_options() : has_stc8u_status(model_.family) ?
            build_stc8u_options() : build_generic_8bit_options();
    }
    if (!legacy_layout) calibrate_uart_irc(options);
    initialize_measured_uart();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::vector<uint8_t> prepare = version < 0x72 ? std::vector<uint8_t>{0x05} :
        std::vector<uint8_t>{0x05, 0, 0, 0x5A, 0xA5};
    const auto password = password_bytes(config_.password);
    prepare.insert(prepare.end(), password.begin(), password.end());
    request(prepare, {0x05}, "prepare UART flash");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const std::vector<uint8_t> erase = version < 0x72 ? std::vector<uint8_t>{0x03, extra_erase_sectors} :
        std::vector<uint8_t>{0x03, extra_erase_sectors, 0, 0x5A, 0xA5};
    const auto erased = request(erase, {0x03}, "erase UART flash", 15000);
    if (version < 0x72) apply_short_uart_erase_uid(erased, {{0, program}});
    else apply_erase_uid(erased, {{0, program}});
    if (config_.erase_only) return;
    write_user_key();

    constexpr size_t block_size = 64;
    TransferProgress progress(program.size());
    for (size_t offset = 0; offset < program.size(); offset += block_size) {
        const auto end = std::min(offset + block_size, program.size());
        const auto begin_it = program.begin() + offset;
        const auto end_it = program.begin() + end;
        // 443453 skips blank blocks only for unencrypted normal UART writes.
        if (version < 0x72 || config_.encrypted_image ||
            std::any_of(begin_it, end_it, [](uint8_t value) { return value != 0xFF; })) {
            std::vector<uint8_t> payload{static_cast<uint8_t>((offset ? 0x02 : 0x22) |
                                                              (config_.encrypted_image ? 0x80 : 0)),
                static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset)};
            if (version >= 0x72)
                payload.insert(payload.end(), {static_cast<uint8_t>(version < 0x75 ? 0x5A : 0),
                                               static_cast<uint8_t>(version < 0x75 ? 0xA5 : 0)});
            payload.insert(payload.end(), begin_it, end_it);
            request(payload, {0x02, 0x54}, "write UART block");
        }
        progress.update(end);
    }
    progress.finish();
    write_test_parameters();
    if (!options.empty() && legacy_layout) {
        request(options, {4, 0x54}, "hardware options");
    } else if (!options.empty() && version < 0x72) {
        // 444057 uses 04 00 00 before the same 44B760 option body.
        options.erase(options.begin() + 3, options.begin() + 5);
        request(options, {4, 0x54}, "hardware options");
    } else {
        write_download_options(options);
    }
}

void Programmer::program_8bit_native_usb(std::vector<uint8_t> program, uint8_t extra_erase_sectors,
                                        const std::vector<uint8_t>& options) {
    validate_uid_regions({{0, program}});
    request({0x01, 0, 0, 0, 0, 0, 0, 0x80}, {0x01}, "initialize 8-bit USB");
    auto password = password_bytes(config_.password);
    std::vector<uint8_t> prepare{0x05, 0, 0, 0x5A, 0xA5};
    prepare.insert(prepare.end(), password.begin(), password.end());
    request(prepare, {0x05}, "prepare 8-bit USB flash");
    const auto erase = request({0x03, extra_erase_sectors, 0, 0x5A, 0xA5}, {0x03},
                               "erase 8-bit USB flash", 30000);
    if (erase.size() != 8)
        throw std::runtime_error("invalid USB erase response: expected 7-byte UID");
    apply_erase_uid(erase, {{0, program}});
    if (config_.erase_only) return;
    write_user_key();
    const bool old_header = (*status_)[17] < 0x75;
    TransferProgress progress(program.size());
    for (size_t offset = 0; offset < program.size(); offset += kBlockSize) {
        const auto end = std::min(offset + kBlockSize, program.size());
        const auto first = program.begin() + offset, last = program.begin() + end;
        if (std::any_of(first, last, [](uint8_t b) { return b != 0xFF; })) {
            // AiCube 44CFC5: USB first block sets bit 5; addresses in this bank set bit 4.
            std::vector<uint8_t> block{static_cast<uint8_t>((offset == 0 ? 0x32 : 0x12) |
                                                            (config_.encrypted_image ? 0x80 : 0)),
                static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset),
                static_cast<uint8_t>(old_header ? 0x5A : 0),
                static_cast<uint8_t>(old_header ? 0xA5 : 0)};
            block.insert(block.end(), first, last);
            block.resize(5 + kBlockSize, image_fill_value_);
            request(block, {0x02, 0x54}, "write 8-bit USB block");
        }
        progress.update(end);
    }
    progress.finish();
    write_download_options(options);
}

void Programmer::program_banked(std::vector<uint8_t> image, uint32_t flash_base, uint32_t reset_offset,
                                uint8_t extra_erase_sectors, const std::vector<uint8_t>& options) {
    const auto& status = *status_;
    // 443240/44CFC5: the last two header bytes become the high address word in 7.5.
    const bool legacy_header = status[17] < 0x75;
    const bool legacy_g12 = model_.family == 76 && status[17] == 0x74 &&
        status_size_ > 22 && status[22] >= 3;
    const bool legacy_8051u = model_.family == 88 && status[17] == 0x74 &&
        status_size_ > 22 && status[22] >= 12;
    if (legacy_header && !legacy_g12 && !legacy_8051u)
        throw std::invalid_argument(model_.name + " requires BSL 7.5 or later");
    if (legacy_header && !uses_uart() && status[22] == 12) {
        // 43E8A0: some G12 and AI8051U 7.4.12 batches need UART.
        if (status_size_ <= 39)
            throw std::invalid_argument(model_.name + " USB status is missing the BSL production date");
        const auto date = uint32_t{status[37]} << 16 | uint32_t{status[38]} << 8 | status[39];
        if (date >= 0x241219 && date <= 0x250124)
            throw std::invalid_argument(model_.name + " from this BSL 7.4.12 batch requires UART or Link1D");
    }
    if (legacy_header && (!user_key_.empty() || config_.encrypted_image))
        throw std::invalid_argument("banked user-key and encrypted writes require BSL 7.5 or later");
    validate_uid_regions({{flash_base, image}});
    const bool extended = model_.family == 76 || model_.family == 89;
    const auto first = std::find_if(image.begin(), image.end(), [](uint8_t b) { return b != 0xFF; });
    const auto erase_start = !extended ? 0u :
        static_cast<uint32_t>(image.empty() ? reset_offset : first - image.begin()) & ~511u;
    const auto password = password_bytes(config_.password);
    auto download_options = options;
    std::vector<uint8_t> prepare{5, 0, 0, 0x5A, 0xA5};
    prepare.insert(prepare.end(), password.begin(), password.end());
    if (uses_uart()) {
        calibrate_uart_irc(download_options);
        initialize_measured_uart();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    } else {
        request({1, 0, 0, 0, 0, 0, 0, 0x80}, {1}, "initialize USB");
    }
    request(prepare, {5}, "prepare flash");
    const auto erase_high = extended ? static_cast<uint8_t>(erase_start >> 16) : extra_erase_sectors;
    const auto erased = request({3, erase_high,
                                 static_cast<uint8_t>(erase_start >> 8), 0x5A, 0xA5},
                                {3}, "erase flash", 30000);
    if (!uses_uart() && erased.size() != 8)
        throw std::runtime_error("invalid USB erase response: expected 7-byte UID");
    apply_erase_uid(erased, {{flash_base, image}});
    if (config_.erase_only) return;
    const size_t block_size = uses_uart() ? 64 : kBlockSize;
    write_user_key();
    TransferProgress progress(image.size());
    for (size_t offset = 0; offset < image.size(); offset += block_size) {
        const auto end = std::min(offset + block_size, image.size());
        const auto begin = image.begin() + offset, last = image.begin() + end;
        if ((uses_uart() && config_.encrypted_image) ||
            std::any_of(begin, last, [](uint8_t b) { return b != 0xFF; })) {
            uint8_t command = offset == 0 ? 0x22 : 0x02;
            if ((!uses_uart() || extended) && offset < 0x10000) command |= 0x10;
            if (config_.encrypted_image) command |= 0x80;
            std::vector<uint8_t> block{command, static_cast<uint8_t>(offset >> 8),
                                       static_cast<uint8_t>(offset), static_cast<uint8_t>(legacy_header ? 0x5A : 0),
                                       static_cast<uint8_t>(legacy_header ? 0xA5 : offset >> 16)};
            block.insert(block.end(), begin, last);
            if (!uses_uart()) block.resize(5 + block_size, image_fill_value_);
            request(block, {2, 0x54}, "write flash block");
        }
        progress.update(end);
    }
    progress.finish();
    write_download_options(std::move(download_options));
}

void Programmer::program_legacy_uart(const std::vector<uint8_t>& image, IspRoute route,
                                    uint8_t extra_erase_sectors) {
    const auto& status = *status_;
    const auto selector = uart_selector(model_);
    const bool stc89 = route == IspRoute::stc89;
    const auto version = status[17];
    const bool upgraded = version >= 0x72;
    const bool timer3 = ((model_.flags >> 9) & 7) == 3;
    const bool six_t = stc89 && !(original_option_byte_ & (model_.family == 6 ? 0x08 : 0x01));
    unsigned count = 0;
    for (size_t index = 1; index <= 15; index += 2)
        count += static_cast<unsigned>(status[index] << 8 | status[index + 1]);
    const auto count_at = [&](size_t i) { return (unsigned{status[i]} << 8) | status[i + 1]; };
    const double reference_clock = !upgraded ? (count / 8.0) * config_.handshake_baud * 12.0 / 7
        : model_.family == 6 ? count_at(3) * double(config_.handshake_baud) * 12.0 / 7
        : count_at(13) * double(config_.handshake_baud) * (stc89 ? 12.0 : 1.0);
    const double clock = !upgraded && six_t ? reference_clock / 2.0 : reference_clock;
    // AiCube 4417D1: selector 2 encodes the prescaler in the high reload byte.
    double ticks_per_bit = reference_clock / (32.0 * config_.baud);
    uint8_t high_reload = 0;
    if (!timer3) {
        for (const auto [prescaler, prefix] : {std::pair{16, 0xC0}, {32, 0x40}, {192, 0x80}, {384, 0}}) {
            ticks_per_bit = reference_clock / (static_cast<double>(prescaler) * config_.baud);
            high_reload = static_cast<uint8_t>(prefix);
            if (ticks_per_bit <= 255) break;
        }
    }
    const long divisor = std::lround(ticks_per_bit);
    if (divisor < 1 || divisor > (timer3 ? 65535 : 255) ||
        std::abs(ticks_per_bit / divisor - 1) > 0.05)
        throw std::invalid_argument("target clock cannot use requested legacy UART transfer baud");
    const auto reload = static_cast<uint16_t>(65536 - divisor);
    if (timer3) high_reload = static_cast<uint8_t>(reload >> 8);
    const uint8_t iap = timer3 ? (clock < 6e6 ? 0x83 : clock < 12e6 ? 0x82 : clock < 24e6 ? 0x81 : 0x80)
                              : (clock < 1e6 ? 0x87 : clock < 2e6 ? 0x86 : clock < 3e6 ? 0x85 :
                                 clock < 6e6 ? 0x84 : clock < 12e6 ? 0x83 : clock < 20e6 ? 0x82 :
                                 clock < 24e6 ? 0x81 : 0x80);
    if (upgraded) {
        // AiCube 43C626, 44293B, 4429BC. The markers also appear in pre-7.5 blocks.
        const bool old_marker = stc89 || (model_.family >= 7 && model_.family <= 9) ||
                                (model_.family >= 17 && model_.family <= 19);
        const uint8_t marker_hi = old_marker ? 0x46 : 0x5A;
        const uint8_t marker_lo = old_marker ? 0xB9 : 0xA5;
        request({1, high_reload, static_cast<uint8_t>(reload), iap}, {1}, "set UART baudrate");
        // 43D6E8: the probe uses parity for the effective selector, now 5.
        if (link1d_) link1d_->set_baud(config_.baud, true);
        else transport_->set_baud(config_.baud);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        request({5, 0, 0, marker_hi, marker_lo}, {5}, "prepare flash");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        request({3, extra_erase_sectors, 0, marker_hi, marker_lo}, {3}, "erase flash", 12000);
        if (config_.erase_only) return;

        TransferProgress progress(image.size());
        for (size_t offset = 0; offset < image.size(); offset += kBlockSize) {
            const auto end = std::min(offset + kBlockSize, image.size());
            std::vector<uint8_t> data{static_cast<uint8_t>(offset ? 0x02 : 0x22),
                static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset),
                static_cast<uint8_t>(version < 0x75 ? marker_hi : 0),
                static_cast<uint8_t>(version < 0x75 ? marker_lo : 0)};
            data.insert(data.end(), image.begin() + offset, image.begin() + end);
            if (std::any_of(data.begin() + 5, data.end(), [](uint8_t b) { return b != 0xFF; }))
                request(data, {2, 0x54}, "write flash block");
            progress.update(end);
        }
        progress.finish();

        const auto option = status[stc89_option_offset(model_, version)];
        if (stc89 && modify_hardware_options_ && option != original_option_byte_) {
            if (model_.family == 6)
                request({0x8D, static_cast<uint8_t>((option & 8) | 0x40)},
                        {0x0D, 0x54}, "write hardware options");
            else
                request({4, 0, 0, marker_hi, marker_lo, static_cast<uint8_t>(option & 0xFD)},
                        {4, 0x54}, "write hardware options");
        } else if (!stc89 && hardware_options_write_required_) {
            const auto hz = static_cast<uint32_t>(clock);
            std::vector<uint8_t> options{4, 0, 0, marker_hi, marker_lo,
                static_cast<uint8_t>(hz >> 24), static_cast<uint8_t>(hz >> 16),
                static_cast<uint8_t>(hz >> 8), static_cast<uint8_t>(hz), legacy_options_[14]};
            if (compact_stc12_options(model_.family))
                options.insert(options.end(), {legacy_options_[1], legacy_options_[0], legacy_options_[4]});
            else
                options.insert(options.end(), {legacy_options_[2], legacy_options_[1], legacy_options_[0]});
            request(options, {4, 0x54}, "write hardware options");
        }
        return;
    }
    const auto guard = static_cast<uint8_t>(
        std::clamp((config_.handshake_baud / 1200) * 20, 40, 250));
    const auto model_command = [&](uint8_t command) {
        return std::vector<uint8_t>{command, 0, 0, 0x36, 1,
            static_cast<uint8_t>(model_.magic >> 8), static_cast<uint8_t>(model_.magic)};
    };
    if (selector == 1) request(model_command(0x50), {0x8F}, "prepare legacy ISP");
    const auto set_baud = [&](int baud, bool wait_for_ack) {
        if (link1d_ && wait_for_ack) {
            link1d_->switch_legacy_baud(baud);
        } else {
            if (!link1d_) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            transport_->set_baud(baud);
        }
    };
    for (const uint8_t command : {0x8F, 0x8E}) {
        std::vector<uint8_t> data{command, high_reload,
            static_cast<uint8_t>(reload), static_cast<uint8_t>(0xFF - high_reload),
            static_cast<uint8_t>(std::min(2 * (256 - (reload & 0xFF)), 254)), guard};
        if (command == 0x8F) data.push_back(iap);
        send_frame(data);
        set_baud(config_.baud, true);
        const auto expected = command == 0x8E && selector != 0 ? 0x84 : command;
        if (const auto response = read_frame(config_.timeout_ms); response.front() != expected)
            throw std::runtime_error("legacy UART baud negotiation failed");
        if (command == 0x8F) set_baud(config_.handshake_baud, false);
    }
    if (selector == 0)
        for (unsigned i = 0; i < 5; ++i)
            request(model_command(0x80), {0x80}, "check legacy ISP handshake");
    const auto erase_extent = config_.erase_only ? model_.code_size : image.size();
    const auto erase_blocks = (erase_extent + 511) / 512;
    std::vector<uint8_t> erase{0x84};
    if (timer3) {
        if (erase_blocks == 0 || erase_blocks > 255)
            throw std::runtime_error("legacy erase size cannot be represented");
        erase.push_back(static_cast<uint8_t>(erase_blocks));
        erase.resize(8, 0x33);
    } else {
        erase.push_back(0);
        for (const auto size : {std::max<size_t>(erase_blocks * 512, model_.code_size),
                                static_cast<size_t>(model_.code_size)}) {
            erase.push_back(static_cast<uint8_t>(size >> 16));
            erase.push_back(static_cast<uint8_t>(size >> 8));
            erase.push_back(static_cast<uint8_t>(size));
        }
        erase.resize(19, 0);
        for (unsigned i = 0; i < 115; ++i) erase.push_back(static_cast<uint8_t>(0x80 - i));
    }
    const auto ack = static_cast<uint8_t>(selector == 0 ? 0x80 : 0);
    request(erase, {ack}, "erase legacy flash", 12000);
    if (config_.erase_only) return;
    TransferProgress progress(image.size());
    for (size_t offset = 0; offset < image.size(); offset += kBlockSize) {
        std::vector<uint8_t> data{0, 0, 0, static_cast<uint8_t>(offset >> 8),
            static_cast<uint8_t>(offset), 0, static_cast<uint8_t>(kBlockSize)};
        const auto end = std::min(offset + kBlockSize, image.size());
        data.insert(data.end(), image.begin() + offset, image.begin() + end);
        data.resize(7 + kBlockSize, image_fill_value_);
        uint8_t checksum = 0;
        for (auto it = data.begin() + 7; it != data.end(); ++it) checksum += *it;
        request(data, {ack, checksum}, "verify legacy write block");
        progress.update(end);
    }
    progress.finish();
    if (selector == 1 && !(model_.flags & 0x20))
        request(model_command(0x69), {0x8D}, "finish legacy program write");
    std::vector<uint8_t> options;
    if (stc89 && modify_hardware_options_ && status[19] != original_option_byte_) {
        options = {0x8D, static_cast<uint8_t>(status[19] & 0xFD), 0xFF, 0xF6, 0xFF};
        if (model_.family == 6) options = {0x8D, static_cast<uint8_t>((status[19] & 8) | 0x40)};
    } else if (hardware_options_write_required_ && route == IspRoute::legacy_stc12) {
        const auto& opt = legacy_options_;
        const auto hz = static_cast<uint32_t>(clock);
        const std::array<uint8_t, 4> hz_be{static_cast<uint8_t>(hz >> 24), static_cast<uint8_t>(hz >> 16),
                                           static_cast<uint8_t>(hz >> 8), static_cast<uint8_t>(hz)};
        if (compact_stc12_options(model_.family)) {
            options.assign(33, 0xFF);
            options[0] = 0x8D;
            options[1] = options[12] = opt[0];
            options[2] = options[13] = opt[1];
            options[3] = options[18] = static_cast<uint8_t>(opt[14] & 0xF7);
            if (model_.family == 7) options[5] = opt[4];
            options[10] = opt[4];
            std::copy(hz_be.begin(), hz_be.end(), options.begin() + 6);
            std::copy(hz_be.begin(), hz_be.end(), options.begin() + 26);
        } else {
            options.assign(21, 0xFF);
            options[0] = 0x8D;
            std::copy_n(opt.begin(), 3, options.begin() + 1);
            options[9] = opt[14];
            std::copy(hz_be.begin(), hz_be.end(), options.begin() + 17);
        }
    }
    if (!options.empty()) {
        send_frame(options);
        const auto reply = read_frame(config_.timeout_ms);
        if (selector == 0) {
            if (reply[0] != 0x8D && reply[0] != 0x80)
                throw std::runtime_error("STC89/STC90 options returned an unexpected response");
            request({0x50}, {0x10}, "verify STC89/STC90 hardware options");
        } else if (reply[0] != 0x50) {
            throw std::runtime_error("STC89 options returned an unexpected response");
        }
    }
}

void Programmer::program_stc15_uart(std::vector<uint8_t> image, IspRoute route,
                                   uint8_t extra_erase_sectors) {
    const auto& status = *status_;
    const auto version = status[17];
    const bool irc15 = route == IspRoute::irc15_uart;
    const bool legacy_selector2 = !irc15 && version < 0x72;
    const bool old_selector2 = legacy_selector2 && version < 0x71;
    const bool old_irc15 = irc15 && model_.family == 28 && version < 0x71;
    const bool old_erase = old_selector2 || old_irc15;
    if (!allowed_uids_.empty() || !uid_bindings_.empty()) {
        if (legacy_selector2)
            throw std::invalid_argument("this UART BSL does not support UID matching after erase");
        if (version <= 0x62 && status_size_ < 38)
            throw std::invalid_argument("this UART BSL did not report a complete UID in the status response");
    }
    validate_uid_regions({{0, image}});
    const auto minimum = !irc15 || model_.family == 28 ? 0x60 : 0x66;
    if (version < minimum)
        throw std::invalid_argument("this BSL version uses an older STC15 UART write protocol");
    // 445348 decodes the inverted counter for selector 4's short/modern
    // packets. The pre-7.1 long packet uses the older oscillator measurement.
    const auto measured = (uint32_t{status[13]} << 8) | status[14];
    if (old_erase && status_size_ <= 27)
        throw std::invalid_argument("target status is missing the legacy STC15 trim value");
    const auto initial_clock = old_erase
        ? uint64_t{(uint32_t{status[3]} << 8) | status[4]} * config_.handshake_baud * 12 / 7
        : uint64_t{irc15 ? (65536 - measured) * 4 : measured} * config_.handshake_baud;
    if (old_selector2)
        request({0x50, 0, 0, 0x36, 1, static_cast<uint8_t>(model_.magic >> 8),
                 static_cast<uint8_t>(model_.magic)}, {0x8F}, "prepare legacy STC15 ISP");
    const bool stc15e_layout = model_.family == 25 || model_.family == 28;
    if (stc15e_layout) calibrate_stc15e_irc(initial_clock);
    else calibrate_stc15_irc();
    const auto clock = legacy_irc_result_ ? uint64_t{legacy_irc_result_->transfer_hz} : initial_clock;
    const auto options = !config_.erase_only && hardware_options_write_required_ ?
        build_stc15_options() : std::vector<uint8_t>{};
    const bool timer1 = ((model_.flags >> 9) & 7) == 1;
    const bool upper_speed = clock >= 20'000'000;
    const int transfer_baud = old_erase ? std::min(config_.baud, upper_speed ? 57600 : 28800) :
        select_measured_uart_baud(clock, config_.baud, timer1, link1d_ != nullptr);
    std::vector<uint8_t> baud;
    if (old_erase) {
        // 43E9E0/441DDE: retain the trim and encode the divider in two 8-bit fields.
        const auto full_ticks = clock / transfer_baud;
        const auto divider = full_ticks < 100 ? 0 : full_ticks / 100 + 1;
        if (divider > 255) throw std::invalid_argument("legacy STC15 divider does not fit");
        const auto period = full_ticks / (divider ? divider : 1);
        if (period < 2) throw std::invalid_argument("legacy STC15 UART clock is too slow");
        const auto reload8 = static_cast<uint8_t>(0 - static_cast<int>(period));
        const auto timing_count = 65536.0 - clock * static_cast<double>(0.0008333333535119891f);
        if (timing_count < 0 || timing_count >= 65536)
            throw std::invalid_argument("legacy STC15 timing count does not fit");
        const auto timing = static_cast<uint16_t>(timing_count);
        baud = {0x8E, static_cast<uint8_t>(upper_speed ? 0x98 : 0x58),
                legacy_irc_result_ ? legacy_irc_result_->transfer_trim : status[27],
                static_cast<uint8_t>(divider), reload8, 0x64, static_cast<uint8_t>(timing >> 8),
                static_cast<uint8_t>(timing), static_cast<uint8_t>(upper_speed ? 0x81 : 0x83), 0x20, 0xFF, 0};
        if (link1d_) Link1dTransport::baud_code(transfer_baud);
    } else {
        const double ticks = static_cast<double>(clock) / ((timer1 ? 4.0 : 1.0) * transfer_baud);
        const auto period = std::lround(ticks);
        if (period < 2 || period > 65535 || std::abs(ticks / period - 1) >= 0.01)
            throw std::invalid_argument("STC15 clock cannot use requested UART transfer baud");
        const auto reload = static_cast<uint16_t>(65536 - period);
        const auto secondary = timer1 ? uint16_t{} :
            static_cast<uint16_t>(65536 - std::lround(1.5 * ticks));
        // The effective selector 5 no-trim path (44F079) uses the current trim.
        baud = {1, legacy_irc_result_ ? legacy_irc_result_->transfer_trim :
                      static_cast<uint8_t>(irc15 ? 0 : status[4]),
                legacy_irc_result_ ? legacy_irc_result_->transfer_band :
                      static_cast<uint8_t>(irc15 ? 0 : 0x40), static_cast<uint8_t>(reload >> 8),
                static_cast<uint8_t>(reload), static_cast<uint8_t>(secondary >> 8),
                static_cast<uint8_t>(secondary), legacy_iap_wait(clock)};
    }
    if (legacy_selector2) {
        // 442350/43D540: 7.1 still uses the legacy switch and checks 84 at the new rate.
        send_frame(baud);
        if (link1d_) link1d_->switch_legacy_baud(transfer_baud);
        else {
            const auto delay = config_.handshake_baud == 1200 || config_.handshake_baud == 2400 ? 200 :
                config_.handshake_baud == 4800 ? 100 : config_.handshake_baud == 9600 ? 50 : 10;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            transport_->set_baud(transfer_baud);
        }
        if (read_frame(config_.timeout_ms).front() != 0x84)
            throw std::runtime_error("legacy STC15 UART baud negotiation failed");
    } else {
        request(baud, {static_cast<uint8_t>(old_irc15 ? 0x0E : 1)}, "set STC15 UART baud");
        transport_->set_baud(transfer_baud);
    }
    if (transfer_baud != config_.baud)
        std::cout << "串口实际传输波特率：" << transfer_baud << '\n';
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (!irc15 && !old_selector2) {
        if (legacy_selector2) request({5}, {5}, "prepare legacy STC15 flash");
        else request({5, 0, 0, 0x5A, 0xA5}, {5}, "prepare STC15 flash");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (old_erase) {
        std::vector<uint8_t> erase{0x84, 0xFF};
        const auto extent = config_.erase_only ? model_.code_size : image.size();
        for (const auto length : {extent, static_cast<size_t>(model_.code_size)})
            erase.insert(erase.end(), {static_cast<uint8_t>(length >> 16),
                                       static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)});
        erase.resize(19, 0);
        for (unsigned i = 0; i < 34; ++i) erase.push_back(static_cast<uint8_t>(0x80 - i));
        apply_short_uart_erase_uid(request(erase, {static_cast<uint8_t>(old_irc15 ? 4 : 0)},
                                          "erase legacy STC15 flash", 15000), {{0, image}});
    } else if (version >= 0x72) {
        apply_erase_uid(request({3, extra_erase_sectors, 0, 0x5A, 0xA5},
                               {3}, "erase STC15 flash", 15000), {{0, image}});
    } else {
        apply_short_uart_erase_uid(request({3, extra_erase_sectors},
                                          {static_cast<uint8_t>(legacy_selector2 ? 0 : 3)},
                                          "erase STC15 flash", 15000), {{0, image}});
    }
    if (config_.erase_only) return;

    constexpr size_t block_size = 64;
    TransferProgress progress(image.size());
    for (size_t offset = 0; offset < image.size(); offset += block_size) {
        const auto end = std::min(offset + block_size, image.size());
        const auto first = image.begin() + offset;
        const auto last = image.begin() + end;
        if (legacy_selector2) {
            std::vector<uint8_t> data{0, 0, 0, static_cast<uint8_t>(offset >> 8),
                static_cast<uint8_t>(offset), 0, static_cast<uint8_t>(end - offset)};
            data.insert(data.end(), first, last);
            request(data, {0, static_cast<uint8_t>(std::accumulate(first, last, 0u))},
                    "verify legacy STC15 flash block");
        } else if (version < 0x72 || std::any_of(first, last, [](uint8_t b) { return b != 0xFF; })) {
            std::vector<uint8_t> data{static_cast<uint8_t>(irc15 || offset ? 2 : 0x22),
                static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset)};
            if (version >= 0x75) data.insert(data.end(), {0, 0});
            else if (version >= 0x72) data.insert(data.end(), {0x5A, 0xA5});
            data.insert(data.end(), first, last);
            request(data, {2, 0x54}, "write STC15 flash block");
        }
        progress.update(end);
    }
    progress.finish();
    write_test_parameters();
    if (legacy_selector2 && !(model_.flags & 0x20) && (!old_selector2 || options.empty()))
        request({0x69, 0, 0, 0x36, 1, static_cast<uint8_t>(model_.magic >> 8),
                 static_cast<uint8_t>(model_.magic)}, {0x8D}, "finish legacy STC15 program write");
    if (!options.empty()) {
        const auto expected = legacy_selector2 ? std::vector<uint8_t>{0x50} :
            std::vector<uint8_t>{static_cast<uint8_t>(options.front() & 0x0F), 0x54};
        request(options, expected, "STC15 hardware options");
    }
}

void Programmer::program_stc32(Stc32Image image) {
    const auto regions = {FlashRegion{kCodeBase, image.program}, FlashRegion{kEepromBase, image.eeprom}};
    validate_uid_regions(regions);
    const bool has_eeprom = !image.eeprom.empty();
    auto options = !config_.erase_only &&
        ((!config_.options.empty() && modify_hardware_options_) ||
         hardware_options_write_required_ || !config_.next_password.empty()) ?
         build_f8d1_options() : std::vector<uint8_t>{};
    if (!options.empty()) set_download_rs485(options);
    request({0x01, 0, 0, 0, 0, 0, 0, 0x80}, {0x01}, "initialize");
    auto password = password_bytes(config_.password);
    std::vector<uint8_t> password_command = {0x05, 0, 0, 0x5A, 0xA5};
    password_command.insert(password_command.end(), password.begin(), password.end());
    request(password_command, {0x05}, "prepare flash");
    const std::vector<uint8_t> erase = config_.erase_only
        ? std::vector<uint8_t>{0x03, 0, 0, 0x5A, 0xA5}
        : (has_eeprom ? std::vector<uint8_t>{0x03, 0, 0, 0x5A, 0xA5}
                      : std::vector<uint8_t>{0x03, 0x02, 0xD8, 0x5A, 0xA5});
    apply_erase_uid(request(erase, {0x03}, "erase flash", 12000), regions);
    if (config_.erase_only) return;
    write_user_key();
    const uint64_t total = image.program.size() + image.eeprom.size();
    uint64_t written = 0;
    TransferProgress progress(total);
    auto report_progress = [&progress](uint64_t completed) { progress.update(completed); };
    if (has_eeprom)
        write_region(kEepromBase, image.eeprom, 0x32, 0x12, kEepromBase, written,
                     report_progress);
    if (!image.program.empty())
        write_region(kCodeBase, image.program, 0x02, 0x02, kEepromBase, written,
                     report_progress);
    progress.finish();
    write_download_options(options);
}

void Programmer::make_simulation(const std::vector<uint8_t>& monitor) {
    auto& status = *status_;
    const bool f8d1 = model_.magic == 0xF8D1;
    const auto version = status[17];
    const bool supported_71 = version == 0x71 &&
        ((status_size_ >= 28 && status[18] >= 0x51 && status[22] >= 3) ||
         (status_size_ >= 56 && status[18] >= 0x49 && status[18] <= 0x4C && status[52] >= 3));
    if (version < 0x72 && !supported_71)
        throw std::invalid_argument(model_.name + " simulation creation requires BSL 7.1.3 or later");
    const auto mode = parse_simulation_mode(config_.options.at("simulation_mode"));
    const bool swd = mode == SimulationMode::swd;
    const bool usb = mode == SimulationMode::usb;
    if (usb && version < 0x74)
        throw std::invalid_argument(model_.name + " USB simulation requires BSL 7.4 or later");
    if (f8d1 && version < 0x75)
        throw std::invalid_argument(model_.name + " simulation creation requires BSL 7.5 or later");
    if (!uses_uart() && (model_.family == 76 || model_.family == 88) && version == 0x74 && status[22] == 12) {
        if (status_size_ <= 39)
            throw std::invalid_argument(model_.name + " USB status is missing the BSL production date");
        const auto date = uint32_t{status[37]} << 16 | uint32_t{status[38]} << 8 | status[39];
        if (date >= 0x241219 && date <= 0x250124)
            throw std::invalid_argument(model_.name + " from this BSL 7.4.12 batch requires UART or Link1D");
    }
    const bool short_uart = uses_uart() && version < 0x72;
    const auto pins = [&](const char* key) -> uint8_t {
        const auto it = config_.options.find(key);
        return it == config_.options.end() ? 0 : simulation_pin_bits(it->second);
    };
    std::vector<uint8_t> options;
    if (f8d1) {
        set_bit(status[11], 0x20, !swd);
        set_bit(status[12], 0x20, swd);
        set_bit(status[15], 0x80, swd);
        if (config_.options.contains("swd_pins"))
            status[11] = (status[11] & 0x3F) | pins("swd_pins");
        options = build_f8d1_options();
    } else if (!monitor.empty()) {
        // 44F079 uses the measured trim; 44BA6A/44BB0B pack the old IAP15 profile.
        if (status_size_ <= 37)
            throw std::invalid_argument("IAP15 simulation status is missing the hardware options");
        legacy_options_.fill(0xFF);
        legacy_options_[0] = status[7];
        legacy_options_[1] = status[6];
        legacy_options_[2] = status[5];
        legacy_options_[8] = status[37];
        legacy_options_[14] = status[12] ^ 0x02;
        legacy_clock_uses_measured_ = true;
        options = build_stc15_options();
        options[options.size() - 4] &= 0xFE;
    } else {
        // 44BBA7 and 44B82D are both 40-byte layouts, but the former
        // leaves the SWD/USB selector slots and newer options reserved.
        const bool short_layout = model_.family <= 52;
        const bool wide_status = model_.family == 76 || model_.family == 79 ||
                                 model_.family == 84 || model_.family == 88;
        const size_t body_size = model_.family == 88 ? 0x29 : 0x28;
        options = {0x04, 0, 0};
        if (!short_uart) options.insert(options.end(), {0x5A, 0xA5});
        const auto header_size = options.size();
        options.resize(header_size + body_size, 0xFF);
        auto* body = options.data() + header_size;
        body[3] = body[6] = body[0x16] = 0;
        std::copy_n(status.begin() + 1, 7, body + 0x18);
        // 44C92A normalizes the native-USB reply before the status decoder.
        body[0x24] = uses_uart() ? status[10] : status[13];
        body[0x25] = uses_uart() ? status[wide_status ? 8 : 11] : status[14];
        if (model_.family == 61 && version < 0x74) body[0x25] ^= 0x10;
        body[0x26] = static_cast<uint8_t>((status[15] & 0x7F) | (swd ? 0x80 : 0));
        if (model_.flags & 8) body[0x27] = status[16];
        if (!(status[9] & 4))
            throw std::invalid_argument("cannot preserve active ISP RS485 settings for " + model_.name);
        body[0x20] = status[9];
        if (!short_layout) {
            // Only the families with those controls have selector bytes.
            if (wide_status)
                body[0x22] = static_cast<uint8_t>(0x1F | (swd ? pins("swd_pins") : 0x20));
            if (wide_status || (model_.flags & 0x4000))
                body[0x23] = static_cast<uint8_t>(0x1F | (usb ? 0 : 0x20) |
                    (mode == SimulationMode::uart ? pins("uart_simulation_pins") : 0));
            if (model_.family == 84) {
                const auto hz = (uint32_t{status[1]} << 24) | (uint32_t{status[2]} << 16) |
                                (uint32_t{status[3]} << 8) | status[4];
                body[0x17] = hz > 52'520'000 ? 2 : 1;
            }
            if (model_.family == 88) body[0x28] = status[51];
        }
    }
    if (uses_uart()) initialize_measured_uart();
    else request({0x01, 0, 0, 0, 0, 0, 0, 0x80}, {0x01}, "initialize");
    auto password = password_bytes(config_.password);
    auto prepare = short_uart ? std::vector<uint8_t>{0x05} : std::vector<uint8_t>{0x05, 0, 0, 0x5A, 0xA5};
    prepare.insert(prepare.end(), password.begin(), password.end());
    request(prepare, {0x05}, "prepare simulation flash");
    const auto erase = request(short_uart ? std::vector<uint8_t>{0x03, 0} :
        std::vector<uint8_t>{0x03, 0, 0, 0x5A, 0xA5}, {0x03}, "erase flash for simulation", 30000);
    if (!f8d1 && !uses_uart() && erase.size() != 8)
        throw std::runtime_error("invalid USB erase response: expected 7-byte UID");
    // 44F2C4: only the old IAP15 layout writes auxiliary blocks.
    for (size_t offset = 0; offset < monitor.size(); offset += 64) {
        std::vector<uint8_t> block{static_cast<uint8_t>(offset == 0 ? 0x62 : 0x42),
            static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset)};
        if (!short_uart)
            block.insert(block.end(), {static_cast<uint8_t>(version >= 0x75 ? 0 : 0x5A),
                                       static_cast<uint8_t>(version >= 0x75 ? 0 : 0xA5)});
        block.insert(block.end(), monitor.begin() + offset, monitor.begin() + offset + 64);
        request(block, {0x02, 0x54}, "write IAP15 simulation monitor");
    }
    // The UART 04 handler only checks the command byte (444088).
    request(options, uses_uart() ? std::vector<uint8_t>{0x04} : std::vector<uint8_t>{0x04, 0x54},
            "write simulation hardware options");
}

void Programmer::load_uid_options() {
    if (!config_.uid_bindings.empty()) {
        if (config_.info_only || config_.erase_only || config_.make_simulation ||
            config_.encrypted_image || config_.image.empty())
            throw std::invalid_argument("--uid-bind requires an unencrypted program image");
        if (config_.uid_bindings.size() > 4)
            throw std::invalid_argument("at most four UID addresses are supported");
        for (const auto& [address, spec] : config_.uid_bindings) {
            if (address > 0xFFFFF9 || (!uid_bindings_.empty() && address < uid_bindings_.back().address + 7))
                throw std::invalid_argument("UID addresses overlap or exceed the address space");
            UidBinding binding{address, {}};
            std::string_view remaining(spec);
            while (!remaining.empty()) {
                const auto comma = remaining.find(',');
                const auto item = remaining.substr(0, comma);
                const auto colon = item.find(':');
                if (colon == std::string_view::npos || binding.operations.size() == 4)
                    throw std::invalid_argument("UID binding accepts up to four op:byte operations");
                const auto name = item.substr(0, colon);
                UidOperation op;
                if (name == "add") op = UidOperation::add;
                else if (name == "mul") op = UidOperation::multiply;
                else if (name == "div") op = UidOperation::divide;
                else if (name == "xor") op = UidOperation::xor_byte;
                else throw std::invalid_argument("UID operations are add, mul, div, and xor");
                const auto operand = static_cast<uint8_t>(
                    parse_unsigned(std::string(item.substr(colon + 1)), UINT8_MAX));
                if (op == UidOperation::divide && operand == 0)
                    throw std::invalid_argument("UID binding cannot divide by zero");
                binding.operations.emplace_back(op, operand);
                if (comma == std::string_view::npos) break;
                remaining.remove_prefix(comma + 1);
                if (remaining.empty())
                    throw std::invalid_argument("trailing separator in UID operations");
            }
            uid_bindings_.push_back(std::move(binding));
        }
    }
    if (!config_.uid_allowlist.empty()) {
        if (config_.info_only || config_.erase_only || config_.make_simulation)
            throw std::invalid_argument("--uid-allowlist requires a program download");
        std::ifstream input(utf8_path(config_.uid_allowlist));
        if (!input) throw std::invalid_argument("cannot open the UID allowlist");
        std::string line;
        for (size_t number = 1; std::getline(input, line); ++number) {
            if (number == 1 && line.starts_with("\xEF\xBB\xBF")) line.erase(0, 3);
            if (const auto comment = line.find('#'); comment != std::string::npos) line.resize(comment);
            std::erase_if(line, [](unsigned char c) { return std::isspace(c); });
            if (line.empty()) continue;
            std::array<uint8_t, 7> uid{};
            if (line.size() != uid.size() * 2 ||
                !std::all_of(line.begin(), line.end(), [](unsigned char c) { return std::isxdigit(c); }))
                throw std::invalid_argument("invalid UID allowlist line " + std::to_string(number));
            for (size_t i = 0; i < uid.size(); ++i)
                uid[i] = static_cast<uint8_t>(parse_unsigned("0x" + line.substr(2 * i, 2), UINT8_MAX));
            allowed_uids_.push_back(uid);
        }
        if (input.bad() || allowed_uids_.empty())
            throw std::invalid_argument("cannot read any UID from the allowlist");
        std::sort(allowed_uids_.begin(), allowed_uids_.end());
    }
}

int Programmer::run() {
    if (!config_.simulation_resources.empty() && !config_.make_simulation)
        throw std::invalid_argument("--simulation-resources requires --make-simulation");
    if (config_.make_tool) return program_tool();
    if (!config_.tool_resources.empty())
        throw std::invalid_argument("--tool-resources requires --make-tool");
    if (!config_.offline_output.empty() || !config_.offline_profile.empty()) return pack_offline();
    if (!config_.offline_image.empty() || config_.erase_offline) return run_offline();
    if (!config_.offline_auxiliary.empty() || !config_.offline_resources.empty())
        throw std::invalid_argument("offline auxiliary resources require offline_image");
    if (config_.transport == "usb-soft") {
        auto wire = make_softusb_control(config_.device_path);
        return run_softusb(*wire);
    }
    if (config_.transport != "usb" && config_.transport != "serial" &&
        config_.transport != "uart" && config_.transport != "link1d")
        throw std::invalid_argument("if must be usb, usb-soft, serial, or link1d");
    if (config_.timeout_ms <= 0 || (uses_uart() && (config_.baud <= 0 || config_.handshake_baud <= 0)))
        throw std::invalid_argument("timeout and UART baud rates must be positive");
    if (config_.transport == "link1d") {
        if (config_.link1d_auto_power) {
            if (!config_.reset_command.empty())
                throw std::invalid_argument("Link1D automatic power and application reset cannot be combined");
            Link1dTransport::baud_code(config_.handshake_baud);
            if (!config_.info_only) Link1dTransport::baud_code(config_.baud);
        } else {
            if (config_.port.empty())
                throw std::invalid_argument("Link1D manual power requires the UART1 --port");
            if (!config_.device_path.empty())
                throw std::invalid_argument("--device-path belongs to Link1D HID automatic power mode");
        }
    }
    const auto* selected = config_.model.empty() ? nullptr : find_model_by_name(config_.model);
    if (!config_.model.empty() && !selected)
        throw std::invalid_argument("unknown model: " + config_.model);
    if (config_.info_only && config_.erase_only)
        throw std::invalid_argument("--info and --erase-only are mutually exclusive");
    if (config_.encrypted_image && (config_.info_only || config_.erase_only || config_.make_simulation ||
                                    config_.image.empty()))
        throw std::invalid_argument("--encrypted-image requires a program image to download");
    load_uid_options();
    if (!config_.user_key_file.empty()) {
        if (config_.info_only || config_.erase_only || config_.make_simulation)
            throw std::invalid_argument("--user-key-file requires a program download");
        const auto key = read_user_key(config_.user_key_file);
        user_key_.assign(key.begin(), key.end());
    }
    std::vector<uint8_t> simulation_monitor;
    if (config_.make_simulation) {
        if (config_.info_only || config_.erase_only || !config_.image.empty() || !config_.next_password.empty())
            throw std::invalid_argument("--make-simulation cannot be combined with --info, --erase-only, --image or --next-password");
        if (!selected) throw std::invalid_argument("--make-simulation requires --model");
        const auto entry = config_.options.find("simulation_mode");
        const auto mode = parse_simulation_mode(entry == config_.options.end() ? "" : entry->second);
        if (!(simulation_modes(*selected) & static_cast<uint8_t>(mode)))
            throw std::invalid_argument("simulation_mode=" + entry->second +
                                        " is not available for " + selected->name);
        if (mode == SimulationMode::swd && !uses_uart())
            throw std::invalid_argument("SWD simulation creation requires serial or Link1D ISP");
        if (!supports_simulation(*selected, mode, uses_uart()))
            throw std::invalid_argument("simulation creation is not implemented for " + selected->name +
                                        " over " + config_.transport);
        if (!config_.password.empty() && selected->family != 88 && selected->family != 89)
            throw std::invalid_argument("download password commands are not implemented for " + selected->name);
        (void)password_bytes(config_.password);
        for (const auto& [name, value] : config_.options) {
            if (name == "simulation_mode") continue;
            if ((name == "swd_pins" && mode == SimulationMode::swd) ||
                (name == "uart_simulation_pins" && mode == SimulationMode::uart &&
                 (selected->flags & 0x4000))) {
                (void)simulation_pin_bits(value);
                continue;
            }
            if (name == "modify_hardware_options" && !bool_value(value)) continue;
            throw std::invalid_argument("unrelated hardware option for --make-simulation: " + name);
        }
        if (selected->family == 29 || selected->family == 38) {
            if (config_.simulation_resources.empty())
                throw std::invalid_argument("IAP15 simulation requires --simulation-resources");
            simulation_monitor = build_aicube_iap15_monitor(config_.simulation_resources, selected->magic);
        } else if (!config_.simulation_resources.empty()) {
            throw std::invalid_argument("--simulation-resources is only used for legacy IAP15 simulation");
        }
    }
    if (uses_uart() && !(config_.transport == "link1d" && config_.link1d_auto_power) && config_.port.empty())
        throw std::invalid_argument("serial transport requires --port");
    const auto resolve_route = [&](const ModelInfo& model) {
        const auto route = isp_route(model, uses_uart());
        if (route == IspRoute::unavailable)
            throw std::invalid_argument("writing " + model.name + " over " + config_.transport +
                                        " is not implemented; --info is available");
        if ((!allowed_uids_.empty() || !uid_bindings_.empty()) && uses_uart() && uart_selector(model) < 2)
            throw std::invalid_argument("UID matching is not available for this legacy UART model");
        if (!user_key_.empty() && route != IspRoute::f8d1 &&
            route != IspRoute::ai8051u_uart && route != IspRoute::ai8051u_usb &&
            route != IspRoute::ai32 && route != IspRoute::ai16)
            throw std::invalid_argument("user key download is not implemented for " + model.name);
        const bool stc8u = has_stc8u_status(model.family) &&
            (route == IspRoute::h8u_usb || route == IspRoute::stc8u_usb ||
             route == IspRoute::modern_8bit_uart);
        if (config_.encrypted_image && !stc8u && route != IspRoute::modern_8bit_uart &&
            route != IspRoute::f8d1 && route != IspRoute::ai8051u_uart &&
            route != IspRoute::ai8051u_usb && route != IspRoute::ai32 && route != IspRoute::ai16)
            throw std::invalid_argument("encrypted image writes are not implemented for " + model.name);
        const bool compact_8bit = route == IspRoute::modern_8bit_uart && model.family >= 45;
        if (!stc8u && !compact_8bit && (route == IspRoute::stc89 || route == IspRoute::legacy_stc12 ||
             route == IspRoute::irc15_uart || route == IspRoute::stc15e_uart ||
             route == IspRoute::h8u_usb || route == IspRoute::modern_8bit_uart ||
             route == IspRoute::stc8u_usb) &&
            (!config_.password.empty() || !config_.next_password.empty()))
            throw std::invalid_argument("download password commands are not implemented for " + model.name);
        return route;
    };
    if (!config_.info_only && !config_.make_simulation && selected) resolve_route(*selected);
    if (!config_.info_only && !config_.reset_command.empty()) validate_reset(config_);
    HexImage input;
    bool binary_image = false;
    if (!config_.info_only && !config_.erase_only && !config_.make_simulation) {
        if (!config_.image.empty()) {
            auto extension = utf8_path(config_.image).extension().u8string();
            std::transform(extension.begin(), extension.end(), extension.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            binary_image = extension == u8".bin";
            input = binary_image ? read_binary_file(config_.image, 0x40000) : read_hex_file(config_.image);
            if (input.bytes.empty()) throw std::invalid_argument("Intel HEX contains no data");
            if (binary_image && selected && input.bytes.size() > selected->code_size)
                throw std::invalid_argument("binary image exceeds the selected model's program capacity");
        } else if (!config_.dry_run) {
            throw std::invalid_argument("image is required");
        }
    }
    const auto load_8bit = [&](uint32_t split, IspRoute route) {
        auto hex = input;
        const bool upper_bank = route == IspRoute::ai8051u_uart || route == IspRoute::ai8051u_usb;
        if (upper_bank) {
            HexImage relative;
            relative.has_eof = hex.has_eof;
            for (const auto& [address, value] : hex.bytes) {
                if (address < kCodeBase || address >= kCodeBase + 0x10000)
                    throw std::invalid_argument("AI8051U HEX must use FF0000..FFFFFF");
                relative.bytes.emplace(address - kCodeBase, value);
            }
            for (uint32_t address = 0; address < 3; ++address)
                if (!relative.bytes.contains(address) || address >= split)
                    throw std::invalid_argument("AI8051U HEX requires a reset entry at FF0000");
            hex = std::move(relative);
        }
        const bool stc15 = route == IspRoute::irc15_uart || route == IspRoute::stc15e_uart;
        if (route == IspRoute::stc89 || route == IspRoute::legacy_stc12 || stc15) {
            if (hex.bytes.rbegin()->first >= model_.code_size)
                throw std::invalid_argument("legacy HEX exceeds the target program region");
        }
        const bool short_tail = stc15 || route == IspRoute::modern_8bit_uart ||
            ((route == IspRoute::stc89 || route == IspRoute::legacy_stc12) && (*status_)[17] >= 0x72);
        auto image = split_stc8_image(hex, split, image_fill_value_, !short_tail);
        if (!image.program.empty() && !upper_bank) {
            for (uint32_t addr = 0; addr < 3; ++addr)
                if (!hex.bytes.contains(addr))
                    throw std::invalid_argument("8-bit HEX requires a reset entry at 0000");
        }
        return image;
    };
    if (!config_.info_only) {
        password_bytes(config_.password);
        password_bytes(config_.next_password);
        if (config_.erase_only && !config_.next_password.empty())
            throw std::invalid_argument("--next-password requires a program download");
    }
    const auto ai32_layout = [&](const ModelInfo& model, std::optional<uint8_t> live_boundary) {
        const bool extended = model.family == 76;
        const uint32_t base = extended ? 0xFE0000 : kCodeBase;
        uint32_t offset = extended ? model.total_size - model.code_size : 0;
        const uint32_t end = base + model.total_size;
        uint32_t program_size = model.code_size;
        const auto valid_entry = [&](uint32_t address) {
            return input.bytes.contains(address) && input.bytes.contains(address + 1) &&
                input.bytes.contains(address + 2) &&
                (config_.encrypted_image || input.bytes.at(address) != 0xFF);
        };
        if (model.flags & 8) {
            if (extended) {
                if (live_boundary) {
                    offset = (uint32_t{*live_boundary} + 1) * 1024;
                    if (offset >= model.total_size)
                        throw std::invalid_argument("invalid AI32G12 EEPROM boundary");
                } else if (!input.bytes.empty()) {
                    // A mixed image can start in EEPROM. Check the actual
                    // 1 KiB partition boundary after reading target status.
                    for (offset = 1024; offset + 2 < model.total_size; offset += 1024)
                        if (valid_entry(base + offset)) break;
                    if (offset + 2 >= model.total_size)
                        throw std::invalid_argument("AI32G12 HEX requires a 1 KiB-aligned program start after EEPROM");
                }
            } else if (live_boundary) {
                const auto code_end = uint32_t{*live_boundary} << 8;
                if (!code_end || code_end > model.code_size)
                    throw std::invalid_argument("invalid AI32 current program boundary");
                program_size = code_end;
            }
        }
        uint8_t extra_erase_sectors = 0;
        if (!input.bytes.empty()) {
            const auto last = input.bytes.rbegin()->first;
            if (input.bytes.begin()->first < base || last >= end)
                throw std::invalid_argument("AI32 HEX is outside the target Flash");
            if (!valid_entry(base + offset))
                throw std::invalid_argument("AI32 HEX lacks a nonblank reset entry at the program start");
            if (!extended && last - base >= program_size) {
                const auto sectors = (last - base + 1 - program_size + 511) / 512;
                if (program_size + sectors * 512 > model.total_size ||
                    (live_boundary && (uint32_t{*live_boundary & 0xFEu} << 8) != program_size))
                    throw std::invalid_argument("AI32 EEPROM erase range does not match the current partition");
                extra_erase_sectors = static_cast<uint8_t>(sectors);
            }
        }
        return std::tuple{base, offset, extra_erase_sectors};
    };
    const auto check_ai16_image = [&](const ModelInfo& model) {
        if (input.bytes.empty()) return;
        // 4B9551–4B957B: HEX uses a 64 KiB buffer. BIN keeps its raw length.
        const auto limit = binary_image ? model.code_size : std::min(model.code_size, 0x10000u);
        if (input.bytes.rbegin()->first >= limit)
            throw std::invalid_argument("AI16 Beta image exceeds the limit for this format");
        if (!input.bytes.contains(0) || !input.bytes.contains(1) || !input.bytes.contains(2) ||
            (input.bytes.at(0) == 0xFF && !config_.encrypted_image))
            throw std::invalid_argument("AI16 Beta image requires a nonblank reset entry at 0000");
    };
    if (!config_.info_only && !config_.make_simulation && selected) {
        const auto route = isp_route(*selected, uses_uart());
        if (route == IspRoute::ai32 && !binary_image) (void)ai32_layout(*selected, std::nullopt);
        if (route == IspRoute::ai16) check_ai16_image(*selected);
    }
    std::optional<uint8_t> eeprom_fill;
    const auto load_modern_8bit = [&](uint32_t code_end) {
        // AiCube 4C1DFF merges the program and EEPROM suffix into one image;
        // 442D08/44CCE5 request additional 512-byte erase sectors as needed.
        const auto limit = std::min<uint32_t>(model_.total_size, 0x10000);
        if (!code_end || code_end > limit)
            throw std::invalid_argument("invalid 8-bit program area boundary");
        if (input.bytes.empty()) return std::pair{std::vector<uint8_t>{}, uint8_t{0}};
        if (!input.bytes.contains(0) || !input.bytes.contains(1) || !input.bytes.contains(2) ||
            (input.bytes.at(0) == 0xFF && !config_.encrypted_image))
            throw std::invalid_argument("8-bit HEX requires a nonblank reset entry at 0000");
        const auto last = input.bytes.rbegin()->first;
        if (last >= limit)
            throw std::invalid_argument("8-bit HEX exceeds the target Flash capacity");
        uint32_t extent = last + 1;
        if (eeprom_fill) {
            // 48E9B0 uses the model's EEPROM length, not total Flash minus program size.
            if (last >= code_end)
                throw std::invalid_argument("EEPROM fill cannot be combined with image data or UID bindings in EEPROM");
            if (model_.legacy_eeprom_size > limit - code_end)
                throw std::invalid_argument("the EEPROM fill range exceeds the target Flash capacity");
            extent = code_end + model_.legacy_eeprom_size;
        }
        const auto extra = extent > code_end ? (extent - code_end + 511) / 512 : 0;
        if (extra && code_end + extra * 512 > limit)
            throw std::invalid_argument("the EEPROM erase range exceeds the target Flash capacity");
        std::vector<uint8_t> image(extent, image_fill_value_);
        if (eeprom_fill)
            std::fill(image.begin() + code_end, image.end(), *eeprom_fill);
        for (const auto& [address, value] : input.bytes) image[address] = value;
        if (test_parameter_patch_ && (*status_)[17] < 0x72) {
            const auto& [address, bytes] = *test_parameter_patch_;
            image.resize(std::max(image.size(), address + bytes.size()), 0xFF);
            std::copy(bytes.begin(), bytes.end(), image.begin() + address);
        }
        return std::pair{std::move(image), static_cast<uint8_t>(extra)};
    };
    const auto code_end_8bit = [&](bool offline, uint8_t live_boundary) {
        const auto& status = *status_;
        if (!offline && has_fixed_63k_partition()) return uint32_t{0xFC00};
        if (!offline && (status[17] == 0x73 || status[17] == 0x74) && status_size_ <= 22)
            throw std::invalid_argument("target status is missing the BSL patch version");
        return !offline && bsl_reports_code_end(status[17], status[22])
            ? uint32_t{live_boundary & 0xFEu} << 8 : model_.code_size;
    };

    const auto place_binary = [&](IspRoute route, uint8_t partition) {
        uint32_t start = 0;
        uint32_t capacity = model_.code_size;
        if (route == IspRoute::f8d1 || route == IspRoute::ai8051u_uart || route == IspRoute::ai8051u_usb ||
            (route == IspRoute::ai32 && model_.family != 76)) {
            start = kCodeBase;
            capacity = std::min(capacity, 0x10000u);
        }
        if (route == IspRoute::ai32 && model_.family == 76) {
            auto offset = model_.total_size - model_.code_size;
            if (model_.flags & 8) offset = (uint32_t{partition} + 1) * 1024;
            if (offset >= model_.total_size)
                throw std::invalid_argument("invalid AI32G12 EEPROM boundary");
            start = 0xFE0000 + offset;
            capacity = model_.total_size - offset;
        }
        if (input.bytes.size() > capacity)
            throw std::invalid_argument("binary image exceeds the program capacity");
        if (start != 0) {
            std::map<uint32_t, uint8_t> absolute;
            for (const auto& [address, value] : input.bytes)
                absolute.emplace_hint(absolute.end(), start + address, value);
            input.bytes = std::move(absolute);
        }
    };
    const auto dispatch = [&](IspRoute route, bool offline) {
        const auto original_eeprom_code = !offline && has_fixed_63k_partition() ?
            uint8_t{0xFC} : (*status_)[16];
        eeprom_fill.reset();
        for (const auto& [key, byte] : {
                 std::pair{"eeprom_fill_zero", uint8_t{0}},
                 std::pair{"eeprom_fill_ff", uint8_t{0xFF}}}) {
            const auto it = config_.options.find(key);
            if (it == config_.options.end()) continue;
            if (!bool_value(it->second)) continue;
            const bool stc15_fill = model_.family == 25 || (model_.family >= 27 && model_.family <= 43);
            if (!model_.legacy_eeprom_size || (model_.family != 8 && (byte == 0 || !stc15_fill)))
                throw std::invalid_argument(model_.name + " does not support " + key);
            if (eeprom_fill) throw std::invalid_argument("select only one EEPROM fill value");
            if (config_.erase_only || (!offline && input.bytes.empty()))
                throw std::invalid_argument("EEPROM fill requires a program image");
            eeprom_fill = byte;
        }
        if (!config_.erase_only) apply_options(route);
        if (!offline) enforce_fixed_63k_partition();
        // 4BE1C0 recomputes the G12 program start from the selected EEPROM size.
        const bool g12 = route == IspRoute::ai32 && model_.family == 76;
        const auto image_partition = g12 ? (*status_)[16] : original_eeprom_code;
        if (binary_image) place_binary(route, image_partition);
        if (!uid_bindings_.empty()) {
            uint32_t reset = 0;
            if (g12) {
                const bool selected_partition = modify_hardware_options_ && config_.options.contains("eeprom_kib");
                const auto [base, offset, ignored] = ai32_layout(model_,
                    offline && !binary_image && !selected_partition ?
                        std::nullopt : std::optional{image_partition});
                reset = base + offset;
            } else if (route == IspRoute::f8d1 || route == IspRoute::ai8051u_uart ||
                       route == IspRoute::ai8051u_usb || route == IspRoute::ai32) {
                reset = kCodeBase;
            }
            reserve_uid_destinations(input, reset);
        }
        const bool have_image = !input.bytes.empty();
        if (!offline && have_image && !config_.erase_only) {
            const auto append = config_.options.find("append_test_parameters");
            if (append != config_.options.end() && bool_value(append->second))
                prepare_test_parameters(input, code_end_8bit(offline, original_eeprom_code));
            if (test_parameter_patch_ && hardware_options_write_required_ && (model_.flags & 8) &&
                (*status_)[16] != original_eeprom_code && test_parameter_patch_->address +
                    test_parameter_patch_->bytes.size() > (uint32_t{(*status_)[16]} << 8))
                throw std::invalid_argument("test parameters do not fit within the requested program partition");
        }
        switch (route) {
        case IspRoute::f8d1: {
            if (!offline && !user_key_.empty() && (*status_)[17] < 0x75)
                throw std::invalid_argument("user key download requires BSL 7.5 or later");
            const auto eeprom_end = offline ? kCodeBase :
                std::min(kEepromBase + (static_cast<uint32_t>(std::min(original_eeprom_code, (*status_)[16])) + 1) * 2048,
                         kCodeBase);
            const auto image = have_image ? load_stc32_image(input, eeprom_end) : Stc32Image{};
            if (offline) break;
            if (!uses_uart()) {
                program_stc32(image);
                break;
            }
            constexpr uint32_t code_offset = kCodeBase - kEepromBase;
            std::vector<uint8_t> data;
            if (have_image) {
                data.resize(input.bytes.rbegin()->first - kEepromBase + 1, image_fill_value_);
                std::fill_n(data.begin(), code_offset, 0xFF);
                std::copy(image.eeprom.begin(), image.eeprom.end(), data.begin());
                for (const auto& [address, value] : input.bytes) data[address - kEepromBase] = value;
            }
            auto options = !config_.erase_only &&
                ((!config_.options.empty() && modify_hardware_options_) ||
                 hardware_options_write_required_ || !config_.next_password.empty()) ?
                build_f8d1_options() : std::vector<uint8_t>{};
            if (!options.empty()) set_download_rs485(options);
            program_banked(std::move(data), kEepromBase, 0, 0, options);
            break;
        }
        case IspRoute::ai16: {
            check_ai16_image(model_);
            if (offline) break;
            std::vector<uint8_t> data;
            uint8_t extra_erase_sectors = 0;
            if (have_image) {
                const auto extent = input.bytes.rbegin()->first + 1;
                const auto boundary = uint32_t{original_eeprom_code & 0xFEu} << 8;
                if (!boundary || boundary > model_.total_size)
                    throw std::invalid_argument("invalid AI16 Beta Flash boundary");
                // 442D08 / 44CCE5 add 512-byte erase sectors if the image
                // extends past the device-reported boundary.
                const auto extra = extent > boundary ? (extent - boundary + 511) / 512 : 0;
                if (extra > 255 || boundary + extra * 512 > model_.total_size)
                    throw std::invalid_argument("AI16 Beta erase exceeds the target Flash capacity");
                extra_erase_sectors = static_cast<uint8_t>(extra);
                data.resize(extent, image_fill_value_);
                for (const auto& [address, value] : input.bytes) data[address] = value;
            }
            const auto options = hardware_options_write_required_ || !config_.next_password.empty() ?
                build_generic_8bit_options() : std::vector<uint8_t>{};
            program_banked(std::move(data), 0, 0, extra_erase_sectors, options);
            break;
        }
        case IspRoute::ai32: {
            const bool has_selected_partition = g12 && modify_hardware_options_ &&
                                               config_.options.contains("eeprom_kib");
            const auto [base, reset_offset, extra_erase_sectors] = ai32_layout(
                model_, offline && (!g12 || (!binary_image && !has_selected_partition)) ?
                    std::nullopt : std::optional{image_partition});
            if (binary_image && extra_erase_sectors)
                throw std::invalid_argument("binary image exceeds the current AI32 program partition");
            if (offline) break;
            if (!g12 && (*status_)[16] != original_eeprom_code && have_image &&
                input.bytes.rbegin()->first - base >= (uint32_t{(*status_)[16]} << 8))
                throw std::invalid_argument("image exceeds the requested AI32 program partition");
            std::vector<uint8_t> data;
            if (have_image) {
                data.resize(input.bytes.rbegin()->first - base + 1, image_fill_value_);
                // The unwritten EEPROM prefix must stay out of the erase
                // calculation and must never be filled with the code fill byte.
                std::fill_n(data.begin(), reset_offset, 0xFF);
                for (const auto& [address, value] : input.bytes) data[address - base] = value;
            }
            const auto options = !config_.erase_only &&
                (hardware_options_write_required_ || !config_.next_password.empty()) ?
                build_ai32_options() : std::vector<uint8_t>{};
            program_banked(std::move(data), base, reset_offset, extra_erase_sectors, options);
            break;
        }
        case IspRoute::ai8051u_usb:
        case IspRoute::ai8051u_uart: {
            const auto program_boundary = [&](uint8_t status_byte) {
                if (!(model_.flags & 8)) return model_.code_size;
                if (status_byte >= 64) throw std::runtime_error("invalid AI8051U EEPROM geometry");
                return 0x10000u - (uint32_t{status_byte} + 1) * 1024;
            };
            const auto eeprom_base = program_boundary((*status_)[16]);
            const auto old_eeprom_base = program_boundary(original_eeprom_code);
            const auto image = have_image ? load_8bit(eeprom_base, route) : Stc8Image{};
            if (binary_image && !image.eeprom.empty())
                throw std::invalid_argument("binary image exceeds the current AI8051U program partition");
            if (image.program.size() > model_.code_size || (!offline &&
                (image.program.size() > old_eeprom_base || (!image.eeprom.empty() && eeprom_base < old_eeprom_base))))
                throw std::invalid_argument("AI8051U image exceeds current flash layout; change EEPROM sizing separately");
            const auto& status = *status_;
            const bool system_area_enabled = !(status[uses_uart() ? 8 : 14] & 0x80) && !(status[51] & 1);
            if (have_image && system_area_enabled &&
                input.bytes.rbegin()->first - kCodeBase >= (uint32_t{status[51]} << 8))
                throw std::invalid_argument("AI8051U firmware overlaps the configured user system area");
            if (offline) break;
            std::vector<uint8_t> merged;
            uint8_t sectors = 0;
            if (have_image) {
                if (image.program.empty() || (!config_.encrypted_image && image.program[0] == 0xFF))
                    throw std::invalid_argument("AI8051U requires a nonblank reset entry");
                // 4C1DFF merges the data before transmission. 442D08/44CCE5
                // count extra erase sectors from the original handshake boundary.
                const auto extent = input.bytes.rbegin()->first - kCodeBase + 1;
                const auto boundary = uint32_t{original_eeprom_code & 0xFEu} << 8;
                if (extent > boundary)
                    sectors = static_cast<uint8_t>((extent - boundary + 511) / 512);
                merged.resize(extent, image_fill_value_);
                for (const auto& [address, value] : input.bytes) merged[address - kCodeBase] = value;
            }
            const auto options = !config_.erase_only &&
                (hardware_options_write_required_ || !config_.next_password.empty()) ?
                build_ai8051_options() : std::vector<uint8_t>{};
            program_banked(std::move(merged), kCodeBase, 0, sectors, options);
            break;
        }
        case IspRoute::stc89:
        case IspRoute::legacy_stc12: {
            const auto minimum = model_.family == 9 ? 0x58 :
                (model_.family == 7 || model_.family == 8 ? 0x50 : 0);
            const auto version = (*status_)[17];
            if (!offline && version < minimum)
                throw std::invalid_argument("this BSL revision predates the legacy UART write protocol");
            if (!offline && model_.family <= 2 && version < 0x38 &&
                (*status_)[19] != original_option_byte_)
                throw std::invalid_argument("changing hardware options requires STC89 BSL 3.8 or later");
            const bool legacy_mixed = route == IspRoute::legacy_stc12 && version < 0x72 &&
                have_image && input.bytes.rbegin()->first >= model_.code_size;
            if (legacy_mixed && input.bytes.rbegin()->first - model_.code_size >= model_.legacy_eeprom_size)
                throw std::invalid_argument("HEX exceeds the legacy STC12 EEPROM area");
            if (version >= 0x72 || eeprom_fill || legacy_mixed) {
                auto [image, extra] = load_modern_8bit(code_end_8bit(offline, original_eeprom_code));
                if (extra && (route == IspRoute::stc89 || (binary_image && !eeprom_fill)))
                    throw std::invalid_argument("image exceeds the current program partition");
                // 4C1E51 rounds the merged buffer before the old 84/00 sender uses it.
                if (legacy_mixed)
                    image.resize((image.size() + 511) & ~size_t{511}, image_fill_value_);
                if (!offline) program_legacy_uart(image, route, extra);
            } else {
                const auto image = have_image ? load_8bit(model_.code_size, route) : Stc8Image{};
                if (!offline) program_legacy_uart(image.program, route, 0);
            }
            break;
        }
        case IspRoute::modern_8bit_uart:
        case IspRoute::stc8u_usb: {
            const bool native_usb = route == IspRoute::stc8u_usb;
            const auto& status = *status_;
            const auto [image, extra_erase_sectors] = load_modern_8bit(
                code_end_8bit(offline, original_eeprom_code));
            if (binary_image && extra_erase_sectors && !eeprom_fill)
                throw std::invalid_argument("binary image exceeds the current 8-bit program partition");
            if (offline) break;
            if (hardware_options_write_required_ && (model_.flags & 8) &&
                (*status_)[16] != original_eeprom_code &&
                image.size() > (uint32_t{(*status_)[16]} << 8))
                throw std::invalid_argument("image exceeds the requested program partition");
            if (native_usb) {
                if (status[17] < 0x74)
                    throw std::invalid_argument("this STC8 USB route requires BSL 7.4 or later");
                const auto options = hardware_options_write_required_ || !config_.next_password.empty() ?
                    build_stc8u_options() : std::vector<uint8_t>{};
                program_8bit_native_usb(image, extra_erase_sectors, options);
            } else {
                program_modern_8bit_uart(image, extra_erase_sectors);
            }
            break;
        }
        case IspRoute::irc15_uart:
        case IspRoute::stc15e_uart: {
            const auto [image, extra_erase_sectors] = load_modern_8bit(
                code_end_8bit(offline, original_eeprom_code));
            if (binary_image && extra_erase_sectors && !eeprom_fill)
                throw std::invalid_argument("binary image exceeds the current STC15 program partition");
            if (!offline) program_stc15_uart(image, route, extra_erase_sectors);
            break;
        }
        case IspRoute::h8u_usb: {
            const auto& status = *status_;
            const auto [combined, extra_erase_sectors] = load_modern_8bit(
                code_end_8bit(offline, original_eeprom_code));
            if (binary_image && extra_erase_sectors)
                throw std::invalid_argument("binary image exceeds the current H8U program partition");
            if (offline) break;
            const bool older = status[17] < 0x74;
            const bool late_73 = status[17] == 0x73 && status[22] >= 12;
            if (older && (!config_.password.empty() || !config_.next_password.empty() || config_.encrypted_image))
                throw std::invalid_argument("H8U password and encrypted writes require BSL 7.4 or later");
            if (older && !late_73 && hardware_options_write_required_)
                throw std::invalid_argument("H8U hardware option writes require BSL 7.3.12 or later");
            if (hardware_options_write_required_ && status[16] != original_eeprom_code &&
                combined.size() > (uint32_t{status[16]} << 8))
                throw std::invalid_argument("image exceeds the requested H8U program partition");
            const auto options = hardware_options_write_required_ || !config_.next_password.empty() ?
                build_stc8u_options() : std::vector<uint8_t>{};
            program_8bit_native_usb(combined, extra_erase_sectors, options);
            break;
        }
        case IspRoute::unavailable:
            throw std::logic_error("no ISP write route selected");
        }
    };
    if (config_.dry_run) {
        if (!config_.info_only && !config_.make_simulation) {
            if (!selected) throw std::invalid_argument("--dry-run requires --model to validate a write");
            model_ = *selected;
            status_.emplace();
            (*status_)[51] = 0xFF;
            dispatch(resolve_route(model_), true);
        }
        std::cout << "Configuration is valid. No device was opened.\n";
        return 0;
    }
    if (!config_.info_only && !config_.reset_command.empty()) {
        send_application_reset(config_);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    try {
        connect();
        if (config_.info_only) {
            print_device_info();
            disconnect(true);
            return 0;
        }
        if (config_.make_simulation) make_simulation(simulation_monitor);
        else dispatch(resolve_route(model_), false);
        disconnect(true);
    } catch (...) {
        try { disconnect(false); } catch (...) {}
        throw;
    }
    std::cout << (config_.make_simulation ? "Simulation chip configured.\n" : "Programming complete.\n");
    return 0;
}

}  // namespace stcisp
