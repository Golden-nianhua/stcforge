#include "stcisp/link1d.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

namespace stcisp {
namespace {
constexpr size_t chunk_size = 56;
constexpr uint8_t voltage_mode = 3;
constexpr uint8_t power_delay = 5;
constexpr uint8_t current_limit = 9;
using namespace std::chrono_literals;
}

Link1dTransport::Link1dTransport(std::unique_ptr<Transport> hid) : hid_(std::move(hid)) {}

void Link1dTransport::open() { hid_->open(); }
void Link1dTransport::close() noexcept { hid_->close(); }

uint8_t Link1dTransport::baud_code(int baud) {
    if (baud >= 1200 && baud <= 115200 && baud % 1200 == 0)
        return static_cast<uint8_t>(baud / 1200);
    if (baud > 115200 && baud <= 921600 && baud % 115200 == 0)
        return static_cast<uint8_t>(0x80 + baud / 115200);
    throw std::invalid_argument("unsupported Link1D baud rate: " + std::to_string(baud));
}

void Link1dTransport::command(uint8_t code, const std::vector<uint8_t>& payload, uint32_t argument,
                               std::optional<uint8_t> parameter) {
    if (payload.size() > chunk_size) throw std::invalid_argument("Link1D report payload too long");
    if (parameter && !payload.empty()) throw std::logic_error("HID parameter cannot carry a payload");
    std::vector<uint8_t> report(64);
    report[0] = 0x5A;
    report[1] = code;
    for (size_t i = 0; i < 4; ++i)
        report[2 + i] = static_cast<uint8_t>(argument >> (24 - 8 * i));
    report[6] = parameter.value_or(static_cast<uint8_t>(payload.size()));
    std::copy(payload.begin(), payload.end(), report.begin() + 7);
    for (size_t i = 0; i < 63; ++i) report[63] -= report[i];
    hid_->write(report);
}

void Link1dTransport::write(const std::vector<uint8_t>& payload) {
    if (payload.size() > 255) throw std::invalid_argument("Link1D UART frame exceeds one-byte commit length");
    if (payload.size() < chunk_size) return command(0x43, payload);
    for (size_t offset = 0; offset < payload.size(); offset += chunk_size) {
        const auto begin = payload.begin() + offset;
        const auto end = begin + std::min(chunk_size, payload.size() - offset);
        command(0x44, std::vector<uint8_t>(begin, end), static_cast<uint32_t>(offset));
    }
    command(0x45, {static_cast<uint8_t>(payload.size())});
}

std::vector<uint8_t> Link1dTransport::read(int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TransportTimeout("Link1D read timeout");
        const auto report = hid_->read(static_cast<int>(remaining));
        if (report.size() != 64 || report[2] > report.size() - 3)
            throw std::runtime_error("invalid Link1D input report");
        if (report[1] != 0)
            throw std::runtime_error("Link1D tool error: " + std::to_string(report[1]));
        if (report[2] > 0) return {report.begin() + 3, report.begin() + 3 + report[2]};
    }
}

void Link1dTransport::set_baud(int baud) {
    command(0x40, {2, baud_code(baud), static_cast<uint8_t>(even_parity_)});
}

void Link1dTransport::set_baud(int baud, bool even_parity) {
    even_parity_ = even_parity;
    set_baud(baud);
}

void Link1dTransport::switch_legacy_baud(int baud) {
    set_baud(baud);
    command(0x4D);
    std::this_thread::sleep_for(50ms);
}

std::vector<uint8_t> Link1dTransport::start(int baud, int timeout_ms, bool even_parity, bool model_flag) {
    even_parity_ = even_parity;
    command(0x00);
    if (read(timeout_ms).front() != 0x51) throw std::runtime_error("unexpected Link1D probe identity");
    set_baud(baud);
    std::this_thread::sleep_for(50ms);
    started_ = true;
    command(0x40, {4, 0});
    command(0x40, {voltage_mode, 0});
    command(0x41, {0, 0, voltage_mode, power_delay, 0, current_limit, 0,
                    static_cast<uint8_t>(model_flag)});
    auto status = read(timeout_ms);
    if (status.front() == 0x80) {
        std::this_thread::sleep_for(50ms);
        write({0x80});
        status = read(timeout_ms);
    }
    return status;
}

void Link1dTransport::finish(bool success, bool keep_power) {
    if (!started_) return;
    started_ = false;
    std::exception_ptr error;
    const auto try_command = [&](uint8_t code, const std::vector<uint8_t>& bytes) {
        try { command(code, bytes); }
        catch (...) { if (!error) error = std::current_exception(); }
    };
    try_command(0x40, {4, static_cast<uint8_t>(success)});
    std::this_thread::sleep_for(100ms);
    const bool retain = success && keep_power && !error;
    // 43DA3F uses the keep-power checkbox, not the status sent with subcommand 04.
    try_command(0x40, {0x0C, static_cast<uint8_t>(retain)});
    try_command(0x40, {0});
    if (retain && !error) {
        std::this_thread::sleep_for(std::chrono::milliseconds(power_delay * 100));
        try_command(0x40, {voltage_mode, 0});
    }
    try_command(0x40, {0x0A, 0});
    try_command(0xFF, {});
    if (error) std::rethrow_exception(error);
}

}  // namespace stcisp
