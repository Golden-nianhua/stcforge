#pragma once

#include "stcisp/isp.hpp"

namespace stcisp {

// Transports target ISP payloads, not framed UART bytes.
class Link1dTransport final : public Transport {
public:
    explicit Link1dTransport(std::unique_ptr<Transport> hid);
    void open() override;
    void close() noexcept override;
    void write(const std::vector<uint8_t>& payload) override;
    std::vector<uint8_t> read(int timeout_ms) override;
    void set_baud(int baud) override;
    void set_baud(int baud, bool even_parity);
    void switch_legacy_baud(int baud);

    std::vector<uint8_t> start(int baud, int timeout_ms, bool even_parity, bool model_flag);
    void finish(bool success, bool keep_power);
    static uint8_t baud_code(int baud);

private:
    friend class Programmer;
    void command(uint8_t code, const std::vector<uint8_t>& payload = {}, uint32_t argument = 0,
                 std::optional<uint8_t> parameter = std::nullopt);
    std::unique_ptr<Transport> hid_;
    bool started_ = false;
    bool even_parity_ = true;
};

}  // namespace stcisp
