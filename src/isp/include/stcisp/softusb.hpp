#pragma once

#include "stcisp/isp.hpp"

namespace stcisp {

class SoftUsbControl {
public:
    virtual ~SoftUsbControl() = default;
    virtual void open() = 0;
    virtual void close() noexcept = 0;
    virtual size_t transfer(bool input, uint8_t request, uint16_t value, uint16_t index,
                            std::span<uint8_t> data, int timeout_ms) = 0;
};

std::unique_ptr<SoftUsbControl> make_softusb_control(const std::string& path);
std::vector<uint8_t> encode_softusb_data(std::span<const uint8_t> data);
std::vector<uint8_t> decode_softusb_reply(std::span<const uint8_t> data);

}  // namespace stcisp
