#include "stcisp/softusb.hpp"
#include "stcisp/crypto.hpp"
#include "stcisp/database.hpp"
#include "utf8_path.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <numeric>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <usbscan.h>
#elif defined(STC_ISP_HAVE_LIBUSB)
#include <libusb.h>
#endif

namespace stcisp {
namespace {
constexpr uint16_t vendor = 0x5354;
constexpr uint16_t product = 0x4312;
using namespace std::chrono_literals;

#ifdef _WIN32
bool control_ioctl(HANDLE device, DWORD code, void* input, DWORD input_size,
                   void* output, DWORD output_size, int timeout_ms, DWORD& received) {
    OVERLAPPED op{};
    op.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!op.hEvent) throw std::runtime_error("cannot create USBSCAN completion event");
    bool success = DeviceIoControl(device, code, input, input_size, output, output_size,
                                   &received, &op) != FALSE;
    auto error = success ? ERROR_SUCCESS : GetLastError();
    if (error == ERROR_IO_PENDING) {
        const auto wait = WaitForSingleObject(op.hEvent, static_cast<DWORD>(timeout_ms));
        if (wait == WAIT_OBJECT_0) {
            success = GetOverlappedResult(device, &op, &received, FALSE) != FALSE;
            error = success ? ERROR_SUCCESS : GetLastError();
        } else {
            CancelIoEx(device, &op);
            GetOverlappedResult(device, &op, &received, TRUE);
            error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_GEN_FAILURE;
        }
    }
    CloseHandle(op.hEvent);
    SetLastError(error);
    return success;
}

class WindowsSoftUsb final : public SoftUsbControl {
public:
    explicit WindowsSoftUsb(std::string path) : path_(std::move(path)) {}
    ~WindowsSoftUsb() override { close(); }
    void open() override {
        if (handle_ != INVALID_HANDLE_VALUE) return;
        constexpr std::string_view prefix = "\\\\.\\usbscan";
        const auto candidate = [&](unsigned int number) {
            const auto name = std::string(prefix) + std::to_string(number);
            auto handle = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            if (handle == INVALID_HANDLE_VALUE) return handle;
            DEVICE_DESCRIPTOR desc{};
            DWORD received = 0;
            if (control_ioctl(handle, IOCTL_GET_DEVICE_DESCRIPTOR, &desc, sizeof(desc), &desc,
                              sizeof(desc), 200, received) &&
                desc.usVendorId == vendor && desc.usProductId == product) return handle;
            CloseHandle(handle);
            return INVALID_HANDLE_VALUE;
        };
        if (!path_.empty()) {
            if (!path_.starts_with(prefix))
                throw std::invalid_argument("software USB device path must use \\\\.\\usbscanN");
            handle_ = candidate(parse_unsigned(path_.substr(prefix.size()), 127));
        } else {
            for (unsigned number = 0; number < 128; ++number) {
                const auto result = candidate(number);
                if (result == INVALID_HANDLE_VALUE) continue;
                if (handle_ != INVALID_HANDLE_VALUE) {
                    CloseHandle(result);
                    close();
                    throw std::runtime_error("multiple software USB devices; select --device-path \\\\.\\usbscanN");
                }
                handle_ = result;
            }
        }
        if (handle_ == INVALID_HANDLE_VALUE)
            throw std::runtime_error("no STC software USB device (5354:4312) found via USBSCAN");
    }
    void close() noexcept override {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    size_t transfer(bool input, uint8_t request, uint16_t value, uint16_t index,
                    std::span<uint8_t> data, int timeout_ms) override {
        IO_BLOCK_EX block{};
        block.uOffset = value;
        block.uLength = static_cast<unsigned>(data.size());
        block.pbyData = data.data();
        block.uIndex = index;
        block.bRequest = request;
        block.bmRequestType = input ? 0xC0 : 0x40;
        block.fTransferDirectionIn = input;
        DWORD received = 0;
        if (!control_ioctl(handle_, IOCTL_SEND_USB_REQUEST, &block, sizeof(block),
                           data.data(), static_cast<DWORD>(data.size()), timeout_ms, received)) {
            const auto error = GetLastError();
            if (error == ERROR_TIMEOUT) throw TransportTimeout("USBSCAN transfer timed out");
            throw std::runtime_error("USBSCAN transfer failed: " + std::to_string(error));
        }
        // UsbScan may report zero bytes in the IOCTL result while filling
        // pbyData. The software-USB frame itself carries a checked length.
        return data.size();
    }
private:
    std::string path_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};
#elif defined(STC_ISP_HAVE_LIBUSB)
class PosixSoftUsb final : public SoftUsbControl {
public:
    explicit PosixSoftUsb(std::string path) : path_(std::move(path)) {}
    ~PosixSoftUsb() override { close(); }
    void open() override {
        if (handle_) return;
        if (libusb_init(&context_) != 0) throw std::runtime_error("libusb initialization failed");
        libusb_device** list = nullptr;
        const auto count = libusb_get_device_list(context_, &list);
        if (count < 0) throw std::runtime_error("cannot enumerate software USB devices");
        libusb_device* selected = nullptr;
        bool multiple = false;
        for (decltype(libusb_get_device_list(context_, &list)) i = 0; i < count; ++i) {
            libusb_device_descriptor info{};
            if (libusb_get_device_descriptor(list[i], &info) != 0 ||
                info.idVendor != vendor || info.idProduct != product) continue;
            const auto address = std::to_string(libusb_get_bus_number(list[i])) + ":" +
                std::to_string(libusb_get_device_address(list[i]));
            if (!path_.empty() && address != path_) continue;
            if (selected) { multiple = true; break; }
            selected = list[i];
        }
        const auto result = selected && !multiple ? libusb_open(selected, &handle_) : LIBUSB_ERROR_NO_DEVICE;
        libusb_free_device_list(list, 1);
        if (multiple) throw std::runtime_error("multiple software USB devices; use --device-path bus:address");
        if (result != 0) throw std::runtime_error("cannot open STC software USB device: " + std::to_string(result));
    }
    void close() noexcept override {
        if (handle_) libusb_close(handle_);
        if (context_) libusb_exit(context_);
        handle_ = nullptr;
        context_ = nullptr;
    }
    size_t transfer(bool input, uint8_t request, uint16_t value, uint16_t index,
                    std::span<uint8_t> data, int timeout_ms) override {
        const int size = libusb_control_transfer(handle_, input ? 0xC0 : 0x40, request, value, index,
            data.data(), static_cast<uint16_t>(data.size()), static_cast<unsigned>(timeout_ms));
        if (size == LIBUSB_ERROR_TIMEOUT) throw TransportTimeout("software USB transfer timed out");
        if (size < 0) throw std::runtime_error("software USB transfer failed: " + std::to_string(size));
        return static_cast<size_t>(size);
    }
private:
    std::string path_;
    libusb_context* context_ = nullptr;
    libusb_device_handle* handle_ = nullptr;
};
#endif
}  // namespace

std::unique_ptr<SoftUsbControl> make_softusb_control(const std::string& path) {
#ifdef _WIN32
    return std::make_unique<WindowsSoftUsb>(path);
#elif defined(STC_ISP_HAVE_LIBUSB)
    return std::make_unique<PosixSoftUsb>(path);
#else
    (void)path;
    throw std::runtime_error("software USB requires libusb on this platform");
#endif
}

std::vector<uint8_t> encode_softusb_data(std::span<const uint8_t> data) {
    std::vector<uint8_t> result;
    result.reserve(data.size() + (data.size() + 6) / 7);
    for (size_t pos = 0; pos < data.size(); pos += 7) {
        const auto group = data.subspan(pos, std::min(size_t{7}, data.size() - pos));
        result.insert(result.end(), group.begin(), group.end());
        result.push_back(static_cast<uint8_t>(0u - std::accumulate(group.begin(), group.end(), 0u)));
    }
    return result;
}

std::vector<uint8_t> decode_softusb_reply(std::span<const uint8_t> data) {
    if (data.size() < 5 || data[0] != 0x46 || data[1] != 0xB9 ||
        data[2] == 0 || size_t{data[2]} + 4 > data.size())
        throw std::runtime_error("invalid software USB reply length or marker");
    const auto frame = data.first(data[2] + 4);
    if (static_cast<uint8_t>(std::accumulate(frame.begin(), frame.end(), 1u)) != 0)
        throw std::runtime_error("software USB reply checksum mismatch");
    return {frame.begin() + 3, frame.end() - 1};
}

int Programmer::run_softusb(SoftUsbControl& wire) {
    if (config_.timeout_ms <= 0 || !config_.port.empty() || config_.make_simulation)
        throw std::invalid_argument("unsupported software USB connection or task options");
    if ((config_.info_only && (config_.erase_only || !config_.image.empty())) ||
        (config_.erase_only && (!config_.image.empty() || !config_.next_password.empty() ||
                                !config_.user_key_file.empty())) ||
        (config_.info_only && (!config_.password.empty() || !config_.next_password.empty() ||
                               !config_.user_key_file.empty() || config_.encrypted_image)) ||
        (!config_.info_only && !config_.erase_only && config_.image.empty()))
        throw std::invalid_argument("software USB requires exactly one of --info, --erase-only, or --image");
    const auto* selected = config_.model.empty() ? nullptr : find_model_by_name(config_.model);
    if (!config_.model.empty() && !selected) throw std::invalid_argument("unknown software USB model");
    const auto writeable = [](const ModelInfo& model) {
        const auto route = isp_route(model, true);
        return !(model.flags & 0x4000) && model.code_size && model.total_size <= 0x10000 &&
            (route == IspRoute::modern_8bit_uart || route == IspRoute::irc15_uart ||
             route == IspRoute::legacy_stc12 || (route == IspRoute::ai32 && model.family != 76));
    };
    if (selected && !config_.info_only && !writeable(*selected))
        throw std::invalid_argument("model is not in the supported software USB write layout");
    load_uid_options();
    const auto password = password_bytes(config_.password);
    const auto next = password_bytes(config_.next_password);
    const auto user_key = config_.user_key_file.empty() ? std::optional<UserKey>{} :
        std::optional<UserKey>{read_user_key(config_.user_key_file)};
    if (!config_.reset_command.empty()) (void)validate_reset(config_);
    if (const auto value = config_.options.find("flash_blank_value"); value != config_.options.end()) {
        image_fill_value_ = static_cast<uint8_t>(parse_unsigned(value->second, 255));
        if (image_fill_value_ != 0xFF && image_fill_value_ != 0)
            throw std::invalid_argument("flash_blank_value must be 0x00 or 0xFF");
    }
    if (const auto value = config_.options.find("modify_hardware_options"); value != config_.options.end())
        modify_hardware_options_ = parse_config_bool(value->second);
    const auto append_option = config_.options.find("append_test_parameters");
    const bool append_test = append_option != config_.options.end() && parse_config_bool(append_option->second);
    if (append_test && (config_.info_only || config_.erase_only ||
                       (selected && !selected->test_parameter_reserve)))
        throw std::invalid_argument("appending test parameters requires a supported program download");
    std::optional<uint8_t> eeprom_fill;
    for (const auto& [name, value] : {std::pair{"eeprom_fill_zero", uint8_t{0}},
                                     std::pair{"eeprom_fill_ff", uint8_t{0xFF}}}) {
        const auto it = config_.options.find(name);
        if (it == config_.options.end() || !parse_config_bool(it->second)) continue;
        if (eeprom_fill || config_.info_only || config_.erase_only || config_.encrypted_image)
            throw std::invalid_argument("EEPROM fill requires one value and an unencrypted program image");
        eeprom_fill = value;
    }
    const auto validate_eeprom_fill = [&](const ModelInfo& model) {
        if (!eeprom_fill) return;
        const bool stc15_fill = model.family == 25 || (model.family >= 27 && model.family <= 43);
        if (!model.legacy_eeprom_size || (model.family != 8 && (*eeprom_fill == 0 || !stc15_fill)))
            throw std::invalid_argument(model.name + " does not support the requested EEPROM fill");
    };
    if (selected) validate_eeprom_fill(*selected);
    HexImage input;
    auto extension = utf8_path(config_.image).extension().u8string();
    for (auto& c : extension) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const bool binary = extension == u8".bin";
    if (!config_.info_only && !config_.erase_only) {
        input = binary ? read_binary_file(config_.image, 0x10000) : read_hex_file(config_.image);
        if (input.bytes.empty()) throw std::invalid_argument("software USB firmware is empty");
    }
    size_t source_length = 0;
    const auto prepare_image = [&](const ModelInfo& model) {
        const uint32_t base = isp_route(model, true) == IspRoute::ai32 ? 0xFF0000 : 0;
        const auto limit = std::max(model.total_size, model.code_size);
        if (input.bytes.empty()) return std::vector<uint8_t>{};
        if (binary && base && input.bytes.begin()->first == 0) {
            HexImage relocated;
            for (const auto& [address, byte] : input.bytes) relocated.bytes.emplace(base + address, byte);
            input = std::move(relocated);
        }
        if (input.bytes.begin()->first != base || input.bytes.rbegin()->first - base >= limit)
            throw std::invalid_argument("software USB firmware must start at the reset address and fit the device");
        source_length = input.bytes.rbegin()->first - base + 1;
        reserve_uid_destinations(input, base);
        if (input.bytes.begin()->first != base || input.bytes.rbegin()->first - base >= limit)
            throw std::invalid_argument("software USB UID binding exceeds the writable image");
        std::vector<uint8_t> program(input.bytes.rbegin()->first - base + 1, image_fill_value_);
        for (const auto& [address, byte] : input.bytes) program[address - base] = byte;
        validate_uid_regions({{base, program}});
        return program;
    };
    if (config_.dry_run) {
        if (selected) (void)prepare_image(*selected);
        std::cout << "软件 USB 参数有效。\n";
        return 0;
    }

    if (!config_.reset_command.empty()) send_application_reset(config_);
    wire.open();
    bool active = false;
    const auto receive = [&] {
        std::array<uint8_t, 0x84> response{};
        const auto length = wire.transfer(true, 0, 0, 0, response, config_.timeout_ms);
        if (length > response.size()) throw std::runtime_error("invalid software USB transfer length");
        return decode_softusb_reply(std::span<const uint8_t>(response).first(length));
    };
    const auto send = [&](uint8_t cmd, std::span<const uint8_t> payload, uint16_t value = 0,
                          uint16_t index = 0xA55A) {
        auto frame = encode_softusb_data(payload);
        if (wire.transfer(false, cmd, value, index, frame, config_.timeout_ms) != frame.size())
            throw std::runtime_error("short software USB control write");
    };
    const auto ack = [&](const char* stage) {
        const auto reply = receive();
        if (reply.size() < 2 || reply[1] != 0x54)
            throw std::runtime_error(std::string("software USB rejected ") + stage);
    };
    const auto close = [&] {
        if (active) {
            const std::array<uint8_t, 1> zero{};
            active = false;
            send(0xFF, zero, 0, 0);
            std::this_thread::sleep_for(50ms);
        }
        wire.close();
    };
    try {
        const auto status = receive();
        if (status.size() < 22) throw std::runtime_error("software USB status is too short");
        active = true;
        const auto magic = static_cast<uint16_t>(status[20] << 8 | status[21]);
        const uint8_t variant = status[17] >= 0x71 && status[18] >= 0x51 ? status[19] : 0;
        const auto* model = find_model_by_magic(magic, variant);
        if (!model || (selected && selected != model))
            throw std::runtime_error("software USB target does not match the selected model");
        model_ = *model;
        status_.emplace();
        status_->fill(0);
        status_size_ = status.size();
        std::copy_n(status.begin(), std::min(status.size(), status_->size()), status_->begin());
        if (config_.info_only) {
            print_device_info();
            close();
            return 0;
        }
        if (!writeable(model_) || status[17] < 0x62)
            throw std::runtime_error("unsupported software USB target or BSL layout");
        const auto route = isp_route(model_, true);
        const uint32_t base = route == IspRoute::ai32 ? 0xFF0000 : 0;
        validate_eeprom_fill(model_);
        auto program = prepare_image(model_);
        if (config_.encrypted_image && (status[17] < 0x72 || config_.erase_only))
            throw std::invalid_argument("this software USB BSL does not accept an encrypted image");
        const auto v = status[17];
        const auto patch = status.size() > 22 ? status[22] : 0;
        const bool compact_options = model_.family >= 45 && model_.family <= 52;
        const bool legacy_options = route == IspRoute::modern_8bit_uart &&
            model_.family >= 27 && model_.family <= 43 && model_.family != 28;
        const bool stc12_options = route == IspRoute::legacy_stc12;
        if (!next.empty() && v < 0x72)
            throw std::invalid_argument("software USB next-password writes require BSL 7.2 or newer");
        if (config_.options.contains("simulation_mode") && config_.options.at("simulation_mode") != "none")
            throw std::invalid_argument("software USB does not set simulation mode");
        const auto options_requested = std::ranges::any_of(config_.options, [](const auto& entry) {
            return entry.first != "flash_blank_value" && entry.first != "modify_hardware_options" &&
                entry.first != "append_test_parameters" && entry.first != "eeprom_fill_zero" &&
                entry.first != "eeprom_fill_ff" && entry.first != "simulation_mode";
        });
        std::vector<uint8_t> options;
        const bool fixed_partition = has_fixed_63k_partition();
        const uint8_t original_partition = fixed_partition ? 0xFC : (*status_)[16];
        if (modify_hardware_options_ && (options_requested || !next.empty())) {
            if (stc12_options ? !next.empty() :
                route != IspRoute::modern_8bit_uart ||
                    (legacy_options ? v < 0x71 : model_.family < 45 || (v < 0x72 && !compact_options)))
                throw std::invalid_argument("software USB hardware write is unavailable for this option or BSL layout");
            apply_options(route);
            enforce_fixed_63k_partition();
            if (hardware_options_write_required_ || !next.empty()) {
                if ((stc12_options || legacy_options) && status_size_ < 40)
                    throw std::invalid_argument("software USB status is missing the saved clock trim");
                if (stc12_options) {
                    // 43E9E0 -> 44B760/44BA6A: preserve the clock and send the
                    // 64-byte control-transfer body, not the STC12 UART packet.
                    options.assign(64, 0xFF);
                    options[3] = options[6] = options[22] = 0;
                    for (size_t i = 0; i < 4; ++i) options[23 + 2 * i] = status[8 + i];
                    options[31] = (legacy_options_[14] | 0x0C) ^ 0x02;
                    options[32] = 1;
                    options[59] = status[38];
                    options[60] = status[39] | 0x3F;
                    options[61] = legacy_options_[2];
                    options[62] = legacy_options_[1];
                    options[63] = legacy_options_[0];
                } else {
                    options = legacy_options ? build_stc15_options() : build_generic_8bit_options();
                    options.erase(options.begin(), options.begin() + 5);
                }
                if (!next.empty()) {
                    options[22] = static_cast<uint8_t>(next.size());
                    options[legacy_options ? 31 : 32] &= 0xF7;
                }
            }
        } else if (!next.empty()) {
            throw std::invalid_argument("software USB next password requires hardware-option writes");
        }
        if (user_key && v < 0x72)
            throw std::invalid_argument("software USB user-key writes require BSL 7.2 or newer");
        const bool reports_boundary = v > 0x74 || (v == 0x74 && patch >= 3) ||
            (v == 0x73 && patch >= 13);
        uint32_t boundary = fixed_partition ? 0xFC00 : model_.code_size;
        if (reports_boundary) {
            // 44DAC1 reads object+698, i.e. byte 16 of the raw status at +688.
            if ((original_partition & 0xFE) == 0)
                throw std::runtime_error("missing software USB program boundary");
            boundary = uint32_t{original_partition & 0xFEu} << 8;
        }
        const auto capacity = std::max(model_.code_size, model_.total_size);
        if (!boundary || boundary > capacity)
            throw std::runtime_error("invalid software USB program boundary");
        if (eeprom_fill) {
            if (program.size() > boundary || model_.legacy_eeprom_size > capacity - boundary)
                throw std::invalid_argument("EEPROM fill overlaps image data, a UID binding, or the Flash boundary");
            program.resize(boundary, 0xFF);
            program.resize(boundary + model_.legacy_eeprom_size, *eeprom_fill);
            source_length = program.size();
        }
        if (append_test) {
            if (!model_.test_parameter_reserve)
                throw std::invalid_argument("this target does not support appending test parameters");
            HexImage offsets;
            for (const auto& [address, byte] : input.bytes) offsets.bytes.emplace(address - base, byte);
            prepare_test_parameters(offsets, boundary);
            if (test_parameter_patch_ && v < 0x72) {
                const auto& [offset, bytes] = *test_parameter_patch_;
                program.resize(std::max(program.size(), offset + bytes.size()), 0xFF);
                std::copy(bytes.begin(), bytes.end(), program.begin() + offset);
            }
        }
        const auto erase_extra = program.size() > boundary ? (program.size() - boundary + 511) / 512 : 0;
        if (erase_extra > 255 || erase_extra * 512 > capacity - boundary)
            throw std::invalid_argument("software USB erase range exceeds the Flash boundary");
        if (!options.empty() && (model_.flags & 8) && (*status_)[16] != original_partition) {
            const uint32_t changed_boundary = uint32_t{(*status_)[16]} << 8;
            if (program.size() > changed_boundary ||
                (test_parameter_patch_ && test_parameter_patch_->address +
                     test_parameter_patch_->bytes.size() > changed_boundary))
                throw std::invalid_argument("software USB image exceeds the requested program partition");
        }
        print_status();
        send(1, std::array<uint8_t, 1>{static_cast<uint8_t>(model_.family >= 53 ? 0x18 : 3)}, 0, 0);
        receive();
        std::this_thread::sleep_for(10ms);
        const uint8_t blank = 0;
        send(5, password.empty() ? std::span<const uint8_t>(&blank, 1) : std::span<const uint8_t>(password));
        std::this_thread::sleep_for(50ms);
        const auto prepared = receive();
        if (prepared[0] == 0x0E || prepared[0] == 0x0F)
            throw std::runtime_error("software USB download password rejected");
        std::this_thread::sleep_for(10ms);
        send(3, std::array<uint8_t, 2>{static_cast<uint8_t>(erase_extra), 0});
        const auto erase_delay = ((model_.code_size + 511) / 512 + erase_extra) * 25u;
        std::this_thread::sleep_for(std::chrono::milliseconds(200 + ((erase_delay + 99) / 100) * 100));
        const auto erased = receive();
        // 44DBAF copies the erase UID before 4425D0/442630, then writes keys and code.
        apply_erase_uid(erased, {{base, program}});
        std::vector<std::pair<uint16_t, std::array<uint8_t, 7>>> uid_writes;
        if (v >= 0x72) {
            // 44AD20 builds the records consumed by the separate 44DDD1 write loop.
            for (const auto& binding : uid_bindings_) {
                const auto offset = static_cast<uint16_t>(binding.address - base);
                std::array<uint8_t, 7> bytes{};
                std::copy_n(program.begin() + offset, bytes.size(), bytes.begin());
                uid_writes.emplace_back(offset, bytes);
                std::fill_n(program.begin() + offset, bytes.size(), 0xFF);
            }
            program.resize(source_length);
        }
        if (user_key) {
            for (size_t pos = 0; pos < user_key->size(); pos += 64) {
                send(pos == 0 ? 0x26 : 0x06, std::span(*user_key).subspan(pos, 64),
                     static_cast<uint16_t>(pos));
                std::this_thread::sleep_for(50ms);
                ack("user key");
            }
        }
        uint8_t command = config_.encrypted_image ? 0xA2 : 0x22;
        for (size_t offset = 0; offset < program.size(); offset += 16) {
            const auto block = std::span<const uint8_t>(program).subspan(
                offset, std::min(size_t{16}, program.size() - offset));
            if (std::ranges::any_of(block, [](uint8_t byte) { return byte != 0xFF; })) {
                send(command, block, static_cast<uint16_t>(offset));
                std::this_thread::sleep_for(10ms);
                ack("program block");
            }
            command &= ~0x20;
        }
        for (const auto& [offset, bytes] : uid_writes) {
            send(0x02, bytes, offset);
            std::this_thread::sleep_for(35ms);
            ack("UID block");
        }
        if (test_parameter_patch_ && v >= 0x72) {
            const auto& [offset, bytes] = *test_parameter_patch_;
            send(0x02, bytes, static_cast<uint16_t>(offset));
            std::this_thread::sleep_for(35ms);
            ack("test parameters");
        }
        if (!options.empty()) {
            const auto send_next = [&] {
                if (next.empty()) return;
                send(7, next);
                std::this_thread::sleep_for(100ms);
                ack("next password");
            };
            const bool early_password = v == 0x73 && patch < 2;
            if (early_password) send_next();
            send(4, options);
            std::this_thread::sleep_for(early_password ? 50ms : 100ms);
            ack("hardware options");
            if (!early_password) send_next();
        }
        close();
        std::cout << (config_.erase_only ? "软件 USB 擦除完成。\n" : "软件 USB 下载完成。\n");
        return 0;
    } catch (...) {
        try { close(); } catch (...) { wire.close(); }
        throw;
    }
}
}  // namespace stcisp
