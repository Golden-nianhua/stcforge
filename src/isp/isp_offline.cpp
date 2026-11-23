#include "stcisp/isp.hpp"
#include "stcisp/crypto.hpp"
#include "stcisp/database.hpp"
#include "stcisp/link1d.hpp"
#include "utf8_path.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <thread>

namespace stcisp {
namespace {
using namespace std::chrono_literals;
constexpr size_t header_size = 0x800;
constexpr size_t max_program_size = 0xA8000;
constexpr std::array<uint8_t, 4> sync_baud{0xFF, 0x06, 0xD0, 0xFF};

uint32_t read_be(std::span<const uint8_t> bytes) {
    uint32_t value = 0;
    for (auto byte : bytes) value = value << 8 | byte;
    return value;
}

void write_be(std::span<uint8_t> bytes, uint32_t value) {
    for (auto pos = bytes.rbegin(); pos != bytes.rend(); ++pos) {
        *pos = static_cast<uint8_t>(value);
        value >>= 8;
    }
}

uint16_t header_checksum(std::span<const uint8_t> bytes) {
    const auto body = bytes.subspan(4, 0x3FC);
    return static_cast<uint16_t>(std::accumulate(body.begin(), body.end(), 0u));
}

struct AuxiliaryNames {
    unsigned serial;
    unsigned hid;
};

AuxiliaryNames auxiliary_names(const ModelInfo& model) {
    // 4C3188 / 4C31A8: the ordinary COM path chooses the first resource.
    const auto family = model.family;
    if (family <= 6 || family == 15 || family == 16) return {12, 66};
    if (family == 7 || family == 8 || family == 17 || family == 18) return {13, 67};
    if ((family >= 9 && family <= 14) || (family >= 19 && family <= 24)) return {14, 68};
    if (family >= 25 && family <= 43) {
        if ((family == 25 || family == 28) && uart_selector(model) == 2) return {15, 69};
        if (uart_selector(model) == 4) return {26, 71};
        return {16, 70};
    }
    if (family >= 45 && family <= 52) return {55, 72};
    if (family == 76 || family == 89) return {63, 74};
    return {57, 73};
}

std::vector<uint8_t> read_blob(const std::filesystem::path& path, size_t maximum) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const auto display = path.u8string();
    const std::string name(display.begin(), display.end());
    const auto length = input.tellg();
    if (length < 0 || static_cast<uint64_t>(length) > maximum)
        throw std::invalid_argument("cannot open offline file or its size exceeds capacity: " + name);
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), length))
        throw std::runtime_error("cannot read offline file: " + name);
    return bytes;
}

std::string trim(std::string s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    return s.substr(begin, s.find_last_not_of(" \t\r\n") - begin + 1);
}

std::string ascii_lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

struct HardwareProfile {
    std::string model;
    std::array<uint8_t, 16> options;
    uint32_t frequency = 0;
    uint8_t pins = 15;
};

uint32_t mhz_as_hz(const std::string& value) {
    const auto dot = value.find('.');
    const auto integral = parse_unsigned(value.substr(0, dot), 128);
    if (dot == std::string::npos) return integral * 1'000'000;
    auto fraction = value.substr(dot + 1);
    if (fraction.empty() || fraction.size() > 6 ||
        !std::all_of(fraction.begin(), fraction.end(), [](char c) { return c >= '0' && c <= '9'; }))
        throw std::invalid_argument("AiCube Frequency must be in MHz with at most six decimal places");
    fraction.resize(6, '0');
    return integral * 1'000'000 + parse_unsigned(fraction, 999'999);
}

HardwareProfile read_hardware_profile(const std::string& path) {
    std::ifstream stream(utf8_path(path));
    if (!stream) throw std::invalid_argument("cannot open AiCube hardware profile: " + path);
    std::map<std::string, std::string> fields;
    for (std::string line; std::getline(stream, line); ) {
        line = trim(std::move(line));
        if (line.empty() || line[0] == '[' || line[0] == ';' || line[0] == '#') continue;
        const auto equal = line.find('=');
        if (equal == std::string::npos) continue;
        auto key = ascii_lower(trim(line.substr(0, equal)));
        if (key != "mcutype" && key != "option" && key != "frequency" && key != "mcupins") continue;
        auto value = trim(line.substr(equal + 1));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            value = value.substr(1, value.size() - 2);
        if (!fields.emplace(std::move(key), std::move(value)).second)
            throw std::invalid_argument("duplicate field in AiCube hardware profile");
    }
    if (!fields.contains("mcutype") || !fields.contains("option"))
        throw std::invalid_argument("AiCube hardware profile must contain McuType and Option");
    HardwareProfile profile{};
    profile.model = fields.at("mcutype");
    const auto& option = fields.at("option");
    if (option.size() != 34)
        throw std::invalid_argument("AiCube Option must contain 16 bytes and its checksum");
    for (size_t i = 0; i < profile.options.size(); ++i)
        profile.options[i] = static_cast<uint8_t>(parse_unsigned("0x" + option.substr(2 * i, 2), 255));
    const auto sum = static_cast<uint8_t>(std::accumulate(profile.options.begin(), profile.options.end(), 0u));
    if (sum != parse_unsigned("0x" + option.substr(32), 255))
        throw std::invalid_argument("AiCube hardware profile checksum mismatch");
    if (fields.contains("frequency")) profile.frequency = mhz_as_hz(fields.at("frequency"));
    if (fields.contains("mcupins"))
        profile.pins = static_cast<uint8_t>(parse_unsigned(fields.at("mcupins"), 255));
    return profile;
}

struct OfflineImage {
    std::vector<uint8_t> bytes;
    uint32_t program_length;

    static OfflineImage load(const std::string& path) {
        auto bytes = read_blob(utf8_path(path), header_size + max_program_size);
        auto view = std::span<const uint8_t>(bytes);
        if (view.size() <= header_size || read_be(view.first(2)) != 0x5AA5)
            throw std::invalid_argument("offline image must contain a 5AA5 header and program");
        if (read_be(view.subspan(2, 2)) != header_checksum(view))
            throw std::invalid_argument("offline image header checksum mismatch");
        const auto length = read_be(view.subspan(6, 4));
        const auto begin = read_be(view.subspan(0x19D, 4));
        const auto end = read_be(view.subspan(0x1B5, 4));
        if (!length || length > max_program_size || end != view.size() - header_size ||
            begin > end || (begin & 0x1FF) != 0)
            throw std::invalid_argument("offline image length or program range is invalid");
        return {std::move(bytes), length};
    }
};

struct OfflineCounter {
    uint32_t address;
    uint8_t width;
    uint8_t format;
    std::array<uint8_t, 16> start;
    std::array<uint8_t, 16> step;
};

OfflineCounter read_counter(std::string_view spec) {
    std::array<std::string_view, 5> fields{};
    for (size_t i = 0; i < fields.size(); ++i) {
        const auto comma = spec.find(',');
        if ((comma == std::string_view::npos) != (i == fields.size() - 1))
            throw std::invalid_argument("offline counter requires format,address,width,start,step");
        fields[i] = spec.substr(0, comma);
        if (comma != std::string_view::npos) spec.remove_prefix(comma + 1);
    }
    const auto format = fields[0] == "hex" ? 0 : fields[0] == "dec" ? 1 : fields[0] == "ascii" ? 2 : -1;
    if (format < 0) throw std::invalid_argument("offline counter format must be hex, dec, or ascii");
    const auto width = parse_unsigned(std::string(fields[2]), 16);
    if (!width) throw std::invalid_argument("offline counter width must be between 1 and 16 bytes");
    const auto encode = [&](std::string_view digits) {
        if (format == 0 && (digits.starts_with("0x") || digits.starts_with("0X")))
            digits.remove_prefix(2);
        if (digits.empty() || digits.size() > (format == 2 ? width : 2 * width) ||
            !std::ranges::all_of(digits, [=](unsigned char c) {
                return format == 0 ? std::isxdigit(c) : c >= '0' && c <= '9';
            }))
            throw std::invalid_argument("offline counter value does not fit its format and width");
        // 4C1AC9 converts decimal input digits to their packed hexadecimal representation.
        std::array<uint8_t, 16> value{};
        size_t nibble = 0;
        for (auto it = digits.rbegin(); it != digits.rend(); ++it, ++nibble) {
            const auto c = static_cast<unsigned char>(*it);
            const unsigned digit = c <= '9' ? c - '0' : std::tolower(c) - 'a' + 10;
            value[15 - nibble / 2] |= static_cast<uint8_t>(digit << ((nibble & 1) * 4));
        }
        return value;
    };
    return {parse_unsigned(std::string(fields[1]), 0xFFFFFF), static_cast<uint8_t>(width),
            static_cast<uint8_t>(format), encode(fields[3]), encode(fields[4])};
}
}  // namespace

int Programmer::program_tool() {
    const auto* selected = find_model_by_name(config_.model);
    const bool uart = config_.transport == "serial" || config_.transport == "uart";
    if (!selected || !(uart ? supports_uart_tool_make(*selected) : supports_usb_tool_make(*selected)))
        throw std::invalid_argument("--make-tool requires a supported controller model for the selected interface");
    if ((!uart && config_.transport != "usb") || config_.timeout_ms <= 0 || config_.tool_resources.empty() ||
        (uart ? config_.port.empty() || !config_.device_path.empty() || config_.baud <= 0 ||
                config_.handshake_baud <= 0 : !config_.port.empty()) ||
        config_.info_only || config_.erase_only || config_.erase_offline ||
        config_.make_simulation || config_.encrypted_image || !config_.image.empty() ||
        !config_.offline_image.empty() || !config_.offline_auxiliary.empty() ||
        !config_.offline_resources.empty() || !config_.offline_profile.empty() ||
        !config_.offline_output.empty() || !config_.next_password.empty() ||
        !config_.user_key_file.empty() || !config_.uid_allowlist.empty() || !config_.uid_bindings.empty() ||
        !config_.reset_command.empty())
        throw std::invalid_argument("--make-tool is a standalone task and requires --tool-resources");
    static constexpr std::array<std::string_view, 6> names{
        "tool_rx1", "tool_rx2", "tool_tx1_idle", "tool_tx2_idle", "tool_tx1_active", "tool_tx2_active",
    };
    uint8_t pin_modes = 0;
    for (const auto& [name, value] : config_.options) {
        const auto field = std::ranges::find(names, name);
        if (uart || field == names.end()) throw std::invalid_argument("unknown tool pin option: " + name);
        const auto bit = field - names.begin() + 2;
        const bool input = bit < 4;
        if (value == (input ? "quasi_pullup" : "push_pull")) pin_modes |= 1u << bit;
        else if (value != (input ? "high_impedance" : "open_drain"))
            throw std::invalid_argument("invalid pin mode for " + name);
    }
    auto binary = read_blob(utf8_path(config_.tool_resources) /
                            (uart ? "res11.bin" : "res65.bin"), uart ? 8192 : 14864);
    if (!uart) configure_aicube_tool_image(binary, pin_modes);
    const auto password = password_bytes(config_.password);
    if (config_.dry_run) {
        if (uart) configure_aicube_uart_tool_image(binary, selected->magic, true);
        std::cout << "工具主控固件参数有效：" << selected->name << "。\n";
        return 0;
    }
    try {
        connect();
        const auto version = (*status_)[17];
        const bool short_uart = uart && version == 0x71;
        if (uart) {
            const auto& status = *status_;
            const bool supported_short = short_uart &&
                ((status_size_ >= 28 && status[18] >= 0x51 && status[22] >= 3) ||
                 (status_size_ >= 56 && status[18] >= 0x49 && status[18] <= 0x4C && status[52] >= 3));
            if ((!supported_short && version < 0x72) || (!short_uart && status_size_ <= 45))
                throw std::invalid_argument("unsupported or truncated UART tool-controller BSL");
            if (short_uart && !password.empty())
                throw std::invalid_argument("this UART tool-controller BSL does not accept a download password");
            configure_aicube_uart_tool_image(binary, model_.magic, short_uart || (status[45] & 0xF0) != 0x50);
            initialize_measured_uart();
            std::this_thread::sleep_for(50ms);
        } else {
            if (version < 0x72 || status_size_ < 23)
                throw std::invalid_argument("unsupported BSL for USB tool controller provisioning");
            if (request({1, 0, 0, 0, 0, 0, 0, 0x80}, {1}, "initialize tool controller").size() != 1)
                throw std::runtime_error("invalid tool controller initialization response");
            std::this_thread::sleep_for(10ms);
        }
        auto prepare = short_uart ? std::vector<uint8_t>{5} : std::vector<uint8_t>{5, 0, 0, 0x5A, 0xA5};
        prepare.insert(prepare.end(), password.begin(), password.end());
        if (request(prepare, {5}, "prepare tool controller").size() != 1 && !uart)
            throw std::runtime_error("invalid tool controller preparation response");
        std::this_thread::sleep_for(10ms);
        const auto erase = short_uart ? std::vector<uint8_t>{3, 0} : std::vector<uint8_t>{3, 0, 0, 0x5A, 0xA5};
        if (request(erase, {3}, "erase tool controller", 30000).size() != 8 && !uart)
            throw std::runtime_error("invalid tool controller erase response");
        const size_t block_size = uart ? 64 : 128;
        for (size_t offset = 0; offset < binary.size(); offset += block_size) {
            const auto block = std::span(binary).subspan(offset, std::min(block_size, binary.size() - offset));
            if (!uart && std::ranges::all_of(block, [](uint8_t byte) { return byte == 0xFF; })) continue;
            std::vector<uint8_t> packet{static_cast<uint8_t>(offset ? 0x42 : 0x62),
                static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset)};
            if (!short_uart)
                packet.insert(packet.end(), {static_cast<uint8_t>(version >= 0x75 ? 0 : 0x5A),
                                              static_cast<uint8_t>(version >= 0x75 ? 0 : 0xA5)});
            packet.insert(packet.end(), block.begin(), block.end());
            if (!uart) packet.resize(133, 0xFF);
            if (request(packet, {2, 0x54}, "write tool controller").size() != 2 && !uart)
                throw std::runtime_error("invalid tool controller block response");
        }
        send_frame({0xFF});
        std::this_thread::sleep_for(50ms);
        disconnect(false);
    } catch (...) {
        try { disconnect(false); } catch (...) {}
        throw;
    }
    std::cout << "工具主控固件写入完成：" << model_.name << "。\n";
    return 0;
}

int Programmer::pack_offline() {
    if (config_.offline_profile.empty() || config_.offline_output.empty() || config_.image.empty())
        throw std::invalid_argument("offline packing requires --offline-profile, --offline-output and --image");
    if (!config_.offline_image.empty() || !config_.offline_auxiliary.empty() ||
        !config_.offline_resources.empty() || config_.info_only ||
        config_.erase_only || config_.erase_offline || config_.make_simulation || !config_.uid_allowlist.empty() ||
        !config_.reset_command.empty())
        throw std::invalid_argument("offline packing cannot be combined with another task, a UID allowlist or application reset");
    load_uid_options();
    if (config_.handshake_baud < 1200 || config_.handshake_baud > 115200 ||
        config_.handshake_baud % 1200 != 0)
        throw std::invalid_argument("offline target handshake baud must be a multiple of 1200 from 1200 to 115200");
    const auto profile = read_hardware_profile(config_.offline_profile);
    const auto* model = find_model_by_name(profile.model);
    if (!model || (!config_.model.empty() && find_model_by_name(config_.model) != model) ||
        (!supports_isp_write(*model, true) && !supports_isp_write(*model, false)))
        throw std::invalid_argument("offline hardware profile has an unsupported or mismatched target");
    const auto route = isp_route(*model, true);
    const uint32_t capacity = std::max(model->code_size + model->table_eeprom_size, model->total_size);
    if (!capacity || capacity > max_program_size)
        throw std::invalid_argument("target does not have a supported offline image layout");

    uint32_t target_hz = profile.frequency;
    uint32_t isp_hz = (profile.options[15] & 1) ? 22'118'400u : 11'059'200u;
    uint32_t tolerance_ppm = 10'000;
    uint32_t handshake_seconds = 5;
    uint32_t quantity = 0;
    uint8_t fill = 0xFF;
    bool keep_power = false;
    bool auto_detect = true;
    bool alternate_led = false;
    bool increment_on_failure = false;
    std::array<std::optional<OfflineCounter>, 2> counters;
    for (const auto& [name, value] : config_.options) {
        if (name == "irc_hz") target_hz = parse_unsigned(value, 128'000'000);
        else if (name == "offline_isp_hz") isp_hz = parse_unsigned(value, 128'000'000);
        else if (name == "offline_irc_tolerance_ppm") tolerance_ppm = parse_unsigned(value, 1'000'000);
        else if (name == "offline_handshake_seconds") handshake_seconds = parse_unsigned(value, 16);
        else if (name == "offline_quantity") quantity = parse_unsigned(value, UINT32_MAX);
        else if (name == "offline_keep_power") keep_power = parse_config_bool(value);
        else if (name == "offline_auto_detect") auto_detect = parse_config_bool(value);
        else if (name == "offline_alternate_led") alternate_led = parse_config_bool(value);
        else if (name == "offline_increment_on_failure") increment_on_failure = parse_config_bool(value);
        else if (name == "offline_program_counter") counters[0] = read_counter(value);
        else if (name == "offline_eeprom_counter") counters[1] = read_counter(value);
        else if (name == "flash_blank_value") {
            fill = static_cast<uint8_t>(parse_unsigned(value, 255));
            if (fill != 0 && fill != 0xFF) throw std::invalid_argument("flash_blank_value must be 0x00 or 0xFF");
        } else throw std::invalid_argument("offline packing does not accept option: " + name);
    }
    if (!isp_hz || target_hz > 128'000'000)
        throw std::invalid_argument("offline IRC frequencies are outside their supported range");

    const auto suffix = utf8_path(config_.image).extension().u8string();
    const auto ext = ascii_lower(std::string(suffix.begin(), suffix.end()));
    const bool raw_binary = ext == ".bin";
    if (!raw_binary && ext != ".hex" && ext != ".ihx")
        throw std::invalid_argument("offline packing requires HEX, IHX or BIN");
    const auto input = raw_binary ? read_binary_file(config_.image, capacity) : read_hex_file(config_.image);
    if (input.bytes.empty()) throw std::invalid_argument("offline firmware is empty");
    const uint32_t base = raw_binary ? 0 :
        route == IspRoute::f8d1 ? 0xFC2800 :
        route == IspRoute::ai32 && model->family == 76 ? 0xFE0000 :
        route == IspRoute::ai32 || route == IspRoute::ai8051u_uart ? 0xFF0000 : 0;
    if (raw_binary && (route == IspRoute::f8d1 ||
            (route == IspRoute::ai32 && model->family == 76)))
        throw std::invalid_argument("offline packing requires addressed HEX for a target with EEPROM before the program");
    if (input.bytes.begin()->first < base || input.bytes.rbegin()->first - base >= capacity)
        throw std::invalid_argument("offline firmware addresses are outside the target Flash layout");
    const auto length = input.bytes.rbegin()->first - base + 1;
    std::vector<uint8_t> program(length, fill);
    for (const auto& [address, byte] : input.bytes) program[address - base] = byte;

    // 449800: compute coverage before padding; the test parameters reserve
    // occupies the tail even if no corresponding bytes are present in HEX.
    const bool test_parameters = profile.options[15] & 2;
    uint32_t extent = length;
    if (test_parameters) {
        if (!model->test_parameter_reserve)
            throw std::invalid_argument("offline profile enables unsupported test-parameter placement");
        extent = std::max(extent, model->code_size - model->table_test_reserve);
        if (model->family < 45) extent = std::max(extent, model->code_size);
    }
    const uint32_t address_base = raw_binary && (route == IspRoute::ai32 || route == IspRoute::ai8051u_uart)
        ? 0xFF0000 : base;
    const auto is_g12 = route == IspRoute::ai32 && model->family == 76;
    const auto default_reset = route == IspRoute::f8d1 ? 0xFF0000 :
        is_g12 ? address_base + model->total_size - model->code_size : address_base;
    const auto profile_reset = address_base + (uint32_t{profile.options[3]} + 1) * 1024;
    const auto active_reset = is_g12 && (model->flags & 8) && profile_reset < address_base + capacity &&
        input.bytes.contains(profile_reset) ? profile_reset : default_reset;
    struct Range { uint32_t offset; uint32_t size; };
    std::vector<Range> patch_ranges;
    const auto reserve_patch = [&](uint32_t address, uint32_t size) {
        const auto overlaps_reset = [&](uint32_t reset) {
            return address < reset + 3 && address + size > reset;
        };
        if (address < address_base || uint64_t{address - address_base} + size > capacity ||
            overlaps_reset(active_reset) || overlaps_reset(default_reset))
            throw std::invalid_argument("offline generated data overlaps the reset entry or exceeds Flash");
        const auto offset = address - address_base;
        if (std::ranges::any_of(patch_ranges, [&](const Range& other) {
            return offset < other.offset + other.size && offset + size > other.offset;
        })) throw std::invalid_argument("offline UID and counter destinations must not overlap");
        patch_ranges.push_back({offset, size});
        extent = std::max(extent, offset + size);
        return offset;
    };
    std::array<uint32_t, 4> uid_offsets{};
    for (size_t i = 0; i < uid_bindings_.size(); ++i) {
        const auto address = uid_bindings_[i].address;
        uid_offsets[i] = reserve_patch(address, 7);
    }
    std::array<uint32_t, 2> counter_offsets{};
    for (size_t i = 0; i < counters.size(); ++i) {
        if (!counters[i]) continue;
        if (config_.encrypted_image)
            throw std::invalid_argument("offline counters require an unencrypted image");
        const auto& counter = *counters[i];
        counter_offsets[i] = reserve_patch(counter.address, counter.width);
        const bool eeprom_first = is_g12 || route == IspRoute::f8d1;
        const auto boundary = eeprom_first ? active_reset : address_base + model->code_size;
        const bool below = i == 0 ? !eeprom_first : eeprom_first;
        if (below ? counter.address + counter.width > boundary : counter.address < boundary)
            throw std::invalid_argument("offline counter does not fit the selected code or EEPROM region");
    }
    auto end = (extent + 127) & ~uint32_t{127};
    if (model->family >= 25 && model->flags & 0x20)
        end = std::min(end, model->code_size - model->table_test_reserve);
    if (end < length || std::ranges::any_of(patch_ranges,
            [&](const Range& region) { return region.offset + region.size > end; }))
        throw std::invalid_argument("offline firmware would overlap the reserved program tail");
    program.resize(std::max(end, extent), 0xFF);
    for (const auto& region : patch_ranges)
        std::fill_n(program.begin() + region.offset, region.size, 0xFF);  // 4C1F0E

    std::vector<uint8_t> bytes(header_size + end, 0xFF);
    const auto header = std::span<uint8_t>(bytes).first(header_size);
    const auto put = [&](size_t position, size_t size, uint32_t value) {
        write_be(header.subspan(position, size), value);
    };
    put(0, 2, 0x5AA5);
    put(4, 2, std::accumulate(program.begin(), program.begin() + extent, 0u));
    put(6, 4, length);
    header[0x0A] = static_cast<uint8_t>(config_.handshake_baud / 1200);
    header[0x0B] = 0;  // first (lowest) entry in the offline maximum-baud list
    put(0x0C, 2, model->magic);
    put(0x0E, 2, model->family >= 53 ? model->magic ^ 0x8000 : model->alternate_magic);
    header[0x10] = static_cast<uint8_t>(0x20 | ((model->flags & 0x20) ? 0x80 : 0) |
                                       (config_.encrypted_image ? 2 : 0));
    header[0x11] = test_parameters && model->family >= 25 ? 0x80 : 0;
    header[0x12] = static_cast<uint8_t>((auto_detect ? 4 : 0) | (increment_on_failure ? 8 : 0) |
                                      (alternate_led ? 0 : 0x10) |
                                      ((model->flags & 4) ? 0x20 : 0) |
                                      (test_parameters && model->family < 25 ? 1 : 0));
    header[0x13] = 0;
    put(0x14, 4, target_hz);
    put(0x18, 4, isp_hz);
    put(0x1C, 4, quantity);
    std::copy(profile.options.begin(), profile.options.end(), header.begin() + 0x20);
    if (model->family >= 45 && !(model->flags & 8)) header[0x23] = 0xFF;
    header[0x32] = profile.pins;
    header[0x33] = model->family;
    header[0x80] = 0;
    put(0x10F, 4, model->code_size);
    put(0x113, 4, model->code_size + model->table_eeprom_size);
    header[0x117] = static_cast<uint8_t>(handshake_seconds ? handshake_seconds * 10 : 50);
    const auto password = password_bytes(config_.password);
    const auto next = password_bytes(config_.next_password);
    header[0x118] = static_cast<uint8_t>(password.size());
    header[0x119] = static_cast<uint8_t>(next.size());
    std::copy(password.begin(), password.end(), header.begin() + 0x11A);
    std::copy(next.begin(), next.end(), header.begin() + 0x15A);
    header[0x19A] = 0;
    header[0x19B] = 0;
    header[0x19C] = 0;
    auto first = static_cast<uint32_t>(std::find_if(program.begin(), program.begin() + length,
        [](uint8_t value) { return value != 0xFF; }) - program.begin());
    first = std::min(first, route == IspRoute::f8d1 ? 0x2D800u : 0x10000u);
    for (const auto& range : patch_ranges) first = std::min(first, range.offset);
    // 449B83/449C01 store two addresses, widths and independent 128-bit counters.
    for (size_t i = 0; i < counters.size(); ++i) {
        if (!counters[i]) continue;
        const auto& counter = *counters[i];
        header[0x11] |= static_cast<uint8_t>(1 << i);
        put(0x34 + 4 * i, 4, counter_offsets[i]);
        header[0x3C + i] = counter.width;
        header[0x3E + i] = counter.format;
        std::copy(counter.start.begin(), counter.start.end(), header.begin() + 0x40 + 16 * i);
        std::copy(counter.step.begin(), counter.step.end(), header.begin() + 0x60 + 16 * i);
    }
    if (!uid_bindings_.empty()) {
        // 449DFD copies four operation bytes, 16 operands, then four BE offsets.
        header[0x11] |= 8;
        std::fill(header.begin() + 0xEB, header.begin() + 0xFF, 0);
        for (size_t i = 0; i < uid_bindings_.size(); ++i) {
            const auto& operations = uid_bindings_[i].operations;
            for (size_t step = 0; step < operations.size(); ++step) {
                const auto [op, operand] = operations[step];
                const uint8_t code = op == UidOperation::add ? 0 :
                    op == UidOperation::multiply ? 1 : op == UidOperation::divide ? 2 : 3;
                header[0xEB + i] |= static_cast<uint8_t>(code << (2 * step));
                header[0xEF + i * 4 + step] = operand;
            }
            put(0xFF + 4 * i, 4, uid_offsets[i]);
        }
    }
    put(0x19D, 4, first & ~uint32_t{511});
    put(0x1A3, 4, uint64_t{target_hz} * tolerance_ppm / 1'000'000);
    std::fill(header.begin() + 0x1A9, header.begin() + 0x1BD, 0);
    put(0x1B5, 4, end);
    if (keep_power) header[0x11] |= 4;
    if (!config_.user_key_file.empty()) {
        const auto key = read_user_key(config_.user_key_file);
        header[0x10] |= 1;
        std::copy(key.begin(), key.end(), header.begin() + 0x300);
    }
    put(2, 2, header_checksum(header));
    std::copy_n(program.begin(), end, bytes.begin() + header_size);
    if (config_.dry_run) {
        std::cout << "离线镜像参数有效：" << model->name << "，传输镜像 " << bytes.size() << " 字节。\n";
        return 0;
    }
    const auto output_path = utf8_path(config_.offline_output);
    if (std::filesystem::symlink_status(output_path).type() != std::filesystem::file_type::not_found)
        throw std::invalid_argument("offline output must be a new file");
    std::ofstream output(output_path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) throw std::runtime_error("cannot write offline image: " + config_.offline_output);
    std::cout << "已生成 " << model->name << " 离线镜像：" << config_.offline_output << '\n';
    return 0;
}

int Programmer::run_offline() {
    if (config_.transport != "usb" && config_.transport != "serial" && config_.transport != "uart")
        throw std::invalid_argument("offline programming requires --if usb|serial");
    const bool usb = config_.transport == "usb";
    if (config_.timeout_ms <= 0 || (!usb && config_.handshake_baud <= 0))
        throw std::invalid_argument("offline timeout and handshake baud must be positive");
    if ((usb && !config_.port.empty()) || (!usb && !config_.device_path.empty()))
        throw std::invalid_argument("offline --port and --device-path apply only to serial and USB respectively");
    if (!usb && config_.port.empty() && !transport_)
        throw std::invalid_argument("serial offline programming requires --port");
    if (config_.erase_offline && (!config_.offline_image.empty() || !config_.offline_auxiliary.empty() ||
                                  !config_.offline_resources.empty()))
        throw std::invalid_argument("offline programmer erase does not accept an image or auxiliary data");
    if (!config_.image.empty() || config_.info_only || config_.erase_only || config_.make_simulation ||
        !config_.model.empty() || config_.encrypted_image || !config_.password.empty() ||
        !config_.next_password.empty() || !config_.user_key_file.empty() || !config_.uid_allowlist.empty() ||
        !config_.uid_bindings.empty() || !config_.reset_command.empty() || !config_.options.empty())
        throw std::invalid_argument("offline image already contains its target and options; do not combine with online ISP settings");

    auto image = config_.erase_offline ? OfflineImage{} : OfflineImage::load(config_.offline_image);
    std::vector<uint8_t> auxiliary;
    if (!config_.erase_offline) {
        const auto magic = read_be(std::span(image.bytes).subspan(0x0C, 2));
        const auto family = image.bytes[0x33];
        const auto& models = model_database();
        const auto model = std::find_if(models.begin(), models.end(), [&](const ModelInfo& candidate) {
            return candidate.magic == magic && candidate.family == family;
        });
        if (model == models.end()) throw std::invalid_argument("offline image contains an unknown model and family");
        if (!config_.offline_auxiliary.empty()) {
            auxiliary = read_blob(utf8_path(config_.offline_auxiliary), max_program_size);
        } else {
            const auto names = auxiliary_names(*model);
            const auto name = "res" + std::to_string(usb ? names.hid : names.serial) + ".bin";
            if (config_.offline_resources.empty())
                throw std::invalid_argument("offline programming requires " + name +
                                            " from AiCube 6.97C; specify --offline-resources");
            auxiliary = read_blob(utf8_path(config_.offline_resources) / name,
                                  max_program_size);
        }
        if (auxiliary.empty()) throw std::invalid_argument("offline auxiliary resource cannot be empty");
    }
    if (config_.dry_run) {
        if (config_.erase_offline) {
            std::cout << "离线编程器清除命令配置有效。\n";
        } else {
            std::cout << "离线镜像有效：程序 " << image.program_length << " 字节，传输镜像 "
                      << image.bytes.size() << " 字节，辅助数据 " << auxiliary.size() << " 字节。\n";
        }
        return 0;
    }
    // Both wire formats contain the complete image, including credentials.
    config_.verbose = false;
    if (!transport_) transport_ = usb ? make_offline_hid_transport(config_.device_path) :
        make_serial_transport(config_.port, config_.handshake_baud, config_.timeout_ms);
    if (usb) {
        auto wrapper = std::make_unique<Link1dTransport>(std::move(transport_));
        link1d_ = wrapper.get();
        transport_ = std::move(wrapper);
    }
    transport_->open();
    bool serial_session = false;
    const auto close = [&] {
        transport_->close();
        link1d_ = nullptr;
    };
    try {
        std::vector<uint8_t> identity;
        if (usb) {
            link1d_->command(0x00);
            identity = link1d_->read(config_.timeout_ms);
        } else {
            legacy_checksum_ = true;
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(config_.timeout_ms);
            do {
                transport_->write({0x7F});
                try {
                    identity = read_frame(50);
                    break;
                } catch (const TransportTimeout&) {
                }
            } while (std::chrono::steady_clock::now() < deadline);
            if (identity.empty()) throw TransportTimeout("offline programmer did not answer the serial handshake");
        }
        if (identity.size() < 6 || identity[0] != 0x51)
            throw std::runtime_error("unexpected offline programmer identity");

        if (!usb) {
            // 447B70 enables 16-bit checksums before the 447E67 baud change.
            legacy_checksum_ = false;
            send_frame({sync_baud.begin(), sync_baud.end()});
            std::this_thread::sleep_for(200ms);
            transport_->set_baud(115200);
            uart_pending_.clear();
            serial_session = true;
        }
        if (!identity[5] && image.program_length > 0xA800)
            throw std::runtime_error("offline programmer without external flash supports at most 42 KiB");

        const auto acknowledge = [&](uint8_t serial_command, const char* stage, int timeout) {
            const auto reply = read_frame(std::max(timeout, config_.timeout_ms));
            const auto expected = usb ? std::vector<uint8_t>{0x54} :
                std::vector<uint8_t>{serial_command, 0x54};
            if (reply.size() < expected.size() || !std::equal(expected.begin(), expected.end(), reply.begin()))
                throw std::runtime_error(std::string(stage) + ": offline programmer rejected command");
        };
        const auto send_chunks = [&](std::span<const uint8_t> bytes,
                                     uint8_t serial_cmd, uint8_t usb_cmd, const char* stage) {
            const auto stride = usb ? size_t{56} : size_t{128};
            for (size_t offset = 0; offset < bytes.size(); offset += stride) {
                const auto chunk = bytes.subspan(offset, std::min(stride, bytes.size() - offset));
                if (usb) {
                    link1d_->command(usb_cmd, {chunk.begin(), chunk.end()}, static_cast<uint32_t>(offset));
                } else {
                    std::vector<uint8_t> packet{serial_cmd, 0, 0, 0};
                    write_be(std::span(packet).subspan(1), static_cast<uint32_t>(offset));
                    packet.insert(packet.end(), chunk.begin(), chunk.end());
                    send_frame(packet);
                }
                acknowledge(serial_cmd, stage, 2000);
            }
        };

        if (!config_.erase_offline) {
            if (usb) link1d_->command(0x46);
            else send_frame({0xF1, 0});
            acknowledge(0xF1, "prepare offline auxiliary storage", 10000);
            send_chunks(auxiliary, 0xF2, 0x47, "write offline auxiliary data");
        }
        std::this_thread::sleep_for(10ms);
        // For 48 the original uses length byte C8 and a null payload pointer.
        if (usb) link1d_->command(0x48, {}, 0, 0xC8);
        else send_frame({0xF3, 0xC8});
        acknowledge(0xF3, "finish offline auxiliary writes", 10000);
        if (config_.erase_offline) {
            // 44E9EB: mode 5 clears the stored program after the F3 handshake.
            if (usb) link1d_->command(0x40, {8, 0x20, 0x36, 0xC9});
            else {
                send_frame({0xFF, 8, 0x20, 0x36, 0xC9});
                serial_session = false;
                send_frame({0xFF});
            }
            close();
            std::cout << "已发送离线编程器清除命令。\n";
            return 0;
        }

        if (usb) {
            const uint8_t mode = image.bytes[0x10] & 0x40 ? 5 : 3;
            link1d_->command(0x40, {0xFF, mode});
            std::this_thread::sleep_for(50ms);
            link1d_->command(0x01, {4});
            const auto reply = link1d_->read(config_.timeout_ms);
            if (reply.size() < 2) throw std::runtime_error("invalid offline programmer slot reply");
            const std::vector<uint8_t> slot{reply[0], reply[1]};
            std::copy(slot.begin(), slot.end(), image.bytes.begin() + 0x1A1);
            link1d_->command(0x02, slot);
            link1d_->read(config_.timeout_ms);
            write_be(std::span(image.bytes).subspan(2, 2), header_checksum(image.bytes));
        }
        send_chunks(image.bytes, 0xF4, 0x49, "write offline image");
        if (serial_session) {
            serial_session = false;
            send_frame({0xFF});
        }
        close();
    } catch (...) {
        if (serial_session) {
            try { send_frame({0xFF}); } catch (...) {}
        }
        close();
        throw;
    }
    std::cout << "离线编程器镜像已写入：" << image.bytes.size() << " 字节。\n";
    return 0;
}
}  // namespace stcisp
