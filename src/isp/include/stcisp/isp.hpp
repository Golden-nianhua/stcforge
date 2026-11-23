#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace stcisp {

struct Config {
    std::string model;
    std::string image;
    std::string offline_image;
    std::string offline_auxiliary;
    std::string offline_resources;
    std::string offline_profile;
    std::string offline_output;
    std::string tool_resources;
    std::string simulation_resources;
    std::string transport = "usb";
    std::string port;
    std::string device_path;
    int handshake_baud = 2400;
    int baud = 19200;
    int timeout_ms = 2000;
    bool dry_run = false;
    bool erase_only = false;
    bool erase_offline = false;
    bool make_simulation = false;
    bool make_tool = false;
    bool info_only = false;
    bool encrypted_image = false;
    bool verbose = false;
    bool link1d_auto_power = true;
    bool link1d_keep_power = true;
    std::string password;
    std::string next_password;
    std::string user_key_file;
    std::string uid_allowlist;
    std::map<uint32_t, std::string> uid_bindings;
    std::string reset_command;
    std::string reset_transport = "hid";
    std::string reset_port;
    int reset_baud = 115200;
    std::string reset_parity = "none";
    int reset_stop_bits = 1;
    bool reset_dtr = false;
    bool reset_rts = false;
    uint16_t reset_vid = 0;
    uint16_t reset_pid = 0;
    std::map<std::string, std::string> options;
};

struct HexImage {
    std::map<uint32_t, uint8_t> bytes;
    bool has_eof = false;
};

struct Stc32Image {
    std::vector<uint8_t> program;
    std::vector<uint8_t> eeprom;
};

struct Stc8Image {
    std::vector<uint8_t> program;
    std::vector<uint8_t> eeprom;
};

HexImage read_hex_file(const std::string& path);
HexImage read_binary_file(const std::string& path, uint32_t max_size);
Stc32Image split_stc32_image(const HexImage& image, uint32_t eeprom_end,
                             uint8_t fill_value = 0xFF);
Stc8Image split_stc8_image(const HexImage& image, uint32_t code_size,
                           uint8_t fill_value = 0xFF, bool pad_to_block = true);

class Transport {
public:
    virtual ~Transport() = default;
    virtual void open() = 0;
    virtual void close() noexcept = 0;
    virtual void write(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> read(int timeout_ms) = 0;
    virtual void set_baud(int baud) { (void)baud; }
};

class TransportTimeout : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Link1dTransport;
class SoftUsbControl;
enum class IspRoute;

struct ModelInfo {
    std::string name;
    uint16_t magic = 0;
    uint32_t code_size = 0;
    uint32_t total_size = 0;
    uint32_t flags = 0;
    uint8_t family = 0;
    uint16_t alternate_magic = 0;
    uint8_t status_variant = 0;
    std::optional<uint8_t> test_parameter_reserve = std::nullopt;
    uint32_t legacy_eeprom_size = 0;
    uint32_t table_eeprom_size = 0;
    uint8_t table_test_reserve = 0;
};

class Programmer {
public:
    explicit Programmer(Config config, std::unique_ptr<Transport> io = {});
    int run();
    int run_softusb(SoftUsbControl& wire);

private:
    Config config_;
    std::unique_ptr<Transport> transport_;
    Link1dTransport* link1d_ = nullptr;
    std::optional<std::array<uint8_t, 54>> status_;
    size_t status_size_ = 0;
    ModelInfo model_;
    bool opened_ = false;
    uint8_t image_fill_value_ = 0xFF;
    bool modify_hardware_options_ = true;
    bool hardware_options_write_required_ = false;
    bool legacy_checksum_ = false;
    uint8_t original_option_byte_ = 0;
    uint16_t uart_clock_count_ = 0;
    std::optional<uint32_t> uart_irc_target_;
    struct LegacyIrcResult {
        uint32_t transfer_hz;
        uint32_t program_hz;
        uint8_t transfer_trim;
        uint8_t transfer_band;
        uint8_t program_trim;
        uint8_t program_band;
    };
    std::optional<LegacyIrcResult> legacy_irc_result_;
    std::array<uint8_t, 7> stc15e_irc_seed_{};
    std::vector<uint8_t> user_key_;
    std::vector<std::array<uint8_t, 7>> allowed_uids_;
    enum class UidOperation { add, multiply, divide, xor_byte };
    struct UidBinding {
        uint32_t address;
        std::vector<std::pair<UidOperation, uint8_t>> operations;
    };
    struct FlashRegion {
        uint32_t base;
        std::span<uint8_t> data;
    };
    std::vector<UidBinding> uid_bindings_;
    std::vector<uint8_t> uart_pending_;
    std::array<uint8_t, 15> legacy_options_{};
    bool legacy_clock_uses_measured_ = false;
    struct TestParameterPatch {
        uint32_t address;
        std::vector<uint8_t> bytes;
    };
    std::optional<TestParameterPatch> test_parameter_patch_;

    void connect();
    int run_offline();
    int pack_offline();
    int program_tool();
    void disconnect(bool success);
    bool uses_uart() const { return config_.transport == "serial" || config_.transport == "uart" ||
                                    config_.transport == "link1d"; }
    std::vector<uint8_t> request(const std::vector<uint8_t>& payload,
                                 const std::vector<uint8_t>& expected,
                                 const std::string& stage,
                                 int timeout_ms = -1);
    void send_frame(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> read_frame(int timeout_ms);
    void print_status() const;
    void print_device_info() const;
    void apply_options(IspRoute route);
    bool has_fixed_63k_partition() const;
    void enforce_fixed_63k_partition();
    std::vector<uint8_t> build_f8d1_options() const;
    std::vector<uint8_t> build_stc8u_options() const;
    std::vector<uint8_t> build_ai8051_options() const;
    std::vector<uint8_t> build_ai32_options() const;
    std::vector<uint8_t> build_generic_8bit_options() const;
    std::vector<uint8_t> build_stc15_options() const;
    void set_download_rs485(std::vector<uint8_t>& packet) const;
    Stc32Image load_stc32_image(const HexImage& hex, uint32_t eeprom_end) const;
    void program_stc32(Stc32Image image);
    void program_modern_8bit_uart(std::vector<uint8_t> image, uint8_t extra_erase_sectors);
    void program_banked(std::vector<uint8_t> image, uint32_t flash_base, uint32_t reset_offset,
                        uint8_t extra_erase_sectors = 0,
                        const std::vector<uint8_t>& options = {});
    void program_legacy_uart(const std::vector<uint8_t>& image, IspRoute route,
                             uint8_t extra_erase_sectors);
    void program_stc15_uart(std::vector<uint8_t> image, IspRoute route,
                           uint8_t extra_erase_sectors);
    void initialize_measured_uart();
    std::vector<uint8_t> request_uart_irc(const std::vector<uint8_t>& probe, uint8_t trigger);
    std::vector<int64_t> measure_uart_irc(const std::vector<uint8_t>& probe, uint8_t trigger,
                                        unsigned multiplier, unsigned divisor);
    void calibrate_stc15_irc();
    void calibrate_stc15e_irc(uint64_t initial_clock);
    uint64_t stc15_isp_clock_target(uint64_t measured) const;
    void calibrate_uart_irc(std::vector<uint8_t>& options);
    void make_simulation(const std::vector<uint8_t>& monitor);
    void program_8bit_native_usb(std::vector<uint8_t> image, uint8_t extra_erase_sectors,
                                const std::vector<uint8_t>& options = {});
    void write_region(uint32_t physical_base, const std::vector<uint8_t>& data,
                      uint8_t first_command, uint8_t continuation_command,
                      uint32_t relative_base,
                      uint64_t& written,
                      const std::function<void(uint64_t)>& report_progress);
    void write_download_options(std::vector<uint8_t> packet);
    void prepare_test_parameters(const HexImage& image, uint32_t code_end);
    void write_test_parameters();
    void write_user_key();
    void load_uid_options();
    void reserve_uid_destinations(HexImage& image, uint32_t reset) const;
    void validate_uid_regions(std::initializer_list<FlashRegion> regions) const;
    void apply_erase_uid(const std::vector<uint8_t>& reply,
                         std::initializer_list<FlashRegion> regions) const;
    void apply_short_uart_erase_uid(const std::vector<uint8_t>& reply,
                                    std::initializer_list<FlashRegion> regions) const;
    static std::vector<uint8_t> password_bytes(const std::string& value);
};

Config load_config_file(const std::string& path);
uint32_t parse_unsigned(const std::string& value, uint32_t max);
bool parse_config_bool(const std::string& value);
std::vector<uint8_t> validate_reset(const Config& config);
void print_usage();
void print_models();
void list_usb_devices();
void list_link1d_devices();
void send_application_reset(const Config& config);

std::unique_ptr<Transport> make_usb_transport(const std::string& path);
std::unique_ptr<Transport> make_link1d_hid_transport(const std::string& path);
std::unique_ptr<Transport> make_offline_hid_transport(const std::string& path);
std::unique_ptr<Transport> make_serial_transport(const std::string& port,
                                                 int baud, int timeout_ms, bool even_parity = true);

}  // namespace stcisp
