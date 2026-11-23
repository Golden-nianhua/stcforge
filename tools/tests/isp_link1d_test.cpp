#include "stcisp/isp.hpp"
#include "stcisp/link1d.hpp"
#include "stcisp/database.hpp"
#include "stcisp/crypto.hpp"
#include "stcisp/softusb.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>

namespace {
using Bytes = std::vector<uint8_t>;
using stcisp::Config;

void check(bool condition, const char* failure) {
    if (!condition) throw std::runtime_error(failure);
}

void crypto_test() {
    stcisp::UserKey key{};
    for (unsigned i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(17 * i + 23);
    Bytes data{0, 0xFF, 0x55, 0x80};
    for (uint8_t i = 0; i < 16; ++i) data.push_back(i);
    stcisp::encrypt_firmware(data, key);
    check(data == Bytes{0xFB, 0x3C, 0x7A, 0x0D, 0x2F, 0xBE, 0x2D, 0, 0x6B, 0xBA,
                        0xA9, 0x44, 0xA7, 0x46, 0xA5, 0xA8, 0xA3, 0xC2, 0xA1, 0x2C},
          "firmware encryption does not match AiCube 6.97C");
    const std::string wrapped_hex =
        "53a837dc97b7f86d78d0409825eb19a551b0ff1558d6f1734cda05e4c8c25447"
        "7c5743d4c7a5d49d3b80c5e4233734b86e5f06a7e0964dbb6816264d6ad376f3"
        "dc4a4b91a953a116c4e2ca3e85604a8ba9159aaf67f243b170e57f5ec3395379"
        "8a4417e0b92d92f0ac41793f980633e7f4f458ac91efa80632c69125ec7cfb72"
        "f58afd2366368a318b809d7ebac7f6fbe197ac7d6a977cc74f55f4a674d4baa2"
        "b5995e4d9cb0d84cfb2dd59b7d3228885ac51809f1134830958c519228dff80f"
        "813b3c7f7a05f3e01f2c6dea026b3003f6518a57bf72b026bf47648a3a975a1d"
        "fc22e1f455f8cfb4d83691f536e07b66551113c6ceb5a0b44418f4f69fed20ad";
    stcisp::UserKey wrapped{}, decoded_key{};
    for (unsigned i = 0; i < wrapped.size(); ++i) {
        wrapped[i] = static_cast<uint8_t>(std::stoul(wrapped_hex.substr(2 * i, 2), nullptr, 16));
        decoded_key[static_cast<uint8_t>(i * 13 + 177)] = static_cast<uint8_t>(i);
    }
    check(stcisp::decode_aicube_key(wrapped) == decoded_key, "6.97C .k import returned the wrong table");
}

struct Wire {
    std::deque<Bytes> replies;
    std::vector<Bytes> writes;
    std::vector<int> baud_rates;
    bool opened = false, closed = false;
};

class Fake final : public stcisp::Transport {
public:
    explicit Fake(Wire& wire) : wire_(wire) {}
    void open() override { wire_.opened = true; }
    void close() noexcept override { wire_.closed = true; }
    void set_baud(int baud) override { wire_.baud_rates.push_back(baud); }
    void write(const Bytes& data) override { wire_.writes.push_back(data); }
    Bytes read(int) override {
        if (wire_.replies.empty()) throw stcisp::TransportTimeout("mock timeout");
        auto answer = std::move(wire_.replies.front());
        wire_.replies.pop_front();
        if (answer.empty()) throw stcisp::TransportTimeout("mock delayed response");
        return answer;
    }
private:
    Wire& wire_;
};

Bytes report(const Bytes& payload, uint8_t status = 0) {
    check(payload.size() <= 61, "bad fixture length");
    Bytes wire(64);
    wire[0] = 0xA5;
    wire[1] = status;
    wire[2] = static_cast<uint8_t>(payload.size());
    std::copy(payload.begin(), payload.end(), wire.begin() + 3);
    return wire;
}

Bytes mcu(uint16_t id, uint8_t initial = 0x50, size_t size = 54) {
    Bytes result(size);
    result[0] = initial;
    result[17] = 0x79;
    result[18] = 'N';
    result[20] = static_cast<uint8_t>(id >> 8);
    result[21] = static_cast<uint8_t>(id);
    if (size > 51) result[51] = 0xFF;
    return result;
}

Bytes uart_reply(const Bytes& payload) {
    const auto length = payload.size() + 6;
    Bytes frame{0x46, 0xB9, 0x68, static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
    frame.insert(frame.end(), payload.begin(), payload.end());
    const auto sum = std::accumulate(frame.begin() + 2, frame.end(), 0);
    frame.insert(frame.end(), {static_cast<uint8_t>(sum >> 8), static_cast<uint8_t>(sum), 0x16});
    return frame;
}

void tool_controller_test(const std::string& resources, uint8_t version) {
    Config config;
    config.model = "USB-Link1D";
    config.make_tool = true;
    config.tool_resources = resources;
    config.options = {{"tool_rx1", "quasi_pullup"}, {"tool_tx2_idle", "push_pull"},
                      {"tool_tx2_active", "push_pull"}};
    auto status = mcu(0xF7EE, 0);
    status[17] = version;
    Wire wire;
    wire.replies = {uart_reply(status), uart_reply({1}), uart_reply({5}),
                    uart_reply({3, 1, 2, 3, 4, 5, 6, 7})};
    constexpr auto blocks = (14864 + 127) / 128;
    for (size_t i = 0; i < blocks; ++i) wire.replies.push_back(uart_reply({2, 0x54}));
    check(stcisp::Programmer(config, std::make_unique<Fake>(wire)).run() == 0 &&
          wire.opened && wire.closed && wire.replies.empty() &&
          wire.writes.size() == 5 + blocks * 3, "tool controller write did not finish");
    check(wire.writes[0][5] == 0 && wire.writes[1][5] == 1 && wire.writes[2][5] == 5 &&
          wire.writes[3][5] == 3 && wire.writes.back()[5] == 0xFF,
          "tool controller phase order differs");
    constexpr std::string_view hex = "0123456789abcdef";
    for (size_t block = 0; block < blocks; ++block) {
        const auto first = 4 + 3 * block;
        Bytes frame;
        for (size_t i = first; i < first + 3; ++i)
            frame.insert(frame.end(), wire.writes[i].begin(), wire.writes[i].end());
        std::cout << "block ";
        for (auto byte : std::span(frame).subspan(5, 133))
            std::cout << hex[byte >> 4] << hex[byte & 0x0F];
        std::cout << '\n';
    }
    Wire wrong_target;
    wrong_target.replies = {uart_reply(mcu(0xF8D1, 0))};
    bool refused = false;
    try { stcisp::Programmer(config, std::make_unique<Fake>(wrong_target)).run(); }
    catch (const std::runtime_error&) { refused = true; }
    check(refused && wrong_target.closed && wrong_target.writes.size() == 1,
          "tool controller task must reject a regular MCU before initialization");
}

void uart_tool_controller_test(const std::string& resources, uint8_t version, uint16_t magic,
                               bool clear_tag_bit) {
    const auto* model = stcisp::find_model_by_magic(magic);
    check(model != nullptr, "invalid UART tool test model");
    Config config;
    config.transport = "serial";
    config.port = "COM8";
    config.model = model->name;
    config.make_tool = true;
    config.tool_resources = resources;
    auto status = mcu(magic);
    status[4] = 0x65;
    status[13] = 0x27;
    status[14] = 0x10;
    status[17] = version;
    status[18] = 'Q';
    status[22] = 3;
    status[45] = clear_tag_bit ? 0x5A : 0x4A;
    Wire wire;
    wire.replies = {uart_reply(status), uart_reply({1}), uart_reply({5}), uart_reply({3})};
    for (size_t i = 0; i < 128; ++i) wire.replies.push_back(uart_reply({2, 0x54}));
    check(stcisp::Programmer(config, std::make_unique<Fake>(wire)).run() == 0 &&
          wire.opened && wire.closed && wire.replies.empty() && wire.writes.size() == 133 &&
          wire.baud_rates == std::vector<int>{19200}, "UART tool controller session did not finish");
    const auto payload = [&](size_t i) -> Bytes {
        const auto& frame = wire.writes[i];
        return {frame.begin() + 5, frame.end() - 3};
    };
    const bool short_header = version < 0x72;
    check(wire.writes.front() == Bytes{0x7F} &&
          payload(1) == Bytes{1, 0x65, 0x40, 0xFE, 0xC7, 0, 0, 0x80} &&
          payload(2) == (short_header ? Bytes{5} : Bytes{5, 0, 0, 0x5A, 0xA5}) &&
          payload(3) == (short_header ? Bytes{3, 0} : Bytes{3, 0, 0, 0x5A, 0xA5}) &&
          payload(132) == Bytes{0xFF}, "UART tool controller phase order differs");
    constexpr std::string_view hex = "0123456789abcdef";
    for (size_t i = 4; i < 132; ++i) {
        std::cout << "block ";
        for (auto byte : payload(i)) std::cout << hex[byte >> 4] << hex[byte & 15];
        std::cout << '\n';
    }

    status[17] = 0x71;
    status[22] = 2;
    Wire old;
    old.replies = {uart_reply(status)};
    bool refused = false;
    try { stcisp::Programmer(config, std::make_unique<Fake>(old)).run(); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && old.closed && old.writes == std::vector<Bytes>{{0x7F}},
          "UART tool provisioning must refuse pre-7.1.3 before baud switch or erase");
}

void software_usb_test(const std::filesystem::path& root) {
    struct FakeControl final : stcisp::SoftUsbControl {
        struct Output { uint8_t cmd; uint16_t value; uint16_t index; Bytes data; };
        std::vector<Output> outputs;
        std::deque<Bytes> replies;
        bool opened = false;
        bool closed = false;
        void open() override { opened = true; }
        void close() noexcept override { closed = true; }
        size_t transfer(bool input, uint8_t request, uint16_t value, uint16_t index,
                        std::span<uint8_t> data, int) override {
            if (!input) {
                outputs.push_back({request, value, index, {data.begin(), data.end()}});
                return data.size();
            }
            check(request == 0 && value == 0 && index == 0 && data.size() == 0x84,
                  "unexpected software USB status request");
            check(!replies.empty(), "unexpected software USB read");
            const auto payload = replies.front();
            replies.pop_front();
            Bytes frame{0x46, 0xB9, static_cast<uint8_t>(payload.size())};
            frame.insert(frame.end(), payload.begin(), payload.end());
            frame.push_back(static_cast<uint8_t>(-std::accumulate(frame.begin(), frame.end(), 1)));
            std::copy(frame.begin(), frame.end(), data.begin());
            return frame.size();
        }
    };
    check(stcisp::encode_softusb_data(Bytes{1, 2, 3, 4, 5, 6, 7, 8}) ==
          Bytes{1, 2, 3, 4, 5, 6, 7, 228, 8, 248}, "software USB checksum grouping mismatch");
    bool bad_frame = false;
    try { (void)stcisp::decode_softusb_reply(Bytes{0x46, 0xB9, 1, 0x54, 0}); }
    catch (const std::runtime_error&) { bad_frame = true; }
    check(bad_frame, "software USB accepted a bad checksum");

    Config config;
    config.transport = "usb-soft";
    config.model = "STC8H1K08";
    config.image = (root / "lower.hex").string();
    config.next_password = "ab";
    for (const auto patch : {1, 13}) {
        FakeControl wire;
        auto status = mcu(0xF734);
        status[9] = 0x0C;  // ISP RS485 and download password disabled.
        status[16] = 0x20;
        status[17] = 0x73;
        status[22] = patch;
        wire.replies = {status, {0x01}, {0x05}, {0x03}, {0x02, 0x54}, {0x04, 0x54}, {0x07, 0x54}};
        check(stcisp::Programmer(config).run_softusb(wire) == 0 &&
              wire.opened && wire.closed && wire.replies.empty(), "software USB programming did not finish");
        std::vector<uint8_t> commands;
        for (const auto& entry : wire.outputs) commands.push_back(entry.cmd);
        check(commands == (patch == 1 ? Bytes{1, 5, 3, 0x22, 7, 4, 0xFF} :
                           Bytes{1, 5, 3, 0x22, 4, 7, 0xFF}), "software USB request order mismatch");
        const auto& config_data = wire.outputs[patch == 1 ? 5 : 4].data;
        check(config_data[22 + 22 / 7] == 2 && config_data[32 + 32 / 7] == 4,
              "software USB configuration must specify the next password length and enable it");
        check(wire.outputs[0].index == 0 && wire.outputs[0].data == Bytes{0x18, 0xE8} &&
              wire.outputs[1].index == 0xA55A && wire.outputs[1].data == Bytes{0, 0} &&
              wire.outputs[2].data == Bytes{0, 0, 0} &&
              wire.outputs[3].value == 0 && wire.outputs[3].index == 0xA55A &&
              wire.outputs[3].data == Bytes{2, 0, 0, 0xFE} &&
              wire.outputs.back().index == 0 && wire.outputs.back().data == Bytes{0, 0},
              "software USB request fields differ from the original control-transfer layout");
    }
    FakeControl denied;
    auto status = mcu(0xF734);
    status[9] = 4;
    status[17] = 0x72;
    denied.replies = {status, {0x01}, {0x0F}};
    bool refused = false;
    try { stcisp::Programmer(config).run_softusb(denied); }
    catch (const std::runtime_error&) { refused = true; }
    check(refused && denied.closed && denied.outputs.size() == 3 &&
          denied.outputs.back().cmd == 0xFF, "software USB must not erase after a bad password");

    const auto key_path = std::filesystem::temp_directory_path() /
        ("stc-isp-softusb-key-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove(path, error); }
    } cleanup{key_path};
    Bytes key(256);
    std::iota(key.begin(), key.end(), 0);
    {
        std::ofstream file(key_path, std::ios::binary);
        check(static_cast<bool>(file.write(reinterpret_cast<const char*>(key.data()), key.size())),
              "could not write temporary software USB test key");
    }
    config.next_password.clear();
    config.image = (root / "softusb-partition.hex").string();
    for (const auto [version, patch, extra] : {
             std::array<uint8_t, 3>{0x73, 12, 0}, {0x73, 13, 1},
             {0x74, 2, 0}, {0x74, 3, 1}}) {
        auto live = status;
        live[16] = 0x1F;  // 0x1E00 boundary, bit 0 is not part of the address.
        live[17] = version;
        live[22] = patch;
        live[42] = 0x20;
        FakeControl partition;
        partition.replies = {live, {1}, {5}, {3}, {2, 0x54}, {2, 0x54}};
        check(stcisp::Programmer(config).run_softusb(partition) == 0 && partition.replies.empty() &&
              partition.outputs[2].cmd == 3 &&
              partition.outputs[2].data == stcisp::encode_softusb_data(Bytes{extra, 0}) &&
              partition.outputs[4].cmd == 2 && partition.outputs[4].value == 0x1FF0,
              "software USB erase must use the correct BSL-dependent partition boundary");
    }
    config.image = (root / "lower.hex").string();
    config.user_key_file = key_path.string();
    config.uid_allowlist = (root / "allowed-uids.txt").string();
    config.uid_bindings = {{0x10, "xor:0x80,add:1"}};
    for (const auto invalid_erase : {Bytes{3, 7, 6, 5, 4, 3, 2, 1}, Bytes{3}}) {
        FakeControl blocked;
        blocked.replies = {status, {0x01}, {0x05}, invalid_erase};
        refused = false;
        try { stcisp::Programmer(config).run_softusb(blocked); }
        catch (const std::runtime_error&) { refused = true; }
        check(refused && blocked.closed && blocked.outputs.size() == 4 &&
              blocked.outputs[2].cmd == 3 && blocked.outputs.back().cmd == 0xFF,
              "invalid software USB erase UID must stop keys and code writes");
    }
    FakeControl provisioned;
    provisioned.replies = {status, {0x01}, {0x05}, {3, 1, 2, 3, 4, 5, 6, 7},
        {6, 0x54}, {6, 0x54}, {6, 0x54}, {6, 0x54}, {2, 0x54}, {2, 0x54}};
    check(stcisp::Programmer(config).run_softusb(provisioned) == 0 && provisioned.replies.empty() &&
          provisioned.outputs.size() == 10, "software USB UID and key download did not finish");
    for (size_t block = 0; block < 4; ++block) {
        const auto& sent = provisioned.outputs[3 + block];
        check(sent.cmd == (block ? 6 : 0x26) && sent.value == block * 64 && sent.index == 0xA55A &&
              sent.data == stcisp::encode_softusb_data(std::span(key).subspan(block * 64, 64)),
              "wrong software USB user key frame");
    }
    const auto& uid = provisioned.outputs[8];
    check(provisioned.outputs[7].cmd == 0x22 && uid.cmd == 2 && uid.value == 0x10 &&
          uid.data == Bytes{0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x5D},
          "software USB UID transform or destination is incorrect");
    FakeControl out_of_range;
    config.uid_bindings = {{0xFFFF, ""}};
    config.dry_run = true;
    refused = false;
    try { stcisp::Programmer(config).run_softusb(out_of_range); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && !out_of_range.opened, "software USB accepted an out-of-range UID destination");

    config.dry_run = false;
    config.user_key_file.clear();
    config.uid_allowlist.clear();
    config.uid_bindings.clear();
    config.options = {{"append_test_parameters", "true"}, {"modify_hardware_options", "false"}};
    const auto footer = [](std::initializer_list<uint8_t> live) {
        Bytes result{0, 0, 0x75, 0xC7, 0x20};
        result.insert(result.end(), live.begin(), live.end());
        return result;
    };
    struct FooterCase { int version; int patch; uint16_t address; Bytes data; };
    const auto footer_cases = {
        FooterCase{0x71, 0, 0x1FEA, footer({4, 28, 0x40, 3, 29, 0x80, 1, 2, 35, 36})},
        FooterCase{0x72, 0, 0x1FEE, footer({26, 25, 23, 24, 35, 36})},
        FooterCase{0x73, 12, 0x1FE4, footer({29, 28, 49, 48, 47, 46, 45, 44, 43, 42, 26, 25, 23, 24, 35, 36})},
        FooterCase{0x74, 3, 0x1FE2, footer({30, 29, 28, 27, 49, 48, 47, 46, 45, 44, 43, 0x22, 26, 25, 23, 24, 35, 36})},
        FooterCase{0x74, 4, 0, {}},
    };
    for (const auto& tc : footer_cases) {
        FakeControl wire;
        auto live = status;
        for (size_t k = 23; k <= 49; ++k) live[k] = static_cast<uint8_t>(k);
        for (size_t k = 1; k <= 4; ++k) live[k] = static_cast<uint8_t>(k);
        live[17] = tc.version;
        live[22] = tc.patch;
        if (tc.version >= 0x74) live[16] = live[42] = 0x22;
        wire.replies = {live, {1}, {5}, {3}, {2, 0x54}};
        if (!tc.data.empty()) {
            wire.replies.push_back({2, 0x54});
            if (tc.version < 0x72) wire.replies.push_back({2, 0x54});
        }
        check(stcisp::Programmer(config).run_softusb(wire) == 0 && wire.replies.empty(),
              "software USB test parameter download did not finish");
        if (tc.version < 0x72) {
            Bytes first(16, 0xFF);
            const auto within = tc.address & 0x0F;
            std::copy_n(tc.data.begin(), 16 - within, first.begin() + within);
            check(wire.outputs[4].cmd == 2 && wire.outputs[4].value == (tc.address & 0xFFF0) &&
                  wire.outputs[4].data == stcisp::encode_softusb_data(first) &&
                  wire.outputs[5].value == ((tc.address & 0xFFF0) + 16) &&
                  wire.outputs[5].data == stcisp::encode_softusb_data(std::span(tc.data).subspan(16 - within)),
                  "software USB legacy footer was not merged into the image");
        } else if (!tc.data.empty()) {
            check(wire.outputs[4].cmd == 2 && wire.outputs[4].value == tc.address &&
                  wire.outputs[4].data == stcisp::encode_softusb_data(tc.data),
                  "software USB separate footer contents or address differ");
        } else {
            check(wire.outputs.size() == 5, "software USB must not append legacy footer on BSL 7.4.4");
        }
    }
    config.model = "STC12C5424";
    status = mcu(0xE018);
    status[17] = 0x71;
    for (const bool zero : {false, true}) {
        config.options = {{"modify_hardware_options", "false"},
                          {zero ? "eeprom_fill_zero" : "eeprom_fill_ff", "true"}};
        FakeControl wire;
        wire.replies = {status, {1}, {5}, {3}, {2, 0x54}};
        if (zero) wire.replies.push_back({2, 0});  // Force rejection of the first EEPROM block.
        refused = false;
        try { stcisp::Programmer(config).run_softusb(wire); }
        catch (const std::runtime_error&) { refused = true; }
        check(refused == zero && wire.closed && wire.replies.empty() &&
              wire.outputs.size() == (zero ? 6 : 5) &&
              wire.outputs[2].data == Bytes{8, 0, 0xF8},
              "software USB EEPROM fill erase range or ACK handling is incorrect");
        if (zero) {
            check(wire.outputs[4].cmd == 2 && wire.outputs[4].value == 0x6000 &&
                  wire.outputs[4].data == Bytes(19, 0),
                  "software USB EEPROM fill did not send zero data at EEPROM start");
        }
    }
    for (const bool compact : {true, false}) {
        config.model = compact ? "STC12C5424" : "STC12C5A08S2";
        config.options = {{"eeprom_erase_enabled", "true"}};
        auto live = mcu(compact ? 0xE018 : 0xD164);
        live[17] = compact ? 0x71 : 0x72;
        live[8] = compact ? 0x00 : 0x91;
        live[9] = 0xA8;
        live[10] = 0xC0;
        live[38] = 0x54;
        live[39] = 0x40;
        if (compact) {
            live[23] = 0x91;
            live[24] = 0xC3;
            live[25] = 0xFF;
        } else {
            live[5] = 0xFF;
            live[6] = 0x25;
            live[7] = 0xC3;
        }
        Bytes body(64, 0xFF);
        body[3] = body[6] = body[22] = body[29] = 0;
        body[23] = live[8];
        body[25] = 0xA8;
        body[27] = 0xC0;
        body[31] = 0xFF;
        body[32] = 1;
        body[59] = 0x54;
        body[60] = 0x7F;
        body[61] = compact ? 0xFF : 0x25;
        body[62] = 0xC3;
        body[63] = 0x91;
        FakeControl stc12;
        stc12.replies = {live, {1}, {5}, {3}, {2, 0x54}, {4, 0x54}};
        check(stcisp::Programmer(config).run_softusb(stc12) == 0, "software USB STC12 write failed");
        const auto sent = std::find_if(stc12.outputs.begin(), stc12.outputs.end(),
            [](const auto& output) { return output.cmd == 4; });
        if (sent == stc12.outputs.end() || sent->index != 0xA55A || !stc12.replies.empty()) {
            std::string trace;
            for (const auto& output : stc12.outputs)
                trace += " " + std::to_string(output.cmd) + "/" + std::to_string(output.index);
            throw std::runtime_error("wrong software USB STC12 configuration request: cmd/index =" +
                trace + ", unread replies = " + std::to_string(stc12.replies.size()));
        }
        const auto encoded = stcisp::encode_softusb_data(body);
        const auto& actual = sent->data;
        check(actual.size() == encoded.size(), "wrong software USB STC12 configuration length");
        for (size_t i = 0; i < encoded.size(); ++i) {
            if (actual[i] != encoded[i])
                throw std::runtime_error("software USB STC12 configuration byte " + std::to_string(i) +
                    ": expected " + std::to_string(encoded[i]) + ", got " + std::to_string(actual[i]));
        }
        live.resize(39);
        FakeControl short_status;
        short_status.replies = {live};
        refused = false;
        try { stcisp::Programmer(config).run_softusb(short_status); }
        catch (const std::invalid_argument&) { refused = true; }
        check(refused && short_status.outputs.size() == 1 && short_status.outputs[0].cmd == 0xFF,
              "software USB STC12 must not erase when saved trim is missing");
    }
    config.model = "STC12C5424";
    config.options = {{"low_voltage_threshold", "1"}};
    status = mcu(0xE018);
    status[17] = 0x71;
    FakeControl threshold;
    threshold.replies = {status};
    refused = false;
    try { stcisp::Programmer(config).run_softusb(threshold); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && threshold.outputs.size() == 1 && threshold.outputs[0].cmd == 0xFF,
          "software USB STC12 must not silently drop the low-voltage threshold");
    config.model = "STC15H4K08S4";
    config.options = {{"por_reset_delay_long", "true"}, {"simulation_mode", "none"}};
    status = mcu(0xF601);
    status[17] = 0x71;
    status[9] = 0x0C;
    status[10] = 0x7F;
    status[11] = 0xAD;
    status[15] = 0x5E;
    for (size_t k = 1; k <= 7; ++k) status[k] = static_cast<uint8_t>(k);
    Bytes compact_body(40, 0xFF);
    compact_body[3] = compact_body[6] = compact_body[22] = 0;
    std::copy_n(status.begin() + 1, 7, compact_body.begin() + 24);
    compact_body[32] = 0x0C;
    compact_body[36] = 0xFF;
    compact_body[37] = 0xAD;
    compact_body[38] = 0x5E;
    for (uint8_t version : {0x62, 0x70, 0x71}) {
        auto live = status;
        live[17] = version;
        FakeControl compact;
        compact.replies = {live, {1}, {5}, {3}, {2, 0x54}, {4, 0x54}};
        check(stcisp::Programmer(config).run_softusb(compact) == 0 && compact.replies.empty(),
              "failed to send software USB compact options on legacy BSL");
        check(compact.outputs[0].data == Bytes{3, 0xFD} &&
              compact.outputs[4].cmd == 4 &&
              compact.outputs[4].data == stcisp::encode_softusb_data(compact_body),
              "wrong 44BBA7 compact software USB configuration");
    }
    config.next_password = "ab";
    FakeControl old_password;
    old_password.replies = {status};
    refused = false;
    try { stcisp::Programmer(config).run_softusb(old_password); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && old_password.outputs.size() == 1 && old_password.outputs[0].cmd == 0xFF,
          "software USB must reject next-password changes before erase on BSL 7.1");

    config.model = "STC15F2K08S2";
    config.options = {{"watchdog_prescale", "64"}, {"cold_start_p32_p33_required", "true"}};
    status = mcu(0xF401);
    status[5] = 0x27;
    status[6] = 0xC3;
    status[7] = 0x91;
    status[9] = 0xA8;
    status[10] = 0xC0;
    status[12] = 0xF6;  // Reserved on 7.1; on 7.2 an existing password is enabled.
    status[37] = 0xFD;
    status[38] = 0x54;
    status[39] = 0x40;
    for (const auto version : {0x71, 0x72}) {
        status[17] = version;
        const bool next = version >= 0x72;
        config.next_password = next ? "ab" : "";
        config.password = next ? "cd" : "";
        FakeControl legacy;
        legacy.replies = {status, {1}, {5}, {3}, {2, 0x54}, {4, 0x54}};
        if (next) legacy.replies.push_back({7, 0x54});
        check(stcisp::Programmer(config).run_softusb(legacy) == 0 && legacy.replies.empty(),
              "software USB legacy option write failed");
        Bytes body(64, 0xFF);
        body[3] = body[6] = body[23] = body[29] = 0;
        body[22] = next ? 2 : 0;
        body[25] = 0xA8;
        body[27] = 0xC0;
        body[31] = next ? 0xF6 : 0xFE;
        body[32] = 1;
        body[55] = 0xFD;
        body[59] = 0x54;
        body[60] = 0x7F;
        body[61] = 0x25;
        body[62] = 0xC3;
        body[63] = 0x91;
        check(legacy.outputs[4].cmd == 4 && legacy.outputs[4].data == stcisp::encode_softusb_data(body) &&
              (!next || legacy.outputs[5].cmd == 7),
              "software USB legacy option body did not preserve clock and hardware settings");
    }
    config.next_password.clear();
    for (const auto [version, flags] : {std::pair{0x72, 0xF6}, std::pair{0x71, 0xFA}}) {
        status[17] = static_cast<uint8_t>(version);
        status[12] = static_cast<uint8_t>(flags);
        config.password = version >= 0x72 ? "cd" : "";
        FakeControl rewrite;
        rewrite.replies = {status, {1}, {5}, {3}, {2, 0x54}, {4, 0x54}};
        check(stcisp::Programmer(config).run_softusb(rewrite) == 0 && rewrite.replies.empty() &&
              rewrite.outputs.size() == 6 && rewrite.outputs[2].cmd == 3 &&
              rewrite.outputs[4].cmd == 4 && rewrite.outputs[5].cmd == 0xFF,
              "software USB must rewrite legacy STC15 options as AiCube does");
        const auto& wire_body = rewrite.outputs[4].data;
        // The body writes disabled flags unless this download supplies new settings.
        check(wire_body[31 + 31 / 7] == 0xFE,
              "rewriting legacy STC15 options did not use the new download settings");
    }
    config.password = "cd";
    status[17] = 0x72;
    status[12] = 0xF6;
    for (const uint8_t rejection : {0x0E, 0x0F}) {
        FakeControl wrong_password;
        wrong_password.replies = {status, {1}, {rejection}};
        refused = false;
        try { stcisp::Programmer(config).run_softusb(wrong_password); }
        catch (const std::runtime_error&) { refused = true; }
        check(refused && wrong_password.replies.empty() && wrong_password.outputs.size() == 3 &&
              wrong_password.outputs[1].cmd == 5 && wrong_password.outputs[2].cmd == 0xFF,
              "software USB must still stop before erase when the current password is rejected");
    }
}

void offline_upload_test() {
    const auto path = std::filesystem::temp_directory_path() /
        ("stcisp-offline-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    } cleanup{path};
    Bytes image(0x980, 0xFF);
    image[0] = 0x5A;
    image[1] = 0xA5;
    const auto put = [&](size_t offset, uint32_t value, int width) {
        for (int byte = width - 1; byte >= 0; --byte) {
            image[offset + byte] = static_cast<uint8_t>(value);
            value >>= 8;
        }
    };
    put(6, 260, 4);
    put(0x0C, 0xF784, 2);
    image[0x33] = 61;
    put(0x19D, 0, 4);
    put(0x1B5, 384, 4);
    image[0x10] = 0x20;
    for (int index = 0; index < 260; ++index) image[0x800 + index] = static_cast<uint8_t>(index);
    put(4, std::accumulate(image.begin() + 0x800, image.begin() + 0x904, 0), 2);
    const auto fix_checksum = [&] {
        put(2, std::accumulate(image.begin() + 4, image.begin() + 0x400, 0), 2);
    };
    const auto save = [&] {
        std::ofstream file(path, std::ios::binary);
        check(file.write(reinterpret_cast<const char*>(image.data()),
                         static_cast<std::streamsize>(image.size())).good(), "cannot write offline test image");
    };
    fix_checksum();
    save();
    for (const bool hid : {false, true}) {
        Wire wire;
        Config config;
        config.transport = hid ? "usb" : "serial";
        config.offline_image = path.string();
        config.offline_auxiliary = path.string();
        const auto enqueue = [&](Bytes payload) {
            wire.replies.push_back(hid ? report(payload) : uart_reply(payload));
        };
        Bytes identity(18);
        identity[0] = 0x51;
        identity[1] = 1;
        identity[2] = 0x21;
        enqueue(identity);
        enqueue(hid ? Bytes{0x54} : Bytes{0xF1, 0x54});
        const size_t stride = hid ? 56 : 128;
        const size_t blocks = (image.size() + stride - 1) / stride;
        for (size_t i = 0; i < blocks; ++i)
            enqueue(hid ? Bytes{0x54} : Bytes{0xF2, 0x54});
        enqueue(hid ? Bytes{0x54} : Bytes{0xF3, 0x54});
        if (hid) {
            enqueue({0xA1, 0xB2});
            enqueue({0x54});
        }
        for (size_t offset = 0; offset < image.size(); offset += stride)
            enqueue(hid ? Bytes{0x54} : Bytes{0xF4, 0x54});
        check(stcisp::Programmer(config, std::make_unique<Fake>(wire)).run() == 0,
              "offline upload failed");
        check(wire.opened && wire.closed && wire.replies.empty(), "offline upload did not complete");
        const std::vector<Bytes> setup = hid ?
            std::vector<Bytes>{{0}, {0x46}, {0x48}, {0x40, 0xFF, 3}, {1, 4}, {2, 0xA1, 0xB2}} :
            std::vector<Bytes>{{0x7F}, {0xFF, 6, 0xD0, 0xFF}, {0xF1, 0}, {0xF3, 0xC8}};
        const auto payload = [&](const Bytes& packet) {
            if (hid) {
                check(packet.size() == 64 && packet[0] == 0x5A &&
                      (std::accumulate(packet.begin(), packet.end(), 0) & 0xFF) == 0,
                      "offline HID framing mismatch");
                if (packet[1] == 0x48)
                    check(packet[6] == 0xC8 && packet[7] == 0, "offline USB finalize parameter mismatch");
                const auto size = packet[1] == 0x48 ? 0 : packet[6];
                Bytes result{packet[1]};
                result.insert(result.end(), packet.begin() + 7, packet.begin() + 7 + size);
                return result;
            }
            if (packet == Bytes{0x7F}) return packet;
            check(packet.size() >= 9 && packet[0] == 0x46 && packet[1] == 0xB9 &&
                  packet[2] == 0x6A && packet.back() == 0x16 &&
                  ((packet[3] << 8) | packet[4]) + 2 == static_cast<int>(packet.size()) &&
                  ((packet[packet.size() - 3] << 8) | packet[packet.size() - 2]) ==
                      (std::accumulate(packet.begin() + 2, packet.end() - 3, 0) & 0xFFFF),
                  "offline UART framing mismatch");
            return Bytes(packet.begin() + 5, packet.end() - 3);
        };
        for (size_t index = 0; index < setup.size(); ++index) {
            const auto auxiliary_count = index < (hid ? 2 : 3) ? 0 : blocks;
            check(payload(wire.writes.at(index + auxiliary_count)) == setup[index],
                  "offline setup sequence mismatch");
        }
        const auto check_block = [&](size_t index, size_t offset, uint8_t cmd,
                                      const Bytes& expected) {
            const auto& packet = wire.writes.at(index);
            const auto block = payload(packet);
            const auto data = hid ? block.begin() + 1 : block.begin() + 4;
            const auto address = hid ? ((size_t{packet[2]} << 24) | (size_t{packet[3]} << 16) |
                 (size_t{packet[4]} << 8) | packet[5]) :
                 ((size_t{block[1]} << 16) | (size_t{block[2]} << 8) | block[3]);
            check(block.front() == cmd && address == offset &&
                  std::equal(data, block.end(), expected.begin() + offset,
                             expected.begin() + std::min(expected.size(), offset + stride)),
                  "offline block data or offset mismatch");
        };
        size_t auxiliary_index = hid ? 2 : 3;
        for (size_t offset = 0; offset < image.size(); offset += stride)
            check_block(auxiliary_index++, offset, hid ? 0x47 : 0xF2, image);

        auto original = image;
        if (hid) {
            put(0x1A1, 0xA1B2, 2);
            fix_checksum();
        } else {
            check(wire.baud_rates == std::vector<int>{115200} && payload(wire.writes.back()) == Bytes{0xFF},
                  "offline UART did not switch speed or terminate");
        }
        size_t index = setup.size() + blocks;
        for (size_t offset = 0; offset < image.size(); offset += stride)
            check_block(index++, offset, hid ? 0x49 : 0xF4, image);
        check(index + (hid ? 0 : 1) == wire.writes.size(), "unexpected write after offline image");
        image = std::move(original);
    }

    Config config;
    config.offline_image = path.string();
    config.offline_auxiliary = path.string();
    Wire rejected;
    rejected.replies.push_back(report({0x51, 1, 0x21, 0, 0, 0}));
    rejected.replies.push_back(report({0x00}));
    bool rejected_early = false;
    try { stcisp::Programmer(config, std::make_unique<Fake>(rejected)).run(); }
    catch (const std::runtime_error&) { rejected_early = true; }
    check(rejected_early && rejected.closed && rejected.writes.size() == 2,
          "offline writer continued after rejected prepare");
    image[3] ^= 1;
    save();
    Wire corrupt;
    bool refused = false;
    try { stcisp::Programmer(config, std::make_unique<Fake>(corrupt)).run(); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && !corrupt.opened, "offline writer opened connection for a damaged header");

    Wire erase;
    erase.replies.push_back(report({0x51, 1, 0x21, 0, 0, 0}));
    erase.replies.push_back(report({0x54}));
    Config clear;
    clear.erase_offline = true;
    check(stcisp::Programmer(clear, std::make_unique<Fake>(erase)).run() == 0 &&
          erase.closed && erase.writes.size() == 3 && erase.writes[1][1] == 0x48 &&
          erase.writes[2][1] == 0x40 &&
          Bytes(erase.writes[2].begin() + 6, erase.writes[2].begin() + 11) ==
              Bytes{4, 8, 0x20, 0x36, 0xC9}, "offline erase command sequence mismatch");
}

struct Command {
    uint8_t code;
    uint32_t offset;
    Bytes data;
};

std::vector<Command> commands(const Wire& wire) {
    std::vector<Command> result;
    for (const auto& bytes : wire.writes) {
        check(bytes.size() == 64 && bytes[0] == 0x5A, "bad output report");
        check((std::accumulate(bytes.begin(), bytes.end(), 0) & 0xFF) == 0, "bad output checksum");
        check(bytes[6] <= 56, "overlong HID fragment");
        const uint32_t arg = (uint32_t{bytes[2]} << 24) | (uint32_t{bytes[3]} << 16) |
                             (uint32_t{bytes[4]} << 8) | bytes[5];
        result.push_back({bytes[1], arg, {bytes.begin() + 7, bytes.begin() + 7 + bytes[6]}});
    }
    return result;
}

std::vector<Bytes> target_commands(const std::vector<Command>& trace) {
    std::vector<Bytes> target;
    Bytes fragments;
    for (const auto& command : trace) {
        if (command.code == 0x43) target.push_back(command.data);
        if (command.code == 0x44) {
            check(command.offset == fragments.size(), "fragment offset not contiguous");
            fragments.insert(fragments.end(), command.data.begin(), command.data.end());
        }
        if (command.code == 0x45) {
            check(command.data == Bytes{static_cast<uint8_t>(fragments.size())}, "incorrect commit length");
            target.push_back(fragments);
            fragments.clear();
        }
    }
    check(fragments.empty(), "uncommitted fragment");
    return target;
}

void check_envelope(const std::vector<Command>& trace, bool success, bool parity, bool model_flag) {
    check(trace.size() >= 10, "incomplete Link1D trace");
    check(trace[0].code == 0 && trace[0].data.empty(), "missing identity");
    check(trace[1].code == 0x40 && trace[1].data == Bytes{2, 2, parity}, "bad initial baud or parity");
    check(trace[2].code == 0x40 && trace[2].data == Bytes{4, 0}, "bad initial tool state");
    check(trace[3].code == 0x40 && trace[3].data == Bytes{3, 0}, "bad initial voltage mode");
    check(trace[4].code == 0x41 && trace[4].data == Bytes{0, 0, 3, 5, 0, 9, 0, model_flag},
          "bad cold-start payload");
    check(trace.back().code == 0xFF && trace.back().data.empty(), "missing tool exit");
    check(trace.end()[-2].code == 0x40 && trace.end()[-2].data == Bytes{10, 0}, "bad tool cleanup");
    check(trace.end()[success ? -6 : -5].data == Bytes{4, success}, "wrong completion state");
}

void run(Config config, Wire& wire) {
    check(stcisp::Programmer(std::move(config), std::make_unique<Fake>(wire)).run() == 0, "run failed");
    check(wire.opened && wire.closed && wire.replies.empty(), "device not closed or leftover reply");
}

void serial_cold_start_test() {
    Wire wire;
    wire.replies = {Bytes{}, uart_reply(mcu(0xF784))};
    Config config;
    config.transport = "serial";
    config.port = "COM8";
    config.info_only = true;
    run(config, wire);
    check(wire.writes.size() == 3 && wire.writes[0] == Bytes{0x7F} &&
          wire.writes[1] == Bytes{0x7F}, "COM did not retry the cold-start handshake");
}

void link1d_keep_power_test(const std::filesystem::path& root) {
    Config config;
    config.model = "STC8H8K64U";
    config.transport = "link1d";
    config.image = (root / "lower.hex").string();
    auto status = mcu(0xF784);
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0xFE;
    for (auto keep : {false, true}) {
        config.link1d_keep_power = keep;
        Wire wire;
        wire.replies = {report({0x51}), report(status), report({1}), report({5}),
                        report({3}), report({2, 0x54})};
        run(config, wire);
        const auto trace = commands(wire);
        const auto tail = trace.end() - (keep ? 6 : 5);
        check(tail[0].code == 0x40 && tail[0].data == Bytes{4, 1} &&
              tail[1].code == 0x40 && tail[1].data == Bytes{0x0C, static_cast<uint8_t>(keep)} &&
              tail[2].code == 0x40 && tail[2].data == Bytes{0} &&
              (!keep || (tail[3].code == 0x40 && tail[3].data == Bytes{3, 0})) &&
              trace.back().code == 0xFF, "wrong Link1D finish or power retention commands");
    }
}

void modern_test(const std::filesystem::path& root, bool ai8051, bool keep_irc = false,
                 bool password = false, bool mixed = false, bool dynamic_irc = false) {
    Wire wire;
    auto status = mcu(ai8051 ? 0x78B4 : 0xF8D1);
    status[11] = 0x20;
    status[12] = 0x20;
    status[15] = 0x80;
    status[4] = 0x65;
    status[9] = 0xFE;
    status[13] = 0x25;
    status[14] = 0x80;  // 9600 counts at 2400 baud = 23.04 MHz.
    status[16] = 3;
    wire.replies = {report({0x51}), report({0x80}), report(status), report({1}), report({5}),
                    report({3}), report({2, 0x54})};
    Config config;
    config.transport = "link1d";
    config.image = (root / (mixed ? "ai8051-usb-eeprom.hex" : "upper.hex")).string();
    if (mixed) wire.replies.push_back(report({2, 0x54}));
    if (dynamic_irc) {
        config.options = {{"irc_adjust_mode", "dynamic"}, {"irc_hz", "24000000"}};
        const auto response = [](std::initializer_list<unsigned> counts) {
            Bytes bytes{0, static_cast<uint8_t>(counts.size())};
            for (const auto count : counts)
                bytes.insert(bytes.end(), {static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
            return report(bytes);
        };
        wire.replies.insert(wire.replies.begin() + 3,
                            {response({3750, 6250, 6300, 8400, 8450, 11000, 8450, 11000}),
                             response({4930, 4940, 4950, 4960, 4970, 4980,
                                       4990, 5000, 5010, 5020, 5030, 5040})});
        wire.replies.push_back(report({4}));
    } else if (password) {
        config.password = "old";
        config.next_password = "new!";
        wire.replies.push_back(report({4, 0x54}));
        wire.replies.push_back(report({7, 0x54}));
    } else if (!ai8051) {
        if (keep_irc) {
            status[15] = 0xE0;
            wire.replies[2] = report(status);
            config.options = {{"irc_adjust_mode", "last_trim"}, {"irc_hz", "24000000"}};
        } else {
            config.options = {{"modify_hardware_options", "false"}, {"simulation_mode", "swd"},
                              {"swd_pins", "p1.6-p1.7"}};
        }
        wire.replies.push_back(report({4, 0x54}));
    }
    run(config, wire);
    const auto trace = commands(wire);
    check_envelope(trace, true, true, false);
    const auto changed_baud = std::find_if(trace.begin(), trace.end(), [](const auto& command) {
        return command.code == 0x40 && command.data == Bytes{2, 16, 1};
    });
    check(changed_baud != trace.end(), "wrong transfer baud");
    auto target = target_commands(trace);
    if (dynamic_irc) {
        check(target.size() == 8, "wrong number of UART IRC probe and flash commands");
        check(target[1] == Bytes{0, 8, 0, 0, 0xFF, 0, 0, 0x10, 0xFF, 0x10,
                                 0, 0x20, 0xFF, 0x20, 0, 0x20, 0xFF, 0x20},
              "wrong F8D1 coarse IRC probe");
        Bytes fine{0, 12};
        for (unsigned trim = 121; trim <= 132; ++trim)
            fine.insert(fine.end(), {static_cast<uint8_t>(trim), 0});
        check(target[2] == fine, "wrong F8D1 fine IRC probe");
        check(Bytes(target.back().begin() + 29, target.back().begin() + 36) ==
              Bytes{0x01, 0x6E, 0x36, 0, 128, 0, 1}, "measured IRC value was not committed");
        target.erase(target.begin() + 1, target.begin() + 3);
    }
    const auto count = 5u + unsigned(mixed) + (password ? 2u : unsigned(!ai8051));
    check(target.size() == count, "wrong modern command count");
    check(target[0] == Bytes{0x80}, "missing status acknowledgement");
    check(target[1] == Bytes{1, 0x65, 0x40, 0xFE, 0xD4, 0, 0, 0x97}, "wrong UART baud command");
    Bytes prepare{5, 0, 0, 0x5A, 0xA5};
    if (password) prepare.insert(prepare.end(), {'o', 'l', 'd'});
    check(target[2] == prepare, "wrong prepare command");
    check(target[3] == Bytes{3, static_cast<uint8_t>(mixed ? 120 : ai8051 ? 0 : 2),
                              static_cast<uint8_t>(ai8051 ? 0 : 0xD8), 0x5A, 0xA5},
          "wrong UART erase command");
    check(target[4].size() == (mixed ? 69 : 8) &&
          target[4][0] == (ai8051 ? 0x22 : 2), "wrong write command");
    check(target[4][3] == 0 && target[4][4] == (ai8051 ? 0 : 2), "wrong address bank");
    check(target[4][5] == 2 && target[4][6] == 0 && target[4][7] == 0,
          "image bytes were not preserved");
    if (mixed)
        check(target[5] == Bytes{2, 0xF0, 0, 0, 0, 2, 0, 0}, "wrong AI8051U EEPROM write");
    if (password) {
        const auto& options = target[target.size() - 2];
        check(options.size() == 46 && options[0] == 4 && options[27] == 4 && options[37] == 0xF6,
              "next password was not declared in the hardware options");
        check(target.back() == Bytes{7, 0, 0, 0x5A, 0xA5, 'n', 'e', 'w', '!'},
              "next password was not sent after hardware options");
    } else if (keep_irc) {
        check(target[5].size() == 46 && target[5][43] == 0xE0, "IRC policy overwrote CPU/WDT bits");
    } else if (!ai8051 && !dynamic_irc) {
        check(target[5].size() == 46 && target[5][39] == 0x80, "SWD configuration not transmitted");
        check(target[5][43] & 0x80, "USB simulation not disabled for SWD");
    }
}

void parser_tests(const std::filesystem::path& root) {
    const auto must_reject = [](auto operation, const char* failure) {
        try { operation(); } catch (const std::invalid_argument&) { return; }
        throw std::logic_error(failure);
    };
    check(stcisp::parse_unsigned("0xFF", 255) == 255, "hex argument rejected");
    must_reject([] { stcisp::parse_unsigned("19200junk", INT32_MAX); }, "trailing number was ignored");
    must_reject([] { stcisp::parse_unsigned("0x100", 255); }, "overflow number was accepted");
    must_reject([] { stcisp::parse_config_bool("yes"); }, "invalid config bool accepted");
    const auto app_reset = stcisp::load_config_file((root / "reset.toml").string());
    check(stcisp::validate_reset(app_reset) == Bytes{'@', 'I', 'S', 'P', '#'}, "quoted # lost");
    const auto read = [&](const char* name) { return stcisp::read_hex_file((root / name).string()); };
    must_reject([&] { read("after-eof.hex"); }, "accepted data after EOF");
    must_reject([&] { read("cross-bank.hex"); }, "accepted crossed bank boundary");
    check(read("extended-segment.hex").bytes.at(0x12342) == 0xA5, "bad segment address");

    Config config;
    config.model = "STC8H8K64U";
    config.image = (root / "h8-multiblock.hex").string();
    config.options["watchdog_prescale"] = "3";
    Wire wire;
    wire.replies = {uart_reply(mcu(0xF784, 0))};
    must_reject([&] { stcisp::Programmer(config, std::make_unique<Fake>(wire)).run(); },
                "H8U accepted an invalid watchdog divider");
    check(wire.writes.size() == 1 && wire.writes[0][5] == 0 && wire.closed,
          "H8U USB invalid option sent commands after status");

    config.model = "STC32G144K246";
    config.image = (root / "empty.hex").string();
    wire = {};
    must_reject([&] { stcisp::Programmer(config, std::make_unique<Fake>(wire)).run(); },
                "erase with empty HEX accepted");
    check(!wire.opened, "malformed image opened a device");
}

void modern_8bit_uart_test(const std::filesystem::path& root, bool auto_power, uint16_t magic = 0xF784,
                           uint8_t version = 0x75, int baud = 19200) {
    Wire wire;
    auto status = mcu(magic);
    status[4] = 0x65;
    status[13] = 0x27;
    status[14] = 0x10;  // 10000 * 2400 = 24 MHz
    const auto* model = stcisp::find_model_by_magic(magic);
    check(model != nullptr, "missing 8-bit fixture model");
    status[16] = static_cast<uint8_t>(model->code_size >> 8);
    status[17] = version;
    status[22] = 3;
    Config config;
    config.transport = "link1d";
    config.link1d_auto_power = auto_power;
    config.baud = baud;
    config.image = (root / "h8-multiblock.hex").string();
    if (auto_power) {
        wire.replies = {report({0x51}), report({0x80}), report(status), report({1}), report({5}),
                        report({3}), report({2, 0x54}), report({2, 0x54})};
    } else {
        config.port = "UART1";
        auto chunk = uart_reply({0x80});
        const auto status_frame = uart_reply(status);
        chunk.insert(chunk.end(), status_frame.begin(), status_frame.begin() + 1);
        wire.replies = {std::move(chunk), Bytes(status_frame.begin() + 1, status_frame.end()),
            uart_reply({1}), uart_reply({5}), uart_reply({3}), uart_reply({2, 0x54}), uart_reply({2, 0x54})};
    }
    const bool short_packets = version < 0x72;
    const auto expected_baud = baud == 921600 ? 460800 : baud;
    if (short_packets)
        wire.replies.push_back(auto_power ? report({2, 0x54}) : uart_reply({2, 0x54}));
    run(config, wire);
    std::vector<Bytes> target;
    if (auto_power) {
        const auto trace = commands(wire);
        check_envelope(trace, true, true, false);
        check(trace[7].data == Bytes{2, stcisp::Link1dTransport::baud_code(expected_baud), 1},
              "wrong H8U Link1D transfer speed");
        target = target_commands(trace);
    } else {
        check(wire.writes[0] == Bytes{0x7F}, "missing UART cold start");
        check(wire.baud_rates == std::vector<int>{expected_baud}, "wrong H8U serial transfer speed");
        for (auto i = 1u; i + 1 < wire.writes.size(); ++i) {
            const auto& message = wire.writes[i];
            check(message.size() >= 9 && message[2] == 0x6A, "bad serial write envelope");
            target.emplace_back(message.begin() + 5, message.end() - 3);
        }
    }
    check(target.size() == (short_packets ? 7 : 6), "unexpected 8-bit UART command count");
    check(target[0] == Bytes{0x80}, "missing H8U UART status acknowledgement");
    const auto wait = static_cast<uint8_t>(magic == 0xF621 || magic == 0xF601 ? 0x80 : 0x98);
    check(target[1] == (expected_baud == 460800 ? Bytes{1, 0x65, 0x40, 0xFF, 0xF3, 0, 0, wait} :
          Bytes{1, 0x65, 0x40, 0xFE, 0xC7, 0, 0, wait}), "wrong 8-bit UART clock packet");
    check(target[2] == (short_packets ? Bytes{5} : Bytes{5, 0, 0, 0x5A, 0xA5}), "wrong UART prepare");
    check(target[3] == (short_packets ? Bytes{3, 0} : Bytes{3, 0, 0, 0x5A, 0xA5}), "wrong UART erase");
    if (short_packets) {
        check(target[4].size() == 67 && target[4][0] == 0x22 && target[4][3] == 2 &&
              target[5][2] == 0x40 && target.back() == Bytes{2, 0, 0x80, 0x42},
              "wrong pre-7.2 UART blocks");
        return;
    }
    const uint8_t hi = version < 0x75 ? 0x5A : 0;
    const uint8_t lo = version < 0x75 ? 0xA5 : 0;
    check(target[4].size() == 69 && target[4][0] == 0x22 && target[4][3] == hi &&
          target[4][4] == lo && target[4][5] == 2 && target[4].back() == 0xFF,
          "wrong first H8U block");
    check(target[5] == Bytes{2, 0, 0x80, hi, lo, 0x42},
          "wrong H8U continuation block or erased block was transmitted");
}

void fixed_63k_partition_test(const std::filesystem::path& root) {
    Config config;
    config.transport = "link1d";
    config.model = "STC8H8K64U";
    config.image = (root / "fixed-63k.hex").string();
    auto status = mcu(0xF784);
    status[9] = 0x0C;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0xFE;
    status[17] = 0x75;
    status[37] = 0x22;
    status[38] = 0x02;
    for (const auto day : {0x23, 0x24}) {
        status[39] = day;
        Wire wire;
        wire.replies = {report({0x51}), report(status), report({1}), report({5}),
                        report({3}), report({2, 0x54}), report({2, 0x54})};
        run(config, wire);
        const auto target = target_commands(commands(wire));
        check(target.size() == 5 &&
              target[2] == Bytes{3, static_cast<uint8_t>(day == 0x24), 0, 0x5A, 0xA5} &&
              target[4] == Bytes{2, 0xFC, 0, 0, 0, 0x42},
              "affected 64 KiB STC8 lot erase must cover EEPROM from FC00");
    }

    config.options["eeprom_kib"] = "2";
    Wire invalid;
    invalid.replies = {report({0x51}), report(status)};
    bool refused = false;
    try { stcisp::Programmer(config, std::make_unique<Fake>(invalid)).run(); }
    catch (const std::invalid_argument& error) {
        refused = std::string_view(error.what()).find("1 KiB") != std::string_view::npos;
    }
    check(refused && target_commands(commands(invalid)).empty(),
          "attempt to repartition the fixed 63 KiB lot must fail before erase");
}

void older_irc_download_test(const std::filesystem::path& root, bool link1d, bool compact = false,
                             bool short_header = false) {
    Wire wire;
    auto status = mcu(compact ? 0xF621 : 0xF784);
    status[4] = 0x65;
    status[9] = 0xFF;
    status[11] = 0xFF;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0x20;
    status[17] = short_header ? 0x71 : compact ? 0x75 : 0x73;
    status[22] = 3;
    const auto reply = [&](const Bytes& payload) {
        wire.replies.push_back(link1d ? report(payload) : uart_reply(payload));
    };
    const auto measure = [&](std::initializer_list<unsigned> counts) {
        Bytes bytes{0, static_cast<uint8_t>(counts.size())};
        for (const auto count : counts)
            bytes.insert(bytes.end(), {static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
        reply(bytes);
    };
    if (link1d) wire.replies.push_back(report({0x51}));
    reply(status);
    if (compact) {
        measure({15000, 25000});
        measure({19940, 19950, 19960, 19970, 19980, 19990, 20000, 20010, 20020, 20030, 20040, 20050});
    } else {
        measure({7500, 12500, 14000, 18000, 21000});
        measure({9970, 9975, 9980, 9985, 9990, 9995, 10000, 10005, 10010, 10015, 10020, 10025});
    }
    for (const Bytes& ack : {Bytes{1}, Bytes{5}, Bytes{3}, Bytes{2, 0x54},
                            short_header ? Bytes{4, 0x54} : Bytes{4}})
        reply(ack);
    Config config;
    config.model = compact ? "STC8A8K08S4A12" : "STC8H8K64U";
    config.transport = link1d ? "link1d" : "serial";
    config.port = "COM8";
    config.image = (root / "lower.hex").string();
    config.options = {{short_header ? "irc_adjust_enabled" : "irc_adjust_mode",
                       short_header ? "true" : "dynamic"}, {"irc_hz", "24000000"}};
    if (short_header) {
        config.options.insert({{"uart1_remap", "true"}, {"uart1_remap_p37_level", "1"},
                               {"reset_pin_level", "0"}, {"reset_pwm_port_open_drain", "false"},
                               {"append_test_parameters", "false"}});
    }
    run(config, wire);
    std::vector<Bytes> target;
    if (link1d) {
        target = target_commands(commands(wire));
    } else {
        check(wire.writes.size() >= 6 && wire.writes[0] == Bytes{0x7F} &&
              wire.writes[2] == Bytes{0x66} && wire.writes[4] == Bytes{0x66},
              "ordinary COM IRC probes must be followed by raw 66 triggers");
        for (const auto& write : wire.writes)
            if (write.size() >= 9)
                target.emplace_back(write.begin() + 5, write.end() - 3);
        check(target.back() == Bytes{0xFF}, "missing UART exit");
        target.pop_back();
    }
    const auto coarse = compact ? Bytes{0, 2, 0, 0, 0x80, 0} :
        Bytes{0, 5, 0, 0, 0x80, 0, 0, 0x80, 0x80, 0x80, 0xFF, 0};
    check(target.size() == 7 && target[0] == coarse,
          "wrong old UART IRC coarse probe");
    Bytes fine{0, 12};
    for (uint8_t trim = 63; trim <= 65; ++trim)
        for (uint8_t step = 0; step < 4; ++step)
            fine.insert(fine.end(), {trim, step});
    check(target[1] == fine && target[2][0] == 1, "wrong old UART IRC fine probe or switch order");
    const auto& options = target.back();
    const auto header = short_header ? 3 : 5;
    check(options.size() == header + 40 && options[0] == 4 &&
          options[header + 37] == (compact ? 0xFF : 0xEF) &&
          Bytes(options.begin() + header + 24, options.begin() + header + 31) ==
              Bytes{1, 0x6E, 0x36, 0, 64, 2, 1},
          "old UART IRC result was not committed");
    if (short_header)
        check(target[3] == Bytes{5} && target[4] == Bytes{3, 0} &&
              target[5] == Bytes{0x22, 0, 0, 2, 0, 0} && options[3] == 0xFF &&
              options[4] == 0xFF && (options[header + 36] & 0x5C) == 0x50,
              "wrong BSL 7.1 headers or pin configuration");
}

void uart_password_order_test(const std::filesystem::path& root, uint8_t version, uint8_t patch) {
    Wire wire;
    auto status = mcu(0xF621);
    const bool resize_partition = version == 0x73;
    if (resize_partition) status = mcu(0xF628);
    status[9] = 0xFE;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0x20;
    status[17] = version;
    status[22] = patch;
    const bool password_first = patch < 2;
    wire.replies = {report({0x51}), report(status), report({1}), report({5}), report({3}),
                    report({2, 0x54}), report(password_first ? Bytes{7} : Bytes{4}),
                    report(password_first ? Bytes{4, 0x54} : Bytes{7, 0x54})};
    Config config;
    config.transport = "link1d";
    config.model = resize_partition ? "STC8A8K64S4A12" : "STC8A8K08S4A12";
    config.image = (root / "lower.hex").string();
    config.next_password = "new!";
    if (resize_partition) config.options = {{"eeprom_kib", "2.25"}, {"irc_adjust_enabled", "false"}};
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 6, "wrong number of versioned UART commands");
    const auto& options = target[password_first ? 5 : 4];
    const auto& password = target[password_first ? 4 : 5];
    check(options.size() == 45 && options[0] == 4 && options[27] == 4 && options[37] == 0xF6 &&
          options[44] == (resize_partition ? 0xF7 : 0xFF) &&
          password == Bytes{7, 0, 0, 0x5A, 0xA5, 'n', 'e', 'w', '!'},
          "wrong UART password or EEPROM partition configuration");
}

void legacy_test(const std::filesystem::path& root, uint16_t magic, const char* name, bool compact_options = false) {
    Wire wire;
    auto status = mcu(magic, 0, 23);
    status[17] = 0x46;
    for (size_t i = 1; i <= 15; i += 2) {
        status[i] = 0x0A;
        status[i + 1] = 0x80;
    }
    status[19] = 0xFF;
    wire.replies = {report({0x51}), report(status), report({0x8F}), report({0x8E}),
                    report({0x80}), report({0x80}), report({0x80}), report({0x80}),
                    report({0x80}), report({0x80}), report({0x80, 0x85}),
                    report({0x8D}), report({0x10})};
    Config config;
    config.transport = "link1d";
    config.model = name;
    config.image = (root / "lower.hex").string();
    config.options[compact_options ? "cpu_6t_enabled" : "xram_enabled"] =
        compact_options ? "true" : "false";
    run(config, wire);
    const auto trace = commands(wire);
    check_envelope(trace, true, false, true);
    check(std::count_if(trace.begin(), trace.end(), [](auto& cmd) { return cmd.code == 0x4D; }) == 2,
          "missing legacy baud acknowledgement");
    const auto target = target_commands(trace);
    check(target.size() == 11 && target[0] == Bytes{0x8F, 0xFF, 0xEE, 0, 0x24, 0x28, 0x82} &&
          target[1] == Bytes{0x8E, 0xFF, 0xEE, 0, 0x24, 0x28},
          "legacy baud commands incorrect");
    check(target[7] == Bytes{0x84, 1, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}, "wrong legacy erase");
    check(target[8].size() == 135 && target[8][7] == 2, "wrong legacy write");
    check(target[9] == (compact_options ? Bytes{0x8D, 0x40} : Bytes{0x8D, 0xBD, 0xFF, 0xF6, 0xFF}),
          "wrong legacy option");
    check(target[10] == Bytes{0x50}, "missing legacy option confirmation");
}

void stc12_test(const std::filesystem::path& root, bool selector_one) {
    Wire wire;
    const uint16_t magic = selector_one ? 0xD164 : 0xF211;
    const uint32_t flash_size = selector_one ? 8192 : 1024;
    auto status = mcu(magic, 0x50, 31);
    std::fill(status.begin() + 23, status.end(), 0xFF);
    status[17] = selector_one ? 0x58 : 0x50;
    for (size_t i = 1; i <= 15; i += 2) {
        status[i] = 0x0A;
        status[i + 1] = 0x80;
    }
    wire.replies = {report({0x51}), report(status)};
    if (selector_one) wire.replies.push_back(report({0x8F}));
    wire.replies.push_back(report({0x8F}));
    wire.replies.push_back(report({static_cast<uint8_t>(selector_one ? 0x84 : 0x8E)}));
    if (!selector_one)
        for (unsigned i = 0; i < 5; ++i) wire.replies.push_back(report({0x80}));
    const auto ack = static_cast<uint8_t>(selector_one ? 0 : 0x80);
    wire.replies.push_back(report({ack}));
    wire.replies.push_back(report({ack, 0x85}));
    if (selector_one) wire.replies.push_back(report({0x8D}));
    wire.replies.push_back(report({static_cast<uint8_t>(selector_one ? 0x50 : 0x80)}));
    if (!selector_one) wire.replies.push_back(report({0x10}));
    Config config;
    config.transport = "link1d";
    config.model = selector_one ? "STC12C5A08S2" : "STC12C1052AD";
    config.image = (root / "lower.hex").string();
    config.options = {{"watchdog_prescale", "32"}, {"eeprom_erase_enabled", "true"}};
    run(config, wire);
    const auto trace = commands(wire);
    check_envelope(trace, true, selector_one, true);
    const auto target = target_commands(trace);
    const size_t baud = selector_one ? 1 : 0;
    const size_t erase = selector_one ? 3 : 7;
    check(target.size() == (selector_one ? 7u : 11u), "wrong STC12 command count");
    if (selector_one) {
        check(target[0] == Bytes{0x50, 0, 0, 0x36, 1, 0xD1, 0x64}, "STC12 preparation packet");
        check(target[5] == Bytes{0x69, 0, 0, 0x36, 1, 0xD1, 0x64}, "STC12 completion packet");
    }
    check(target[baud] == Bytes{0x8F, 0xC0, 0xDC, 0x3F, 0x48, 0x28, 0x83} &&
          target[baud + 1] == Bytes{0x8E, 0xC0, 0xDC, 0x3F, 0x48, 0x28}, "STC12 baud packets");
    Bytes expected_erase{0x84, 0};
    for (unsigned n = 0; n < 2; ++n)
        expected_erase.insert(expected_erase.end(), {0, static_cast<uint8_t>(flash_size >> 8), 0});
    expected_erase.resize(19, 0);
    for (unsigned n = 0x80; n >= 0x0E; --n) expected_erase.push_back(static_cast<uint8_t>(n));
    check(target[erase] == expected_erase, "STC12 erase packet differs from AiCube");
    Bytes expected_write{0, 0, 0, 0, 0, 0, 0x80, 2, 0, 0};
    expected_write.resize(135, 0xFF);
    check(target[erase + 1] == expected_write, "STC12 write packet differs from AiCube");
    if (selector_one) {
        check(target[6] == Bytes{0x8D, 0xFF, 0xFF, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0xA8, 0xC0, 0},
              "STC12 extended configuration packet");
    } else {
        check(target[9] == Bytes{0x8D, 0xFF, 0xFC, 0xF5, 0xFF, 0xFF, 0, 0xA8, 0xC0, 0, 0xFF, 0xFF,
                                 0xFF, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0, 0xA8, 0xC0, 0, 0xFF, 0xFF, 0xFF},
              "STC12 compact configuration packet");
        check(target[10] == Bytes{0x50}, "STC12 compact configuration confirmation");
    }
}

void legacy_stc12_mixed_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xF211, 0x50, 31);
    status[17] = 0x50;
    for (size_t i = 1; i <= 15; i += 2) {
        status[i] = 0x0A;
        status[i + 1] = 0x80;
    }
    wire.replies = {report({0x51}), report(status), report({0x8F}), report({0x8E})};
    for (unsigned i = 0; i < 6; ++i) wire.replies.push_back(report({0x80}));
    for (unsigned i = 0; i < 12; ++i)
        wire.replies.push_back(report({0x80, static_cast<uint8_t>(i == 0 ? 0x85 : i == 8 ? 0xC3 : 0x80)}));
    Config config;
    config.model = "STC12C1052AD";
    config.transport = "link1d";
    config.image = (root / "stc12-mixed.hex").string();
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 20, "legacy STC12 did not write the merged image");
    const auto& erase = target.at(7);
    const Bytes erase_prefix{0x84, 0, 0, 6, 0, 0, 4, 0};
    check(erase.size() == 134 && std::equal(erase_prefix.begin(), erase_prefix.end(), erase.begin()),
          "legacy STC12 erase did not cover EEPROM");
    const auto& eeprom = target.at(16);
    const Bytes eeprom_prefix{0, 0, 0, 4, 0, 0, 128, 0x42};
    check(eeprom.size() == 135 && std::equal(eeprom_prefix.begin(), eeprom_prefix.end(), eeprom.begin()),
          "legacy STC12 EEPROM block is not at the model's EEPROM address");
}

void make_simulation_test(const std::string& interface, bool swd) {
    Wire wire;
    const bool native_usb = interface == "usb";
    auto status = mcu(0xF8D1, native_usb ? 0 : 0x50);
    status[4] = 0x65;
    status[11] = 0x27;
    status[12] = 0x2B;
    status[13] = 0x27;
    status[14] = 0x10;
    status[15] = 0xD6;
    status[16] = 2;
    Config config;
    config.model = "STC32G144K246";
    config.transport = interface;
    config.port = interface == "serial" ? "COM1" : "";
    config.make_simulation = true;
    config.options["simulation_mode"] = swd ? "swd" : "usb";
    if (swd) config.options["swd_pins"] = "p1.6-p1.7";
    const bool is_link1d = interface == "link1d";
    if (is_link1d) wire.replies.push_back(report({0x51}));
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, Bytes{3}, Bytes{4, 0x54}})
        wire.replies.push_back(is_link1d ? report(reply) : uart_reply(reply));
    run(config, wire);
    std::vector<Bytes> target;
    if (is_link1d) {
        const auto trace = commands(wire);
        check_envelope(trace, true, true, false);
        target = target_commands(trace);
    } else {
        check(wire.writes.size() == 6, "wrong simulation transfer count");
        check(wire.writes.front()[native_usb ? 5 : 0] == (native_usb ? 0 : 0x7F),
              "unexpected simulation initial handshake");
        check(wire.writes.back()[5] == 0xFF, "missing simulation exit");
        for (auto it = wire.writes.begin() + 1; it != wire.writes.end() - 1; ++it) {
            const auto length = (uint16_t{(*it)[3]} << 8) | (*it)[4];
            target.emplace_back(it->begin() + 5, it->begin() + length - 1);
        }
    }
    check(target.size() == 4, "F8D1 simulation must not send monitor or program blocks");
    check(target[0] == (native_usb ? Bytes{1, 0, 0, 0, 0, 0, 0, 0x80} :
                        Bytes{1, 0x65, 0x40, 0xFE, 0xC7, 0, 0, 0x98}), "wrong simulation init");
    check(target[1] == Bytes{5, 0, 0, 0x5A, 0xA5} &&
          target[2] == Bytes{3, 0, 0, 0x5A, 0xA5}, "wrong simulation prepare/erase");
    const auto& options = target[3];
    check(options.size() == 46 && options[0] == 4 &&
          options[39] == (swd ? 0x87 : 0x27) &&
          options[40] == (swd ? 0x2B : 0x0B) &&
          options[43] == (swd ? 0xD6 : 0x56) && options[44] == 2,
          "simulation did not preserve other hardware bits");
}

void stc15_selector3_test(const std::filesystem::path& root, const char* name,
                          uint16_t magic, bool timer1, uint8_t version, bool configure = false,
                          std::optional<bool> internal_clock = std::nullopt, int baud = 19200,
                          bool bind_uid = false) {
    Wire wire;
    auto status = mcu(magic);
    status[4] = 0x65;
    status[13] = 0x12;
    status[14] = 0x00;
    status[16] = 0x10;
    status[17] = version;
    status[5] = 0x27;
    status[6] = 0xC3;
    status[7] = internal_clock == true ? 0x90 : 0x91;
    status[8] = 0x00;
    status[9] = 0xA8;
    status[10] = internal_clock.has_value() ? 0xB0 : 0xC0;
    status[11] = 0x00;
    status[12] = 0xFF;
    status[37] = 0xFD;
    status[38] = 0x54;
    status[39] = 0x40;
    if (bind_uid)
        for (size_t i = 0; i < 7; ++i) status[31 + i] = static_cast<uint8_t>(i + 1);
    if (magic == 0xF290) {
        status[18] = 'Q';
        status[19] = 3;
    }
    wire.replies = {report({0x51}), report(status), report({1}), report({5}),
                    report({3}), report({2, 0x54})};
    Config config;
    config.model = name;
    config.transport = "link1d";
    config.baud = baud;
    config.image = (root / "lower.hex").string();
    if (bind_uid) {
        config.uid_allowlist = (root / "allowed-uids.txt").string();
        config.uid_bindings = {{0x10, "add:1"}};
    }
    if (configure) {
        config.options = {{"watchdog_prescale", "64"}, {"cold_start_p32_p33_required", "true"},
                          {"irc_adjust_enabled", "false"}};
        if (internal_clock) {
            config.options["internal_irc_clock"] = *internal_clock ? "true" : "false";
            config.options["irc_adjust_enabled"] = "true";
        }
        wire.replies.push_back(report({4, 0x54}));
    }
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == (configure ? 5 : 4), "wrong STC15 selector 3 command count");
    check(target[0] == (baud == 115200 ? Bytes{1, 0x65, 0x40, 0xFE, 0xE0, 0xFE, 0x50, 0x83} :
          timer1 ? Bytes{1, 0x65, 0x40, 0xFF, 0x70, 0, 0, 0x83} :
          Bytes{1, 0x65, 0x40, 0xFD, 0xC0, 0xFC, 0xA0, 0x83}), "wrong STC15 selector 3 baud");
    check(target[1] == (version < 0x72 ? Bytes{5} : Bytes{5, 0, 0, 0x5A, 0xA5}), "wrong STC15 prepare");
    check(target[2] == (version < 0x72 ? Bytes{3, 0} : Bytes{3, 0, 0, 0x5A, 0xA5}), "wrong STC15 erase");
    Bytes first{0x22, 0, 0};
    if (version >= 0x72) first.insert(first.end(), {0x5A, 0xA5});
    first.insert(first.end(), {2, 0, 0});
    if (bind_uid) {
        first.resize(3 + 0x10, 0xFF);
        first.insert(first.end(), {2, 3, 4, 5, 6, 7, 8});
    }
    check(target[3] == first, "wrong STC15 selector 3 write");
    if (configure) {
        Bytes expected{4, 0, 0};
        if (version >= 0x72) expected.insert(expected.end(), {0x5A, 0xA5});
        const auto header = expected.size();
        expected.resize(header + 64, 0xFF);
        auto body = std::span(expected).subspan(header);
        body[3] = body[6] = body[22] = body[23] = body[29] = 0;
        body[25] = 0xA8;
        body[27] = 0xC0;
        body[31] = 0xFE;
        body[32] = 1;
        body[55] = 0xFD;
        body[59] = internal_clock.has_value() ? 0x65 : 0x54;
        body[60] = 0x7F;
        body[61] = 0x25;
        body[62] = 0xC3;
        body[63] = internal_clock == false ? 0x90 : 0x91;
        check(target[4] == expected, "wrong STC15 legacy hardware packet");
    }
}

void stc15_dynamic_irc_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xF401);
    status[7] = 0x81;
    status[12] = 0xFF;
    status[13] = 0x13;
    status[14] = 0x88;  // 12 MHz at 2400 baud.
    status[16] = 0x20;
    status[22] = 3;
    const auto measurement = [](uint8_t command, std::initializer_list<unsigned> counts) {
        Bytes bytes{0, command};
        for (const auto count : counts)
            bytes.insert(bytes.end(), {static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
        return report(bytes);
    };
    wire.replies = {report({0x51}), report(status),
        measurement(11, {3000, 6000, 8000, 8500, 11000, 13000, 14000, 17000, 19500, 20500, 24000, 27000}),
        measurement(12, {19996, 19997, 19998, 19999, 20000, 20001, 9998, 9999, 10000, 10001, 10002, 10003}),
        report({1}), report({5}), report({3}), report({2, 0x54}), report({4, 0x54})};
    Config config;
    config.model = "STC15F2K08S2";
    config.transport = "link1d";
    config.image = (root / "lower.hex").string();
    config.options = {{"irc_adjust_enabled", "true"}, {"irc_hz", "24000000"}};
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 7 && target[0] == Bytes{0, 11, 0, 0xC0, 0x80, 0xC0, 0xFF, 0xC0,
          0, 0x80, 0x80, 0x80, 0xFF, 0x80, 0, 0x40, 0x80, 0x40, 0xFF, 0x40, 0, 0, 0x80, 0, 0, 0},
          "wrong STC15 four-band coarse packet");
    check(target[1] == Bytes{0, 12, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0,
           0x49, 0x80, 0x4A, 0x80, 0x4B, 0x80, 0x4C, 0x80, 0x4D, 0x80, 0x4E, 0x80},
          "wrong STC15 dual-purpose fine packet");
    check(target[2] == Bytes{1, 0x4B, 0x80, 0xFF, 0x64, 0, 0, 0x82},
          "wrong STC15 IRC transfer trim");
    const auto& options = target.back();
    check(options.size() == 69 && options[28] == 1 && options[30] == 0x6E && options[32] == 0x36 &&
          options[34] == 0 && options[64] == 4 && options[65] == 0x3F,
          "wrong STC15 IRC application trim");
}

void append_test_parameters_test(const std::filesystem::path& root, bool collision) {
    Wire wire;
    auto status = mcu(0xF621);
    std::iota(status.begin() + 1, status.begin() + 17, uint8_t{1});
    std::iota(status.begin() + 23, status.end(), uint8_t{23});
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0x20;
    status[17] = 0x74;
    status[22] = 3;
    wire.replies = {report({0x51}), report(status)};
    Config config;
    config.model = "STC8A8K08S4A12";
    config.transport = "link1d";
    config.image = (root / "lower.hex").string();
    config.options = {{"append_test_parameters", "true"}};
    if (collision) {
        config.uid_bindings = {{0x1FE2, "add:1"}};
        bool rejected = false;
        try {
            run(config, wire);
        } catch (const std::invalid_argument& error) {
            rejected = std::string_view(error.what()).find("test parameters overlap") != std::string_view::npos;
        }
        check(rejected && target_commands(commands(wire)).empty(), "test parameter overlap must fail before erase");
        return;
    }
    for (const Bytes& ack : {Bytes{1}, Bytes{5}, Bytes{3}, Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(report(ack));
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 5 && target.back() == Bytes{2, 0x1F, 0xE2, 0x5A, 0xA5,
          0, 0, 0x75, 0xC7, 0x20, 30, 29, 28, 27, 49, 48, 47, 46, 45, 44, 43, 42,
          26, 25, 23, 24, 35, 36}, "wrong standalone test parameter write");
}

void ai32_bank_test(const std::filesystem::path& root, bool usb, bool valid_boundary = true,
                    uint8_t version = 0x75, bool with_options = false, bool resize_partition = false,
                    int patch = 0, bool affected_batch = false) {
    Wire wire;
    auto status = mcu(0x77E3, usb ? 0 : 0x50);
    status[4] = 0x65;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = valid_boundary ? 1 : 3;
    status[17] = version;
    status[22] = static_cast<uint8_t>(patch);
    status[9] = 0xFE;
    if (affected_batch) {
        status[37] = 0x25;
        status[38] = 0x01;
        status[39] = 0x02;
    }
    Config config;
    config.transport = usb ? "usb" : "link1d";
    config.model = "AI32G12K128";
    config.image = (root / "ai32-banks.hex").string();
    if (with_options) {
        config.options = {{"watchdog_prescale", "32"}, {"rs485_enabled", "true"},
                          {"rs485_rx_pin", "P3.2"}, {"rs485_tx_pin", "P5.4"},
                          {"rs485_rx_active_high", "true"}, {"rs485_tx_active_high", "false"}};
    }
    if (!usb) wire.replies.push_back(report({0x51}));
    const auto add_reply = [&](const Bytes& bytes) {
        wire.replies.push_back(usb ? uart_reply(bytes) : report(bytes));
    };
    add_reply(status);
    if (resize_partition) config.options["eeprom_kib"] = "2";
    if ((!valid_boundary && !resize_partition) || (version < 0x75 && patch < 3) ||
        (affected_batch && usb)) {
        try {
            run(config, wire);
            throw std::logic_error("incompatible AI32 target was accepted");
        } catch (const std::invalid_argument&) {}
        check(wire.writes.size() == 1, "incompatible AI32 target received an erase/write command");
        return;
    }
    for (const Bytes& payload : {Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                                 Bytes{2, 0x54}, Bytes{2, 0x54}})
        add_reply(payload);
    const bool write_options = with_options || resize_partition;
    if (write_options) add_reply({4, 0x54});
    run(config, wire);
    const uint8_t marker = version < 0x75 ? 0x5A : 0;
    const uint8_t lower_bank = version < 0x75 ? 0xA5 : 0;
    const uint8_t upper_bank = version < 0x75 ? 0xA5 : 1;
    if (!usb) {
        const auto target = target_commands(commands(wire));
        check(target.size() == 5 + unsigned(write_options), "wrong number of UART AI32 commands");
        check(target[2] == Bytes{3, 0, 8, 0x5A, 0xA5}, "wrong AI32 erase prefix");
        check(target[3].size() == 69 && Bytes(target[3].begin(), target[3].begin() + 8) ==
              Bytes{0x12, 8, 0, marker, lower_bank, 2, 0, 0}, "wrong AI32 UART bank 0");
        check(target[4] == Bytes{2, 0, 0, marker, upper_bank, 0x42}, "wrong AI32 UART bank 1");
    } else {
        check(wire.writes.size() == 11 + unsigned(write_options), "wrong number of USB AI32 reports");
        check(Bytes(wire.writes[3].begin() + 5, wire.writes[3].begin() + 10) ==
              Bytes{3, 0, 8, 0x5A, 0xA5}, "wrong USB AI32 erase prefix");
        check(Bytes(wire.writes[4].begin() + 5, wire.writes[4].begin() + 13) ==
              Bytes{0x12, 8, 0, marker, lower_bank, 2, 0, 0}, "wrong AI32 USB bank 0");
        check(Bytes(wire.writes[7].begin() + 5, wire.writes[7].begin() + 11) ==
              Bytes{2, 0, 0, marker, upper_bank, 0x42}, "wrong AI32 USB bank 1");
    }
    if (write_options) {
        Bytes packet;
        if (usb) {
            const auto& frame = wire.writes[wire.writes.size() - 2];
            packet.assign(frame.begin() + 5, frame.begin() + 50);
        } else {
            packet = target_commands(commands(wire)).back();
        }
        check(packet.size() == 45 && packet[0] == 4 && packet[44] == 1,
              "AI32 configuration did not encode the selected EEPROM boundary");
        if (with_options)
            check(packet[8] == 0x10 && packet[9] == 0xB2 && packet[11] == 0 && packet[12] == 0xCC &&
                  packet[37] == 0xFA && packet[43] == 0x84,
                  "AI32 configuration did not encode RS485 and watchdog fields");
    }
}

void ai32_preflight_test(const std::filesystem::path& root) {
    Wire wire;
    Config config;
    config.transport = "usb";
    config.model = "AI32G12K128";
    config.image = (root / "lower.hex").string();
    try {
        run(config, wire);
        throw std::logic_error("relative HEX accepted for AI32");
    } catch (const std::invalid_argument&) {}
    check(!wire.opened && wire.writes.empty(), "invalid AI32 HEX opened the device");
}

void ai32_eeprom_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0x77E3, 0);
    status[16] = 1;
    Config config;
    config.model = "AI32G12K128";
    config.image = (root / "ai32-eeprom.hex").string();
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(uart_reply(reply));
    run(config, wire);
    check(wire.writes.size() == 11, "AI32 mixed HEX did not write two blocks");
    const Bytes erase{3, 0, 4, 0x5A, 0xA5};
    const Bytes eeprom{0x12, 4, 0, 0, 0, 0x42};
    const Bytes code{0x12, 8, 0, 0, 0, 2, 0, 0};
    check(std::equal(erase.begin(), erase.end(), wire.writes[3].begin() + 5), "wrong AI32 EEPROM erase start");
    check(std::equal(eeprom.begin(), eeprom.end(), wire.writes[4].begin() + 5), "wrong AI32 EEPROM block");
    check(std::equal(code.begin(), code.end(), wire.writes[7].begin() + 5), "wrong AI32 code block");
}

void ai16_beta_test(const std::filesystem::path& root, bool usb) {
    Wire wire;
    const uint16_t magic = usb ? 0x77E0 : 0xF7E0;
    auto status = mcu(magic, usb ? 0 : 0x50);
    status[4] = 0x65;
    status[9] = 0xFC;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 0xFE;
    Config config;
    config.transport = usb ? "usb" : "link1d";
    config.model = usb ? "AI16F40K128-Beta" : "STC16F40K128-Beta";
    config.image = (root / "lower.hex").string();
    if (usb) config.options["usb_isp_clock_source"] = "1";
    if (!usb) wire.replies.push_back(report({0x51}));
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}})
        wire.replies.push_back(usb ? uart_reply(reply) : report(reply));
    if (usb) wire.replies.push_back(uart_reply({4, 0x54}));
    run(config, wire);
    if (usb) {
        check(Bytes(wire.writes[3].begin() + 5, wire.writes[3].begin() + 10) ==
              Bytes{3, 0, 0, 0x5A, 0xA5}, "wrong AI16 USB erase");
        check(Bytes(wire.writes[4].begin() + 5, wire.writes[4].begin() + 13) ==
              Bytes{0x32, 0, 0, 0, 0, 2, 0, 0}, "wrong AI16 USB write");
        const auto options = std::find_if(wire.writes.begin() + 5, wire.writes.end(),
            [](const auto& p) { return p.size() > 41 && p[5] == 4; });
        check(options != wire.writes.end() && (*options)[41] == 0xFD,
              "AI16 USB clock source was not serialized");
    } else {
        const auto target = target_commands(commands(wire));
        check(target.size() == 4 && target[2] == Bytes{3, 0, 0, 0x5A, 0xA5} &&
              target[3] == Bytes{0x22, 0, 0, 0, 0, 2, 0, 0}, "wrong AI16 UART write");
    }
    config.options.clear();
    Wire high;
    config.image = (root / "ai16-out-of-range.hex").string();
    try {
        run(config, high);
        throw std::logic_error("out-of-range AI16 HEX was accepted");
    } catch (const std::invalid_argument&) {}
    check(!high.opened && high.writes.empty(), "out-of-range AI16 HEX opened a device");

    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("stc-isp-ai16-" + std::to_string(stamp) + ".bin");
    struct RemoveFixture {
        std::filesystem::path path;
        ~RemoveFixture() {
            std::error_code error;
            std::filesystem::remove(path, error);
        }
    } temporary{path};
    {
        Bytes binary(0x10003, 0xFF);
        binary[0] = 2;
        binary[1] = binary[2] = 0;
        binary[0x10000] = 0x42;
        std::ofstream file(path, std::ios::binary);
        check(static_cast<bool>(file.write(reinterpret_cast<const char*>(binary.data()),
                                          static_cast<std::streamsize>(binary.size()))),
              "could not create AI16 BIN test fixture");
    }
    config.image = path.string();
    if (!usb) high.replies.push_back(report({0x51}));
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{2, 0x54}})
        high.replies.push_back(usb ? uart_reply(reply) : report(reply));
    run(config, high);
    const Bytes high_erase{3, 2, 0, 0x5A, 0xA5};
    const Bytes high_write{2, 0, 0, 0, 1, 0x42, 0xFF, 0xFF};
    if (usb) {
        check(std::equal(high_erase.begin(), high_erase.end(), high.writes.at(3).begin() + 5),
              "wrong AI16 high-bank USB erase");
        check(std::equal(high_write.begin(), high_write.end(), high.writes.at(7).begin() + 5),
              "wrong AI16 high-bank USB write");

        Wire g12;
        auto g12_status = mcu(0x77E3, 0);
        g12_status[16] = 1;
        config.model = "AI32G12K128";
        for (const auto& reply : {g12_status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                                  Bytes{2, 0x54}, Bytes{2, 0x54}})
            g12.replies.push_back(uart_reply(reply));
        run(config, g12);
        const Bytes g12_erase{3, 0, 8, 0x5A, 0xA5};
        const Bytes first{0x12, 8, 0, 0, 0, 2, 0, 0};
        const Bytes second{2, 8, 0, 0, 1, 0x42, 0xFF, 0xFF};
        check(std::equal(g12_erase.begin(), g12_erase.end(), g12.writes.at(3).begin() + 5) &&
              std::equal(first.begin(), first.end(), g12.writes.at(4).begin() + 5) &&
              std::equal(second.begin(), second.end(), g12.writes.at(7).begin() + 5),
              "AI32G12 BIN was not placed after the current EEPROM partition");
    } else {
        const auto target = target_commands(commands(high));
        check(target.size() == 5 && target[2] == high_erase && target[4] == high_write,
              "wrong AI16 high-bank UART erase or write");
    }
}

void make_other_simulation_test(const char* model, uint16_t magic, const std::string& interface,
                                const std::string& mode, const char* pair, uint8_t swd_pins,
                                uint8_t uart_pins, uint8_t boundary, uint8_t wait = 0xFF,
                                uint8_t version = 0x75) {
    Wire wire;
    const bool usb = interface == "usb";
    const bool link1d = interface == "link1d";
    const bool wide = magic == 0x77E3 || magic == 0x7874 || magic == 0x78B4;
    auto status = mcu(magic, usb ? 0 : 0x50);
    status[17] = version;
    if (version == 0x71) status[18] = 'Q';
    status[22] = 3;
    const Bytes trim{2, 0xDC, 0x6C, 0, 0x65, 0x30, 1};
    std::copy(trim.begin(), trim.end(), status.begin() + 1);
    status[8] = wide ? 0x51 : 0xAB;
    status[9] = 0xFE;
    status[10] = usb ? 0xCD : 0x92;
    status[11] = wide || usb ? 0xAB : 0x51;
    status[13] = usb ? 0x92 : 0x27;
    status[14] = usb ? 0x51 : 0x10;
    status[15] = 0xEE;
    status[16] = boundary;
    status[51] = 4;
    Config config;
    config.model = model;
    config.transport = interface;
    config.port = interface == "serial" ? "COM1" : "";
    config.make_simulation = true;
    config.options["simulation_mode"] = mode;
    if (*pair) config.options[mode == "swd" ? "swd_pins" : "uart_simulation_pins"] = pair;
    if (link1d) wire.replies.push_back(report({0x51}));
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7}, Bytes{4, 0x54}})
        wire.replies.push_back(link1d ? report(reply) : uart_reply(reply));
    run(config, wire);
    Bytes options(45 + (magic == 0x78B4), 0xFF);
    const Bytes prefix{4, 0, 0, 0x5A, 0xA5};
    std::copy(prefix.begin(), prefix.end(), options.begin());
    options[8] = options[11] = options[27] = 0;
    options[28] = wait;
    std::copy(trim.begin(), trim.end(), options.begin() + 29);
    options[37] = 0xFE;
    options[39] = swd_pins;
    options[40] = uart_pins;
    options[41] = 0x92;
    options[42] = 0x51;
    if (magic == 0xF784 && version < 0x74) options[42] ^= 0x10;
    options[43] = mode == "swd" ? 0xEE : 0x6E;
    options[44] = boundary;
    if (magic == 0x78B4) options[45] = 4;
    if (version < 0x72) options.erase(options.begin() + 3, options.begin() + 5);
    if (link1d) {
        const auto trace = commands(wire);
        check_envelope(trace, true, true, false);
        const auto target = target_commands(trace);
        check(target.size() == 4 && target.back() == options, "unexpected Link1D simulation option payload");
    } else {
        check(wire.writes.size() == 6, "simulation sent an unexpected program block");
        check(wire.writes.back()[5] == 0xFF, "missing simulation exit command");
        const auto& frame = wire.writes[4];
        const auto length = (uint16_t{frame[3]} << 8) | frame[4];
        check(Bytes(frame.begin() + 5, frame.begin() + length - 1) == options,
              "unexpected serial/USB simulation option payload");
    }
}

void iap15_simulation_test(const char* resources, uint8_t version, uint16_t magic) {
    const auto* model = stcisp::find_model_by_magic(magic);
    check(model != nullptr, "missing IAP15 model");
    auto status = mcu(magic);
    status[17] = version;
    if (version == 0x71) status[18] = 'Q';
    status[22] = 3;
    status[4] = 0x65;
    status[5] = 0x65;
    status[6] = 0x43;
    status[7] = 0x21;
    status[12] = 0x12;
    status[13] = 0x27;
    status[14] = 0x10;
    status[37] = 0x87;
    Config config;
    config.model = model->name;
    config.transport = "serial";
    config.port = "COM1";
    config.make_simulation = true;
    config.simulation_resources = resources;
    config.options["simulation_mode"] = "uart";
    Wire wire;
    wire.replies = {uart_reply(status), uart_reply({1}), uart_reply({5}), uart_reply({3})};
    const unsigned size = magic == 0xF569 || magic == 0xF56D ? 0xE400 : 0xF000;
    for (unsigned offset = 0; offset < size; offset += 64) wire.replies.push_back(uart_reply({2, 0x54}));
    wire.replies.push_back(uart_reply({4}));
    run(config, wire);
    check(wire.writes.size() == size / 64 + 6, "unexpected IAP15 simulation packet count");
    for (size_t i = 1; i < wire.writes.size(); ++i) {
        const auto& frame = wire.writes[i];
        const auto length = (uint16_t{frame[3]} << 8) | frame[4];
        std::cout << "packet ";
        for (auto it = frame.begin() + 5; it != frame.begin() + length - 1; ++it)
            std::cout << "0123456789abcdef"[*it >> 4] << "0123456789abcdef"[*it & 15];
        std::cout << '\n';
    }
}

void ai8051_usb_test(const std::filesystem::path& root, bool mixed = false, int old_patch = 0,
                    bool affected_batch = false) {
    Wire wire;
    Config config;
    config.model = "AI8051U-34K64";
    config.image = (root / (mixed ? "ai8051-usb-eeprom.hex" : "ai8051-usb.hex")).string();
    auto status = mcu(0x78B4, 0);
    status[16] = 3;
    if (old_patch) {
        status[17] = 0x74;
        status[22] = static_cast<uint8_t>(old_patch);
    }
    if (affected_batch) {
        status[37] = 0x24;
        status[38] = 0x12;
        status[39] = 0x20;
        wire.replies.push_back(uart_reply(status));
        try {
            run(config, wire);
            throw std::logic_error("affected AI8051U batch accepted a native USB write");
        } catch (const std::invalid_argument& error) {
            check(std::string_view(error.what()).find("requires UART") != std::string_view::npos,
                  "wrong reason for rejecting the affected AI8051U batch");
        }
        check(std::none_of(wire.writes.begin(), wire.writes.end(), [](const auto& packet) { return packet[5] == 3; }),
              "affected AI8051U batch received an erase command");
        return;
    }
    const auto erase_ack = Bytes{3, 1, 2, 3, 4, 5, 6, 7};
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, erase_ack,
                               Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(uart_reply(reply));
    run(config, wire);
    check(wire.writes.size() == 11, "AI8051U sent an unexpected USB packet");
    check(wire.writes[0][5] == 0 && wire.writes[1][5] == 1 && wire.writes[2][5] == 5 &&
          wire.writes[3][5] == 3 && wire.writes[10][5] == 0xFF, "wrong AI8051U USB session");
    if (mixed)
        check(Bytes(wire.writes[3].begin() + 5, wire.writes[3].begin() + 10) ==
              Bytes{3, 120, 0, 0x5A, 0xA5}, "wrong AI8051U USB EEPROM erase");
    for (const auto [start, offset, command] : {std::tuple{4, 0, 0x32}, {7, mixed ? 0xF000 : 0x100, 0x12}}) {
        Bytes block;
        for (auto index = start; index < start + 3; ++index)
            block.insert(block.end(), wire.writes[index].begin(), wire.writes[index].end());
        const auto expected = Bytes{static_cast<uint8_t>(command), static_cast<uint8_t>(offset >> 8),
                                    0, static_cast<uint8_t>(old_patch ? 0x5A : 0),
                                    static_cast<uint8_t>(old_patch ? 0xA5 : 0), 2, 0, 0};
        check(((uint16_t{block[3]} << 8) | block[4]) == 139 &&
              std::equal(expected.begin(), expected.end(), block.begin() + 5),
              "AI8051U USB block differs from AiCube or blank block was sent");
    }
}

void usb_live_irc_test(const std::filesystem::path& root, bool ai8051, bool old_h8 = false) {
    Wire wire;
    auto status = mcu(ai8051 ? 0x78B4 : 0xF784, 0);
    status[9] = 0xFE;
    status[16] = ai8051 ? 3 : 0x20;
    status[17] = old_h8 ? 0x73 : ai8051 ? 0x75 : 0x74;
    status[22] = old_h8 ? 12 : 8;
    status[46] = 0x93;
    status[50] = 0x10;
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{4, 0x54}})
        wire.replies.push_back(uart_reply(reply));
    Config config;
    config.transport = "usb";
    config.model = ai8051 ? "AI8051U-34K64" : "STC8H8K64U";
    config.image = (root / (ai8051 ? "upper.hex" : "lower.hex")).string();
    config.options = {{"irc_adjust_mode", "dynamic"}, {"irc_hz", "36864000"}};
    run(config, wire);
    const auto& packet = wire.writes.at(7);
    const Bytes expected{0x02, 0x32, 0x80, 0, 0x93, static_cast<uint8_t>(old_h8 ? 0x80 : 0x30), 1};
    check(packet.at(5) == 4 && std::equal(expected.begin(), expected.end(), packet.begin() + 34),
          "USB IRC options did not use the detected trim and band selector");
}

void download_options_test(const std::filesystem::path& root, bool ai8051, bool usb) {
    Wire wire;
    Config config;
    config.transport = usb ? "usb" : "link1d";
    config.image = (root / (ai8051 ? "upper.hex" : "h8-multiblock.hex")).string();
    config.options = {{"oscillator_gain_high", "false"}, {"low_voltage_threshold", "2"},
                      {"watchdog_por_enabled", "true"}, {"watchdog_stop_idle", "false"},
                      {"watchdog_prescale", "32"}, {"eeprom_kib", "4"},
                      {"cold_start_p32_p33_required", "true"}};
    if (ai8051) {
        config.options["user_system_enabled"] = "true";
        config.options["user_system_kib"] = "1.5";
    }
    auto status = mcu(ai8051 ? 0x78B4 : 0xF784, usb ? 0 : 0x50);
    const Bytes trim{0x01, 0x6E, 0x36, 0x00, 0x48, 0x20, 0x01};
    std::copy(trim.begin(), trim.end(), status.begin() + 1);
    if (!usb) {
        status[13] = 0x27;
        status[14] = 0x10;
        wire.replies = {report({0x51}), report({0x80})};
    }
    status[9] = 0xFF;
    status[ai8051 && usb ? 13 : 10] = 0x92;
    status[ai8051 ? (usb ? 14 : 8) : 11] = ai8051 ? 0xD3 : 0x53;
    status[12] = 0xBF;
    status[15] = 0xEE;
    status[16] = ai8051 ? 1 : 0xFC;
    const auto enqueue = [&](const Bytes& bytes) {
        wire.replies.push_back(usb ? uart_reply(bytes) : report(bytes));
    };
    enqueue(status);
    enqueue({1});
    enqueue({5});
    enqueue(usb ? Bytes{3, 1, 2, 3, 4, 5, 6, 7} : Bytes{3});
    enqueue({2, 0x54});
    if (!ai8051) enqueue({2, 0x54});
    enqueue({4, 0x54});
    run(config, wire);
    const auto expected = [&](Bytes packet) {
        Bytes options(ai8051 ? 46 : 45, 0xFF);
        options[0] = 4;
        options[1] = options[2] = options[8] = options[11] = options[27] = 0;
        options[3] = 0x5A;
        options[4] = 0xA5;
        std::copy(trim.begin(), trim.end(), options.begin() + 29);
        options[37] = 0xFE;
        options[40] = 0xBF;
        options[41] = 0x90;
        options[42] = 0x51;
        options[43] = 0xCC;
        options[44] = ai8051 ? 3 : 0xF0;
        if (ai8051) {
            options[39] = status[11] | 0x20;
            options[45] = 0xFA;
        }
        check(packet == options, "ordinary download hardware options differ from AiCube layout");
    };
    if (usb) {
        const auto& frame = wire.writes[wire.writes.size() - 2];
        expected(Bytes(frame.begin() + 5, frame.begin() + 5 + (ai8051 ? 46 : 45)));
    } else {
        const auto packets = target_commands(commands(wire));
        expected(packets.back());
    }
}

void user_key_test(const std::filesystem::path& root, bool usb) {
    Wire wire;
    Config config;
    config.transport = usb ? "usb" : "link1d";
    config.model = "AI8051U-34K64";
    config.image = (root / "upper.hex").string();
    const auto path = std::filesystem::temp_directory_path() /
        ("stc-isp-test-key-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove(path, error); }
    } cleanup{path};
    Bytes key(256);
    for (unsigned i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i * 17);
    {
        std::ofstream file(path, std::ios::binary);
        check(static_cast<bool>(file.write(reinterpret_cast<const char*>(key.data()), key.size())),
              "could not write temporary test key");
    }
    config.user_key_file = path.string();
    auto status = mcu(0x78B4, usb ? 0 : 0x50);
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 3;
    if (!usb) wire.replies = {report({0x51})};
    for (const auto& reply : {status, Bytes{1}, Bytes{5},
                              usb ? Bytes{3, 1, 2, 3, 4, 5, 6, 7} : Bytes{3},
                              Bytes{6, 0x54}, Bytes{6, 0x54}, Bytes{6, 0x54}, Bytes{6, 0x54},
                              Bytes{2, 0x54}})
        wire.replies.push_back(usb ? uart_reply(reply) : report(reply));
    run(config, wire);
    std::vector<Bytes> packets;
    if (usb) {
        for (size_t i = 4; i < 12; i += 2) {
            Bytes packet(wire.writes[i].begin(), wire.writes[i].end());
            packet.insert(packet.end(), wire.writes[i + 1].begin(), wire.writes[i + 1].end());
            packets.emplace_back(packet.begin() + 5, packet.begin() + 74);
        }
        check(wire.writes.at(12).at(5) == 0x32, "code did not follow USB key");
    } else {
        const auto target = target_commands(commands(wire));
        check(target.size() == 8 && target[2][0] == 3 && target[7][0] == 0x22,
              "UART key was not sent between erase and code");
        packets.assign(target.begin() + 3, target.begin() + 7);
    }
    for (size_t block = 0; block < packets.size(); ++block) {
        const auto offset = block * 64;
        Bytes expected{static_cast<uint8_t>(block ? 6 : 0x26), 0, static_cast<uint8_t>(offset), 0x5A, 0xA5};
        expected.insert(expected.end(), key.begin() + offset, key.begin() + offset + 64);
        check(packets[block] == expected, "wrong user key block");
    }
}

void uid_allowlist_test(const std::filesystem::path& root, bool usb, bool match) {
    Wire wire;
    auto status = mcu(0x78B4, usb ? 0 : 0x50);
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 3;
    const Bytes uid{3, 1, 2, 3, 4, 5, 6, static_cast<uint8_t>(match ? 7 : 8)};
    const auto add_reply = [&](const Bytes& payload) {
        wire.replies.push_back(usb ? uart_reply(payload) : report(payload));
    };
    if (!usb) wire.replies.push_back(report({0x51}));
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, uid}) add_reply(reply);
    if (match) add_reply({2, 0x54});
    Config config;
    config.model = "AI8051U-34K64";
    config.transport = usb ? "usb" : "link1d";
    config.image = (root / "upper.hex").string();
    config.uid_allowlist = (root / "allowed-uids.txt").string();
    if (match) {
        run(config, wire);
        check(usb ? wire.writes[4][5] == 0x32 : target_commands(commands(wire))[3][0] == 0x22,
              "matching UID did not allow programming");
    } else {
        try {
            run(config, wire);
            throw std::logic_error("UID outside the allowlist was accepted");
        } catch (const std::runtime_error& error) {
            check(std::string(error.what()).find("UID") != std::string::npos, "wrong UID rejection");
        }
        check(usb ? wire.writes.size() == 4 : target_commands(commands(wire)).size() == 3,
              "a write followed the non-matching erase UID");
        check(wire.closed && wire.replies.empty(), "failed UID check did not close the connection");
    }
}

void encrypted_download_test(const std::filesystem::path& root, bool usb) {
    Wire wire;
    auto status = mcu(0x78B4, usb ? 0 : 0x50);
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 3;
    if (!usb) wire.replies.push_back(report({0x51}));
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(usb ? uart_reply(reply) : report(reply));
    if (!usb)
        for (unsigned i = 0; i < 3; ++i) wire.replies.push_back(report({2, 0x54}));
    Config config;
    config.model = "AI8051U-34K64";
    config.transport = usb ? "usb" : "link1d";
    config.image = (root / "ai8051-usb.hex").string();
    config.encrypted_image = true;
    run(config, wire);
    if (usb) {
        check(wire.writes[4][5] == 0xB2 && wire.writes[7][5] == 0x92,
              "wrong encrypted USB first/continuation commands");
    } else {
        const auto target = target_commands(commands(wire));
        check(target.size() == 8 && target[3][0] == 0xA2 && target[7][0] == 0x82,
              "wrong encrypted UART first/continuation commands");
        for (size_t pos = 1; pos <= 3; ++pos) {
            Bytes block{0x82, 0, static_cast<uint8_t>(pos * 64), 0, 0};
            block.resize(69, 0xFF);
            check(target[3 + pos] == block, "encrypted UART must send all-FF blocks");
        }
    }
}

void uid_binding_test(const std::filesystem::path& root, bool usb) {
    Wire wire;
    auto status = mcu(0x78B4, usb ? 0 : 0x50);
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 3;
    if (!usb) wire.replies.push_back(report({0x51}));
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(usb ? uart_reply(reply) : report(reply));
    Config config;
    config.model = "AI8051U-34K64";
    config.transport = usb ? "usb" : "link1d";
    config.image = (root / "upper.hex").string();
    config.uid_bindings[0xFF0080] = "add:1,mul:3,div:2,xor:0x55";
    run(config, wire);
    const Bytes tail{static_cast<uint8_t>(usb ? 0x12 : 2), 0, 0x80, 0, 0,
                     0x56, 0x51, 0x53, 0x52, 0x5C, 0x5F, 0x59};
    if (usb) {
        check(wire.writes.size() == 11 &&
              std::equal(tail.begin(), tail.end(), wire.writes[7].begin() + 5),
              "wrong UID binding bytes or USB address");
    } else {
        const auto target = target_commands(commands(wire));
        check(target.size() == 5 && target.back() == tail, "wrong UID binding bytes or UART address");
    }
}

void stc8u_usb_test(const std::filesystem::path& root, uint16_t id, uint8_t bsl) {
    Config config;
    config.image = (root / "h8-multiblock.hex").string();
    config.options["modify_hardware_options"] = "false";
    auto status = mcu(id, 0);
    status[17] = bsl;
    status[22] = 3;
    status[16] = 8;
    const Bytes uid{3, 1, 2, 3, 4, 5, 6, 7};
    Wire wire;
    for (const Bytes& reply : {status, Bytes{1}, Bytes{5}, uid, Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(uart_reply(reply));
    run(config, wire);
    check(wire.writes.size() == 11, "unexpected STC8U USB reports");
    for (const auto& [index, expected] : {std::pair{1, Bytes{1, 0, 0, 0, 0, 0, 0, 0x80}},
                                        {2, {5, 0, 0, 0x5A, 0xA5}},
                                        {3, {3, 0, 0, 0x5A, 0xA5}}}) {
        check(std::equal(expected.begin(), expected.end(), wire.writes[index].begin() + 5),
              "wrong STC8U USB initialization");
    }
    for (const auto [start, command, offset, first] :
         {std::tuple{4, 0x32, 0, 2}, {7, 0x12, 0x80, 0x42}}) {
        const auto& block = wire.writes[start];
        Bytes expected{static_cast<uint8_t>(command), 0, static_cast<uint8_t>(offset),
                       static_cast<uint8_t>(bsl == 0x74 ? 0x5A : 0),
                       static_cast<uint8_t>(bsl == 0x74 ? 0xA5 : 0),
                       static_cast<uint8_t>(first)};
        check(block[3] == 0 && block[4] == 139 &&
              std::equal(expected.begin(), expected.end(), block.begin() + 5),
              "wrong STC8U USB block");
    }
    Wire malformed;
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3}})
        malformed.replies.push_back(uart_reply(reply));
    try {
        run(config, malformed);
        throw std::logic_error("accepted STC8U USB erase without a UID");
    } catch (const std::runtime_error& e) {
        check(std::string(e.what()).find("expected 7-byte UID") != std::string::npos,
              "wrong STC8U USB erase exception");
    }
    check(std::none_of(malformed.writes.begin(), malformed.writes.end(), [](const auto& bytes) {
        return bytes[5] == 0x32 || bytes[5] == 0x12;
    }), "STC8U USB wrote after invalid erase response");

    Wire beyond;
    status[16] = 0;
    beyond.replies.push_back(uart_reply(status));
    try {
        run(config, beyond);
        throw std::logic_error("accepted unknown STC8U USB flash boundary");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()).find("program area") != std::string::npos,
              "wrong STC8U USB boundary exception");
    }
    check(beyond.writes.size() == 1 && beyond.writes[0][5] == 0,
          "STC8U USB sent a write before validating flash layout");
}

void eeprom_suffix_test(const std::filesystem::path& root, bool usb, uint16_t id = 0xF784) {
    Wire wire;
    auto status = mcu(id, usb ? 0 : 0x50);
    status[4] = 0x65;
    status[13] = 0x27;
    status[14] = 0x10;
    status[16] = 4;
    Config config;
    config.transport = usb ? "usb" : "link1d";
    config.image = (root / "eeprom-suffix.hex").string();
    if (!usb) wire.replies = {report({0x51}), report({0x80})};
    for (const auto& reply : {status, Bytes{1}, Bytes{5}, Bytes{3, 1, 2, 3, 4, 5, 6, 7},
                              Bytes{2, 0x54}, Bytes{2, 0x54}})
        wire.replies.push_back(usb ? uart_reply(reply) : report(reply));
    run(config, wire);
    const Bytes erase{3, 2, 0, 0x5A, 0xA5};
    if (usb) {
        check(wire.writes.size() == 11, "USB sent an unexpected EEPROM sector or skipped the suffix");
        check(std::equal(erase.begin(), erase.end(), wire.writes[3].begin() + 5), "wrong USB EEPROM erase range");
        const Bytes suffix{0x12, 6, 0, 0, 0, 0x42};
        check(std::equal(suffix.begin(), suffix.end(), wire.writes[7].begin() + 5), "wrong USB suffix address");
    } else {
        const auto target = target_commands(commands(wire));
        check(target.size() == 6 && target[3] == erase, "wrong UART EEPROM erase range");
        check(target.back() == Bytes{2, 6, 0, 0, 0, 0x42}, "wrong UART suffix address");
    }
}

void h8_info_test() {
    Wire wire;
    auto status = mcu(0xF784, 0);
    status[9] = 0x02;
    status[10] = 0x82;
    status[11] = 0x02;
    status[12] = 0xA0;
    status[15] = 0x04;
    status[16] = 0xF6;
    wire.replies.push_back(uart_reply(status));
    Config config;
    config.info_only = true;
    std::ostringstream output;
    auto* old = std::cout.rdbuf(output.rdbuf());
    try {
        run(config, wire);
    } catch (...) {
        std::cout.rdbuf(old);
        throw;
    }
    std::cout.rdbuf(old);
    const auto text = output.str();
    const auto has = [&](const char* item) { return text.find(item) != std::string::npos; };
    check(has("用户 EEPROM 容量: 2.5 KiB") && has("低压检测电压: 2.40 V") &&
          has("看门狗定时器分频系数: 32") && has("选择串口仿真端口: P1.6/P1.7") &&
          has("使能USB仿真功能: 未启用") && !has("IRC调节模式"), "wrong H8U status fields");
    check(wire.writes.size() == 2 && wire.writes[0][5] == 0 && wire.writes[1][5] == 0xFF,
          "H8U info issued a write operation");
}

void stc89_selector_one_serial_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xF050, 0x50, 23);
    status[17] = 0x46;
    status[19] = 0xFF;
    for (size_t i = 1; i <= 15; i += 2) {
        status[i] = 0x0A;
        status[i + 1] = 0x80;
    }
    for (const Bytes& reply : {status, Bytes{0x8F}, Bytes{0x8F}, Bytes{0x84},
                               Bytes{0}, Bytes{0, 0x85}, Bytes{0x8D}, Bytes{0x50}})
        wire.replies.push_back(uart_reply(reply));
    Config config;
    config.model = "STC89C51";
    config.transport = "serial";
    config.port = "COM1";
    config.image = (root / "lower.hex").string();
    config.options["xram_enabled"] = "false";
    run(config, wire);
    check(wire.writes.size() == 10 && wire.writes[0] == Bytes{0x7F}, "wrong STC89C51 serial session");
    const auto payload = [&](size_t n) {
        const auto& frame = wire.writes[n];
        check(((uint16_t{frame[3]} << 8) | frame[4]) == frame.size() - 2 &&
              ((uint16_t{frame[frame.size() - 3]} << 8) | frame[frame.size() - 2]) ==
                  std::accumulate(frame.begin() + 2, frame.end() - 3, 0),
              "wrong STC89C51 two-byte checksum");
        return Bytes(frame.begin() + 5, frame.end() - 3);
    };
    check(payload(1) == Bytes{0x50, 0, 0, 0x36, 1, 0xF0, 0x50} &&
          payload(2) == Bytes{0x8F, 0xFF, 0xEE, 0, 0x24, 0x28, 0x82} &&
          payload(7) == Bytes{0x8D, 0xBD, 0xFF, 0xF6, 0xFF} &&
          payload(8) == Bytes{0xFF} && payload(9) == Bytes{0x82},
          "wrong STC89C51 preparation, configuration or exit");
}

void upgraded_legacy_test(const std::filesystem::path& root, bool stc89, bool invalid_ack = false,
                          bool compact = false) {
    Wire wire;
    auto status = mcu(stc89 ? 0xF002 : compact ? 0xF211 : 0xD164, 0x50, 31);
    status[1] = 0xFB;
    status[5] = 0xE7;
    status[6] = 0xDF;
    status[7] = 0xBF;
    status[8] = 0x7F;
    status[13] = stc89 ? 0x01 : 0x12;
    status[14] = stc89 ? 0x80 : 0x00;
    status[16] = 0x20;
    status[17] = stc89 ? 0x72 : 0x75;
    wire.replies = {report({0x51}), report(status), report({1})};
    if (invalid_ack) wire.replies.push_back(report({0x0F}));
    else {
        wire.replies.push_back(report({5}));
        wire.replies.push_back(report({3, 1, 2, 3, 4, 5, 6, 7}));
        wire.replies.push_back(report({2, 0x54}));
        wire.replies.push_back(report({4, 0x54}));
    }
    Config config;
    config.model = stc89 ? "STC89C52RC" : compact ? "STC12C1052AD" : "STC12C5A08S2";
    config.transport = "link1d";
    config.image = (root / "lower.hex").string();
    if (stc89) config.options["xram_enabled"] = "false";
    else config.options["watchdog_prescale"] = "32";
    if (invalid_ack) {
        try {
            run(config, wire);
            throw std::logic_error("bad prepare ACK was accepted");
        } catch (const std::runtime_error& error) {
            check(std::string(error.what()).find("prepare flash") != std::string::npos, "wrong failure stage");
        }
    } else {
        run(config, wire);
    }
    const auto trace = commands(wire);
    check_envelope(trace, !invalid_ack, !stc89 && !compact, true);
    const auto target = target_commands(trace);
    check(target.size() == (invalid_ack ? 2u : 5u), "wrong upgraded command count");
    const uint8_t h = stc89 || compact ? 0x46 : 0x5A;
    const uint8_t l = stc89 || compact ? 0xB9 : 0xA5;
    check(target[0] == (stc89 ? Bytes{1, 0xFF, 0xEE, 0x82} : Bytes{1, 0xC0, 0xDC, 0x83}) &&
          target[1] == Bytes{5, 0, 0, h, l}, "wrong upgraded baud/prepare");
    check(std::none_of(trace.begin(), trace.end(), [](const auto& frame) { return frame.code == 0x4D; }),
          "upgraded BSL used the old probe baud command");
    check(std::count_if(trace.begin(), trace.end(), [](const auto& frame) {
        return frame.code == 0x40 && frame.data == Bytes{2, 16, 1};
    }) == 1, "upgraded BSL did not switch the probe to the new baud and even parity");
    if (invalid_ack) return;
    check(target[2] == Bytes{3, 0, 0, h, l}, "wrong upgraded erase");
    Bytes write{0x22, 0, 0, static_cast<uint8_t>(stc89 ? h : 0),
                static_cast<uint8_t>(stc89 ? l : 0), 2, 0, 0};
    check(target[3] == write, "wrong upgraded write block");
    if (stc89) check(target[4] == Bytes{4, 0, 0, h, l, 0xB9}, "wrong upgraded STC89 option packet");
    else if (compact) check(target[4] == Bytes{4, 0, 0, h, l, 0, 0xA8, 0xC0, 0, 0xE7, 0xDC, 0xBF, 0x7F},
                            "wrong upgraded compact STC12 option packet");
    else check(target[4] == Bytes{4, 0, 0, h, l, 0, 0xA8, 0xC0, 0, 0xE7, 0xDC, 0xBF, 0x7F},
               "wrong upgraded STC12 option packet");
}

void upgraded_stc12_eeprom_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xD164, 0x50, 31);
    status[13] = 0x12;
    status[16] = 0x10;  // Active 4 KiB program partition, not the nominal 8 KiB.
    status[17] = 0x75;
    wire.replies = {report({0x51}), report(status), report({1}), report({5}),
                    report({3, 1, 2, 3, 4, 5, 6, 7}), report({2, 0x54}), report({2, 0x54})};
    Config config;
    config.model = "STC12C5A08S2";
    config.transport = "link1d";
    config.image = (root / "stc15-eeprom.hex").string();
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 5, "wrong upgraded STC12 EEPROM sequence");
    check(target[2] == Bytes{3, 2, 0, 0x5A, 0xA5},
          "upgraded STC12 must erase two sectors past the active partition");
    check(target[3].size() == 133 && target[3][0] == 0x22 &&
          target[4] == Bytes{2, 0x12, 0, 0, 0, 0x42},
          "wrong upgraded STC12 mixed program/EEPROM blocks");
}

void stc12_eeprom_fill_test(const std::filesystem::path& root, uint8_t fill) {
    Wire wire;
    auto status = mcu(0xE061, 0x50, 31);
    status[13] = 0x12;
    status[16] = 0x04;
    status[17] = 0x75;
    wire.replies = {report({0x51}), report(status), report({1}), report({5}), report({3}),
                    report({2, 0x54})};
    constexpr size_t eeprom_size = 0x6C00;
    if (fill == 0)
        for (size_t i = 0; i < eeprom_size / 128; ++i) wire.replies.push_back(report({2, 0x54}));
    Config config;
    config.model = "STC12C5401AD";
    config.transport = "link1d";
    config.image = (root / "lower.hex").string();
    config.options = {{"modify_hardware_options", "false"},
                      {fill == 0 ? "eeprom_fill_zero" : "eeprom_fill_ff", "true"}};
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target[2] == Bytes{3, 0x36, 0, 0x46, 0xB9}, "EEPROM fill requested the wrong erase size");
    check(target.size() == 4 + (fill == 0 ? eeprom_size / 128 : 0),
          "EEPROM fill wrote the wrong number of blocks");
    if (fill == 0) {
        for (size_t i = 0; i < eeprom_size / 128; ++i) {
            const auto address = 0x400 + i * 128;
            Bytes expected{2, static_cast<uint8_t>(address >> 8), static_cast<uint8_t>(address), 0, 0};
            expected.resize(133, 0);
            check(target[i + 4] == expected, "EEPROM fill wrote outside the model's EEPROM area");
        }
    }
}

void stc15_test(const std::filesystem::path& root, uint8_t version, bool timer1, bool irc15 = true) {
    Wire wire;
    auto status = mcu(!irc15 ? 0xF294 : timer1 ? 0xF44A : 0xF2A6);
    status[4] = 0x65;
    status[13] = irc15 ? 0xFB : 0x12;
    status[14] = irc15 ? 0x80 : 0x00;
    status[16] = irc15 ? 0x1C : 0x10;
    status[17] = version;
    wire.replies = {report({0x51}), report(status), report({1})};
    if (!irc15) wire.replies.push_back(report({5}));
    wire.replies.push_back(report({3}));
    wire.replies.push_back(report({2, 0x54}));
    if (version < 0x72) wire.replies.push_back(report({2, 0x54}));
    wire.replies.push_back(report({2, 0x54}));
    Config config;
    config.transport = "link1d";
    config.model = !irc15 ? "STC15F104E" : timer1 ? "IRC15F2K63S2" : "IRC15W107";
    config.image = (root / "h8-multiblock.hex").string();
    run(config, wire);
    const auto trace = commands(wire);
    check_envelope(trace, true, true, true);
    const auto target = target_commands(trace);
    const Bytes initial = !irc15 ? Bytes{1, 0x65, 0x40, 0xFD, 0xC0, 0xFC, 0xA0, 0x83}
        : timer1 ? Bytes{1, 0, 0, 0xFF, 0x70, 0, 0, 0x83}
                 : Bytes{1, 0, 0, 0xFD, 0xC0, 0xFC, 0xA0, 0x83};
    const size_t erase_index = irc15 ? 1 : 2;
    check(target.size() == erase_index + (version < 0x72 ? 4u : 3u) && target[0] == initial,
          "incorrect STC15 sequence or baud packet");
    if (!irc15) check(target[1] == Bytes{5, 0, 0, 0x5A, 0xA5}, "wrong STC15 prepare packet");
    check(target[erase_index] == (version < 0x72 ? Bytes{3, 0} : Bytes{3, 0, 0, 0x5A, 0xA5}),
          "wrong STC15 erase packet");
    const auto block = [&](uint8_t offset) {
        Bytes header{static_cast<uint8_t>(irc15 || offset ? 2 : 0x22), 0, offset};
        if (version >= 0x75) header.insert(header.end(), {0, 0});
        else if (version >= 0x72) header.insert(header.end(), {0x5A, 0xA5});
        return header;
    };
    auto first = block(0);
    first.insert(first.end(), {2, 0, 0});
    first.insert(first.end(), 61, 0xFF);
    auto tail = block(0x80);
    tail.push_back(0x42);
    check(target[erase_index + 1] == first && target.back() == tail, "wrong STC15 first or final block");
    if (version < 0x72) {
        auto blank = block(0x40);
        blank.insert(blank.end(), 64, 0xFF);
        check(target[3] == blank, "old IRC15 BSL must receive blank blocks");
    }
}

void legacy_stc15_test(const std::filesystem::path& root, bool link1d, uint8_t version) {
    Wire wire;
    const bool old = version < 0x71;
    auto status = mcu(0xF294);
    status[3] = old ? 0x0A : 0;
    status[4] = old ? 0x80 : 0x65;
    status[13] = 0x12;
    status[17] = version;
    status[27] = 0x65;
    const auto reply = [&](const Bytes& payload) {
        wire.replies.push_back(link1d ? report(payload) : uart_reply(payload));
    };
    if (link1d) wire.replies.push_back(report({0x51}));
    reply(status);
    if (old) reply({0x8F});
    reply({0x84});
    if (!old) reply({5});
    for (const Bytes& payload : {Bytes{0, 1, 2, 3, 4, 5, 6, 7},
                                 Bytes{0, 0xC5}, Bytes{0, 0xC0}, Bytes{0, 0x42}, Bytes{0x8D}})
        reply(payload);
    Config config;
    config.transport = link1d ? "link1d" : "serial";
    config.port = "COM8";
    config.model = "STC15F104E";
    config.image = (root / "h8-multiblock.hex").string();
    run(config, wire);
    std::vector<Bytes> target;
    if (link1d) {
        const auto trace = commands(wire);
        check_envelope(trace, true, true, true);
        check(std::any_of(trace.begin(), trace.end(), [](const auto& cmd) { return cmd.code == 0x4D; }),
              "missing STC15 legacy Link1D switch");
        target = target_commands(trace);
    } else {
        check(wire.baud_rates == std::vector<int>{19200}, "wrong legacy STC15 serial baud");
        for (const auto& frame : wire.writes)
            if (frame.size() >= 8 && frame[0] == 0x46)
                target.emplace_back(frame.begin() + 5, frame.end() - 3);
        check(target.size() >= 2 && target[target.size() - 2] == Bytes{0xFF} &&
              target.back() == Bytes{0x82}, "missing legacy STC15 exit");
        target.resize(target.size() - 2);
    }
    check(target.size() == 7 && target[6] == Bytes{0x69, 0, 0, 0x36, 1, 0xF2, 0x94},
          "wrong legacy STC15 command sequence");
    if (old) {
        Bytes erase{0x84, 0xFF, 0, 0, 0x81, 0, 0x10, 0};
        erase.resize(19, 0);
        for (uint8_t value = 0x80; value >= 0x5F; --value) erase.push_back(value);
        check(target[0] == Bytes{0x50, 0, 0, 0x36, 1, 0xF2, 0x94} &&
              target[1] == Bytes{0x8E, 0x58, 0x65, 0x06, 0xA0, 0x64, 0xDB, 0xFF, 0x83, 0x20, 0xFF, 0} &&
              target[2] == erase, "wrong STC15 pre-7.1 prepare, speed or erase payload");
    } else {
        check(target[0] == Bytes{1, 0x65, 0x40, 0xFD, 0xC0, 0xFC, 0xA0, 0x83} &&
              target[1] == Bytes{5} && target[2] == Bytes{3, 0}, "wrong STC15 7.1 command sequence");
    }
    Bytes first{0, 0, 0, 0, 0, 0, 64, 2, 0, 0};
    first.resize(71, 0xFF);
    Bytes blank{0, 0, 0, 0, 0x40, 0, 64};
    blank.resize(71, 0xFF);
    check(target[3] == first && target[4] == blank &&
          target[5] == Bytes{0, 0, 0, 0, 0x80, 0, 1, 0x42}, "wrong legacy STC15 block data");
}

void stc15e_dynamic_irc_test(const std::filesystem::path& root, uint8_t version, bool fast = false) {
    Wire wire;
    auto status = mcu(0xF294, 0x50, 58);
    status[3] = 0x0A;
    status[4] = 0x80;
    status[5] = 0xD7;
    status[6] = 0xE7;
    status[7] = 0xFF;
    status[12] = 0xFC;
    status[13] = 0x12;
    status[17] = version;
    status[27] = 0x65;
    const Bytes seed{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE};
    std::copy(seed.begin(), seed.end(), status.begin() + 51);
    Bytes coarse(12, 0);
    coarse[0] = 0x65;
    const uint8_t transfer_band = fast ? 0x98 : 0x58;
    const Bytes stats{0x98, 0, 0x12, 0xC0, 0x98, 0x80, 0x19, 0, 0x98, 0x80, 0x1F, 0x40,
        0x98, 0xB4, 0x25, 0x1C, transfer_band, 0, 7, 0xD0, transfer_band, 0x65, 0x0A, 0x71};
    coarse.insert(coarse.end(), stats.begin(), stats.end());
    Bytes fine(12, 0);
    fine[0] = 0x65;
    for (unsigned i = 0; i < 11; ++i) {
        const auto count = 5789 + 5 * i;
        fine.insert(fine.end(), {0x98, static_cast<uint8_t>(0x4C + i),
            static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
    }
    wire.replies = {report({0x51}), report(status)};
    if (version < 0x71) wire.replies.push_back(report({0x8F}));
    wire.replies.push_back(report(coarse));
    wire.replies.push_back(report(fine));
    wire.replies.push_back(report({static_cast<uint8_t>(version < 0x72 ? 0x84 : 1)}));
    if (version >= 0x71) wire.replies.push_back(report({5}));
    wire.replies.push_back(report({static_cast<uint8_t>(version < 0x72 ? 0 : 3)}));
    wire.replies.push_back(report(version < 0x72 ? Bytes{0, 2} : Bytes{2, 0x54}));
    if (version == 0x71) wire.replies.push_back(report({0x8D}));
    wire.replies.push_back(report(version < 0x72 ? Bytes{0x50} : Bytes{4, 0x54}));
    Config config;
    config.transport = "link1d";
    config.model = "STC15F104E";
    config.image = (root / "lower.hex").string();
    config.options = {{"irc_adjust_enabled", "true"}, {"irc_hz", "24000000"}, {"por_reset_delay_long", "true"}};
    config.options["fast_download_enabled"] = fast ? "true" : "false";
    run(config, wire);
    const auto target = target_commands(commands(wire));
    const size_t index = version < 0x71 ? 1 : 0;
    Bytes prefix{0x65, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF, 0xFF, 6};
    auto coarse_probe = prefix;
    const Bytes coarse_body{6, 0x98, 0, 2, 0, 0x98, 0x80, 2, 0, 0x98, 0x80, 2, 0,
        0x98, 0xFF, 2, 0, transfer_band, 0, 2, 0, transfer_band, 0x80, 2, 0};
    coarse_probe.insert(coarse_probe.end(), coarse_body.begin(), coarse_body.end());
    auto fine_probe = prefix;
    fine_probe.push_back(11);
    for (uint8_t trim = 0x4C; trim <= 0x56; ++trim)
        fine_probe.insert(fine_probe.end(), {0x98, trim, 2, 0});
    check(target.at(index) == coarse_probe && target.at(index + 1) == fine_probe,
          "STC15E IRC probes differ from original sender");
    check(target.at(index + 2).at(version < 0x71 ? 2 : 1) == 0x65,
          "STC15E measured ISP trim was not passed to baud negotiation");
    Bytes options;
    if (version < 0x71) {
        options = {0x8D, 0xFF, 0xE7, 0xD7, 0x98, 0x51, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    } else {
        options = version < 0x72 ? Bytes{4, 0, 0} : Bytes{4, 0, 0, 0x5A, 0xA5};
        Bytes body(64, 0xFF);
        body[3] = body[6] = body[22] = 0;
        for (unsigned i = 0; i < 4; ++i) body[23 + 2 * i] = static_cast<uint8_t>(24'000'942u >> (24 - 8 * i));
        body[31] = 0xFC;
        body[59] = 0x51;
        body[60] = 0xBF;
        body[61] = 0xD7;
        body[62] = 0xE7;
        options.insert(options.end(), body.begin(), body.end());
    }
    check(target.back() == options, "STC15E measured hardware packet differs from original sender");
}

void legacy_irc15_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xF3B6);
    status[3] = 0x0A;
    status[4] = 0x80;
    status[17] = 0x65;
    status[27] = 0x65;
    wire.replies = {report({0x51}), report(status), report({0x0E}), report({4}), report({2, 0x54})};
    Config config;
    config.transport = "link1d";
    config.model = "IRC15F207A";
    config.image = (root / "lower.hex").string();
    run(config, wire);
    const auto target = target_commands(commands(wire));
    check(target.size() == 3, "unexpected legacy IRC15 sequence");
    check(target[0] == Bytes{0x8E, 0x58, 0x65, 6, 0xA0, 0x64, 0xDB, 0xFF, 0x83, 0x20, 0xFF, 0},
          "wrong legacy IRC15 baud packet");
    check(target[1].size() == 53 && target[1][0] == 0x84 && target[1][4] == 3 &&
          target[1][6] == 0x1C && target[1].back() == 0x5F, "wrong legacy IRC15 erase");
    check(target[2] == Bytes{2, 0, 0, 2, 0, 0}, "wrong legacy IRC15 write");
}

void legacy_stc15_eeprom_test(const std::filesystem::path& root) {
    Wire wire;
    auto status = mcu(0xF294);
    status[3] = 0x0A;
    status[4] = 0x80;
    status[17] = 0x65;
    status[27] = 0x65;
    wire.replies = {report({0x51}), report(status), report({0x8F}), report({0x84}),
                    report({0, 1, 2, 3, 4, 5, 6, 7}), report({0, 0xC5})};
    for (unsigned offset = 64; offset < 0x1200; offset += 64)
        wire.replies.push_back(report({0, 0xC0}));
    wire.replies.push_back(report({0, 0x42}));
    wire.replies.push_back(report({0x8D}));
    Config config;
    config.transport = "link1d";
    config.model = "STC15F104E";
    config.image = (root / "stc15-eeprom.hex").string();
    run(config, wire);
    const auto target = target_commands(commands(wire));
    const Bytes erase_prefix{0x84, 0xFF, 0, 0x12, 1, 0, 0x10, 0};
    check(std::equal(erase_prefix.begin(), erase_prefix.end(), target.at(2).begin()),
          "legacy STC15 erase extent does not include EEPROM");
    check(target.end()[-2] == Bytes{0, 0, 0, 0x12, 0, 0, 1, 0x42},
          "wrong legacy STC15 EEPROM write");
}

void safety_tests() {
    Wire unsupported;
    unsupported.replies = {report({0x51}), report(mcu(0xF78F))};
    Config config;
    config.transport = "link1d";
    config.erase_only = true;
    try {
        stcisp::Programmer(config, std::make_unique<Fake>(unsupported)).run();
        throw std::logic_error("unsupported target was not rejected");
    } catch (const std::invalid_argument& error) {
        check(std::string(error.what()).find("not implemented") != std::string::npos, "wrong rejection");
    }
    const auto failed = commands(unsupported);
    check_envelope(failed, false, true, false);
    check(target_commands(failed).empty() && unsupported.closed, "unsupported target received ISP commands");

    Wire legacy_new_bsl;
    auto bad_clock = mcu(0xF002, 0, 23);
    bad_clock[16] = 0x20;
    legacy_new_bsl.replies = {report({0x51}), report(bad_clock)};
    try {
        stcisp::Programmer(config, std::make_unique<Fake>(legacy_new_bsl)).run();
        throw std::logic_error("missing clock measurement was not rejected");
    } catch (const std::invalid_argument& error) {
        check(std::string(error.what()).find("target clock") != std::string::npos, "wrong clock rejection");
    }
    check(target_commands(commands(legacy_new_bsl)).empty(), "write commands sent despite invalid clock");

    Wire unported_options;
    auto stc12 = mcu(0xD164, 0x50, 23);
    stc12[17] = 0x58;
    unported_options.replies = {report({0x51}), report(stc12)};
    Config overwrite;
    overwrite.transport = "link1d";
    overwrite.model = "STC12C5A08S2";
    overwrite.options["cpu_mode"] = "32";
    overwrite.dry_run = true;
    try {
        stcisp::Programmer(overwrite, std::make_unique<Fake>(unported_options)).run();
        throw std::logic_error("unsupported configuration write was accepted");
    } catch (const std::invalid_argument& error) {
        check(std::string(error.what()).find("hardware option write") != std::string::npos,
              "wrong hardware option rejection");
    }
    check(!unported_options.opened, "offline configuration opened a device");

    Wire invalid_simulation;
    Config unavailable;
    unavailable.model = "STC32G144K246";
    unavailable.make_simulation = true;
    unavailable.options["simulation_mode"] = "swd";
    try {
        stcisp::Programmer(unavailable, std::make_unique<Fake>(invalid_simulation)).run();
        throw std::logic_error("USB to SWD simulation should be rejected");
    } catch (const std::invalid_argument& error) {
        check(std::string(error.what()).find("requires serial or Link1D") != std::string::npos,
              "wrong simulation interface rejection");
    }
    check(!invalid_simulation.opened, "invalid simulation opened a device");
    for (const auto& [model, mode] : {std::pair{"AI8051U-34K64", "swd"},
                                      std::pair{"STC32G144K246", "uart"},
                                      std::pair{"AI8H2K02U", "uart"},
                                      std::pair{"STC89C52RC/LE52RC", "uart"},
                                      std::pair{"IAP15F2K61S2", "uart"}}) {
        Wire rejected;
        unavailable.transport = "serial";
        unavailable.port = "COM1";
        unavailable.model = model;
        unavailable.options["simulation_mode"] = mode;
        try {
            stcisp::Programmer(unavailable, std::make_unique<Fake>(rejected)).run();
            throw std::logic_error("unavailable simulation mode was accepted");
        } catch (const std::invalid_argument&) {}
        check(!rejected.opened, "unavailable simulation mode opened a device");
    }

    Wire failed_identity;
    failed_identity.replies = {report({0x51}, 7)};
    try {
        stcisp::Programmer(config, std::make_unique<Fake>(failed_identity)).run();
        throw std::logic_error("tool error was ignored");
    } catch (const std::runtime_error& error) {
        check(std::string(error.what()).find("tool error") != std::string::npos, "wrong identity error");
    }
    check(failed_identity.writes.size() == 1 && failed_identity.closed, "bad identity caused power commands");

    Wire manual;
    config.link1d_auto_power = false;
    config.port = "UART1";
    config.info_only = true;
    config.erase_only = false;
    manual.replies = {{0xFF}, uart_reply(mcu(0xF8D1))};
    run(config, manual);
    check(manual.writes.size() == 2 && manual.writes[0] == Bytes{0x7F} &&
          manual.writes[1][0] == 0x46, "manual power did not use UART only");
}

void catalogue_test() {
    const auto* old_variant = stcisp::find_model_by_magic(0xF294);
    const auto* new_variant = stcisp::find_model_by_magic(0xF294, 3);
    check(old_variant && old_variant->name == "STC15F104E", "wrong STC15E model variant");
    check(new_variant && new_variant->name == "STC15F104W", "wrong STC15W model variant");
    const auto& catalogue = stcisp::model_database();
    check(catalogue.size() == 1345, "incomplete model catalogue");
    check(std::count_if(catalogue.begin(), catalogue.end(), [](const auto& model) {
        return stcisp::supports_isp_write(model, true);
    }) == 1340, "UART write coverage changed");
    check(std::count_if(catalogue.begin(), catalogue.end(), [](const auto& model) {
        return stcisp::supports_isp_write(model, false);
    }) == 67, "USB write coverage changed");
    for (const auto& model : catalogue) {
        for (bool uart : {false, true}) {
            if (stcisp::isp_route(model, uart) == stcisp::IspRoute::f8d1)
                check(model.magic == 0xF8D1 && model.family == 89, "non-F8D1 routed to STC32");
            if (stcisp::isp_route(model, uart) == stcisp::IspRoute::modern_8bit_uart)
                check((model.flags & 0x1000) == 0 && model.code_size <= 0xFE00,
                      "extended-address model routed to 16-bit UART sender");
        }
    }
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 5 && std::string_view(argv[1]) == "--iap15-simulation") {
            iap15_simulation_test(argv[2], static_cast<uint8_t>(stcisp::parse_unsigned(argv[3], 255)),
                                  static_cast<uint16_t>(stcisp::parse_unsigned(argv[4], 65535)));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "--tool-controller") {
            tool_controller_test(argv[2], static_cast<uint8_t>(stcisp::parse_unsigned(argv[3], 255)));
            return 0;
        }
        if (argc == 6 && std::string_view(argv[1]) == "--uart-tool-controller") {
            uart_tool_controller_test(argv[2], static_cast<uint8_t>(stcisp::parse_unsigned(argv[3], 255)),
                                      static_cast<uint16_t>(stcisp::parse_unsigned(argv[4], 65535)),
                                      std::string_view(argv[5]) == "clear");
            return 0;
        }
        check(argc == 2, "missing fixture directory");
        const std::filesystem::path root(argv[1]);
        crypto_test();
        offline_upload_test();
        software_usb_test(root);
        serial_cold_start_test();
        link1d_keep_power_test(root);
        modern_test(root, false);
        modern_test(root, false, true);
        modern_test(root, true);
        modern_test(root, false, false, true);
        modern_test(root, true, false, true, true);
        modern_test(root, false, false, false, false, true);
        modern_8bit_uart_test(root, true);
        modern_8bit_uart_test(root, false);
        modern_8bit_uart_test(root, true, 0xF784, 0x75, 921600);
        fixed_63k_partition_test(root);
        modern_8bit_uart_test(root, true, 0x7891, 0x74);
        modern_8bit_uart_test(root, true, 0xF784, 0x72);
        modern_8bit_uart_test(root, false, 0xF621, 0x72);
        modern_8bit_uart_test(root, true, 0x7701, 0x73);
        modern_8bit_uart_test(root, false, 0xF621, 0x65);
        modern_8bit_uart_test(root, true, 0x78A1);
        modern_8bit_uart_test(root, false, 0xF8A8);
        modern_8bit_uart_test(root, true, 0x7701);  // AI8C
        modern_8bit_uart_test(root, false, 0x7721); // AI8H
        modern_8bit_uart_test(root, true, 0x7819);  // AI8H LCD
        modern_8bit_uart_test(root, false, 0xF621); // STC8A
        modern_8bit_uart_test(root, true, 0xF601);  // STC15H
        older_irc_download_test(root, false);
        older_irc_download_test(root, true);
        older_irc_download_test(root, true, true);
        older_irc_download_test(root, true, true, true);
        uart_password_order_test(root, 0x72, 1);
        uart_password_order_test(root, 0x73, 2);
        legacy_test(root, 0xF002, "STC89C52RC");
        legacy_test(root, 0xF022, "STC90C52RC");
        legacy_test(root, 0xFFFF, "STC89C516RD", true);
        stc12_test(root, false);
        stc12_test(root, true);
        legacy_stc12_mixed_test(root);
        make_simulation_test("link1d", true);
        make_simulation_test("serial", true);
        make_simulation_test("usb", false);
        make_other_simulation_test("STC8A8K08S4A12", 0xF621, "serial", "uart", "", 0xFF, 0xFF, 0xFF);
        make_other_simulation_test("STC8H3K16S4", 0xF741, "serial", "uart", "", 0xFF, 0xFF, 0xFF);
        make_other_simulation_test("STC8H8K64U", 0xF784, "link1d", "uart", "p1.6-p1.7", 0xFF, 0xBF, 0xFC);
        make_other_simulation_test("STC8H8K64U", 0xF784, "usb", "usb", "", 0xFF, 0x1F, 0xFC);
        make_other_simulation_test("USB-2UART", 0xF78F, "usb", "usb", "", 0xFF, 0x1F, 0xFC);
        make_other_simulation_test("USB-2CDC+HID", 0xF89F, "usb", "usb", "", 0xFF, 0x1F, 0xFC);
        make_other_simulation_test("AI8051U-34K64", 0x78B4, "usb", "usb", "", 0x3F, 0x1F, 2);
        make_other_simulation_test("AI32G12K128", 0x77E3, "link1d", "swd", "p1.6-p1.7", 0x9F, 0x3F, 1);
        make_other_simulation_test("AI32G12K128", 0x77E3, "serial", "uart", "p1.6-p1.7", 0x3F, 0xBF, 1);
        make_other_simulation_test("AI32G12K128", 0x77E3, "usb", "usb", "", 0x3F, 0x1F, 1);
        make_other_simulation_test("STC8A8K08S4A12", 0xF621, "serial", "uart", "", 0xFF, 0xFF, 0xFF, 0xFF, 0x71);
        make_other_simulation_test("STC8H8K64U", 0xF784, "link1d", "uart", "p1.6-p1.7", 0xFF, 0xBF, 0xFC, 0xFF, 0x73);
        make_other_simulation_test("AI32F12K54", 0x7874, "serial", "swd", "p3.6-p3.7", 0x5F, 0x3F, 0xD0, 1);
        ai8051_usb_test(root);
        ai8051_usb_test(root, true);
        ai8051_usb_test(root, true, 13);
        ai8051_usb_test(root, false, 12, true);
        usb_live_irc_test(root, false);
        usb_live_irc_test(root, true);
        usb_live_irc_test(root, false, true);
        for (const bool usb : {false, true}) {
            download_options_test(root, true, usb);
            download_options_test(root, false, usb);
            user_key_test(root, usb);
            uid_allowlist_test(root, usb, true);
            uid_allowlist_test(root, usb, false);
            encrypted_download_test(root, usb);
            uid_binding_test(root, usb);
        }
        stc8u_usb_test(root, 0xF784, 0x74);
        stc8u_usb_test(root, 0x7891, 0x74);
        stc8u_usb_test(root, 0x78A1, 0x75);
        stc8u_usb_test(root, 0xF8A8, 0x75);
        h8_info_test();
        stc89_selector_one_serial_test(root);
        upgraded_legacy_test(root, true);
        upgraded_legacy_test(root, false);
        upgraded_legacy_test(root, false, true);
        upgraded_legacy_test(root, false, false, true);
        upgraded_stc12_eeprom_test(root);
        stc12_eeprom_fill_test(root, 0x00);
        stc12_eeprom_fill_test(root, 0xFF);
        stc15_test(root, 0x71, false);
        legacy_stc15_test(root, true, 0x71);
        legacy_stc15_test(root, false, 0x71);
        legacy_stc15_test(root, true, 0x66);
        legacy_stc15_test(root, false, 0x60);
        legacy_stc15_test(root, false, 0x62);
        legacy_stc15_test(root, false, 0x70);
        legacy_irc15_test(root);
        for (uint8_t version : {0x66, 0x71, 0x72}) stc15e_dynamic_irc_test(root, version);
        stc15e_dynamic_irc_test(root, 0x72, true);
        legacy_stc15_eeprom_test(root);
        stc15_test(root, 0x72, false);
        stc15_test(root, 0x75, true);
        stc15_test(root, 0x72, false, false);
        stc15_test(root, 0x75, false, false);
        stc15_selector3_test(root, "STC15F100W", 0xF290, false, 0x71);
        stc15_selector3_test(root, "STC15F2K08S2", 0xF401, true, 0x61, false, std::nullopt, 19200, true);
        stc15_selector3_test(root, "STC15F100W", 0xF290, false, 0x71, false, std::nullopt, 115200);
        stc15_selector3_test(root, "STC15F2K08S2", 0xF401, true, 0x72);
        stc15_selector3_test(root, "STC15F100W", 0xF290, false, 0x71, true);
        stc15_selector3_test(root, "STC15F2K08S2", 0xF401, true, 0x72, true);
        stc15_selector3_test(root, "STC15F2K08S2", 0xF401, true, 0x72, true, false);
        stc15_selector3_test(root, "STC15F2K08S2", 0xF401, true, 0x72, true, true);
        stc15_dynamic_irc_test(root);
        append_test_parameters_test(root, false);
        append_test_parameters_test(root, true);
        ai32_bank_test(root, false);
        ai32_bank_test(root, true);
        ai32_bank_test(root, false, true, 0x75, true);
        ai32_bank_test(root, true, true, 0x75, true);
        ai32_bank_test(root, true, false);
        ai32_bank_test(root, true, true, 0x74);
        ai32_bank_test(root, false, true, 0x74, false, false, 12, true);
        ai32_bank_test(root, true, true, 0x74, false, false, 12, true);
        ai32_bank_test(root, true, true, 0x74, false, false, 13);
        ai32_preflight_test(root);
        ai32_eeprom_test(root);
        ai32_bank_test(root, false, false, 0x75, false, true);
        ai32_bank_test(root, true, false, 0x75, false, true);
        ai16_beta_test(root, false);
        ai16_beta_test(root, true);
        eeprom_suffix_test(root, false);
        eeprom_suffix_test(root, true);
        eeprom_suffix_test(root, true, 0x7891);
        safety_tests();
        catalogue_test();
        parser_tests(root);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
