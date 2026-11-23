#include "stcisp/isp.hpp"
#include "stcisp/database.hpp"
#include "utf8_path.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace stcisp {

uint32_t parse_unsigned(const std::string& value, uint32_t max) {
    uint32_t result = 0;
    const bool hex = value.starts_with("0x") || value.starts_with("0X");
    const auto end = value.data() + value.size();
    const auto [ptr, error] = std::from_chars(value.data() + (hex ? 2 : 0), end, result, hex ? 16 : 10);
    if (error != std::errc{} || ptr != end || result > max)
        throw std::invalid_argument("invalid unsigned integer: " + value);
    return result;
}

bool parse_config_bool(const std::string& value) {
    if (value == "true") return true;
    if (value == "false") return false;
    throw std::invalid_argument("expected true or false, got '" + value + "'");
}

namespace {

std::string trim(std::string value) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(),
                                            [&](unsigned char ch) { return !is_space(ch); }));
    value.erase(std::find_if(value.rbegin(), value.rend(),
                             [&](unsigned char ch) { return !is_space(ch); }).base(),
                value.end());
    return value;
}

std::string unquote(std::string value) {
    value = trim(std::move(value));
    if (value.size() >= 2 &&
        ((value.front() == '"' && value.back() == '"') ||
         (value.front() == '\'' && value.back() == '\''))) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

size_t comment_start(const std::string& line) {
    char quote = 0;
    for (size_t index = 0; index < line.size(); ++index) {
        const char ch = line[index];
        if (quote == '"' && ch == '\\') { ++index; continue; }
        if (quote) {
            if (ch == quote) quote = 0;
        } else if (ch == '"' || ch == '\'') {
            quote = ch;
        } else if (ch == '#') {
            return index;
        }
    }
    return std::string::npos;
}

void set_value(Config& config, const std::string& key, const std::string& raw_value,
               const std::string& section) {
    const std::string value = unquote(raw_value);
    const std::string full_key = section.empty() ? key : section + "." + key;
    if (full_key == "model") config.model = value;
    else if (full_key == "image") config.image = value;
    else if (full_key == "offline_image") config.offline_image = value;
    else if (full_key == "offline_auxiliary") config.offline_auxiliary = value;
    else if (full_key == "offline_resources") config.offline_resources = value;
    else if (full_key == "offline_profile") config.offline_profile = value;
    else if (full_key == "offline_output") config.offline_output = value;
    else if (full_key == "tool_resources") config.tool_resources = value;
    else if (full_key == "simulation_resources") config.simulation_resources = value;
    else if (full_key == "make_tool") config.make_tool = parse_config_bool(value);
    else if (full_key == "encrypted_image") config.encrypted_image = parse_config_bool(value);
    else if (full_key == "if") config.transport = value;
    else if (full_key == "link1d_auto_power") config.link1d_auto_power = parse_config_bool(value);
    else if (full_key == "link1d_keep_power") config.link1d_keep_power = parse_config_bool(value);
    else if (full_key == "port") config.port = value;
    else if (full_key == "device_path") config.device_path = value;
    else if (full_key == "handshake_baud") config.handshake_baud = static_cast<int>(parse_unsigned(value, INT32_MAX));
    else if (full_key == "baud") config.baud = static_cast<int>(parse_unsigned(value, INT32_MAX));
    else if (full_key == "timeout_ms") config.timeout_ms = static_cast<int>(parse_unsigned(value, INT32_MAX));
    else if (full_key == "password") config.password = value;
    else if (full_key == "next_password") config.next_password = value;
    else if (full_key == "user_key_file") config.user_key_file = value;
    else if (full_key == "uid_allowlist") config.uid_allowlist = value;
    else if (full_key == "reset_command") config.reset_command = value;
    else if (full_key == "reset_transport") config.reset_transport = value;
    else if (full_key == "reset_port") config.reset_port = value;
    else if (full_key == "reset_baud") config.reset_baud = static_cast<int>(parse_unsigned(value, INT32_MAX));
    else if (full_key == "reset_parity") config.reset_parity = value;
    else if (full_key == "reset_stop_bits") config.reset_stop_bits = static_cast<int>(parse_unsigned(value, 2));
    else if (full_key == "reset_dtr") config.reset_dtr = parse_config_bool(value);
    else if (full_key == "reset_rts") config.reset_rts = parse_config_bool(value);
    else if (full_key == "reset_vid") config.reset_vid = static_cast<uint16_t>(parse_unsigned(value, UINT16_MAX));
    else if (full_key == "reset_pid") config.reset_pid = static_cast<uint16_t>(parse_unsigned(value, UINT16_MAX));
    else if (full_key == "dry_run") config.dry_run = parse_config_bool(value);
    else if (full_key == "erase_only") config.erase_only = parse_config_bool(value);
    else if (full_key == "erase_offline") config.erase_offline = parse_config_bool(value);
    else if (full_key == "make_simulation") config.make_simulation = parse_config_bool(value);
    else if (full_key == "info" || full_key == "info_only") config.info_only = parse_config_bool(value);
    else if (full_key == "verbose") config.verbose = parse_config_bool(value);
    else if (section == "uid_bind") {
        const auto address = parse_unsigned(unquote(key), 0xFFFFF9);
        config.uid_bindings[address] = value;
    }
    else if (section == "hardware" || section == "options" ||
             full_key.rfind("hardware.", 0) == 0 ||
             full_key.rfind("options.", 0) == 0) {
        const auto dot = full_key.find('.');
        config.options[dot == std::string::npos ? full_key : full_key.substr(dot + 1)] = value;
    } else {
        throw std::invalid_argument("unknown configuration key: " + full_key);
    }
}

}  // namespace

Config load_config_file(const std::string& path) {
    std::ifstream input(utf8_path(path));
    if (!input) {
        throw std::runtime_error("cannot open config file: " + path);
    }
    Config config;
    std::string section;
    std::string line;
    size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (line_number == 1 && line.starts_with("\xEF\xBB\xBF")) line.erase(0, 3);
        const auto comment = comment_start(line);
        if (comment != std::string::npos) {
            line.resize(comment);
        }
        line = trim(std::move(line));
        if (line.empty()) continue;
        if (line.front() == '[' && line.back() == ']') {
            section = trim(line.substr(1, line.size() - 2));
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            throw std::invalid_argument("invalid config line " + std::to_string(line_number));
        }
        try {
            set_value(config, trim(line.substr(0, separator)),
                      trim(line.substr(separator + 1)), section);
        } catch (const std::exception& error) {
            throw std::invalid_argument("config line " + std::to_string(line_number) +
                                        ": " + error.what());
        }
    }
    return config;
}

void print_usage() {
    std::cout <<
        "stc-isp 0.1.1\n"
        "用法：stc-isp [--config file] [options]\n"
        "      stc-isp --encrypt-bin INPUT --key-file FILE --output OUTPUT\n\n"
        "连接与镜像：\n"
        "  --if usb|usb-soft|serial|link1d  ISP 接口，默认 usb；usb-soft 为软件 USB\n"
        "  --link1d-auto-power true|false  Link1D 自动断电上电，默认 true；false 时指定 UART1 的 --port\n"
        "  --link1d-keep-power true|false  Link1D 下载成功后持续供电，默认 true\n"
        "  --image file               Intel HEX 或 BIN 固件\n"
        "  --offline-image file       向离线编程器写入 5AA5 格式镜像（--if usb|serial）\n"
        "  --offline-resources dir    从此目录挑选离线编程器所需的 AiCube 辅助资源\n"
        "  --offline-auxiliary file   手动指定辅助资源，覆盖自动选择\n"
        "  --offline-profile file     生成离线镜像时导入的 AiCube 硬件配置 .cfg\n"
        "  --offline-output file      从 --image 生成离线编程器镜像，不连接设备\n"
        "  --erase-offline            清除离线编程器存储的程序和辅助数据，不擦目标芯片\n"
        "  --make-tool                制作工具主控：USB-Link1D / USB-Writer1 用 HID，U7 / U8 / U8W 用串口\n"
        "  --tool-resources dir       提供原始 AiCube 6.97C res65.bin 的目录\n"
        "  --encrypted-image         固件已加密，使用加密写块命令\n"
        "  --model name               指定型号\n"
        "  --device-path path         指定 USB HID 路径\n"
        "  --port COM3                串口 ISP 端口\n"
        "  --handshake-baud 2400     串口初始波特率\n"
        "  --baud 19200               串口切换波特率\n"
        "  --password text            当前下载口令\n"
        "  --next-password text       下一次下载口令\n"
        "  --user-key-file file       写入用户密钥（原始密钥表或 AiCube .k 文件）\n"
        "  --uid-allowlist file       仅向名单内的芯片写入程序；擦除后校验 UID\n"
        "  --uid-bind address=ops     将芯片 UID 写到固件地址，可重复最多四处\n"
        "  --option name=value        设置硬件选项，可重复\n"
        "  --erase-only               只执行擦除；擦除范围由芯片协议和当前配置决定\n"
        "  --make-simulation          制作仿真芯片，会擦除程序区；指定 --model 和 simulation_mode=uart|usb|swd\n"
        "  --simulation-resources dir  旧 IAP15 仿真需要的 AiCube 6.97C 资源目录\n"
        "  --info                    读取型号和硬件配置，不写 Flash；Link1D 默认会重新上电\n"
        "  --dry-run                  只校验配置和镜像，不发送写入帧\n"
        "  --reset-command value      下载前发送应用侧复位命令\n"
        "  --reset-transport hid|serial  应用侧复位通道，USB CDC 使用 serial\n"
        "  --reset-port COM3          应用侧 CDC/串口端口\n"
        "  --reset-baud 115200       应用侧复位波特率\n"
        "  --reset-parity none|even|odd\n"
        "  --reset-stop-bits 1|2     应用侧停止位\n"
        "  --reset-dtr true|false --reset-rts true|false\n"
        "  --reset-vid VID --reset-pid PID\n"
        "  --list-models              列出内置型号索引\n"
        "  --list-usb                 列出 STC USB ISP 设备\n"
        "  --list-link1d              列出 Link1D HID 设备\n"
        "  --verbose                  输出 ISP 原始帧\n";
}

}  // namespace stcisp
