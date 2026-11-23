#include "stcisp/database.hpp"
#include "stcisp/crypto.hpp"
#include "stcisp/isp.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {
void configure_console_encoding() {
#ifdef _WIN32
    // 所有中文消息都以 UTF-8 字节写入 std::cout/std::cerr。
    // 仅当输出连接到 Windows 控制台时切换代码页；重定向到文件或管道
    // 时不改变其原始字节流，便于保存为 UTF-8 文本。
    DWORD mode = 0;
    const bool output_is_console =
        GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) != FALSE;
    const bool error_is_console =
        GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode) != FALSE;
    if (output_is_console || error_is_console) {
        SetConsoleOutputCP(CP_UTF8);
    }
#endif
}

std::string next_value(int& index, int argc, char** argv, const char* option) {
    if (index + 1 >= argc) throw std::invalid_argument(std::string(option) + " requires a value");
    return argv[++index];
}

uint16_t parse_u16(const std::string& value) {
    return static_cast<uint16_t>(stcisp::parse_unsigned(value, UINT16_MAX));
}

int int_value(const std::string& value) {
    return static_cast<int>(stcisp::parse_unsigned(value, INT32_MAX));
}
void set_option(stcisp::Config& config, const std::string& value) {
    const auto separator = value.find('=');
    if (separator == std::string::npos || separator == 0) {
        throw std::invalid_argument("--option requires name=value");
    }
    config.options[value.substr(0, separator)] = value.substr(separator + 1);
}

void encrypt_bin(int argc, char** argv) {
    std::string output;
    std::string key_file;
    for (int index = 3; index < argc; ++index) {
        const std::string option = argv[index];
        if (option == "--output") output = next_value(index, argc, argv, "--output");
        else if (option == "--key-file") key_file = next_value(index, argc, argv, "--key-file");
        else throw std::invalid_argument("unknown --encrypt-bin argument: " + option);
    }
    if (argc < 3 || output.empty() || key_file.empty())
        throw std::invalid_argument("usage: --encrypt-bin INPUT --key-file FILE --output OUTPUT");
    stcisp::encrypt_binary_file(argv[2], output, key_file);
    std::cout << "已生成加密 BIN：" << output << '\n';
}
int run(int argc, char** argv) {
    configure_console_encoding();
    try {
        if (argc == 1) {
            stcisp::print_usage();
            return 2;
        }
        if (std::string(argv[1]) == "--encrypt-bin") {
            encrypt_bin(argc, argv);
            return 0;
        }
        std::string config_path;
        for (int index = 1; index < argc; ++index) {
            if (std::string(argv[index]) == "--config") config_path = next_value(index, argc, argv, "--config");
        }
        stcisp::Config config;
        if (!config_path.empty()) config = stcisp::load_config_file(config_path);
        for (int index = 1; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--help" || argument == "-h") {
                stcisp::print_usage();
                return 0;
            } else if (argument == "--config") {
                ++index;
            } else if (argument == "--model") config.model = next_value(index, argc, argv, "--model");
            else if (argument == "--image") config.image = next_value(index, argc, argv, "--image");
            else if (argument == "--offline-image") config.offline_image = next_value(index, argc, argv, "--offline-image");
            else if (argument == "--offline-auxiliary") config.offline_auxiliary = next_value(index, argc, argv, "--offline-auxiliary");
            else if (argument == "--offline-resources") config.offline_resources = next_value(index, argc, argv, "--offline-resources");
            else if (argument == "--offline-profile") config.offline_profile = next_value(index, argc, argv, "--offline-profile");
            else if (argument == "--offline-output") config.offline_output = next_value(index, argc, argv, "--offline-output");
            else if (argument == "--tool-resources") config.tool_resources = next_value(index, argc, argv, "--tool-resources");
            else if (argument == "--simulation-resources") config.simulation_resources = next_value(index, argc, argv, "--simulation-resources");
            else if (argument == "--make-tool") config.make_tool = true;
            else if (argument == "--encrypted-image") config.encrypted_image = true;
            else if (argument == "--if") config.transport = next_value(index, argc, argv, "--if");
            else if (argument == "--link1d-auto-power") {
                const auto value = next_value(index, argc, argv, "--link1d-auto-power");
                if (value != "true" && value != "false")
                    throw std::invalid_argument("--link1d-auto-power requires true or false");
                config.link1d_auto_power = value == "true";
            }
            else if (argument == "--link1d-keep-power") {
                const auto value = next_value(index, argc, argv, "--link1d-keep-power");
                if (value != "true" && value != "false")
                    throw std::invalid_argument("--link1d-keep-power requires true or false");
                config.link1d_keep_power = value == "true";
            }
            else if (argument == "--port") config.port = next_value(index, argc, argv, "--port");
            else if (argument == "--device-path") config.device_path = next_value(index, argc, argv, "--device-path");
            else if (argument == "--handshake-baud") config.handshake_baud = int_value(next_value(index, argc, argv, "--handshake-baud"));
            else if (argument == "--baud") config.baud = int_value(next_value(index, argc, argv, "--baud"));
            else if (argument == "--timeout-ms") config.timeout_ms = int_value(next_value(index, argc, argv, "--timeout-ms"));
            else if (argument == "--password") config.password = next_value(index, argc, argv, "--password");
            else if (argument == "--next-password") config.next_password = next_value(index, argc, argv, "--next-password");
            else if (argument == "--user-key-file") config.user_key_file = next_value(index, argc, argv, "--user-key-file");
            else if (argument == "--uid-allowlist") config.uid_allowlist = next_value(index, argc, argv, "--uid-allowlist");
            else if (argument == "--uid-bind") {
                const auto value = next_value(index, argc, argv, "--uid-bind");
                const auto separator = value.find('=');
                const auto address = stcisp::parse_unsigned(value.substr(0, separator), 0xFFFFF9);
                config.uid_bindings[address] = separator == std::string::npos ? "" : value.substr(separator + 1);
            }
            else if (argument == "--option" || argument == "--hardware-option")
                set_option(config, next_value(index, argc, argv, argument.c_str()));
            else if (argument == "--reset-command") config.reset_command = next_value(index, argc, argv, "--reset-command");
            else if (argument == "--reset-transport") config.reset_transport = next_value(index, argc, argv, "--reset-transport");
            else if (argument == "--reset-port") config.reset_port = next_value(index, argc, argv, "--reset-port");
            else if (argument == "--reset-baud") config.reset_baud = int_value(next_value(index, argc, argv, "--reset-baud"));
            else if (argument == "--reset-parity") config.reset_parity = next_value(index, argc, argv, "--reset-parity");
            else if (argument == "--reset-stop-bits") config.reset_stop_bits = int_value(next_value(index, argc, argv, "--reset-stop-bits"));
            else if (argument == "--reset-dtr") config.reset_dtr = stcisp::parse_config_bool(next_value(index, argc, argv, "--reset-dtr"));
            else if (argument == "--reset-rts") config.reset_rts = stcisp::parse_config_bool(next_value(index, argc, argv, "--reset-rts"));
            else if (argument == "--reset-vid") config.reset_vid = parse_u16(next_value(index, argc, argv, "--reset-vid"));
            else if (argument == "--reset-pid") config.reset_pid = parse_u16(next_value(index, argc, argv, "--reset-pid"));
            else if (argument == "--dry-run") config.dry_run = true;
            else if (argument == "--erase-only") config.erase_only = true;
            else if (argument == "--erase-offline") config.erase_offline = true;
            else if (argument == "--make-simulation") config.make_simulation = true;
            else if (argument == "--info" || argument == "--device-info") config.info_only = true;
            else if (argument == "--verbose") config.verbose = true;
            else if (argument == "--list-models") {
                stcisp::print_models();
                return 0;
            } else if (argument == "--list-usb") {
                stcisp::list_usb_devices();
                return 0;
            } else if (argument == "--list-link1d") {
                stcisp::list_link1d_devices();
                return 0;
            } else if (argument == "--version") {
                std::cout << "stc-isp 0.1.1\n";
                return 0;
            } else {
                throw std::invalid_argument("unknown argument: " + argument);
            }
        }
        return stcisp::Programmer(std::move(config)).run();
    } catch (const std::exception& error) {
        std::cerr << "stc-isp error: " << error.what() << "\n";
        return 1;
    }
}
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> values;
    values.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i],
                                               -1, nullptr, 0, nullptr, nullptr);
        if (!length) {
            std::cerr << "stc-isp error: invalid command-line encoding\n";
            return 2;
        }
        std::string value(length, '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i],
                                 -1, value.data(), length, nullptr, nullptr)) {
            std::cerr << "stc-isp error: cannot decode command line\n";
            return 2;
        }
        value.pop_back();
        values.push_back(std::move(value));
    }
    std::vector<char*> arguments;
    arguments.reserve(values.size());
    for (auto& value : values) arguments.push_back(value.data());
    return run(argc, arguments.data());
}
#else
int main(int argc, char** argv) {
    return run(argc, argv);
}
#endif
