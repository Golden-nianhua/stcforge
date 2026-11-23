#include "stcisp/isp.hpp"

#include <chrono>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <hidpi.h>
#include <string>
#include <vector>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef STC_ISP_HAVE_HIDAPI
#include <hidapi/hidapi.h>
#endif
#endif

namespace stcisp {
namespace {

constexpr uint16_t kVid = 0x34BF;
constexpr uint16_t kIspPid = 0x1001;
bool is_link1d_pid(uint16_t pid) { return pid == 0x1004 || pid == 0x1005; }
// 6.97C 44E5FA: standalone programming probes also use the 5A HID envelope.
bool is_offline_pid(uint16_t pid) { return is_link1d_pid(pid) || pid == 0x1003 || pid == 0xFF09 || pid == 0xFF0F; }

#ifdef _WIN32

std::wstring wide(const std::string& value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) throw std::runtime_error("cannot convert HID path to UTF-16");
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), length);
    return result;
}

std::string error_message(const char* operation) {
    const DWORD code = GetLastError();
    return std::string(operation) + " failed with Win32 error " + std::to_string(code);
}

std::vector<std::wstring> enumerate_windows_hid(bool link1d, uint16_t vid = kVid,
                                                uint16_t pid = kIspPid, bool offline = false) {
    GUID hid_guid{};
    HidD_GetHidGuid(&hid_guid);
    HDEVINFO info = SetupDiGetClassDevsW(&hid_guid, nullptr, nullptr,
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (info == INVALID_HANDLE_VALUE) throw std::runtime_error(error_message("SetupDiGetClassDevs"));
    std::vector<std::wstring> result;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(info, nullptr, &hid_guid, index, &interface_data)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            continue;
        }
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(info, &interface_data, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) continue;
        std::vector<uint8_t> storage(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(storage.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(info, &interface_data, detail, required,
                                              nullptr, nullptr)) continue;
        HANDLE handle = CreateFileW(detail->DevicePath, 0,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) continue;
        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(attributes);
        if (HidD_GetAttributes(handle, &attributes) &&
            attributes.VendorID == vid &&
            (offline ? is_offline_pid(attributes.ProductID) :
                link1d ? is_link1d_pid(attributes.ProductID) : attributes.ProductID == pid)) {
            if (!link1d) {
                result.emplace_back(detail->DevicePath);
            } else {
                PHIDP_PREPARSED_DATA parsed = nullptr;
                if (HidD_GetPreparsedData(handle, &parsed)) {
                    HIDP_CAPS caps{};
                    if (HidP_GetCaps(parsed, &caps) == HIDP_STATUS_SUCCESS &&
                        caps.InputReportByteLength == 65 && caps.OutputReportByteLength == 65)
                        result.emplace_back(detail->DevicePath);
                    HidD_FreePreparsedData(parsed);
                }
            }
        }
        CloseHandle(handle);
    }
    SetupDiDestroyDeviceInfoList(info);
    return result;
}

class WindowsHidTransport final : public Transport {
public:
    explicit WindowsHidTransport(std::string path, bool link1d = false, bool offline = false)
        : path_(std::move(path)), link1d_(link1d), offline_(offline) {}
    ~WindowsHidTransport() override { close(); }

    void open() override {
        if (handle_ != INVALID_HANDLE_VALUE) return;
        std::wstring path = (path_.empty() || link1d_) ? select_path() : wide(path_);
        handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error(error_message("CreateFile HID"));
        auto cleanup = [this] { close(); };
        PHIDP_PREPARSED_DATA preparsed = nullptr;
        if (!HidD_GetPreparsedData(handle_, &preparsed)) {
            cleanup();
            throw std::runtime_error(error_message("HidD_GetPreparsedData"));
        }
        HIDP_CAPS caps{};
        const NTSTATUS status = HidP_GetCaps(preparsed, &caps);
        HidD_FreePreparsedData(preparsed);
        if (status != HIDP_STATUS_SUCCESS) {
            cleanup();
            throw std::runtime_error("HidP_GetCaps failed");
        }
        input_length_ = caps.InputReportByteLength;
        output_length_ = caps.OutputReportByteLength;
        read_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        write_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!read_event_ || !write_event_) {
            cleanup();
            throw std::runtime_error(error_message("CreateEvent"));
        }
    }

    void close() noexcept override {
        if (read_event_) {
            CloseHandle(read_event_);
            read_event_ = nullptr;
        }
        if (write_event_) {
            CloseHandle(write_event_);
            write_event_ = nullptr;
        }
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    void write(const std::vector<uint8_t>& data) override {
        require_open();
        if (data.size() != 64) throw std::invalid_argument("ISP report must be 64 bytes");
        std::vector<uint8_t> report(output_length_, 0);
        if (output_length_ == data.size() + 1) {
            std::copy(data.begin(), data.end(), report.begin() + 1);
        } else if (output_length_ >= data.size()) {
            std::copy(data.begin(), data.end(), report.begin());
        } else {
            throw std::runtime_error("HID output report is shorter than 64 bytes");
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = write_event_;
        ResetEvent(write_event_);
        DWORD written = 0;
        if (!WriteFile(handle_, report.data(), static_cast<DWORD>(report.size()), &written, &overlapped)) {
            if (GetLastError() != ERROR_IO_PENDING) throw std::runtime_error(error_message("WriteFile HID"));
            if (WaitForSingleObject(write_event_, 2000) != WAIT_OBJECT_0 ||
                !GetOverlappedResult(handle_, &overlapped, &written, FALSE)) {
                const auto message = error_message("GetOverlappedResult HID write");
                CancelIoEx(handle_, &overlapped);
                GetOverlappedResult(handle_, &overlapped, &written, TRUE);
                throw std::runtime_error(message);
            }
        }
        if (written != report.size()) throw std::runtime_error("short USB HID output report");
    }

    std::vector<uint8_t> read(int timeout_ms) override {
        require_open();
        std::vector<uint8_t> report(input_length_, 0);
        OVERLAPPED overlapped{};
        overlapped.hEvent = read_event_;
        ResetEvent(read_event_);
        DWORD received = 0;
        if (!ReadFile(handle_, report.data(), static_cast<DWORD>(report.size()), &received, &overlapped)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                throw std::runtime_error(error_message("ReadFile HID"));
            }
            const DWORD wait = WaitForSingleObject(read_event_, static_cast<DWORD>(timeout_ms));
            if (wait != WAIT_OBJECT_0) {
                const auto message = error_message("WaitForSingleObject HID read");
                CancelIoEx(handle_, &overlapped);
                if (!GetOverlappedResult(handle_, &overlapped, &received, TRUE)) {
                    if (wait == WAIT_TIMEOUT && GetLastError() == ERROR_OPERATION_ABORTED)
                        throw TransportTimeout("USB HID read timeout");
                    throw std::runtime_error(message);
                }
            } else if (!GetOverlappedResult(handle_, &overlapped, &received, FALSE)) {
                throw std::runtime_error(error_message("GetOverlappedResult HID read"));
            }
        }
        if (link1d_ && (received != 65 || report[0] != 0))
            throw std::runtime_error("invalid Link1D HID report ID or length");
        if (received == 65 && report[0] == 0) {
            report.erase(report.begin());
            report.resize(64);
        } else if (received < 64) {
            throw std::runtime_error("short USB HID input report");
        } else {
            report.resize(64);
        }
        return report;
    }

private:
    std::wstring select_path() {
        const auto paths = enumerate_windows_hid(link1d_, kVid, kIspPid, offline_);
        const std::string device = offline_ ? "offline programmer HID" :
            link1d_ ? "Link1D HID" : "STC USB ISP (34BF:1001)";
        if (!path_.empty()) {
            const auto wanted = wide(path_);
            for (const auto& path : paths)
                if (CompareStringOrdinal(path.c_str(), -1, wanted.c_str(), -1, TRUE) == CSTR_EQUAL)
                    return path;
            throw std::runtime_error("--device-path is not a " + device + " interface");
        }
        if (paths.empty()) throw std::runtime_error("no " + device + " device found");
        if (paths.size() != 1) throw std::runtime_error("multiple " + device + " devices found, use --device-path");
        return paths.front();
    }
    void require_open() const {
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("USB HID is not open");
    }
    std::string path_;
    bool link1d_;
    bool offline_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    HANDLE read_event_ = nullptr;
    HANDLE write_event_ = nullptr;
    USHORT input_length_ = 64;
    USHORT output_length_ = 65;
};

class WindowsSerialTransport final : public Transport {
public:
    WindowsSerialTransport(std::string port, int baud, int timeout_ms, bool even_parity)
        : port_(std::move(port)), baud_(baud), timeout_ms_(timeout_ms), even_parity_(even_parity) {}
    ~WindowsSerialTransport() override { close(); }

    void open() override {
        if (handle_ != INVALID_HANDLE_VALUE) return;
        std::string name = port_;
        if (name.rfind("\\\\.\\", 0) != 0) name = "\\\\.\\" + name;
        handle_ = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error(error_message("CreateFile serial"));
        DCB dcb{};
        dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(handle_, &dcb)) fail("GetCommState");
        dcb.BaudRate = baud_;
        dcb.ByteSize = 8;
        dcb.Parity = even_parity_ ? EVENPARITY : NOPARITY;
        dcb.StopBits = ONESTOPBIT;
        dcb.fParity = even_parity_;
        dcb.fBinary = TRUE;
        dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = dcb.fDsrSensitivity = FALSE;
        dcb.fOutX = dcb.fInX = dcb.fErrorChar = dcb.fNull = dcb.fAbortOnError = FALSE;
        dcb.fDtrControl = DTR_CONTROL_DISABLE;
        dcb.fRtsControl = RTS_CONTROL_DISABLE;
        if (!SetCommState(handle_, &dcb)) fail("SetCommState");
        COMMTIMEOUTS timeouts{};
        timeouts.ReadIntervalTimeout = MAXDWORD;
        timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
        timeouts.ReadTotalTimeoutConstant = timeout_ms_;
        timeouts.WriteTotalTimeoutConstant = timeout_ms_;
        if (!SetCommTimeouts(handle_, &timeouts)) fail("SetCommTimeouts");
        PurgeComm(handle_, PURGE_RXCLEAR | PURGE_TXCLEAR);
    }
    void close() noexcept override {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }
    void set_baud(int baud) override {
        require_open();
        DCB dcb{};
        dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(handle_, &dcb)) fail("GetCommState");
        dcb.BaudRate = baud;
        if (!SetCommState(handle_, &dcb)) fail("SetCommState");
    }
    void write(const std::vector<uint8_t>& data) override {
        require_open();
        DWORD written = 0;
        if (!WriteFile(handle_, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) ||
            written != data.size()) fail("WriteFile serial");
    }
    std::vector<uint8_t> read(int timeout_ms) override {
        require_open();
        COMMTIMEOUTS timeouts{};
        if (!GetCommTimeouts(handle_, &timeouts)) fail("GetCommTimeouts");
        timeouts.ReadTotalTimeoutConstant = timeout_ms;
        if (!SetCommTimeouts(handle_, &timeouts)) fail("SetCommTimeouts");
        std::vector<uint8_t> result(512);
        DWORD received = 0;
        if (!ReadFile(handle_, result.data(), static_cast<DWORD>(result.size()), &received, nullptr))
            fail("ReadFile serial");
        if (received == 0) throw TransportTimeout("serial read timeout");
        result.resize(received);
        return result;
    }
private:
    [[noreturn]] void fail(const char* operation) {
        close();
        throw std::runtime_error(error_message(operation));
    }
    void require_open() const {
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("serial port is not open");
    }
    std::string port_;
    int baud_;
    int timeout_ms_;
    bool even_parity_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

#else

#ifdef STC_ISP_HAVE_HIDAPI
class PosixHidTransport final : public Transport {
public:
    explicit PosixHidTransport(std::string path, bool link1d = false, bool offline = false)
        : path_(std::move(path)), link1d_(link1d), offline_(offline) {}
    ~PosixHidTransport() override { close(); }
    void open() override {
        if (device_) return;
        if (hid_init() != 0) throw std::runtime_error("hid_init failed");
        hid_device_info* list = hid_enumerate(kVid, link1d_ ? 0 : kIspPid);
        const std::string label = offline_ ? "offline programmer HID" :
            link1d_ ? "Link1D HID" : "STC USB ISP (34BF:1001)";
        hid_device_info* selected = nullptr;
        for (auto* item = list; item; item = item->next) {
            if (link1d_ && (!(offline_ ? is_offline_pid(item->product_id) : is_link1d_pid(item->product_id)) ||
                            (item->interface_number != 0 && item->interface_number != -1))) continue;
            const std::string path = item->path ? item->path : "";
            if (path_.empty() || path == path_) {
                if (selected) {
                    hid_free_enumeration(list);
                    throw std::runtime_error("multiple " + label + " devices found, use --device-path");
                }
                selected = item;
            }
        }
        if (!selected) {
            hid_free_enumeration(list);
            throw std::runtime_error("no matching " + label + " device found");
        }
        device_ = hid_open_path(selected->path);
        hid_free_enumeration(list);
        if (!device_) throw std::runtime_error("hid_open_path failed");
    }
    void close() noexcept override {
        if (device_) hid_close(device_);
        device_ = nullptr;
        hid_exit();
    }
    void write(const std::vector<uint8_t>& data) override {
        if (data.size() != 64) throw std::invalid_argument("ISP report must be 64 bytes");
        std::vector<unsigned char> report(65, 0);
        std::copy(data.begin(), data.end(), report.begin() + 1);
        if (hid_write(device_, report.data(), report.size()) != static_cast<int>(report.size())) {
            throw std::runtime_error("hid_write failed");
        }
    }
    std::vector<uint8_t> read(int timeout_ms) override {
        std::vector<unsigned char> report(64);
        const int length = hid_read_timeout(device_, report.data(), report.size(), timeout_ms);
        if (length == 0) throw TransportTimeout("USB HID read timeout");
        if (length < 0) throw std::runtime_error("USB HID read failed");
        return std::vector<uint8_t>(report.begin(), report.begin() + std::min(length, 64));
    }
private:
    std::string path_;
    bool link1d_;
    bool offline_;
    hid_device* device_ = nullptr;
};
#endif

class PosixSerialTransport final : public Transport {
public:
    PosixSerialTransport(std::string port, int baud, int timeout_ms, bool even_parity)
        : port_(std::move(port)), baud_(baud), timeout_ms_(timeout_ms), even_parity_(even_parity) {}
    ~PosixSerialTransport() override { close(); }
    void open() override {
        if (fd_ >= 0) return;
        fd_ = ::open(port_.c_str(), O_RDWR | O_NOCTTY);
        if (fd_ < 0) throw std::runtime_error("cannot open serial port: " + port_);
        termios config{};
        if (tcgetattr(fd_, &config) != 0) fail("tcgetattr");
        cfmakeraw(&config);
        config.c_cflag |= CLOCAL | CREAD;
        config.c_cflag &= ~(PARODD | PARENB);
        if (even_parity_) config.c_cflag |= PARENB;
        config.c_cflag &= ~CSTOPB;
        const speed_t speed = baud_value(baud_);
        cfsetispeed(&config, speed);
        cfsetospeed(&config, speed);
        config.c_cc[VMIN] = 0;
        config.c_cc[VTIME] = static_cast<cc_t>((timeout_ms_ + 99) / 100);
        if (tcsetattr(fd_, TCSANOW, &config) != 0) fail("tcsetattr");
        tcflush(fd_, TCIOFLUSH);
    }
    void close() noexcept override {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    void set_baud(int baud) override {
        if (fd_ < 0) throw std::runtime_error("serial port is not open");
        termios config{};
        if (tcgetattr(fd_, &config) != 0) fail("tcgetattr");
        const speed_t speed = baud_value(baud);
        cfsetispeed(&config, speed);
        cfsetospeed(&config, speed);
        if (tcsetattr(fd_, TCSANOW, &config) != 0) fail("tcsetattr");
    }
    void write(const std::vector<uint8_t>& data) override {
        if (fd_ < 0) throw std::runtime_error("serial port is not open");
        size_t offset = 0;
        while (offset < data.size()) {
            const ssize_t count = ::write(fd_, data.data() + offset, data.size() - offset);
            if (count <= 0) fail("write serial");
            offset += static_cast<size_t>(count);
        }
        tcdrain(fd_);
    }
    std::vector<uint8_t> read(int timeout_ms) override {
        if (fd_ < 0) throw std::runtime_error("serial port is not open");
        pollfd descriptor{fd_, POLLIN, 0};
        const int ready = poll(&descriptor, 1, timeout_ms);
        if (ready < 0) fail("poll serial");
        if (ready == 0) throw TransportTimeout("serial read timeout");
        if (!(descriptor.revents & POLLIN)) throw std::runtime_error("serial port disconnected");
        std::vector<uint8_t> result(512);
        const ssize_t count = ::read(fd_, result.data(), result.size());
        if (count <= 0) fail("read serial");
        result.resize(static_cast<size_t>(count));
        return result;
    }
private:
    static speed_t baud_value(int baud) {
        switch (baud) {
            case 1200: return B1200; case 2400: return B2400; case 4800: return B4800;
            case 9600: return B9600; case 19200: return B19200; case 38400: return B38400;
            case 57600: return B57600; case 115200: return B115200;
            default: throw std::invalid_argument("unsupported POSIX baud rate");
        }
    }
    [[noreturn]] void fail(const char* operation) {
        const std::string message = std::string(operation) + ": " + std::strerror(errno);
        close();
        throw std::runtime_error(message);
    }
    std::string port_;
    int baud_;
    int timeout_ms_;
    bool even_parity_;
    int fd_ = -1;
};

#endif

}  // namespace

std::unique_ptr<Transport> make_usb_transport(const std::string& path) {
#ifdef _WIN32
    return std::make_unique<WindowsHidTransport>(path);
#elif defined(STC_ISP_HAVE_HIDAPI)
    return std::make_unique<PosixHidTransport>(path);
#else
    (void)path;
    throw std::runtime_error("USB support requires hidapi on this platform");
#endif
}

std::unique_ptr<Transport> make_link1d_hid_transport(const std::string& path) {
#ifdef _WIN32
    return std::make_unique<WindowsHidTransport>(path, true);
#elif defined(STC_ISP_HAVE_HIDAPI)
    return std::make_unique<PosixHidTransport>(path, true);
#else
    (void)path;
    throw std::runtime_error("Link1D HID requires hidapi on this platform");
#endif
}

std::unique_ptr<Transport> make_offline_hid_transport(const std::string& path) {
#ifdef _WIN32
    return std::make_unique<WindowsHidTransport>(path, true, true);
#elif defined(STC_ISP_HAVE_HIDAPI)
    return std::make_unique<PosixHidTransport>(path, true, true);
#else
    (void)path;
    throw std::runtime_error("offline programmer HID requires hidapi on this platform");
#endif
}

std::unique_ptr<Transport> make_serial_transport(const std::string& port,
                                                 int baud, int timeout_ms, bool even_parity) {
    return std::make_unique<
#ifdef _WIN32
        WindowsSerialTransport
#else
        PosixSerialTransport
#endif
    >(port, baud, timeout_ms, even_parity);
}

void list_usb_devices() {
#ifdef _WIN32
    const auto paths = enumerate_windows_hid(false);
    if (paths.empty()) {
        std::cout << "No STC USB ISP devices (34BF:1001) found.\n";
    } else {
        for (const auto& path : paths) {
            std::wcout << path << L"\n";
        }
    }
#elif defined(STC_ISP_HAVE_HIDAPI)
    hid_device_info* list = hid_enumerate(kVid, kIspPid);
    for (auto* item = list; item; item = item->next) {
        std::cout << (item->path ? item->path : "") << "\n";
    }
    hid_free_enumeration(list);
#else
    std::cout << "USB listing requires hidapi on this platform.\n";
#endif
}

void list_link1d_devices() {
#ifdef _WIN32
    const auto paths = enumerate_windows_hid(true);
    if (paths.empty()) std::cout << "No Link1D HID devices (34BF:1004/1005) found.\n";
    for (const auto& path : paths) std::wcout << path << L"\n";
#elif defined(STC_ISP_HAVE_HIDAPI)
    hid_device_info* list = hid_enumerate(kVid, 0);
    bool found = false;
    for (auto* item = list; item; item = item->next) {
        if (is_link1d_pid(item->product_id) && item->path &&
            (item->interface_number == 0 || item->interface_number == -1)) {
            std::cout << item->path << "\n";
            found = true;
        }
    }
    hid_free_enumeration(list);
    if (!found) std::cout << "No Link1D HID devices (34BF:1004/1005) found.\n";
#else
    std::cout << "Link1D HID listing requires hidapi on this platform.\n";
#endif
}

std::vector<uint8_t> validate_reset(const Config& config) {
    std::vector<uint8_t> command;
    if (config.reset_command.rfind("hex:", 0) == 0) {
        const std::string value = config.reset_command.substr(4);
        if (value.size() % 2 != 0) throw std::invalid_argument("hex reset command must have an even number of digits");
        for (size_t index = 0; index < value.size(); index += 2) {
            const auto byte = parse_unsigned("0x" + value.substr(index, 2), UINT8_MAX);
            command.push_back(static_cast<uint8_t>(byte));
        }
    } else {
        command.assign(config.reset_command.begin(), config.reset_command.end());
    }
    if (command.empty() || command.size() > 32) {
        throw std::invalid_argument("application reset command must contain 1..32 bytes");
    }
    const bool serial_reset = config.reset_transport == "serial" || config.reset_transport == "cdc";
    if (!serial_reset && config.reset_transport != "hid") {
        throw std::invalid_argument("reset_transport must be hid, serial, or cdc");
    }
    if (serial_reset) {
        if (config.reset_port.empty() || config.reset_baud < 1 ||
            (config.reset_parity != "none" && config.reset_parity != "even" && config.reset_parity != "odd") ||
            (config.reset_stop_bits != 1 && config.reset_stop_bits != 2))
            throw std::invalid_argument("invalid application serial reset port or line settings");
    } else if (config.reset_vid == 0 || config.reset_pid == 0) {
        throw std::invalid_argument("HID reset requires --reset-vid and --reset-pid");
    }
    return command;
}

void send_application_reset(const Config& config) {
    const auto command = validate_reset(config);
    const bool serial_reset = config.reset_transport == "serial" || config.reset_transport == "cdc";
    if (serial_reset) {
#ifdef _WIN32
        std::string name = config.reset_port;
        if (name.rfind("\\.\\", 0) != 0) name = "\\.\\" + name;
        HANDLE handle = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error(error_message("CreateFile application serial"));
        DCB dcb{};
        dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(handle, &dcb)) { CloseHandle(handle); throw std::runtime_error(error_message("GetCommState application serial")); }
        dcb.BaudRate = config.reset_baud;
        dcb.ByteSize = 8;
        dcb.fParity = config.reset_parity != "none";
        dcb.Parity = config.reset_parity == "even" ? EVENPARITY :
                     config.reset_parity == "odd" ? ODDPARITY : NOPARITY;
        dcb.StopBits = config.reset_stop_bits == 2 ? TWOSTOPBITS : ONESTOPBIT;
        dcb.fBinary = TRUE;
        dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = dcb.fDsrSensitivity = FALSE;
        dcb.fOutX = dcb.fInX = dcb.fErrorChar = dcb.fNull = dcb.fAbortOnError = FALSE;
        dcb.fDtrControl = config.reset_dtr ? DTR_CONTROL_ENABLE : DTR_CONTROL_DISABLE;
        dcb.fRtsControl = config.reset_rts ? RTS_CONTROL_ENABLE : RTS_CONTROL_DISABLE;
        if (!SetCommState(handle, &dcb)) { CloseHandle(handle); throw std::runtime_error(error_message("SetCommState application serial")); }
        DWORD written = 0;
        const bool ok = WriteFile(handle, command.data(), static_cast<DWORD>(command.size()), &written, nullptr);
        const std::string error = ok ? "short application serial write" : error_message("WriteFile application serial");
        CloseHandle(handle);
        if (!ok || written != command.size()) throw std::runtime_error(error);
        return;
#else
        const auto speed = [&]() -> speed_t {
            switch (config.reset_baud) {
                case 1200: return B1200; case 2400: return B2400; case 4800: return B4800;
                case 9600: return B9600; case 19200: return B19200; case 38400: return B38400;
                case 57600: return B57600; case 115200: return B115200;
                default: throw std::invalid_argument("unsupported application serial baud rate");
            }
        }();
        const int fd = ::open(config.reset_port.c_str(), O_RDWR | O_NOCTTY);
        if (fd < 0) throw std::runtime_error("cannot open application CDC/serial port: " + config.reset_port);
        termios settings{};
        if (tcgetattr(fd, &settings) != 0) { ::close(fd); throw std::runtime_error("cannot read application serial settings"); }
        cfmakeraw(&settings);
        settings.c_cflag |= CLOCAL | CREAD;
        settings.c_cflag &= ~(PARENB | PARODD);
        if (config.reset_parity == "even") settings.c_cflag |= PARENB;
        else if (config.reset_parity == "odd") settings.c_cflag |= PARENB | PARODD;
        if (config.reset_stop_bits == 2) settings.c_cflag |= CSTOPB;
        else settings.c_cflag &= ~CSTOPB;
        cfsetispeed(&settings, speed); cfsetospeed(&settings, speed);
        if (tcsetattr(fd, TCSANOW, &settings) != 0) { ::close(fd); throw std::runtime_error("cannot configure application serial port"); }
        int modem = 0;
        if (config.reset_dtr) modem |= TIOCM_DTR;
        if (config.reset_rts) modem |= TIOCM_RTS;
        int disabled = (TIOCM_DTR | TIOCM_RTS) & ~modem;
        if (disabled) ioctl(fd, TIOCMBIC, &disabled);
        if (modem) ioctl(fd, TIOCMBIS, &modem);
        const ssize_t written = ::write(fd, command.data(), command.size());
        tcdrain(fd);
        ::close(fd);
        if (written != static_cast<ssize_t>(command.size())) throw std::runtime_error("application serial command write failed");
        return;
#endif
    }
#ifdef _WIN32
    const auto paths = enumerate_windows_hid(false, config.reset_vid, config.reset_pid);
    if (paths.size() != 1) throw std::runtime_error("expected one application HID device for reset command");
    HANDLE handle = CreateFileW(paths.front().c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error(error_message("CreateFile application HID"));
    PHIDP_PREPARSED_DATA preparsed = nullptr;
    HIDP_CAPS caps{};
    if (!HidD_GetPreparsedData(handle, &preparsed) ||
        HidP_GetCaps(preparsed, &caps) != HIDP_STATUS_SUCCESS) {
        if (preparsed) HidD_FreePreparsedData(preparsed);
        CloseHandle(handle);
        throw std::runtime_error(error_message("read application HID capabilities"));
    }
    HidD_FreePreparsedData(preparsed);
    std::vector<uint8_t> report(std::max<USHORT>(caps.OutputReportByteLength, 65), 0);
    std::copy(command.begin(), command.end(), report.begin() + 1);
    DWORD written = 0;
    const bool ok = WriteFile(handle, report.data(), static_cast<DWORD>(report.size()), &written, nullptr);
    CloseHandle(handle);
    if (!ok || written != report.size()) throw std::runtime_error(error_message("WriteFile application HID"));
#elif defined(STC_ISP_HAVE_HIDAPI)
    hid_device_info* list = hid_enumerate(config.reset_vid, config.reset_pid);
    hid_device_info* selected = nullptr;
    for (auto* item = list; item; item = item->next) {
        if (selected) {
            hid_free_enumeration(list);
            throw std::runtime_error("multiple application HID devices found for reset command");
        }
        selected = item;
    }
    if (!selected) {
        hid_free_enumeration(list);
        throw std::runtime_error("application HID device for reset command was not found");
    }
    hid_device* device = hid_open_path(selected->path);
    hid_free_enumeration(list);
    if (!device) throw std::runtime_error("cannot open application HID device");
    std::vector<unsigned char> report(65, 0);
    std::copy(command.begin(), command.end(), report.begin() + 1);
    const int written = hid_write(device, report.data(), report.size());
    hid_close(device);
    if (written != static_cast<int>(report.size())) throw std::runtime_error("application HID command write failed");
#else
    throw std::runtime_error("application HID reset requires hidapi on this platform");
#endif
}

}  // namespace stcisp
