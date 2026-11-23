#include <Python.h>
#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

int wmain(int argc, wchar_t** argv) {
    std::wstring module(32768, L'\0');
    const auto size = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
    if (!size || size >= module.size()) {
        std::fputs("STCForge: cannot locate the bundled runtime.\n", stderr);
        return 1;
    }
    module.resize(size);
    // CLion's helper re-runs `sys.executable -m stcforge`, so expose the
    // bundled interpreter rather than this application-specific entry point.
    const auto python = std::filesystem::path(module).parent_path() / L"python.exe";

    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    auto status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.parse_argv = 0;
    config.buffered_stdio = 0;
    config.write_bytecode = 0;
    config.site_import = 0;
    status = PyConfig_SetArgv(&config, argc, argv);
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetString(&config, &config.executable, python.c_str());
    }
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetString(&config, &config.run_module, L"stcforge");
    }
    if (!PyStatus_Exception(status)) {
        status = Py_InitializeFromConfig(&config);
    }
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }
    return Py_RunMain();
}
