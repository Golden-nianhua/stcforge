cmake_minimum_required(VERSION 3.20)
project(stc-isp VERSION 0.1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(STC_ISP_BUILD_TESTS "Build protocol and parser tests" ON)
set(STCFORGE_PYTHON_SDK "" CACHE PATH "Windows CPython 3.12 SDK for the portable stcforge launcher")

if (STCFORGE_PYTHON_SDK)
    if (NOT WIN32 OR NOT EXISTS "${STCFORGE_PYTHON_SDK}/include/Python.h"
                  OR NOT EXISTS "${STCFORGE_PYTHON_SDK}/libs/python312.lib")
        message(FATAL_ERROR "STCFORGE_PYTHON_SDK must point to a Windows CPython 3.12 SDK")
    endif()
    add_executable(stcforge-launcher src/native/launcher/main.cpp)
    set_target_properties(stcforge-launcher PROPERTIES OUTPUT_NAME stcforge)
    target_include_directories(stcforge-launcher PRIVATE "${STCFORGE_PYTHON_SDK}/include")
    target_link_libraries(stcforge-launcher PRIVATE "${STCFORGE_PYTHON_SDK}/libs/python312.lib")
    if (MINGW)
        target_link_options(stcforge-launcher PRIVATE -municode -static -static-libgcc -static-libstdc++)
    endif()
endif()

add_library(stc-isp-core STATIC
    src/isp/isp_database.cpp
    src/isp/isp_config.cpp
    src/isp/isp_crypto.cpp
    src/isp/isp_hex.cpp
    src/isp/isp_transport.cpp
    src/isp/isp_link1d.cpp
    src/isp/isp_offline.cpp
    src/isp/isp_softusb.cpp
    src/isp/isp_protocol.cpp
)

target_include_directories(stc-isp-core PUBLIC src/isp/include)
add_executable(stc-isp src/isp/isp_main.cpp)
target_link_libraries(stc-isp PRIVATE stc-isp-core)

if (WIN32)
    target_compile_definitions(stc-isp PRIVATE NOMINMAX UNICODE _UNICODE)
    target_compile_definitions(stc-isp-core PRIVATE NOMINMAX UNICODE _UNICODE)
    target_link_libraries(stc-isp-core PRIVATE setupapi hid)
else()
    find_path(HIDAPI_INCLUDE_DIR hidapi/hidapi.h)
    find_library(HIDAPI_LIBRARY NAMES hidapi-hidraw hidapi-libusb hidapi)
    if (HIDAPI_INCLUDE_DIR AND HIDAPI_LIBRARY)
        target_include_directories(stc-isp-core PRIVATE ${HIDAPI_INCLUDE_DIR})
        target_link_libraries(stc-isp-core PRIVATE ${HIDAPI_LIBRARY})
        target_compile_definitions(stc-isp-core PRIVATE STC_ISP_HAVE_HIDAPI=1)
    else()
        message(WARNING "hidapi was not found. USB support will report a build-time dependency error.")
    endif()
    find_path(LIBUSB_INCLUDE_DIR libusb.h PATH_SUFFIXES libusb-1.0)
    find_library(LIBUSB_LIBRARY NAMES usb-1.0 libusb-1.0)
    if (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARY)
        target_include_directories(stc-isp-core PRIVATE ${LIBUSB_INCLUDE_DIR})
        target_link_libraries(stc-isp-core PRIVATE ${LIBUSB_LIBRARY})
        target_compile_definitions(stc-isp-core PRIVATE STC_ISP_HAVE_LIBUSB=1)
    endif()
endif()

if (MINGW)
    target_link_options(stc-isp PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()

if (MSVC)
    target_compile_options(stc-isp PRIVATE /W4 /permissive-)
    target_compile_options(stc-isp-core PRIVATE /W4 /permissive-)
else()
    target_compile_options(stc-isp PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(stc-isp-core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (STC_ISP_BUILD_TESTS)
    enable_testing()
    add_executable(stc-isp-link1d-test tools/tests/isp_link1d_test.cpp)
    target_link_libraries(stc-isp-link1d-test PRIVATE stc-isp-core)
    if (MINGW)
        target_link_options(stc-isp-link1d-test PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
    add_test(NAME isp-link1d COMMAND stc-isp-link1d-test "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/fixtures/isp-link1d")
    add_test(NAME isp-link1d-config-override COMMAND stc-isp
        --config "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/fixtures/isp-link1d/auto.toml"
        --link1d-auto-power true --dry-run)
    add_test(NAME isp-swd-simulation-dry-run COMMAND stc-isp
        --config "${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/stc32g144k246-swd-simulation.toml"
        --dry-run)
    add_test(NAME isp-link1d-manual-needs-port COMMAND stc-isp
        --if link1d --link1d-auto-power false --dry-run)
    set_tests_properties(isp-link1d-manual-needs-port PROPERTIES WILL_FAIL TRUE)
    add_test(NAME isp-unported-model-no-write COMMAND stc-isp
        --if link1d --model USB-2UART --image "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/fixtures/isp-link1d/lower.hex" --dry-run)
    set_tests_properties(isp-unported-model-no-write PROPERTIES WILL_FAIL TRUE)
endif()

include(GNUInstallDirs)
install(TARGETS stc-isp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY docs/examples/ DESTINATION ${CMAKE_INSTALL_DATADIR}/stc-isp/examples
        FILES_MATCHING PATTERN "*.toml" PATTERN "hardware-families/README.md")
install(FILES docs/research/aicube-isp-v6.97a/models-6.97c.json
        DESTINATION ${CMAKE_INSTALL_DATADIR}/stc-isp/research)

