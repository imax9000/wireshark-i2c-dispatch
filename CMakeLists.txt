cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0148 OLD)

project(wireshark-i2c-dispatch)

# Ubuntu-specific hacks.
list(APPEND CMAKE_MODULE_PATH "/usr/lib/x86_64-linux-gnu/wireshark/cmake")
set(ENV{PYTHONPATH} "$ENV{PYTHONPATH}:/usr/share/pyshared")

include(WiresharkConfig)
include(UseMakePluginReg)

add_custom_target(plugins)
set(PLUGIN_DIR "${CMAKE_BINARY_DIR}")
set(PLUGIN_INSTALL_VERSION_LIBDIR "$ENV{HOME}/.local/lib/wireshark/plugins/${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}" CACHE PATH "Install location")

# I know, I know... But somehow this is less annoying that doing split-license or something.
file(DOWNLOAD "https://gitlab.com/wireshark/wireshark/-/raw/master/cmake/modules/WiresharkPlugin.cmake" WiresharkPlugin.cmake)
include(${CMAKE_BINARY_DIR}/WiresharkPlugin.cmake)

set(SRC i2c-dispatch.c)

set_module_info(i2c-dispatch 0 0 1 0)
register_plugin_files(plugin.c plugin ${SRC})

set(PLUGIN_FILES plugin.c ${SRC})

add_wireshark_plugin_library(i2c-dispatch epan)
target_link_libraries(i2c-dispatch epan)
install_plugin(i2c-dispatch epan)
