# Copyright (c) 2012-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# webos-connman-adapter/CMakeLists.txt
#


cmake_minimum_required(VERSION 2.8.7)

project(webos-connman-adapter C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(1 1 0)

set(WIFI_IFACE_NAME "wlan0" CACHE STRING "WiFi interface name")
set(WIRED_IFACE_NAME "eth0" CACHE STRING "Wired interface name")
set(CONNMAN_CONFIG_DIR "/var/lib/connman" CACHE STRING "Default connman config folder")

find_program(GDBUS_CODEGEN_EXECUTABLE NAMES gdbus-codegen DOC "gdbus-codegen executable")
if(NOT GDBUS_CODEGEN_EXECUTABLE)
	message(FATAL_ERROR "Executable gdbus-codegen not found")
endif()

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS_OTHER})

pkg_check_modules(GIO-UNIX REQUIRED gio-unix-2.0)
include_directories(${GIO-UNIX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GIO-UNIX_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

pkg_check_modules(LUNAPREFS REQUIRED luna-prefs)
include_directories(${LUNAPREFS_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNAPREFS_CFLAGS_OTHER})

pkg_check_modules(PMLOG REQUIRED PmLogLib)
include_directories(${PMLOG_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOG_CFLAGS_OTHER})

pkg_check_modules(WCA_SUPPORT REQUIRED wca-support)
include_directories(${WCA_SUPPORT_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${WCA_SUPPORT_CFLAGS_OTHER})

pkg_check_modules(WCA_SUPPORT_API REQUIRED wca-support-api>=0.1.0)
include_directories(${WCA_SUPPORT_API_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${WCA_SUPPORT_API_CFLAGS_OTHER})

pkg_check_modules(NYXLIB REQUIRED nyx)
include_directories(${NYXLIB_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${NYXLIB_CFLAGS_OTHER})

webos_add_compiler_flags(ALL -Wall -g)

webos_add_linker_options(ALL --no-undefined)

set(GDBUS_IF_DIR ${WEBOS_BINARY_CONFIGURED_DIR}/src)

file (MAKE_DIRECTORY ${GDBUS_IF_DIR})

execute_process(COMMAND ${GDBUS_CODEGEN_EXECUTABLE} --c-namespace ConnmanInterface --generate-c-code 
			${GDBUS_IF_DIR}/connman-interface --interface-prefix net.connman. 
			${CMAKE_CURRENT_SOURCE_DIR}/files/xml/connman.xml
			RESULT_VARIABLE codegen_failed)
if(codegen_failed)
		message(FATAL_ERROR "Error in generating code for connman interface using gdbus-codegen")
endif()

execute_process(COMMAND ${GDBUS_CODEGEN_EXECUTABLE} --c-namespace PacrunnerInterface --generate-c-code
			${GDBUS_IF_DIR}/pacrunner-interface --interface-prefix org.pacrunner.
			${CMAKE_CURRENT_SOURCE_DIR}/files/xml/pacrunner.xml
			RESULT_VARIABLE codegen_failed)
if(codegen_failed)
		message(FATAL_ERROR "Error in generating code for pacrunner interface using gdbus-codegen")
endif()


set(ENABLE_SINGLE_PROFILE FALSE CACHE BOOL "Enable support for maintaining only a single profile")
if (ENABLE_SINGLE_PROFILE)
webos_add_compiler_flags(ALL -DENABLE_SINGLE_PROFILE)
endif()

if (ENABLE_QUICK_WOL)
webos_add_compiler_flags(ALL -DENABLE_QUICK_WOL)
endif()

include_directories(src ${GDBUS_IF_DIR})
webos_configure_header_files(src)

file(GLOB SOURCE_FILES
    src/common.c
    src/connectionmanager_service.c
    src/connman_agent.c
    src/connman_counter.c
    src/connman_group.c
    src/connman_manager.c
    src/connman_service.c
    src/connman_service_discovery.c
    src/connman_technology.c
    src/json_utils.c
    src/lunaservice_utils.c
    src/main.c
    src/nyx.c
    src/pacrunner_client.c
    src/utils.c
    src/wifi_tethering_service.c
    src/wifi_profile.c
    src/wifi_service.c
    src/wifi_setting.c
    src/wifi_scan.c
    src/wan_service.c
    src/pan_service.c
    src/state_recovery.c
    ${GDBUS_IF_DIR}/connman-interface.c
    ${GDBUS_IF_DIR}/pacrunner-interface.c)

add_executable(webos-connman-adapter ${SOURCE_FILES})
target_link_libraries(webos-connman-adapter
                        ${GLIB2_LDFLAGS}
                        ${LUNASERVICE2_LDFLAGS}
                        ${GIO-UNIX_LDFLAGS}
                        ${PBNJSON_C_LDFLAGS}
                        ${OPENSSL_LDFLAGS}
                        ${LUNAPREFS_LDFLAGS}
                        ${PMLOG_LDFLAGS}
                        ${WCA_SUPPORT_LDFLAGS}
                        ${NYXLIB_LDFLAGS}
                        rt
                        pthread)

webos_build_daemon()
webos_build_system_bus_files()

webos_config_build_doxygen(doc Doxyfile)

add_subdirectory(tests)
