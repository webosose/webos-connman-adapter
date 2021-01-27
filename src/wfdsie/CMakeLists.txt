# @@@LICENSE
#
# Copyright (c) 2021 LG Electronics, Inc.
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
# LICENSE@@@

#
# webos-connman-adapter/src/wfdsie/CMakeLists.txt

project(libwfdsie CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")

include_directories(${CMAKE_SOURCE_DIR}/src/wfdsie)

set(WFDSIE_LIB wfdsie)

set(SRC_LIB
        ${CMAKE_SOURCE_DIR}/src/wfdsie/information-element.cpp ${CMAKE_SOURCE_DIR}/src/wfdsie/wfdinfoelemwrapper.cpp
    )

add_library(${WFDSIE_LIB} SHARED ${SRC_LIB})

webos_build_library(NAME ${WFDSIE_LIB} NOHEADERS)

install(TARGETS ${WFDSIE_LIB} DESTINATION ${WEBOS_INSTALL_LIBDIR})
