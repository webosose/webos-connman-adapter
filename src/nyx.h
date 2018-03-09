// Copyright (c) 2016-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef _NYX_H_
#define _NYX_H_

#include <stdbool.h>

#define UNUSED(x) (void)(x)

#define MAC_ADDR_STRING_LEN 32

extern bool init_nyx();

extern void release_nyx();

extern bool retrieve_wired_mac_address(char* buffer, size_t buffer_size);

extern bool retrieve_wifi_mac_address(char* buffer, size_t buffer_size);

#endif /* _NYX_H_ */
