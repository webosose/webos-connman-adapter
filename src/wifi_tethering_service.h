// Copyright (c) 2014-2018 LG Electronics, Inc.
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

/**
 * @file  wifi_tethering_service.h
 *
 */

#ifndef _WIFI_TETHERING_SERVICE_H_
#define _WIFI_TETHERING_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define LUNA_CATEGORY_TETHERING              "/tethering"

/**
 * @name Luna WiFi tethering Method Names
 * @{
 */

#define LUNA_METHOD_TETHERING_SETSTATE       "setState"
#define LUNA_METHOD_TETHERING_GETSTATE       "getState"
#define LUNA_METHOD_TETHERING_GETSTACOUNT    "getStationCount"

extern void send_tethering_state_to_subscribers(void);
extern void send_sta_count_to_subscribers(void);
extern int initialize_wifi_tethering_ls2_calls(GMainLoop *mainloop,
        LSHandle *pLsHandle);

#endif /* _WIFI_TETHERING_SERVICE_H_ */
