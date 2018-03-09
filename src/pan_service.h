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
 * @file  pan_service.h
 *
 */

#ifndef _PAN_SERVICE_H_
#define _PAN_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define PAN_LUNA_SERVICE_NAME "com.webos.service.pan"


#define LUNA_CATEGORY_ROOT               "/"

/**
 * @name Luna PAN Method Names
 * @{
 */

#define LUNA_METHOD_PAN_CONNECT          "connect"
#define LUNA_METHOD_PAN_DISCONNECT       "disconnect"
#define LUNA_METHOD_PAN_GETSTATUS        "getStatus"
#define LUNA_METHOD_PAN_SETTETHERING     "setTethering"

extern void append_nap_info(jvalue_ref *status);
extern void send_pan_connection_status_to_subscribers(void);
extern int initialize_pan_ls2_calls(GMainLoop *mainloop,
                                    LSHandle **pan_handle);
extern void check_and_initialize_bluetooth_technology(void);

#endif /* _PAN_SERVICE_H_ */
