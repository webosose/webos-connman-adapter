// Copyright (c) 2012-2018 LG Electronics, Inc.
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

#ifndef _WAN_SERVICE_H_
#define _WAN_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define WAN_LUNA_SERVICE_NAME "com.webos.service.wan"

#define LUNA_CATEGORY_ROOT            "/"

#define LUNA_METHOD_WAN_CONNECT       "connect"
#define LUNA_METHOD_WAN_DISCONNECT    "disconnect"
#define LUNA_METHOD_WAN_GETSTATUS     "getStatus"
#define LUNA_METHOD_WAN_GETCONTEXTS   "getContexts"
#define LUNA_METHOD_WAN_GETCONTEXT    "getContext"
#define LUNA_METHOD_WAN_SETHOSTROUTES "setHostRoutes"

extern void check_and_initialize_cellular_technology(void);
extern void send_wan_connection_status_to_subscribers(void);
extern void send_wan_contexts_update_to_subscribers(void);
extern void append_wan_status(jvalue_ref reply_obj);
extern int initialize_wan_ls2_calls(GMainLoop *mainloop, LSHandle **wan_handle);

#endif /* _WAN_SERVICE_H_ */
