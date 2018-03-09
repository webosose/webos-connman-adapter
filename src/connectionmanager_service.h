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

/**
 * @file  connectionmanager_service.h
 *
 */

#ifndef _CONNECTIONMANAGER_SERVICE_H_
#define _CONNECTIONMANAGER_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define CONNECTIONMANAGER_LUNA_SERVICE_NAME "com.webos.service.connectionmanager"

#define LUNA_CATEGORY_ROOT                 "/"

/**
 * @name Luna Connectionmanager Method Names
 * @{
 */
#define LUNA_METHOD_GETSTATUS             "getstatus"
#define LUNA_METHOD_GETSTATUS2            "getStatus"
#define LUNA_METHOD_SETIPV4               "setipv4"
#define LUNA_METHOD_SETIPV6               "setipv6"
#define LUNA_METHOD_SETDNS                "setdns"
#define LUNA_METHOD_SETSTATE              "setstate"
#define LUNA_METHOD_GETINFO               "getinfo"
#define LUNA_METHOD_SETWOLWOWLSTATUS      "setwolwowlstatus"
#define LUNA_METHOD_GETWOLWOWLSTATUS      "getwolwowlstatus"
#define LUNA_METHOD_MONITORACTIVITY       "monitorActivity"
#define LUNA_METHOD_SETTECHNOLOGYSTATE    "setTechnologyState"
#define LUNA_METHOD_SETETHERNETTETHERING  "setEthernetTethering"
#define LUNA_METHOD_SETPROXY              "setProxy"
#define LUNA_METHOD_FINDPROXYFORURL       "findProxyForURL"

enum ipadress_type
{
	IPADDRESS_TYPE_UNKNOWN = 0,
	IPADDRESS_TYPE_IPV4 = 1,
	IPADDRESS_TYPE_IPV6 = 2,
};

extern void connectionmanager_send_status_to_subscribers(void);
extern int initialize_connectionmanager_ls2_calls(GMainLoop *mainloop,
        LSHandle **cm_handle);
extern void send_getinfo_to_subscribers(void);

#endif /* _CONNECTIONMANAGER_SERVICE_H_ */
