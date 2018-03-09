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


#ifndef _COMMON_H_
#define _COMMON_H_

#include "connman_manager.h"
#include "connman_agent.h"


extern connman_manager_t *manager;
extern connman_agent_t *agent;

extern gboolean connman_status_check(connman_manager_t *manager, LSHandle *sh,
                                     LSMessage *message);
extern gboolean is_wifi_powered(void);
extern gboolean is_wifi_tethering(void);
extern gboolean is_cellular_powered(void);
extern gboolean wifi_technology_status_check(LSHandle *sh, LSMessage *message);
extern gboolean cellular_technology_status_check(LSHandle *sh,
        LSMessage *message);
extern gboolean wifi_technology_status_check_with_subscription(LSHandle *sh,
                                                        LSMessage *message, bool subscribed);
extern gboolean connman_status_check_with_subscription(connman_manager_t *manager,
                                                LSHandle *sh, LSMessage *message, bool subscribed);
extern gboolean set_wifi_powered_status(gboolean state);
extern const gchar *get_current_system_locale();
extern void retrieve_system_locale_info(LSHandle *handle);
extern void set_cellular_powered_status(gboolean state);
extern gboolean is_ethernet_tethering(void);
extern gboolean is_bluetooth_powered(void);
extern gboolean is_bluetooth_tethering(void);
extern bool is_valid_ipv6address(char *ipAddress);
extern bool is_valid_ipaddress(char *ipAddress);
extern gboolean bluetooth_technology_status_check(LSHandle *sh,
        LSMessage *message);
extern gboolean bluetooth_technology_status_check_with_subscription(
    LSHandle *sh, LSMessage *message, bool subscribed);
extern gboolean ethernet_technology_status_check(LSHandle *sh, LSMessage *message);

#endif /* _COMMON_H_ */

