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
 * @file  wifi_setting.h
 *
 */


#ifndef _WIFI_SETTING_H_
#define _WIFI_SETTING_H_

#include "wifi_service.h"

#define WIFI_LUNA_PREFS_ID          WIFI_LUNA_SERVICE_NAME

typedef enum
{
	WIFI_NULL_SETTING,
	WIFI_PROFILELIST_SETTING,
	WIFI_LAST_SETTING,
} wifi_setting_type_t;

extern gboolean load_wifi_setting(wifi_setting_type_t setting, void *data);
extern gboolean store_wifi_setting(wifi_setting_type_t setting, void *data);

extern gboolean store_network_config(connection_settings_t *settings,
                              const char *security);
extern gboolean change_network_passphrase(const char *ssid, const char *security,
                                         const char *passphrase);
extern gboolean create_config_inotify_watch(void);
extern void sync_network_configs_with_profiles(void);
extern gboolean change_network_ipv4(const char *ssid, const char *security,
                                    const char *address, const char *netmask, const char *gateway);
extern gboolean change_network_ipv6(const char *ssid, const char *security,
                                    const char *address, const char *prefixLen, const char *gateway);
extern gboolean change_network_remove_entry(const char *ssid, const char *security, const char *key);
extern void remove_config_inotify_watch(void);


#endif /* _WIFI_SETTING_H_ */
