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
 * @file  wifi_profile.h
 *
 */


#ifndef _WIFI_PROFILE_H_
#define _WIFI_PROFILE_H_

#include <glib-object.h>

typedef struct wifi_profile
{
	guint profile_id;
	gchar *ssid;
	gboolean hidden;
	GStrv security;
	gboolean configured;
} wifi_profile_t;

extern void init_wifi_profile_list(void);
extern wifi_profile_t *get_profile_by_id(guint profile_id);
extern wifi_profile_t *get_profile_by_ssid(gchar *ssid);
extern wifi_profile_t *get_profile_by_ssid_security(gchar *ssid,
        gchar *security);
extern wifi_profile_t *create_new_profile(gchar *ssid, GStrv security,
        gboolean hidden, gboolean configured);
extern void delete_profile(wifi_profile_t *profile);
extern void delete_all_profiles_except_one(guint id);
extern gboolean profile_list_is_empty(void);
extern wifi_profile_t *get_next_profile(wifi_profile_t *curr_profile);
extern void move_profile_to_head(wifi_profile_t *new_head);

#endif /* _WIFI_PROFILE_H_ */
