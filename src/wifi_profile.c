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
 * @file  wifi_profile.c
 *
 * @brief Functions for manipulating wifi profile list
 *
 */

#include <glib.h>

#include "wifi_profile.h"
#include "wifi_setting.h"
#include "logging.h"

static GSList *wifi_profile_list = NULL;
static guint gprofile_id = 777; //! First assigned profile ID

extern gboolean remove_network_config(const char *ssid, const char *security);

/**
 * @brief Search all wifi profiles to match the given profile Id.
 */

wifi_profile_t *get_profile_by_id(guint profile_id)
{
	GSList *iter;

	for (iter = wifi_profile_list; NULL != iter; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);

		if (profile->profile_id == profile_id)
		{
			return profile;
		}
	}

	return NULL;
}

/**
 * @brief Lookup wifi profile with given ssid
 */

wifi_profile_t *get_profile_by_ssid(gchar *ssid)
{
	if (NULL == ssid)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = wifi_profile_list; NULL != iter; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);

		if (!g_strcmp0(profile->ssid, ssid))
		{
			return profile;
		}
	}

	return NULL;
}

/**
 * @brief Lookup wifi profile with given ssid and security
 */

wifi_profile_t *get_profile_by_ssid_security(gchar *ssid,  gchar *security)
{
	if (NULL == ssid)
	{
		return NULL;
	}

	GSList *iter;
	int n = 0;

	for (iter = wifi_profile_list; NULL != iter; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);

		if (!g_strcmp0(profile->ssid, ssid))
		{
			if (profile->security != NULL)
			{
				for (n = 0; n < g_strv_length(profile->security); n++)
					if (!g_strcmp0(profile->security[n], security))
					{
						return profile;
					}
			}
			else
			{
				return profile;
			}
		}
	}

	return NULL;
}

/**
 * @brief Create a new profile
 *
 * For open networks we only need to add its ssid and generate a profile ID
 * However more fields to be added when supporting secured wifi networks.
 */
wifi_profile_t *create_new_profile(gchar *ssid, GStrv security, gboolean hidden,
                                   gboolean configured)
{
	if (NULL == ssid)
	{
		return NULL;
	}

	WCALOG_DEBUG("Create profile %s", ssid);

	wifi_profile_t *new_profile = g_new0(wifi_profile_t, 1);

	if (NULL == new_profile)
	{
		return NULL;
	}

	new_profile->profile_id = gprofile_id++;
	new_profile->ssid = g_strdup(ssid);
	new_profile->hidden = hidden;
	new_profile->configured = configured;

	if (NULL != security)
	{
		gsize i, num_elems = g_strv_length(security);
		new_profile->security = (GStrv) g_new0(GStrv, num_elems + 1);

		for (i = 0; i < num_elems; i++)
		{
			new_profile->security[i] = g_strdup(security[i]);
		}

		new_profile->security[num_elems] = NULL;
	}

	wifi_profile_list = g_slist_append(wifi_profile_list, (gpointer)new_profile);
	/* Store wifi profiles */
	store_wifi_setting(WIFI_PROFILELIST_SETTING, NULL);

	return new_profile;
}

/**
 * @brief Delete a wifi profile
 */

void delete_profile(wifi_profile_t *profile)
{
	if (NULL == profile)
	{
		return;
	}

	/* Delete the link from the list */
	GSList *node = g_slist_find(wifi_profile_list, profile);

	if (NULL != node)
	{
		wifi_profile_list = g_slist_delete_link(wifi_profile_list,
		                                        g_slist_find(wifi_profile_list, profile));
	}

	WCALOG_DEBUG("Delete profile %s", profile->ssid);

	if (profile->configured)
	{
		remove_network_config(profile->ssid, profile->security[0]);
	}

	g_free(profile->ssid);
	g_strfreev(profile->security);
	g_free(profile);
	profile = NULL;
	store_wifi_setting(WIFI_PROFILELIST_SETTING, NULL);
}

/**
 * @brief Delete all profiles but not the one specified with the supplied ID
 * @param id ID of the profile not to delete
 */
void delete_all_profiles_except_one(guint id)
{
	GSList *iter, *delete_profiles = NULL;

	for (iter = wifi_profile_list; NULL != iter; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);

		if (profile->profile_id != id)
		{
			delete_profiles = g_slist_prepend(delete_profiles, (gpointer) profile);
		}
	}

	for (iter = delete_profiles; iter != NULL; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);
		delete_profile(profile);
	}

	g_slist_free(delete_profiles);
}

/**
 * @brief Return TRUE if profile list is empty
 */

gboolean profile_list_is_empty(void)
{
	return (0 == g_slist_length(wifi_profile_list));
}

/**
 * @brief Traverse the profile list and get the one after the supplied profile
 */

wifi_profile_t *get_next_profile(wifi_profile_t *curr_profile)
{
	// Return first profile (if present), if NULL argument is passed
	if (NULL == curr_profile)
	{
		if (NULL != wifi_profile_list)
		{
			return (wifi_profile_t *)(wifi_profile_list->data);
		}
		else
		{
			return NULL;
		}
	}

	GSList *node = g_slist_find(wifi_profile_list, curr_profile);

	if (node != NULL && node->next != NULL)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(node->next->data);
		return profile;
	}

	return NULL;
}

/**
 * @brief Move the supplied profile to top of the list
 * This is useful to prioritize a profile to be the first one in the list
 */

void move_profile_to_head(wifi_profile_t *profile)
{
	if (NULL == profile)
	{
		return;
	}

	GSList *node = g_slist_find(wifi_profile_list, profile);

	if (NULL != node)
	{
		/* If the given profile is already the head, return */
		if (node == wifi_profile_list)
		{
			return;
		}

		/* Delete the link from the list */
		wifi_profile_list = g_slist_delete_link(wifi_profile_list,
		                                        g_slist_find(wifi_profile_list, profile));
		/* Then add it to start of the list */
		wifi_profile_list = g_slist_prepend(wifi_profile_list, profile);
	}

	store_wifi_setting(WIFI_PROFILELIST_SETTING, NULL);
}

/**
 * @brief Load the stored wifi profiles (from luna-prefs)
 */

void init_wifi_profile_list(void)
{
	load_wifi_setting(WIFI_PROFILELIST_SETTING, NULL);
	return;
}


