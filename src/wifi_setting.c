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
 * @file  wifi_setting.c
 *
 * @brief Functions for storing/loading wifi settings & profiles from luna-prefs
 *
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <openssl/blowfish.h>
#include <lunaprefs.h>
#include <pbnjson.h>
#include <sys/inotify.h>

#include "wifi_setting.h"
#include "wifi_profile.h"
#include "connman_common.h"
#include "logging.h"

/**
 * WiFi setting keys used to identify settings stored in luna-prefs database.
 * THE SEQUENCE MUST MATCH THE VALUES OF WIFI SETTINGS DEFINED IN wifi_setting.h
 */
static const char *SettingKey[] =
{
	"Null-DO-NOT-USE", /**< Marker used to indicate the start of setting keys */

	"profileList", /**< Setting key for profile list */

	"Last-DO-NOT-USE" /**< Marker used to indicate the end of setting keys */
};

/**
 * @brief Encrypt the given input using the supplied key
 * The encrypt /decrypt functions are useful for storing wifi profiles
 * which may contain secret passwords / passphrases
 */

static char *wifi_setting_encrypt(const char *input_str, const char *key)
{
	BF_KEY *pBfKey = g_new0(BF_KEY, 1);
	gchar *b64str = NULL;
	char *result = NULL;
	long len;
	char *output_str = NULL;
	unsigned char ivec[8] = {0};
	int num = 0;

	if (pBfKey == NULL)
	{
		goto Exit;
	}

	if (!input_str || !key || !strlen(input_str) || !strlen(key))
	{
		goto Exit;
	}

	BF_set_key(pBfKey, strlen(key), (const unsigned char *)(key));

	len = strlen(input_str);

	output_str = g_new0(char, len + 1);

	if (!output_str)
	{
		goto Exit;
	}

	memset(output_str, 0, len + 1);

	BF_cfb64_encrypt((const unsigned char *)(input_str),
	                 (unsigned char *)(output_str),
	                 len, pBfKey, ivec, &num, BF_ENCRYPT);

	b64str = g_base64_encode((const guchar *)(output_str), len);

	if (b64str)
	{
		result = strdup(b64str);
		g_free(b64str);
	}

Exit:
	g_free(output_str);
	g_free(pBfKey);
	return result;
}

/**
 * @brief Decrypt the given input using the supplied key
 * The encrypt /decrypt functions are useful for storing wifi profiles
 * which may contain secret passwords / passphrases
 */


static char *wifi_setting_decrypt(const char *input_str, const char *key)
{
	BF_KEY *pBfKey = g_new0(BF_KEY, 1);
	char *result = NULL;
	long len = 0;
	guchar *b64str = NULL;
	char *output_str = NULL;
	unsigned char ivec[8] = {0};
	int num = 0;

	if (pBfKey == NULL)
	{
		goto Exit;
	}

	if (!input_str || !key || !strlen(input_str) || !strlen(key))
	{
		goto Exit;
	}

	BF_set_key(pBfKey, strlen(key), (const unsigned char *)key);


	b64str = g_base64_decode((const gchar *)(input_str), (gsize *)(&len));

	if (b64str)
	{
		output_str = g_new0(char, len + 1);

		if (!output_str)
		{
			g_free(b64str);
			goto Exit;
		}

		memset(output_str, 0, len + 1);

		BF_cfb64_encrypt((const unsigned char *)(b64str), (unsigned char *)(output_str),
		                 len, pBfKey, ivec, &num, BF_DECRYPT);

		result = strdup(output_str);

		g_free(output_str);
		g_free(b64str);
	}

Exit:
	g_free(pBfKey);
	return result;
}


static gboolean populate_wifi_profile(jvalue_ref profileObj)
{
	gboolean ret = FALSE;
	jvalue_ref wifiProfileObj, ssidObj, securityListObj, hiddenObj, configuredObj;

	if (jobject_get_exists(profileObj, J_CSTR_TO_BUF("wifiProfile"),
	                       &wifiProfileObj))
	{
		raw_buffer enc_profile_buf = jstring_get(wifiProfileObj);
		gchar *enc_profile = g_strdup(enc_profile_buf.m_str);
		jstring_free_buffer(enc_profile_buf);
		gchar *dec_profile = wifi_setting_decrypt(enc_profile, WIFI_LUNA_PREFS_ID);

		jvalue_ref parsedObj = {0};
		jschema_ref input_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT,
		                           NULL);

		if (!input_schema)
		{
			goto Exit;
		}

		JSchemaInfo schemaInfo;
		jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
		parsedObj = jdom_parse(j_cstr_to_buffer(dec_profile), DOMOPT_NOOPT,
		                       &schemaInfo);
		jschema_release(&input_schema);

		if (jis_null(parsedObj))
		{
			goto Exit;
		}

		gchar *ssid = NULL;
		GStrv security = NULL;

		if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
		{
			raw_buffer ssid_buf = jstring_get(ssidObj);
			ssid = g_strdup(ssid_buf.m_str);
			jstring_free_buffer(ssid_buf);
			ret = TRUE;
		}
		else
		{
			WCALOG_DEBUG("ssid object not found");
		}

		bool hidden = false;
		bool configured = false;

		if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("security"), &securityListObj))
		{
			ssize_t i, num_elems = jarray_size(securityListObj);
			security = (GStrv) g_new0(GStrv, num_elems + 1);

			for (i = 0; i < num_elems; i++)
			{
				jvalue_ref securityObj = jarray_get(securityListObj, i);
				raw_buffer security_buf = jstring_get(securityObj);
				security[i] = g_strdup(security_buf.m_str);
				jstring_free_buffer(security_buf);
			}

			security[num_elems] = NULL;
		}

		if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wasCreatedWithJoinOther"),
		                       &hiddenObj))
		{
			jboolean_get(hiddenObj, &hidden);
		}

		if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("configured"), &configuredObj))
		{
			jboolean_get(configuredObj, &configured);
		}

		// Converting bool to gboolean as create_new_profile expects gboolean
		if ((security != NULL &&
		        NULL == get_profile_by_ssid_security(ssid, security[0])) ||
		        ((security == NULL && NULL == get_profile_by_ssid(ssid))))
		{
			create_new_profile(ssid, security, hidden ? TRUE : FALSE,
			                   configured ? TRUE : FALSE);
		}

		g_strfreev(security);
		g_free(ssid);
Exit:
		j_release(&parsedObj);
		g_free(dec_profile);
		g_free(enc_profile);
	}

	return ret;
}

/**
 * @brief Get the values of given settings from luna-prefs
 *
 * The param data can be supplied for copying the values of settings
 * (Not required for WIFI_PROFILELIST_SETTING since this function
 * will update the wifi profile list itself
 */

gboolean load_wifi_setting(wifi_setting_type_t setting, void *data)
{
	LPErr lpErr = LP_ERR_NONE;
	LPAppHandle handle;
	char *setting_value = NULL;
	gboolean ret = FALSE;

	lpErr = LPAppGetHandle(WIFI_LUNA_PREFS_ID, &handle);

	if (lpErr)
	{
		WCALOG_ERROR(MSGID_SETTING_LPAPP_GET_ERROR, 1, PMLOGKS("PrefsId",
		             WIFI_LUNA_PREFS_ID), "");
		goto Exit;
	}

	lpErr = LPAppCopyValue(handle, SettingKey[setting], &setting_value);
	(void) LPAppFreeHandle(handle, false);

	if (lpErr)
	{
		WCALOG_ERROR(MSGID_SETTING_LPAPP_COPY_ERROR, 1, PMLOGKS("Key",
		             SettingKey[setting]), "");
		goto Exit;
	}


	switch (setting)
	{
		case WIFI_PROFILELIST_SETTING:
		{
			jvalue_ref parsedObj = {0};
			jschema_ref input_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT,
			                           NULL);

			if (!input_schema)
			{
				goto Exit;
			}

			JSchemaInfo schemaInfo;
			jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
			parsedObj = jdom_parse(j_cstr_to_buffer(setting_value), DOMOPT_NOOPT,
			                       &schemaInfo);
			jschema_release(&input_schema);

			if (jis_null(parsedObj))
			{
				goto Exit;
			}

			jvalue_ref profileListObj = {0};

			if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileList"),
			                       &profileListObj))
			{
				if (!jis_array(profileListObj))
				{
					goto Exit_Case;
				}

				ssize_t i, num_elems = jarray_size(profileListObj);

				for (i = 0; i < num_elems; i++)
				{
					jvalue_ref profileObj = jarray_get(profileListObj, i);

					// Parse json strings to create profiles and append them to profile list
					if (populate_wifi_profile(profileObj) == FALSE)
					{
						goto Exit_Case;
					}
				}

				ret = TRUE;
			}

Exit_Case:
			j_release(&parsedObj);
		}

		default:
			break;
	}

Exit:
	g_free(setting_value);
	return ret;
}

static void add_wifi_profile(jvalue_ref *profile_j, wifi_profile_t *profile)
{
	jobject_put(*profile_j, J_CSTR_TO_JVAL("ssid"), jstring_create(profile->ssid));
	jobject_put(*profile_j, J_CSTR_TO_JVAL("profileId"),
	            jnumber_create_i32(profile->profile_id));

	if (profile->hidden)
	{
		jobject_put(*profile_j, J_CSTR_TO_JVAL("wasCreatedWithJoinOther"),
		            jboolean_create(profile->hidden));
	}

	if (profile->configured)
	{
		jobject_put(*profile_j, J_CSTR_TO_JVAL("configured"),
		            jboolean_create(profile->configured));
	}

	if (profile->security != NULL)
	{
		jvalue_ref security_list = jarray_create(NULL);
		gsize i;

		for (i = 0; i < g_strv_length(profile->security); i++)
		{
			jarray_append(security_list, jstring_create(profile->security[i]));
		}

		jobject_put(*profile_j, J_CSTR_TO_JVAL("security"), security_list);
	}
}

static gchar *add_wifi_profile_list(void)
{
	if (profile_list_is_empty())
	{
		return NULL;
	}

	gchar *profile_list_str = NULL;
	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		jvalue_ref profilelist_j = jobject_create();
		jvalue_ref profilelist_arr_j = jarray_create(NULL);

		wifi_profile_t *profile = get_next_profile(NULL);

		while (NULL != profile)
		{
			jvalue_ref profileinfo_j = jobject_create();
			jvalue_ref profile_j = jobject_create();
			add_wifi_profile(&profile_j, profile);
			const gchar *profile_str = jvalue_tostring(profile_j, response_schema);
			gchar *enc_profile_str = wifi_setting_encrypt(profile_str, WIFI_LUNA_PREFS_ID);
			j_release(&profile_j);
			jobject_put(profileinfo_j, J_CSTR_TO_JVAL("wifiProfile"),
			            jstring_create(enc_profile_str));
			jarray_append(profilelist_arr_j, profileinfo_j);
			profile = get_next_profile(profile);
			g_free(enc_profile_str);
		}

		jobject_put(profilelist_j, J_CSTR_TO_JVAL("profileList"), profilelist_arr_j);
		profile_list_str = g_strdup(jvalue_tostring(profilelist_j, response_schema));
		jschema_release(&response_schema);
		j_release(&profilelist_j);
	}

	return profile_list_str;
}

/**
 * @brief Set the values of given settings in luna-prefs
 *
 * The param data can be supplied for providing the values of settings
 * (Not required for WIFI_PROFILELIST_SETTING since this function
 * will fetch from wifi profile list itself
 */

gboolean store_wifi_setting(wifi_setting_type_t setting, void *data)
{
	LPErr lpErr = LP_ERR_NONE;
	LPAppHandle handle;
	gboolean ret = FALSE;

	lpErr = LPAppGetHandle(WIFI_LUNA_PREFS_ID, &handle);

	if (lpErr)
	{
		WCALOG_ERROR(MSGID_SETTING_LPAPP_GET_ERROR, 1, PMLOGKS("PrefsId",
		             WIFI_LUNA_PREFS_ID), "");
		return FALSE;
	}

	switch (setting)
	{
		case WIFI_PROFILELIST_SETTING:
		{
			/* Convert list of profiles to json string for storing */
			lpErr = LPAppRemoveValue(handle, SettingKey[setting]);

			if (lpErr && (lpErr != LP_ERR_NO_SUCH_KEY))
			{
				WCALOG_ERROR(MSGID_SETTING_LPAPP_REMOVE_ERROR, 1, PMLOGKS("Key",
				             SettingKey[setting]), "");
				goto Exit;
			}

			char *profile_list_str = add_wifi_profile_list();

			if (NULL == profile_list_str)
			{
				WCALOG_DEBUG("No wifi profiles found");
				goto Exit;
			}

			lpErr = LPAppSetValue(handle, SettingKey[setting], profile_list_str);
			g_free(profile_list_str);

			if (lpErr)
			{
				WCALOG_ERROR(MSGID_SETTING_LPAPP_SET_ERROR, 1, PMLOGKS("Key",
				             SettingKey[setting]), "");
				goto Exit;
			}

			ret = TRUE;
			break;
		}

		default:
			break;
	}

Exit:
	(void) LPAppFreeHandle(handle, true);
	return ret;
}

static gboolean store_config(GKeyFile *keyfile, char *pathname)
{
	gchar *data = NULL;
	gsize length = 0;

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (length > 0)
	{
		FILE *fp;
		fp = g_fopen(pathname, "w");

		if (fp == NULL)
		{
			return FALSE;
		}

		fprintf(fp, "%s", data);
		fclose(fp);
	}

	g_free(data);

	return TRUE;
}

static GKeyFile *load_config(const char *pathname)
{
	GKeyFile *keyfile = NULL;
	GError *error = NULL;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, pathname, 0, &error))
	{
		g_clear_error(&error);

		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	return keyfile;
}

static gchar *build_config_path(const char *ssid, const char *security)
{
	return g_strdup_printf("%s/wifi_%s_%s.config", CONNMAN_SAVED_PROFILE_CONFIG_DIR,
	                       ssid, security);
}


gboolean store_enterprise_network_config_entries(GKeyFile *keyfile,
        const gchar *config_group, connection_settings_t *settings)
{
	if (settings->eap_type != NULL)
	{
		g_key_file_set_string(keyfile, config_group, "Type", "wifi");
		g_key_file_set_string(keyfile, config_group, "Name", settings->ssid);
		g_key_file_set_string(keyfile, config_group, "Security", "ieee8021x");
		g_key_file_set_string(keyfile, config_group, "EAP", settings->eap_type);
	}
	else
	{
		return FALSE;
	}

	if (settings->identity != NULL && strlen(settings->identity) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "Identity", settings->identity);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "Identity", NULL);
	}

	if (settings->ca_cert_file != NULL && strlen(settings->ca_cert_file) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "CACertFile",
		                      settings->ca_cert_file);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "CACertFile", NULL);
	}

	if (settings->client_cert_file != NULL &&
	        strlen(settings->client_cert_file) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "ClientCertFile",
		                      settings->client_cert_file);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "ClientCertFile", NULL);
	}

	if (settings->private_key_file != NULL &&
	        strlen(settings->private_key_file) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "PrivateKeyFile",
		                      settings->private_key_file);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "PrivateKeyFile", NULL);
	}

	if (settings->private_key_passphrase != NULL &&
	        strlen(settings->private_key_passphrase) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "PrivateKeyPassphrase",
		                      settings->private_key_passphrase);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "PrivateKeyPassphrase", NULL);
	}

	if (settings->phase2 != NULL && strlen(settings->phase2) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "Phase2", settings->phase2);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "Phase2", NULL);
	}

	if (settings->passphrase != NULL && strlen(settings->passphrase) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "Passphrase",
		                      settings->passphrase);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "Passphrase", NULL);
	}

	return TRUE;
}


gboolean store_network_config(connection_settings_t *settings,
                              const char *security)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = g_key_file_new();
	gboolean ret = FALSE;

	if (NULL == settings->ssid || NULL == security)
	{
		g_key_file_free(keyfile);
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", settings->ssid);

	pathname = build_config_path(settings->ssid, security);

	if (pathname == NULL)
	{
		goto cleanup;
	}

	g_key_file_set_string(keyfile, config_group, "Type", "wifi");
	g_key_file_set_string(keyfile, config_group, "Name", settings->ssid);

	if (settings->passkey != NULL && strlen(settings->passkey) > 0)
	{
		g_key_file_set_string(keyfile, config_group, "Passphrase", settings->passkey);
		g_key_file_set_string(keyfile, config_group, "Security", security);
	}
	else
	{
		g_key_file_remove_key(keyfile, config_group, "Passphrase", NULL);
	}

	if (settings->hidden)
	{
		g_key_file_set_boolean(keyfile, config_group, "Hidden", TRUE);
	}

	if (!g_strcmp0(security, WIFI_ENTERPRISE_SECURITY_TYPE))
	{
		if (store_enterprise_network_config_entries(keyfile, config_group,
		        settings) == FALSE)
		{
			goto cleanup;
		}
	}

	GStrv security_type = (GStrv) g_new0(GStrv, 2);
	security_type[0] = g_strdup(security);
	security_type[1] = NULL;

	wifi_profile_t *profile = get_profile_by_ssid_security(settings->ssid,
	                          security);

	if (NULL != profile)
	{
		delete_profile(profile);
	}

	create_new_profile(settings->ssid, security_type, settings->hidden, TRUE);

	ret = store_config(keyfile, pathname);

	send_getnetworks_status_to_subscribers();

	g_free(security_type);

cleanup:
	g_free(pathname);
	g_free(config_group);
	g_key_file_free(keyfile);
	return ret;
}

gboolean remove_network_config(const char *ssid, const char *security)
{
	gchar *pathname = NULL;
	gboolean ret = FALSE;

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	ret = (g_unlink(pathname) == 0);

	g_free(pathname);

	return ret;
}

gboolean change_network_passphrase(const char *ssid, const char *security,
                                   const char *passphrase)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = NULL;
	gboolean ret = FALSE;

	if (NULL == ssid || NULL == security || NULL == passphrase)
	{
		return FALSE;
	}

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	keyfile = load_config(pathname);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", ssid);

	g_key_file_set_string(keyfile, config_group, "Passphrase", passphrase);

	ret = store_config(keyfile, pathname);

	g_free(pathname);
	g_free(config_group);
	return ret;
}

gboolean change_network_ipv4(const char *ssid, const char *security,
                             const char *address, const char *netmask, const char *gateway)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = NULL;
	gboolean ret = FALSE;

	if (NULL == ssid || NULL == security || NULL == address || NULL == netmask ||
	        NULL == gateway)
	{
		return FALSE;
	}

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	keyfile = load_config(pathname);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", ssid);

	gchar *ipv4str = g_strdup_printf("%s/%s/%s", address, netmask, gateway);
	g_key_file_set_string(keyfile, config_group, "IPv4", ipv4str);

	ret = store_config(keyfile, pathname);

	g_free(ipv4str);
	g_free(pathname);
	g_free(config_group);
	return ret;
}


gboolean change_network_ipv6(const char *ssid, const char *security,
                             const char *address, const char *prefixLen, const char *gateway)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = NULL;
	gboolean ret = FALSE;

	if (NULL == ssid || NULL == security || NULL == address || NULL == prefixLen ||
	        NULL == gateway)
	{
		return FALSE;
	}

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	keyfile = load_config(pathname);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", ssid);

	gchar *ipv6str = g_strdup_printf("%s/%s/%s", address, prefixLen, gateway);
	g_key_file_set_string(keyfile, config_group, "IPv6", ipv6str);

	ret = store_config(keyfile, pathname);

	g_free(ipv6str);
	g_free(pathname);
	g_free(config_group);
	return ret;
}

gboolean change_network_dns(const char *ssid, const char *security,
                            const GStrv *dns)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = NULL;
	gboolean ret = FALSE;

	if (NULL == ssid || NULL == security || NULL == dns)
	{
		return FALSE;
	}

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	keyfile = load_config(pathname);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", ssid);

	gsize i, num_elems = g_strv_length(dns);
	gchar *dnsstr = g_strnfill(16 * (num_elems + 1), 0);

	for (i = 0; i < num_elems; i++)
	{
		dnsstr = strcat(dnsstr, dns[i]);

		if (i < (num_elems - 1))
		{
			dnsstr = strcat(dnsstr, ",");
		}
	}

	g_key_file_set_string(keyfile, config_group, "Nameservers", dnsstr);

	ret = store_config(keyfile, pathname);

	g_free(dnsstr);
	g_free(pathname);
	g_free(config_group);
	return ret;
}

gboolean change_network_remove_entry(const char *ssid, const char *security,
                                     const char *key)
{
	gchar *pathname = NULL, *config_group = NULL;
	GKeyFile *keyfile = NULL;
	gboolean ret = FALSE;

	if (NULL == ssid || NULL == security || NULL == key)
	{
		return FALSE;
	}

	pathname = build_config_path(ssid, security);

	if (pathname == NULL)
	{
		return FALSE;
	}

	keyfile = load_config(pathname);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	config_group = g_strdup_printf("service_%s", ssid);

	g_key_file_remove_key(keyfile, config_group, key, NULL);

	ret = store_config(keyfile, pathname);

	g_free(pathname);
	g_free(config_group);
	return ret;

}

/**
 * @brief For a given .config file, check if there is a profile present, if not create it
 */

gboolean check_profile_or_create(const char *file, gchar **pathname)
{
	GKeyFile *keyfile = NULL;
	char **groups;
	int i;
	gboolean ret = FALSE;

	keyfile = load_config(file);

	if (keyfile == NULL)
	{
		return FALSE;
	}

	groups = g_key_file_get_groups(keyfile, NULL);

	for (i = 0; groups[i] != NULL; i++)
	{
		char *ident, *type, *ssid, *security;
		gboolean hidden = FALSE, security_found = FALSE;

		if (g_str_has_prefix(groups[i], "service_") == FALSE)
		{
			continue;
		}

		ident = groups[i] + 8;

		if (strlen(ident) < 1)
		{
			continue;
		}

		// Read the type, ssid, security and hidden flag for this config file
		type = g_key_file_get_string(keyfile, groups[i], "Type", NULL);

		if (type == NULL || g_strcmp0(type, "wifi") != 0)
		{
			continue;
		}

		ssid = g_key_file_get_string(keyfile, groups[i], "Name", NULL);

		if (ssid == NULL || g_strcmp0(ssid, ident) != 0)
		{
			continue;
		}

		security = g_key_file_get_string(keyfile, groups[i], "Security", NULL);

		if (security == NULL)
		{
			security = g_strdup("none");
		}
		else
		{
			security_found = TRUE;
		}

		hidden = g_key_file_get_boolean(keyfile, groups[i], "Hidden", NULL);

		// This is the pathname of the config file with the format wifi_<SSID>_<security>.config
		*pathname = build_config_path(ssid, security);

		// Check if there is wifi profile already for this config file, else create one
		wifi_profile_t *profile = get_profile_by_ssid_security(ssid, security);

		if (profile == NULL)
		{
			gchar *security_type[2];
			security_type[0] = security;
			security_type[1] = NULL;
			create_new_profile(ssid, security_type, hidden, TRUE);
		}

		g_free(security);

		// Found a valid service_* entry, so skipping other service_* entries, if any
		ret = TRUE;
		break;
	}

	g_strfreev(groups);
	return ret;
}

/**
 * @brief Delete all configured profiles with no corresponding config file
 */
void delete_invalid_configured_profiles(void)
{
	GSList *iter = NULL;
	GSList *delete_profiles = NULL;

	wifi_profile_t *profile = NULL;

	while (NULL != (profile = get_next_profile(profile)))
	{
		if (profile->configured == FALSE)
		{
			continue;
		}
		else
		{
			gchar *pathname = build_config_path(profile->ssid, profile->security[0]);

			if (!pathname)
			{
				continue;
			}

			// if the corresponding .config file doesnt exist, delete the profile
			if (g_file_test(pathname, G_FILE_TEST_EXISTS) == FALSE)
			{
				delete_profiles = g_slist_prepend(delete_profiles, (gpointer) profile);
			}

			g_free(pathname);
		}
	}

	for (iter = delete_profiles; iter != NULL; iter = iter->next)
	{
		wifi_profile_t *profile = (wifi_profile_t *)(iter->data);
		delete_profile(profile);
	}

	g_slist_free(delete_profiles);
}


typedef struct rename_files
{
	gchar *oldpath;
	gchar *newpath;
} rename_files_t;

/**
 * @brief Check all .config files under CONNMAN_SAVED_PROFILE_CONFIG_DIR folder, and if a config file
 * is found with no corresponding profile, create one, however if a configured profile is found with
 * no .config file, delete the profile
 */
void sync_network_configs_with_profiles(void)
{
	GDir *dir;
	const gchar *file;
	GSList *rename_files_list = NULL;

	dir = g_dir_open(CONNMAN_SAVED_PROFILE_CONFIG_DIR, 0, NULL);

	if (!dir)
	{
		return;
	}

	while ((file = g_dir_read_name(dir)) != NULL)
	{
		if (g_str_has_suffix(file, ".config") == FALSE)
		{
			continue;
		}

		gchar *config_pathname = NULL;
		gchar *abs_filename = g_strdup_printf("%s/%s", CONNMAN_SAVED_PROFILE_CONFIG_DIR,
		                                      file);

		if (check_profile_or_create(abs_filename, &config_pathname) == FALSE)
		{
			g_free(abs_filename);
			continue;
		}

		if (config_pathname == NULL)
		{
			break;
		}

		// If the name of the config file doesn't match the wifi_<SSID>_<security>.config
		// format that we want, rename the file later
		if (g_strcmp0(abs_filename, config_pathname) != 0)
		{
			rename_files_t *fileptrs = g_new0(rename_files_t, 1);
			fileptrs->oldpath = abs_filename;
			fileptrs->newpath = config_pathname;
			rename_files_list = g_slist_prepend(rename_files_list, (gpointer) fileptrs);
		}
		else
		{
			g_free(config_pathname);
			g_free(abs_filename);
		}
	}

	g_dir_close(dir);

	GSList *iter = rename_files_list;

	while (iter != NULL)
	{
		rename_files_t *fileptrs = (rename_files_t *)(iter->data);
		g_rename(fileptrs->oldpath, fileptrs->newpath);
		g_free(fileptrs->oldpath);
		g_free(fileptrs->newpath);
		iter = iter->next;
		g_free(fileptrs);
	}

	delete_invalid_configured_profiles();
	g_slist_free(rename_files_list);
}


/**
 * @brief Callback function for any modifications to CONNMAN_SAVED_PROFILE_CONFIG_DIR folder
 */
static gboolean inotify_data(GIOChannel *channel, GIOCondition cond,
                             gpointer user_data)
{
	char buffer[256];
	char *next_event;
	gsize bytes_read;
	GIOStatus status;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
	{
		return FALSE;
	}

	status = g_io_channel_read_chars(channel, buffer,
	                                 sizeof(buffer) - 1, &bytes_read, NULL);

	switch (status)
	{
		case G_IO_STATUS_NORMAL:
			break;

		case G_IO_STATUS_AGAIN:
			return TRUE;

		default:
			WCALOG_DEBUG("Reading from inotify channel failed");
			return FALSE;
	}

	next_event = buffer;

	while (bytes_read > 0)
	{
		struct inotify_event *event;
		gchar *file;
		gsize len;

		event = (struct inotify_event *) next_event;

		if (event->len)
		{
			file = next_event + sizeof(struct inotify_event);
		}
		else
		{
			continue;
		}

		len = sizeof(struct inotify_event) + event->len;

		/* check if inotify_event block fit */
		if (len > bytes_read)
		{
			break;
		}

		next_event += len;
		bytes_read -= len;

		WCALOG_DEBUG("New event found for file %s, event mask : %lx", file,
		             event->mask);

		if (event->mask & IN_CREATE || event->mask & IN_MOVED_TO ||
		        event->mask & IN_MODIFY)
		{
			if (g_str_has_suffix(file, ".config") == FALSE)
			{
				continue;
			}

			gchar *config_pathname = NULL;
			gchar *abs_filename = g_strdup_printf("%s/%s", CONNMAN_SAVED_PROFILE_CONFIG_DIR,
			                                      file);
			if (check_profile_or_create(abs_filename, &config_pathname) == TRUE)
			{
				if (g_strcmp0(abs_filename, config_pathname) != 0)
				{
					g_rename(abs_filename, config_pathname);
				}
				g_free(config_pathname);
			}

			g_free(abs_filename);
		}

		if (event->mask & IN_DELETE || event->mask & IN_MOVED_FROM ||
		        event->mask & IN_MODIFY)
		{
			delete_invalid_configured_profiles();
		}
	}

	return TRUE;
}


int wd = 0;
GIOChannel *channel = NULL;
uint watch = 0;

/**
 * @brief Create a watch for any new file created/modified/deleted/moved in CONNMAN_SAVED_PROFILE_CONFIG_DIR folder
 */
gboolean create_config_inotify_watch(void)
{
	int fd;

	fd = inotify_init();

	if (fd < 0)
	{
		return FALSE;
	}

	wd = inotify_add_watch(fd, CONNMAN_SAVED_PROFILE_CONFIG_DIR,
	                       IN_MODIFY | IN_CREATE | IN_DELETE |
	                       IN_MOVED_TO | IN_MOVED_FROM);

	if (wd < 0)
	{
		close(fd);
		return FALSE;
	}

	channel = g_io_channel_unix_new(fd);

	if (channel == NULL)
	{
		inotify_rm_watch(fd, wd);
		close(fd);
		return FALSE;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	watch = g_io_add_watch(channel,
	                       G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
	                       inotify_data, NULL);

	return TRUE;
}

void remove_config_inotify_watch(void)
{
	int fd;

	if (channel == NULL)
	{
		return;
	}

	if (watch > 0)
	{
		g_source_remove(watch);
	}

	fd = g_io_channel_unix_get_fd(channel);

	if (wd >= 0)
	{
		inotify_rm_watch(fd, wd);
	}

	g_io_channel_unref(channel);
}
