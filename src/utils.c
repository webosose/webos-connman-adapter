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

#include <glib.h>
#include <string.h>

#include "utils.h"

struct language_encodings
{
	const char *language;
	const char *encoding1;
	const char *encoding2;
	const char *encoding3;
};

static struct language_encodings encodings[] =
{
	{ "ko-KR", "EUC-KR", "ISO-2022-KR", "JOHAB" },
	{ "zh-Hans-CN", "EUC-CN", "GB2312", "GB18030" },
	{ "ja-JP", "EUC-JP", "SHIFT-JIS", NULL },
	{ NULL, NULL, NULL, NULL }
};

static struct language_encodings *get_encodings_for_language(const char *lang)
{
	int n;

	if (lang == NULL)
	{
		return NULL;
	}

	for (n = 0; encodings[n].language != NULL; n++)
	{
		if (g_strcmp0(encodings[n].language, lang) == 0)
		{
			return &encodings[n];
		}
	}

	return NULL;
}

char *convert_ssid_to_utf8(const gchar *ssid, gsize ssid_len,
                           const gchar *system_locale)
{
	struct language_encodings *laenc;
	const char *encoding1 = NULL;
	const char *encoding2 = NULL;
	const char *encoding3 = NULL;
	char *converted_ssid = NULL;

	if (ssid == NULL || ssid_len == 0)
	{
		return NULL;
	}

	laenc = get_encodings_for_language(system_locale);

	if (laenc == NULL)
	{
		encoding1 = "iso-8859-1";
		encoding2 = "windows-1251";
		encoding3 = NULL;
	}
	else
	{
		encoding1 = laenc->encoding1;
		encoding2 = laenc->encoding2;
		encoding3 = laenc->encoding3;
	}

	converted_ssid = g_convert(ssid, ssid_len, "UTF-8", encoding1,
	                           NULL, NULL, NULL);

	if (!converted_ssid && encoding2)
	{
		converted_ssid = g_convert(ssid, ssid_len, "UTF-8", encoding2,
		                           NULL, NULL, NULL);
	}

	if (!converted_ssid && encoding3)
	{
		converted_ssid = g_convert(ssid, ssid_len, "UTF-8", encoding3,
		                           NULL, NULL, NULL);
	}

	if (!converted_ssid)
		converted_ssid = g_convert_with_fallback(ssid, ssid_len,
		                 "UTF-8", encoding1, "?",
		                 NULL, NULL, NULL);

	return converted_ssid;
}

char *strip_prefix(const char *str, const char *prefix)
{
	if (!str || !prefix)
	{
		return NULL;
	}

	size_t prefix_len = strlen(prefix);
	size_t str_len = strlen(str);

	if (str_len < prefix_len)
	{
		return NULL;
	}

	if (strncmp(str, prefix, prefix_len) != 0)
	{
		return NULL;
	}

	size_t result_len = str_len - prefix_len;
	char *result = g_new0(char, result_len + 1);
	strncpy(result, str + prefix_len , result_len);

	return result;
}

static bool is_xstring(const char* string)
{
	if (!string)
	{
		return false;
	}

	size_t len = strlen(string);
	size_t i;

	for (i = 0; i < len; i++)
	{
		if (!g_ascii_isxdigit(string[i]))
		{
			return false;
		}
	}

	return true;
}

bool is_valid_wifi_passphrase(const char* passphrase, const char* security)
{
	if  (!passphrase || !security)
	{
		return false;
	}

	bool is_hex = is_xstring(passphrase);
	size_t len = strlen(passphrase);

	if (g_strcmp0(security, "wep") == 0)
	{
		/* valid passphrases are 5 or 13 chars
		 * if in hex - also 10 or 26 chars.
		 * */
		return ((len == 5 || len == 13) ||
		        (is_hex && (len == 10 || len == 26)));
	}
	else if (g_strcmp0(security, "psk") == 0)
	{
		/* valid passphrases are 8 .. 63 chars
		 * if in hex - 64 chars.
		 * */
		return (len >= 8 && (len <= 63 || (is_hex && len == 64)));
	}
	else
	{
		/**
		 * Don't know how to validate other security types.
		 */
		return true;
	}
}
