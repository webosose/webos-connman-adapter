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

#ifndef UTILS_H_
#define UTILS_H_

#include <stdbool.h>

#define UNUSED(x) (void)(x)

struct cb_data
{
	void *cb;
	void *data;
	void *user;
};

static inline struct cb_data *cb_data_new(void *cb, void *data)
{
	struct cb_data *ret;

	ret = g_new0(struct cb_data, 1);
	ret->cb = cb;
	ret->data = data;
	ret->user = NULL;

	return ret;
}

char *convert_ssid_to_utf8(const gchar *ssid, gsize ssid_len,
                           const gchar *system_locale);

char *strip_prefix(const char *str, const char *prefix);

bool is_valid_wifi_passphrase(const char* passphrase, const char* security);

#endif
