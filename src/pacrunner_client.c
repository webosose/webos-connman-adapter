// Copyright (c) 2016-2018 LG Electronics, Inc.
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
 * @file pacrunner_client.c
 *
 * @brief pacrunner client interface
 *
 */

#include "pacrunner_client.h"
#include "utils.h"
#include "logging.h"


gchar *pacrunner_client_find_proxy_for_url(pacrunner_client_t *client,
		const gchar *url, const gchar *host)
{
	if (NULL == client)
	{
		return NULL;
	}

	GError *error = NULL;
	gchar *proxy;

	pacrunner_interface_client_call_find_proxy_for_url_sync(client->remote,
				url, host, &proxy, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_PACRUNNER_CLIENT_FINDPROXYFORURL_ERROR, error->message);
		g_error_free(error);
		return NULL;
	}

	return proxy;
}

/**
 * Initialize a new client instance
 * (see header for API details)
 */

pacrunner_client_t *pacrunner_client_new(void)
{
	GError *error = NULL;
	pacrunner_client_t *client = g_new0(pacrunner_client_t, 1);

	if (client == NULL)
	{
		return NULL;
	}

	client->remote = pacrunner_interface_client_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM,
						G_DBUS_PROXY_FLAGS_NONE,
						"org.pacrunner", "/org/pacrunner/client",
						NULL,
						&error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_PACRUNNER_CLIENT_INIT_ERROR, error->message);
		g_error_free(error);
		g_free(client);
		return NULL;
	}

	return client;
}

/**
 * Free the client instance (see header for API details)
 */

void pacrunner_client_free(pacrunner_client_t *client)
{

	if (NULL == client)
	{
		return;
	}

	g_object_unref(client->remote);
	g_free(client);
	client = NULL;
}
