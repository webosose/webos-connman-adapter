// Copyright (c) 2013-2018 LG Electronics, Inc.
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
 * @file connman_service_discovery.c
 *
 * @brief Connman service discovery interface
 *
 */

#include "connman_service_discovery.h"
#include "connman_manager.h"
#include "common.h"

#include "logging.h"

static ConnmanInterfaceServiceDiscovery *sd = NULL;

static gboolean get_remote_service_discovery_object(void)
{
	if (sd == NULL)
	{
		GError *error = NULL;
		sd = connman_interface_service_discovery_proxy_new_for_bus_sync(
		         G_BUS_TYPE_SYSTEM,
		         G_DBUS_PROXY_FLAGS_NONE,
		         "net.connman", "/",
		         NULL,
		         &error);

		if (error)
		{
			return FALSE;
		}
	}

	return TRUE;
}

static void
discovery_response_cb(ConnmanInterfaceManager *proxy, const gchar *address,
                      const gint ref, const GVariant *tlv)
{
	connman_service_t *service = NULL;
	GSList *listnode = NULL;
	gchar *tlvstr = NULL, *tmpstr = NULL;

	GVariantIter *iter;
	guchar byte;
	g_variant_get(tlv, "ay", &iter);
	gsize tlvstr_len = g_variant_n_children(tlv) * 3;
	tlvstr = g_new0(gchar, tlvstr_len);

	while (g_variant_iter_loop(iter, "y", &byte))
	{
		if (!strlen(tlvstr))
		{
			snprintf(tlvstr, tlvstr_len, "0%x", byte);
		}
		else
		{
			tmpstr = g_strdup(tlvstr);
			snprintf(tlvstr, tlvstr_len, "%s 0%x", tmpstr, byte);
			g_free(tmpstr);
		}
	}

	g_variant_iter_free(iter);
	g_free(tlvstr);
}

gboolean connman_service_discovery_request(const connman_service_type type,
        const gchar *address, const gint version, const gchar *description,
        const gchar *query)
{
	if (NULL == address)
	{
		return FALSE;
	}

	GError *error = NULL;

	if (!get_remote_service_discovery_object())
	{
		return FALSE;
	}

	switch (type)
	{
		case CONNMAN_SERVICE_TYPE_UPNP:
			if (NULL == description)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_request_discover_upn_pservice_sync(sd,
			        address,
			        version, description, NULL, NULL, &error);
			break;

		case CONNMAN_SERVICE_TYPE_BONJOUR:
			if (NULL == query)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_request_discover_bonjour_service_sync(
			    sd, address,
			    query, NULL, NULL, &error);
			break;

		default:
			return FALSE;
	}

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_SERVICE_DISCOVERY_REQUEST_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	g_signal_connect(G_OBJECT(sd), "discovery-response",
	                 G_CALLBACK(discovery_response_cb), NULL);

	return TRUE;
}

gboolean connman_service_discovery_register(const connman_service_type type,
        const gchar *description, const gchar *query, const gchar *response)
{
	GError *error = NULL;

	if (!get_remote_service_discovery_object())
	{
		return FALSE;
	}

	switch (type)
	{
		case CONNMAN_SERVICE_TYPE_UPNP:
			if (NULL == description)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_register_upn_pservice_sync(sd,
			        description, NULL, &error);
			break;

		case CONNMAN_SERVICE_TYPE_BONJOUR:
			if (NULL == query)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_register_bonjour_service_sync(sd,
			        query, response, NULL, &error);
			break;

		default:
			return FALSE;
	}

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_SERVICE_DISCOVERY_REGISTER_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

gboolean connman_service_discovery_remove(const connman_service_type type,
        const gchar *description, const gchar *query)
{
	GError *error = NULL;

	if (!get_remote_service_discovery_object())
	{
		return FALSE;
	}

	switch (type)
	{
		case CONNMAN_SERVICE_TYPE_UPNP:
			if (NULL == description)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_remove_upn_pservice_sync(sd,
			        description, NULL, &error);
			break;

		case CONNMAN_SERVICE_TYPE_BONJOUR:
			if (NULL == query)
			{
				return FALSE;
			}

			connman_interface_service_discovery_call_remove_bonjour_service_sync(sd, query,
			        NULL, &error);
			break;

		default:
			return FALSE;
	}

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_SERVICE_DISCOVERY_REMOVE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}
