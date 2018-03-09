// Copyright (c) 2015-2018 LG Electronics, Inc.
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
 * @file connman_counter.c
 *
 * @brief Connman counter interface
 * @brief connman_counter implements a wrapper around the dbus net.connman.Counter interface
 */

#include <string.h>

#include "connman_counter.h"
#include "logging.h"

#define COUNTER_DBUS_PATH           "/"

void connman_counter_parse_counter_data(GVariant *variant,
                                        connman_counter_data_t *data)
{
	GVariantIter iter;
	gchar *key;
	GVariant *value;

	if (!variant || !data)
	{
		return;
	}

	g_variant_iter_init(&iter, variant);

	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{
		if (g_strcmp0(key, "RX.Packets") == 0)
		{
			data->rx_packet = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "TX.Packets") == 0)
		{
			data->tx_packet = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "RX.Bytes") == 0)
		{
			data->rx_bytes = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "TX.Bytes") == 0)
		{
			data->tx_bytes = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "RX.Errors") == 0)
		{
			data->rx_errors = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "TX.Errors") == 0)
		{
			data->tx_errors = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "RX.Dropped") == 0)
		{
			data->rx_dropped = g_variant_get_uint32(value);
		}
		else if (g_strcmp0(key, "TX.Dropped") == 0)
		{
			data->tx_dropped = g_variant_get_uint32(value);
		}

		g_variant_unref(value);
		g_free(key);
	}
}

static gboolean usage_cb(ConnmanInterfaceAgent *interface,
                         GDBusMethodInvocation *invocation,
                         const gchar *path,
                         GVariant *home,
                         GVariant *roaming,
                         gpointer user_data)
{
	connman_counter_t *counter = user_data;

	if (NULL != counter && NULL != counter->usage_cb)
	{
		counter->usage_cb(path, home, roaming, counter->usage_data);
	}

	g_object_unref(invocation);
	return TRUE;
}

static gboolean release_cb(ConnmanInterfaceAgent *interface,
                           GDBusMethodInvocation *invocation,
                           gpointer user_data)
{
	g_object_unref(invocation);
	return TRUE;
}

static void bus_acquired_cb(GDBusConnection *connection, const gchar *name,
                            gpointer user_data)
{
	GError *error = NULL;
	connman_counter_t *counter = user_data;

	counter->path = g_strdup(COUNTER_DBUS_PATH);
	counter->interface = connman_interface_counter_skeleton_new();

	g_signal_connect(counter->interface, "handle-usage", G_CALLBACK(usage_cb),
	                 counter);
	g_signal_connect(counter->interface, "handle-release", G_CALLBACK(release_cb),
	                 counter);

	error = NULL;

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(
	        counter->interface), connection,
	                                      counter->path, &error))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_COUNTER_INIT_ERROR, error->message);
		g_error_free(error);
	}

	if (counter->registered_cb != NULL)
	{
		counter->registered_cb(counter->registered_data);
	}

	WCALOG_INFO(MSGID_COUNTER_EXPORT_SUCCESS, 0, "Counter successfully exported");
}

connman_counter_t *connman_counter_new(GSourceFunc _counter_usage_send_func)
{
	connman_counter_t *counter;

	counter = g_new0(connman_counter_t, 1);

	if (counter == NULL)
	{
		return NULL;
	}

	counter->bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
	                                 "com.webos.service.connectionmanager", G_BUS_NAME_OWNER_FLAGS_NONE,
	                                 bus_acquired_cb, NULL, NULL, counter, NULL);

	WCALOG_INFO(MSGID_CM_DATA_ACTIVITY, 0, "Initialize of the data usage timer.");
	counter->timer = g_new(struct data_usage_timer_params, 1);
	counter->timer->interval = 1;
	counter->timer->timeout  = g_timeout_add_seconds(counter->timer->interval,
	                           _counter_usage_send_func, NULL);

	return counter;
}

void connman_counter_free(connman_counter_t *counter)
{
	if (counter == NULL)
	{
		return;
	}

	g_bus_unown_name(counter->bus_id);

	if (counter->timer)
	{
		if (counter->timer->timeout > 0)
		{
			g_source_remove(counter->timer->timeout);
		}

		g_free(counter->timer);
	}

	g_free(counter->path);

	if (counter->interface)
	{
		g_object_unref(counter->interface);
	}

	g_free(counter);
}

gchar *connman_counter_get_path(connman_counter_t *counter)
{
	if (counter == NULL)
	{
		return NULL;
	}

	return counter->path;
}

void connman_counter_set_registered_callback(connman_counter_t *counter,
        connman_counter_registered_cb cb, gpointer user_data)
{
	if (counter == NULL)
	{
		return;
	}

	counter->registered_cb = cb;
	counter->registered_data = user_data;
}

void connman_counter_set_usage_callback(connman_counter_t *counter,
                                        connman_counter_usage_cb cb, gpointer user_data)
{
	if (counter == NULL)
	{
		return;
	}

	counter->usage_cb = cb;
	counter->usage_data = user_data;
}
