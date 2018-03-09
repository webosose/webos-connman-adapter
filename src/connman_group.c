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
 * @file connman_group.c
 *
 * @brief Connman group interface
 *
 */

#include "connman_group.h"
#include "connman_manager.h"
#include "logging.h"
#include "common.h"

/**
 * @brief Set the group's tethering property
 *
 * @param group Group object to operate on
 * @param enable TRUE to enable tethering or FALSE to disable it
 * @return TRUE if operation was successfull. FALSE otherwise.
 */

gboolean connman_group_set_tethering(connman_group_t *group, gboolean enable)
{
	if (NULL == group)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_group_call_set_property_sync(group->remote,
	        "Tethering",
	        g_variant_new_variant(g_variant_new_boolean(enable)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_GROUP_SET_PROPERTY_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	group->tethering = enable;
	return TRUE;
}

/**
 * @brief Disconnect from a connman group
 *
 * @param group Group object to operate on
 * @return TRUE if operation was successfull. FALSE otherwise.
 */

gboolean connman_group_disconnect(connman_group_t *group)
{
	if (NULL == group)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_group_call_disconnect_sync(group->remote, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_GROUP_DISCONNECT_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief Invite a peer to join the specified group
 *
 * @param group Group to which the specified peer should be invited
 * @param service Connman service object of the peer which should be invited.
 * @return TRUE if operation was successfull. FALSE otherwise.
 */

gboolean connman_group_invite_peer(connman_group_t *group,
                                   connman_service_t *service)
{
	if (NULL == group || NULL == service)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_group_call_invite_sync(group->remote, service->path, NULL,
	        &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_GROUP_INVITE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief Update a single property specified by it's key with a new value and clear
 * the old one
 *
 * @param group Group to which the specified peer should be invited
 * @param name Name of the property which was updated
 * @param val Value of the updated property.
 */

static void __connman_group_update_property(connman_group_t *group,
        const gchar *name, GVariant *val)
{
	if (!g_strcmp0(name, "Name"))
	{
		g_free(group->name);
		group->name = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(name, "Passphrase"))
	{
		g_free(group->passphrase);
		group->passphrase = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(name, "OwnerPath"))
	{
		g_free(group->group_owner);
		group->group_owner = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(name, "Owner"))
	{
		group->is_group_owner = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(name, "Persistent"))
	{
		group->is_persistent = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(name, "Tethering"))
	{
		group->tethering = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(name, "Freq"))
	{
		group->freq = g_variant_get_uint32(val);
	}
	else if (!g_strcmp0(name, "LocalAddress"))
	{
		g_free(group->local_address);
		group->local_address = g_variant_dup_string(val, NULL);
	}
}

/**
 * @brief Fetch the local address of the supplied group object.
 *
 * @param group Group to which the specified peer should be invited
 * @return TRUE if operation was successfull. FALSE otherwise.
 */

gboolean connman_group_get_local_address(connman_group_t *group)
{
	if (NULL == group)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *properties;
	gsize i;

	connman_interface_group_call_get_properties_sync(group->remote, &properties,
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_GROUP_GET_PROPERTIES_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		GVariant *val_v = g_variant_get_child_value(property, 1);
		GVariant *val = g_variant_get_variant(val_v);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (!g_strcmp0(key, "LocalAddress"))
		{
			__connman_group_update_property(group, key, val);
		}

		g_variant_unref(property);
		g_variant_unref(key_v);
		g_variant_unref(val_v);
		g_variant_unref(val);
	}

	g_variant_unref(properties);
	return TRUE;
}

static void property_changed_cb(ConnmanInterfaceTechnology *proxy,
                                const gchar *property,
                                GVariant *v, connman_group_t *group)
{
	GVariant *va = g_variant_get_child_value(v, 0);
	__connman_group_update_property(group, property, va);

	if (connman_update_callbacks->group_property_changed)
	{
		connman_update_callbacks->group_property_changed(group->path, property, va);
	}

	if (NULL != group->handle_property_change_fn)
	{
		(group->handle_property_change_fn)((gpointer) group, property, v);
	}

	if (NULL != manager->handle_groups_change_fn)
	{
		(manager->handle_groups_change_fn)((gpointer)manager, FALSE);
	}

	g_variant_unref(va);
}

/**
 * @brief Register for group's "properties_changed" signal, calling the provided function
 * whenever the callback function for the signal is called (see header for API details)
 *
 * @param group Group object the handler should be registered for
 * @param func The handler function.
 */

void connman_group_register_property_changed_cb(connman_group_t *group,
        connman_property_changed_cb func)
{
	if (NULL == func)
	{
		return;
	}

	group->handle_property_change_fn = func;
}

/**
 * Create a new group instance and set its properties (see header for API details)
 */

/**
 * @brief Create a new group instance and set its properties (see header for API details)
 *
 * @param variant Initial set of properties to initialize the group object with
 * @return The new created group object
 */

connman_group_t *connman_group_new(GVariant *variant)
{
	if (NULL == variant)
	{
		return NULL;
	}

	connman_group_t *group = g_new0(connman_group_t, 1);

	if (group == NULL)
	{
		return NULL;
	}

	GVariant *group_v = g_variant_get_child_value(variant, 0);
	GVariant *properties;
	gsize i;
	GError *error = NULL;

	group->path = g_variant_dup_string(group_v, NULL);

	group->remote = connman_interface_group_proxy_new_for_bus_sync(
	                    G_BUS_TYPE_SYSTEM,
	                    G_DBUS_PROXY_FLAGS_NONE, "net.connman",
	                    group->path, NULL, &error);
	g_variant_unref(group_v);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_GROUP_INIT_ERROR, error->message);
		g_error_free(error);
		g_free(group);
		return NULL;
	}

	group->sighandler_id = g_signal_connect_data(G_OBJECT(group->remote),
	                       "property-changed",
	                       G_CALLBACK(property_changed_cb), group, NULL, 0);

	properties = g_variant_get_child_value(variant, 1);

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		GVariant *val_v = g_variant_get_child_value(property, 1);
		GVariant *val = g_variant_get_variant(val_v);
		const gchar *key = g_variant_get_string(key_v, NULL);

		__connman_group_update_property(group, key, val);

		g_variant_unref(property);
		g_variant_unref(key_v);
		g_variant_unref(val_v);
		g_variant_unref(val);
	}

	g_variant_unref(properties);

	return group;
}

/**
 * @brief Free the group instance ( see header for API details)
 *
 * @param data Pointer to the group object to free
 * @param user_data User context data
 */

void connman_group_free(gpointer data, gpointer user_data)
{
	connman_group_t *group = (connman_group_t *)data;

	if (NULL == group)
	{
		return;
	}

	g_free(group->path);
	g_free(group->name);
	g_free(group->passphrase);
	g_free(group->group_owner);
	g_free(group->local_address);

	if (group->sighandler_id)
	{
		g_signal_handler_disconnect(G_OBJECT(group->remote), group->sighandler_id);
	}

	group->handle_property_change_fn = NULL;
	g_slist_free(group->peer_list);

	g_object_unref(group->remote);

	g_free(group);
	group = NULL;

}
