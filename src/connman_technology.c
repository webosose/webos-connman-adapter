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
 * @file connman_technology.c
 *
 * @brief Connman technology interface
 *
 */

#include "connman_technology.h"
#include "connman_manager.h"
#include "logging.h"

/**
 * Power on/off the given technology (see header for API details)
 */

gboolean connman_technology_set_powered(connman_technology_t *technology,
                                        gboolean state, bool* not_supported)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	/* don't set power again if we're already in the right power state */
	if (state == technology->powered)
	{
		return TRUE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "Powered",
	        g_variant_new_variant(g_variant_new_boolean(state)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_POWERED_ERROR, error->message);

		/**
		 * Match error message, connman does not return error codes.
		 * error->code is always 36.
		 */
		if (g_strcmp0(error->message,
		              "GDBus.Error:net.connman.Error.NotSupported: Not supported") == 0)
		{
			*not_supported = true;
		}

		g_error_free(error);
		return FALSE;
	}

	technology->powered = state;
	return TRUE;
}

/**
 * Enable/Disable tethering the given technology (see header for API details)
 */

extern gboolean connman_technology_set_tethering(connman_technology_t
        *technology, gboolean state)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "Tethering",
	        g_variant_new_variant(g_variant_new_boolean(state)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_TETHERING_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->tethering = state;
	g_usleep(1000000);
	return TRUE;
}

/**
 * Set the name of ssid used in tethering (see header for API details)
 */

extern gboolean connman_technology_set_tethering_identifier(
    connman_technology_t *technology, const gchar *tethering_identifier)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "TetheringIdentifier",
	        g_variant_new_variant(g_variant_new_string(tethering_identifier)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_TETHERING_IDENTIFIER_ERROR,
		                      error->message);
		g_error_free(error);
		return FALSE;
	}

	g_free(technology->tethering_identifier);
	technology->tethering_identifier = g_strdup(tethering_identifier);
	return TRUE;
}

/**
 * Set the name of ssid used in tethering (see header for API details)
 */

extern gboolean connman_technology_set_tethering_passphrase(
    connman_technology_t *technology, const gchar *tethering_passphrase)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "TetheringPassphrase",
	        g_variant_new_variant(g_variant_new_string(tethering_passphrase)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_TETHERING_PASSPHRASE_ERROR,
		                      error->message);
		g_error_free(error);
		return FALSE;
	}

	g_free(technology->tethering_passphrase);
	technology->tethering_passphrase = g_strdup(tethering_passphrase);
	return TRUE;
}

/**
 * Cancel any active P2P connection (see header for API details)
 */

gboolean connman_technology_cancel_p2p(connman_technology_t *technology)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_cancel_p2_p_sync(technology->remote, NULL,
	        &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_CANCEL_P2P_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Cancel any active WPS connection (see header for API details)
 */

gboolean connman_technology_cancel_wps(connman_technology_t *technology)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_cancel_wps_sync(technology->remote, NULL,
	        &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_CANCEL_WPS_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Start WPS authentication (see header for API details)
 */

gboolean connman_technology_start_wps(connman_technology_t *technology,
                                      const gchar *pin)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_start_wps_sync(technology->remote,
	        pin, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_START_WPS_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Set RemovePersistentInfo value to delete stored profiles (see header for API details)
 */

gboolean connman_technology_delete_profile(connman_technology_t *technology,
        const gchar *address)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "RemovePersistentInfo",
	        g_variant_new_variant(g_variant_new_string(address)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_DELETE_PROFILE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Set MultiChannelShedMode value to specified mode (see header for API details)
 */

gboolean connman_technology_set_multi_channel_mode(connman_technology_t
        *technology, const guint32 mode)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "MultiChannelSchedMode",
	        g_variant_new_variant(g_variant_new_uint32(mode)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_MULTI_CHANNEL_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->multi_channel_mode = mode;
	return TRUE;
}
/**
 * Set P2P state (see header for API details)
 */

gboolean connman_technology_set_p2p(connman_technology_t *technology,
                                    gboolean state)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "P2P",
	        g_variant_new_variant(g_variant_new_boolean(state)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_P2P_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->p2p = state;
	return TRUE;
}

/**
 * Set P2P identifier (see header for API details)
 */

gboolean connman_technology_set_p2p_identifier(connman_technology_t *technology,
        const gchar *device_name)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "P2PIdentifier",
	        g_variant_new_variant(g_variant_new_string(device_name)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_P2P_IDENTIFIER_ERROR,
		                      error->message);
		g_error_free(error);
		return FALSE;
	}

	g_free(technology->p2p_identifier);
	technology->p2p_identifier = g_strdup(device_name);
	return TRUE;
}

/**
 * Set WFD state (see header for API details)
 */

gboolean connman_technology_set_wfd(connman_technology_t *technology,
                                    gboolean state)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "WFD",
	        g_variant_new_variant(g_variant_new_boolean(state)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_WFD_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->wfd = state;
	return TRUE;
}

/**
 * Set WFDDevType (see header for API details)
 */

gboolean connman_technology_set_wfd_devtype(connman_technology_t *technology,
        connman_wfd_dev_type devtype)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "WFDDevType",
	        g_variant_new_variant(g_variant_new_uint16(devtype)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_WFD_DEVTYPE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	technology->wfd_devtype = devtype;
	return TRUE;
}

/**
 * Callback for the technology scan call after it finishes
 */

static void connman_technology_scan_callback(GObject *source_object,
        GAsyncResult *res, gpointer user_data)
{
	connman_technology_t *technology = user_data;
	ConnmanInterfaceTechnology *proxy = (ConnmanInterfaceTechnology *)
	                                    source_object;
	GError *error = NULL;

	/* Print eror if any, no functional purpose */
	connman_interface_technology_call_scan_finish(proxy, res, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SCAN_ERROR, error->message);
		g_error_free(error);
	}

	//Check if technology has been removed.
	technology->calls_pending -= 1;
	if (technology->removed)
	{
		if (technology->calls_pending == 0)
		{
			WCALOG_DEBUG("Freeing removed technology after async call");
			connman_technology_free(technology);
		}
		return;
	}

	if (technology->handle_after_scan_fn)
	{
		technology->handle_after_scan_fn(technology->after_scan_data);
	}
}

/**
 * Scan the network for available services asynchronously (see header for API details)
 */

gboolean connman_technology_scan_network(connman_technology_t *technology,
        gboolean p2p)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	technology->calls_pending += 1;
	connman_interface_technology_call_scan(technology->remote,
	                                       NULL, connman_technology_scan_callback,
	                                       (gpointer)technology);

	return TRUE;
}

gboolean connman_technology_remove_saved_profiles(connman_technology_t
        *technology, gchar *exception)
{
	GError *error = NULL;

	if (NULL == technology)
	{
		return FALSE;
	}

	connman_interface_technology_call_remove_saved_services_sync(technology->remote,
	        exception, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SAVED_SERVICES_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

gboolean connman_technology_set_listen_params(connman_technology_t *technology,
        const gint32 period, const gint32 interval)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GVariantBuilder *listen_params_b;
	GVariant *listen_params_v;
	listen_params_b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(listen_params_b, "{sv}", "Period",
	                      g_variant_new_int32(period));
	g_variant_builder_add(listen_params_b, "{sv}", "Interval",
	                      g_variant_new_int32(interval));
	listen_params_v = g_variant_builder_end(listen_params_b);
	g_variant_builder_unref(listen_params_b);

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "P2PListenParams",
	        g_variant_new_variant(listen_params_v),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_LISTEM_PARAMS_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

gboolean connman_technology_set_listen_channel(connman_technology_t *technology,
        const guint32 listen_channel)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
	        "P2PListenChannel",
	        g_variant_new_variant(g_variant_new_uint32(listen_channel)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_LISTEM_CHANNEL_ERROR,
		                      error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

gboolean connman_technology_set_go_intent(connman_technology_t *technology, const guint32 go_intent)
{
	if(NULL == technology)
		return FALSE;

	GError *error = NULL;

	connman_interface_technology_call_set_property_sync(technology->remote,
			"P2PGOIntent",
			g_variant_new_variant(g_variant_new_uint32(go_intent)),
			NULL, &error);
	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_SET_GO_INTENT_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Stores new property value.
 */
static void set_property_value(connman_technology_t *technology,
                               const gchar * key,
                               GVariant *val)
{
	if (!g_strcmp0(key, "Type"))
	{
		g_free(technology->type);
		technology->type = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "Name"))
	{
		g_free(technology->name);
		technology->name = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "Powered"))
	{
		technology->powered = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "Connected"))
	{
		technology->connected = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "P2P"))
	{
		technology->p2p = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "P2PIdentifier"))
	{
		g_free(technology->p2p_identifier);
		technology->p2p_identifier = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "WFD"))
	{
		technology->wfd = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "P2PListen"))
	{
		technology->p2p_listen = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "P2PPersistent"))
	{
		technology->persistent_mode = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "LegacyScan"))
	{
		technology->legacy_scan = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "WFDDevType"))
	{
		technology->wfd_devtype = (connman_wfd_dev_type) g_variant_get_uint16(val);
	}
	else if (!g_strcmp0(key, "WFDSessionAvail"))
	{
		technology->wfd_sessionavail = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "WFDCPSupport"))
	{
		technology->wfd_cpsupport = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "WFDRtspPort"))
	{
		technology->wfd_rtspport = g_variant_get_uint32(val);
	}
	else if (!g_strcmp0(key, "MultiChannelSchedMode"))
	{
		technology->multi_channel_mode = g_variant_get_uint32(val);
	}
	else if (!g_strcmp0(key, "DiagnosticInfo"))
	{
		g_free(technology->diagnostic_info);
		technology->diagnostic_info = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "Tethering"))
	{
		technology->tethering = g_variant_get_boolean(val);
	}
	else if (!g_strcmp0(key, "TetheringIdentifier"))
	{
		g_free(technology->tethering_identifier);
		technology->tethering_identifier = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "TetheringPassphrase"))
	{
		g_free(technology->tethering_passphrase);
		technology->tethering_passphrase = g_variant_dup_string(val, NULL);
	}
	else if (!g_strcmp0(key, "CountryCode"))
	{
		g_free(technology->country_code);
		technology->country_code = g_variant_dup_string(val, NULL);
	}
}

/**
 * Callback for technology's "property_changed" signal
 */
static void
property_changed_cb(ConnmanInterfaceTechnology *proxy, const gchar *property,
                    GVariant *v, gpointer user_data)
{
	connman_technology_t *technology = user_data;

	WCALOG_DEBUG("Property %s updated for technology %s", property,
	             technology->name);
	GVariant *val = g_variant_get_variant(v);

	set_property_value(technology, property, val);

	/** Notify wca-support */
	if (connman_update_callbacks->technology_property_changed)
	{
		connman_update_callbacks->technology_property_changed(technology->path,
		                                                      property, val);
	}

	/** Notify internal handlers */
	if (NULL != technology->handle_property_changed_fn)
	{
		(technology->handle_property_changed_fn)((gpointer)technology, property, v);
	}

	g_variant_unref(val);
}

/**
 * Get all properties for a technology.
 * Returns the returned GVariant or null if failed.
 * The caller needs to release the result.
 */

static GVariant* connman_technology_get_properties(connman_technology_t *technology)
{
	if (NULL == technology)
	{
		return NULL;
	}

	GError *error = NULL;
	GVariant *properties;
	gsize i;

	connman_interface_technology_call_get_properties_sync(technology->remote,
	        &properties, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_GET_PROPERTIES_ERROR, error->message);
		g_error_free(error);
		return NULL;
	}

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		GVariant *val_v = g_variant_get_child_value(property, 1);
		GVariant *val = g_variant_get_variant(val_v);
		const gchar *key = g_variant_get_string(key_v, NULL);

		set_property_value(technology, key, val);

		g_variant_unref(property);
		g_variant_unref(key_v);
		g_variant_unref(val_v);
		g_variant_unref(val);
	}

	return properties;
}

/**
 * Get all properties for a technology (see header for API details)
 */

gboolean connman_technology_update_properties(connman_technology_t *technology)
{
	GVariant *properties = connman_technology_get_properties(technology);

	if (NULL == properties)
	{
		return FALSE;
	}

	g_variant_unref(properties);
	return TRUE;
}

/**
 * Get all properties for a given interface for a technology (see header for API details)
 */

gboolean connman_technology_get_interface_properties(connman_technology_t
        *technology, const gchar *interface,
        connman_technology_interface_t *interface_properties)
{
	if (NULL == technology)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *properties;
	gsize i;

	connman_interface_technology_call_get_interface_properties_sync(
	    technology->remote, interface, &properties, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_GET_INTERFACE_PROPERTIES_ERROR,
		                      error->message);
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

		if (!g_strcmp0(key, "WiFi.RSSI"))
		{
			interface_properties->rssi = g_variant_get_uint32(val);
		}

		else if (!g_strcmp0(key, "WiFi.LinkSpeed"))
		{
			interface_properties->link_speed = g_variant_get_uint32(val);
		}

		else if (!g_strcmp0(key, "WiFi.Frequency"))
		{
			interface_properties->frequency = g_variant_get_uint32(val);
		}

		else if (!g_strcmp0(key, "WiFi.Noise"))
		{
			interface_properties->noise = g_variant_get_uint32(val);
		}

		g_variant_unref(property);
		g_variant_unref(key_v);
		g_variant_unref(val_v);
		g_variant_unref(val);
	}

	g_variant_unref(properties);
	return TRUE;
}

/**
 * Register for technology's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_technology_register_property_changed_cb(connman_technology_t
        *technology, connman_property_changed_cb cb)
{
	if (!cb || !technology)
	{
		return;
	}

	technology->handle_property_changed_fn = cb;
}

/**
 * Register a handler for the technology's "TetheringStaAuthorized" signal.
 */
void connman_technology_register_sta_authorized_cb(connman_technology_t
        *technology, connman_common_cb cb, gpointer user_data)
{
	if (!cb || !technology)
	{
		return;
	}

	technology->handle_sta_authorized_fn = cb;
	technology->sta_authorized_data = user_data;
}

static void tethering_sta_authorized_cb(ConnmanInterfaceTechnology *proxy,
                                        gpointer user_data)
{
	connman_technology_t *technology = user_data;

	if (technology->handle_sta_authorized_fn)
	{
		technology->handle_sta_authorized_fn(technology->sta_authorized_data);
	}
}

/**
 * Register a handler for the technology's "TetheringStaUnauthorized" signal.
 */
void connman_technology_register_sta_deauthorized_cb(connman_technology_t
        *technology, connman_common_cb cb, gpointer user_data)
{
	if (!cb || !technology)
	{
		return;
	}

	technology->handle_sta_deauthorized_fn = cb;
	technology->sta_deauthorized_data = user_data;
}

static void tethering_sta_deunauthorized_cb(ConnmanInterfaceTechnology *proxy,
        gpointer user_data)
{
	connman_technology_t *technology = user_data;

	if (technology->handle_sta_deauthorized_fn)
	{
		technology->handle_sta_deauthorized_fn(technology->sta_deauthorized_data);
	}
}

/**
 * Create a new technology instance and set its properties (see header for API details)
 */

connman_technology_t *connman_technology_new(const gchar* path)
{
	if (NULL == path)
	{
		return NULL;
	}

	connman_technology_t *technology = g_new0(connman_technology_t, 1);
	GError *error = NULL;

	technology->path = g_strdup(path);

	technology->remote = connman_interface_technology_proxy_new_for_bus_sync(
	                         G_BUS_TYPE_SYSTEM,
	                         G_DBUS_PROXY_FLAGS_NONE,
	                         "net.connman",
	                         technology->path,
	                         NULL,
	                         &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TECHNOLOGY_INIT_ERROR, error->message);
		g_error_free(error);
		goto error;
	}

	technology->property_changed_sighandler = g_signal_connect_data(G_OBJECT(
	            technology->remote), "property-changed",
	        G_CALLBACK(property_changed_cb), technology, NULL, 0);

	technology->sta_authorized_sighandler = g_signal_connect_data(G_OBJECT(
	        technology->remote), "tethering-sta-authorized",
	                                        G_CALLBACK(tethering_sta_authorized_cb), technology, NULL, 0);
	technology->sta_deauthorized_sighandler = g_signal_connect_data(G_OBJECT(
	            technology->remote), "tethering-sta-deauthorized",
	        G_CALLBACK(tethering_sta_deunauthorized_cb), technology, NULL, 0);

	/* If connman has a change in it's properties while we process the data and
	 * before we register the signals, we do not get the update.
	 * So, we need to get all that information from connman again.
	 */
	GVariant* properties = connman_technology_get_properties(technology);

	if (NULL == properties)
	{
		goto error;
	}

	if (connman_update_callbacks->technology_added)
	{
		connman_update_callbacks->technology_added(technology->path, properties);
	}

	g_variant_unref(properties);

	return technology;

error:
	connman_technology_free(technology);
	return NULL;
}

/**
 * Free the technology instance ( see header for API details)
 * Note that this method is partially re-enterable - callback handler might re-call it.
 *
 */

void connman_technology_free(connman_technology_t *technology)
{
	if (NULL == technology)
	{
		return;
	}

	/** Remove signal handlers even if async calls are in progress */
	if (technology->property_changed_sighandler)
	{
		g_signal_handler_disconnect(G_OBJECT(technology->remote),
		                            technology->property_changed_sighandler);
		technology->property_changed_sighandler = 0;
	}

	if (technology->sta_authorized_sighandler)
	{
		g_signal_handler_disconnect(G_OBJECT(technology->remote),
		                            technology->sta_authorized_sighandler);
		technology->sta_authorized_sighandler = 0;
	}

	if (technology->sta_deauthorized_sighandler)
	{
		g_signal_handler_disconnect(G_OBJECT(technology->remote),
		                            technology->sta_deauthorized_sighandler);
		technology->sta_deauthorized_sighandler = 0;
	}

	/* If async call to technology is in progress, scan callback will free the technology. */
	if (technology->calls_pending > 0)
	{
		WCALOG_DEBUG("Not freeing removed technology - %d async calls in progress", technology->calls_pending);
		technology->removed = true;
		return;
	}

	g_free(technology->path);
	technology->path = NULL;
	g_free(technology->type);
	technology->type = NULL;
	g_free(technology->name);
	technology->name = NULL;
	g_free(technology->p2p_identifier);
	g_free(technology->country_code);
	g_free(technology->diagnostic_info);
	g_free(technology->tethering_identifier);
	g_free(technology->tethering_passphrase);

	g_object_unref(technology->remote);
	technology->remote = NULL;

	g_free(technology);
}
