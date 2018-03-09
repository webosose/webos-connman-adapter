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
 * @file  connman_technology.h
 *
 * @brief Header file defining functions and data structures for interacting with connman technologies
 *
 */


#ifndef CONNMAN_TECHNOLOGY_H_
#define CONNMAN_TECHNOLOGY_H_

#include <gio/gio.h>
#include <glib-object.h>
#include <stdbool.h>

#include "connman_common.h"



/**
 * Local instance of a connman technology
 * Caches all required information for a technology
 */
typedef struct connman_technology
{
	ConnmanInterfaceTechnology *remote;
	gchar *type;
	gchar *name;
	gchar *path;
	gchar *p2p_identifier;
	gchar *country_code;
	gchar *diagnostic_info;
	gchar *tethering_identifier;
	gchar *tethering_passphrase;
	gboolean powered;
	gboolean connected;
	gboolean tethering;
	gboolean p2p;
	gboolean wfd;
	gboolean p2p_listen;
	gboolean persistent_mode;
	gboolean wfd_sessionavail;
	gboolean wfd_cpsupport;
	gboolean legacy_scan;
	connman_wfd_dev_type wfd_devtype;
	guint32 wfd_rtspport;
	guint32 multi_channel_mode;
	gulong property_changed_sighandler;
	connman_property_changed_cb handle_property_changed_fn;
	gulong sta_authorized_sighandler;
	connman_common_cb handle_sta_authorized_fn;
	gpointer sta_authorized_data;
	gulong sta_deauthorized_sighandler;
	connman_common_cb handle_sta_deauthorized_fn;
	gpointer sta_deauthorized_data;
	connman_common_cb handle_after_scan_fn;
	gpointer after_scan_data;

	gboolean removed; /* If true, the technology has been removed and should be deleted when callbacks complete*/
	gint32 calls_pending; /* Number of connman DBUS calls pending. */
} connman_technology_t;


/*
 * Properties for a particular interface in a given technology
 */
typedef struct connman_technology_interface
{
	guint32 rssi;
	guint32 link_speed;
	guint32 frequency;
	guint32 noise;
} connman_technology_interface_t;


/**
 * Power on/off the given technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE for power on, FALSE for off
 * @param[OUT] not_supported is set to true if changing power mode for this
 *             technology is not supported by connman. Left as-is otherwise.
 *             May be NULL, if don't care about supported,
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern int connman_technology_set_powered(connman_technology_t *technology,
        gboolean state, bool* not_supported);

/**
 * Enable/Disable tethering the given technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE for power on, FALSE for off
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_tethering(connman_technology_t
        *technology, gboolean state);

/**
 * Set the name of ssid used in tethering
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  tethering_identifier of the tethering
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_tethering_identifier(
    connman_technology_t *technology, const gchar *tethering_identifier);

/**
 * Set the name of passphrase used in tethering
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  tethering_passphrase of the tethering
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_tethering_passphrase(
    connman_technology_t *technology, const gchar *tethering_passphrase);

/**
 * Enable/disable wifi-direct technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE to enable P2P, FALSE otherwise
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_p2p(connman_technology_t *technology,
        gboolean state);

/**
 * Set the name of the device used in p2p communication
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  device_name Name of the device
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_p2p_identifier(connman_technology_t
        *technology, const gchar *device_name);

/**
 * Enable/disable WiFi Display technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE to enable WFD, FALSE otherwise
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_wfd(connman_technology_t *technology,
        gboolean state);

/**
 * Set the WFD device type
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  devtype Device type enum
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_wfd_devtype(connman_technology_t
        *technology, connman_wfd_dev_type devtype);

/**
 * Set the WFD session available bit
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  sessionavail Session available bit
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_wfd_sessionavail(
    connman_technology_t *technology, const gboolean sessionavail);

/**
 * Set the WFD cp support bit
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  cpsupport cp support bit
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_wfd_cpsupport(connman_technology_t
        *technology, const gboolean cpsupport);

/**
 * Set the WFD rtsp port
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  rtspport RTSP Port value
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_wfd_rtspport(connman_technology_t
        *technology, const guint32 rtspport);

/**
 * Enable/disable P2P listen state so that it can allow incoming connections
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE to enable listen state, FALSE otherwise
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_p2p_listen_state(
    connman_technology_t *technology, gboolean state);

/**
 * Enable/disable P2P persistent mode so that it can make persistent connections
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE to enable listen state, FALSE otherwise
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_p2p_persistent_mode(
    connman_technology_t *technology, gboolean state);

/**
 * Cancel any active P2P connection
 *
 * @param[IN]  technology A technology instance
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_cancel_p2p(connman_technology_t *technology);

/**
 * Start WPS authenticaiton
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  pin Pin for WPS-PIN mode
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_start_wps(connman_technology_t *technology,
        const gchar *pin);

/**
 * Cancel any active WPS connection
 *
 * @param[IN]  technology A technology instance
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_cancel_wps(connman_technology_t *technology);

/**
 * Delete stored p2p profiles
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  address Address of peer
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_delete_profile(connman_technology_t
        *technology, const gchar *address);

/**
 * Set multi channel scheduling mode
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  mode Either of 0/1/2
 * (0 -> fair scheduling, 1 -> Favour STA, 2-> Favour P2P)
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_multi_channel_mode(
    connman_technology_t *technology, const guint32 mode);

/**
 * Scan the network for available services
 * This is usually called to scan all wifi APs whenever the list of APs is requested
 *
 * @param[IN]  technology A technology instance
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_scan_network(connman_technology_t
        *technology, gboolean p2p);

/**
 * Set listen channel parameter for technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  channel number

 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_listen_channel(connman_technology_t *technology,
                                               const guint32 listen_channel);


/**
 * Set listen interval and period.
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  listen interval in ms
 * @param[IN]  listen period in ms.

 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_listen_params(connman_technology_t *technology,
                                              const gint32 period,
                                              const gint32 interval);

/**
 * Register for technology's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] technology A technology instance
 * @param[IN] func User function to register
 *
 */
extern void connman_technology_register_property_changed_cb(
    connman_technology_t *technology, connman_property_changed_cb func);

/**
 * @brief Register a handler for the technology's "TetheringStaAuthorized" signal.
 *
 * @param[IN] technology A technology instance
 * @param[IN] cb Handler function to register.
 * @param[IN] user_data User data passed with the callback when called.
 */
extern void connman_technology_register_sta_authorized_cb(
    connman_technology_t *technology, connman_common_cb cb, gpointer user_data);

/**
 * @brief Register a handler for the technology's "TetheringStaDeauthorized" signal.
 *
 * @param[IN] technology A technology instance
 * @param[IN] cb Handler function to register.
 * @param[IN] user_data User data passed with the callback when called.
 */
extern void connman_technology_register_sta_deauthorized_cb(
    connman_technology_t *technology, connman_common_cb cb, gpointer user_data);

/**
 * Fetch all the properties for a technology instance and save the new values
 * in technology fields.
 *
 * @param[IN] technology A technology instance
 *
 */
extern gboolean connman_technology_update_properties(connman_technology_t *technology);

/**
 * Fetch the properties for a particular interface of a technology instance
 *
 * @param[IN] technology A technology instance
 * @param[IN] interface Name of the interface
 * @param[OUT] interface_properties Populated connman_technology_interface_t struct for the interface
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_get_interface_properties(
    connman_technology_t *technology, const gchar *interface,
    connman_technology_interface_t *interface_properties);

/**
 * @brief Remove all saved services (marked as favorite) but not a single one handed as exception.
 *
 * @param technology A technology instance
 * @param exception Single service not to remove
 */
extern gboolean connman_technology_remove_saved_profiles(connman_technology_t
        *technology, gchar *exception);

/**
 * Create a new technology instance and set its properties
 *
 * @param[IN]  variant List of properties for a new technology
 *
 */
extern connman_technology_t *connman_technology_new(const gchar* path);

/**
 * Free the connman technology instance
 *
 * @param[IN] data Pointer to the technology to be freed
 */

extern void connman_technology_free(connman_technology_t *technology);

#endif /* CONNMAN_TECHNOLOGY_H_ */

