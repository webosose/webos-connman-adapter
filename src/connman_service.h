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
 * @file  connman_service.h
 *
 * @brief Header file defining functions and data structures for interacting with connman services
 *
 */

#ifndef CONNMAN_SERVICE_H_
#define CONNMAN_SERVICE_H_

#include "connman_common.h"

typedef void (*connman_p2p_request_cb)(gpointer, const int, const gchar *,
                                       const gchar *, const gchar *);

/**
 * IPv4 information structure for the service
 *
 * Includes method (dhcp/manual), ip address, netmask and gateway address
 */
typedef struct ipv4info
{
	gchar *method;
	gchar *address;
	gchar *netmask;
	gchar *gateway;
} ipv4info_t;

/**
 * IPv6 information structure for the service
 *
 * Includes method (auto/manual), ip address, prefix length and gateway address
 */
typedef struct ipv6info
{
	gchar *method;
	gchar *address;
	gint prefix_length;
	gchar *gateway;
} ipv6info_t;

/**
 * IP information for the service
 *
 * Includes interface name and dns server list along with IPv4 information
 */
typedef struct ipinfo
{
	gchar *iface;
	ipv4info_t ipv4;
	GStrv dns;
	ipv6info_t ipv6;
} ipinfo_t;

/**
 * Proxy information for the service
 *
 */
typedef struct proxyinfo
{
	gchar *method;
	gchar *url;
	GStrv servers;
	GStrv excludes;
} proxyinfo_t;

/**
 * BSSinformation for the service
 *
 */
typedef struct bssinfo
{
	gchar bssid[18]; /* "20:AA:4B:DB:C5:A8" */
	gint signal;
	gint frequency;
} bssinfo_t;

typedef struct peer
{
	gchar *address;
	gboolean group_owner;
	gboolean wfd_enabled;
	gboolean wfd_sessionavail;
	gboolean wfd_cpsupport;
	guint16 config_method;
	connman_wfd_dev_type wfd_devtype;
	guint32 wfd_rtspport;
	gchar *service_discovery_response;
} peer_t;

/**
 * Local instance of a connman service
 *
 * Caches all the required information about a service
 */

/* com.webos.service.wifi/findnetworks */
#define CONNMAN_SERVICE_CHANGE_CATEGORY_FINDNETWORKS    1
/* com.webos.service.connectionmanager/getstatus */
#define CONNMAN_SERVICE_CHANGE_CATEGORY_GETSTATUS       2

typedef struct connman_service
{
	/** Remote instance */
	ConnmanInterfaceService *remote;
	gchar *path;
	gchar *identifier;
	gchar *name; /* Service name, can be null for hidden wifi networks */
	gchar *display_name; /* Service display name, can be null for hidden wifi networks */
	gchar *state;
	gchar *error;
	gchar *address;

	guchar strength;
	GStrv security;
	gboolean auto_connect;
	/* Set to true while service is disconnecting.
	 * To handle intermediate state changes while disconnecting.
	 **/
	gboolean disconnecting;
	gboolean immutable;
	gboolean favorite;
	gboolean hidden;
	gboolean online;
	gboolean online_checking;
	gint type;
	ipinfo_t ipinfo;
	proxyinfo_t proxyinfo;
	GStrv hostroutes;
	gulong sighandler_id;
	peer_t peer;

	/**
	 * Called on select properties only:
	 * - Online
	 * - State
	 */
	connman_property_changed_cb handle_property_change_fn;
	connman_p2p_request_cb handle_p2p_request_fn;

	/** Array of bssinfo */
	GArray* bss;

	/* this is a indicator for the connection manager status update wether something has
	 * changed which needs to be send as update to the user */
	gboolean is_changed;
	unsigned int change_mask;

	gchar *ssid; /* Wifi service ssid, can be null for hidden networks */
	gsize ssid_len;
	GCancellable *cancellable;
} connman_service_t;

/**
 * Enum for service types
 */
typedef enum
{
	CONNMAN_SERVICE_TYPE_UNKNOWN = 0,
	CONNMAN_SERVICE_TYPE_ETHERNET,
	CONNMAN_SERVICE_TYPE_WIFI,
	CONNMAN_SERVICE_TYPE_P2P,
	CONNMAN_SERVICE_TYPE_CELLULAR,
	CONNMAN_SERVICE_TYPE_BLUETOOTH,
	CONNMAN_SERVICE_TYPE_MAX
} connman_service_types;

/**
 * Enum for service states
 */
enum
{
	CONNMAN_SERVICE_STATE_UNKNOWN       = 0,
	CONNMAN_SERVICE_STATE_IDLE,
	CONNMAN_SERVICE_STATE_ASSOCIATION,
	CONNMAN_SERVICE_STATE_CONFIGURATION,
	CONNMAN_SERVICE_STATE_READY,
	CONNMAN_SERVICE_STATE_ONLINE,
	CONNMAN_SERVICE_STATE_DISCONNECT,
	CONNMAN_SERVICE_STATE_FAILURE
};

#define WPS_DISPLAY 1
#define WPS_PBC 4
#define WPS_KEYPAD  5

/**
 * Callback function letting callers handle remote "connect" call responses
 */
typedef void (*connman_service_connect_cb)(gboolean success,
        gpointer user_data);

/**
 * Check if the type of the service is wifi
 *
 * @param[IN]  service A service instance
 *
 * @return TRUE if the service has "wifi" type
 */
extern gboolean connman_service_type_wifi(connman_service_t *service);

/**
 * Check if the type of the service is ethernet
 *
 * @param[IN]  service A service instance
 *
 * @return TRUE if the service has "ethernet" type
 */
extern gboolean connman_service_type_ethernet(connman_service_t *service);

/**
 * Check if the type of the service is p2p
 *
 * @param[IN]  service A service instance
 *
 * @return TRUE if the service has "Peer" type
 */
extern gboolean connman_service_type_p2p(connman_service_t *service);

/**
* Check if the type of the service is wan
*
* @param[IN]  service A service instance
*
* @return TRUE if the service has "wan" type
*/
extern gboolean connman_service_type_wan(connman_service_t *service);

/**
* Check if the type of the service is bluetooth
*
* @param[IN]  service A service instance
*
* @return TRUE if the service has "bluetooth" type
*/
extern gboolean connman_service_type_bluetooth(connman_service_t *service);

/**
 * Stringify the service connection status to corresponding webos state
 * This function is required to send appropriate connection status to the webos world.
 *
 * @param[IN]  connman_state Enum representing service state
 *
 * @return String representing connection state in webos world.
 */
extern gchar *connman_service_get_webos_state(int connman_state);

/**
 * Convert the connection state string to its enum value
 *
 * @param[IN]  state String from service's "State" property
 *
 * @return Enum value
 */
extern int connman_service_get_state(const gchar *state);

/**
 * Connect to a remote connman service
 *
 * @param[IN]  service A service instance (to connect)
 * @param[IN]  cb Callback called when connect call returns
 * @param[IN]  user_data User data (if any) to pass with the callback function
 *             See "connman_service_connect_cb" function pointer above
 *
 * @return FALSE if the connect call failed , TRUE otherwise
 */
extern gboolean connman_service_connect(connman_service_t *service,
                                        connman_service_connect_cb cb, gpointer user_data);

/**
 * Disconnect from a remote connman service
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the disconnect call failed, TRUE otherwise
 */
extern gboolean connman_service_disconnect(connman_service_t *service);

/**
 * Reject incoming P2P connection from another peer device
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the disconnect call failed, TRUE otherwise
 */
extern gboolean connman_service_reject_peer(connman_service_t *service);

/**
 * remove a remote connman service
 *
 * @param[in]  service a service instance
 *
 * @return false if the remove call failed, true otherwise
 */
extern gboolean connman_service_remove(connman_service_t *service);


/**
 * @brief  Sets ipv4 properties for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  ipv4 Ipv4 structure
 *
 * @return FALSE if the call to set "IPv4.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_ipv4(connman_service_t *service,
        ipv4info_t *ipv4);

/**
 * @brief  Sets ipv6 properties for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  ipv4 Ipv6 structure
 *
 * @return FALSE if the call to set "IPv6.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_ipv6(connman_service_t *service, ipv6info_t *ipv6);

/**
 * @brief  Sets proxy properties for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  proxyinfo proxyinfo structure
 *
 * @return FALSE if the call to set "Proxy.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_proxy(connman_service_t *service,
        proxyinfo_t *proxyinfo);

/**
 * @brief  Sets nameservers for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  dns DNS server list
 *
 * @return FALSE if the call to set "Nameservers.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_nameservers(connman_service_t *service,
        GStrv dns);

/**
 * Set the "autoconnect" flag for a service
 *
 * @param[IN]  service A service instance
 * @param[IN]  value New autoconnet value (TRUE/FALSE)
 *
 * @return FALSE if the call to set "AutoConnect" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_autoconnect(connman_service_t *service,
        gboolean value);

/**
 * Get all the network related information for a connected service (in online state)
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the call to get properties failed, TRUE otherwise
 */
extern gboolean connman_service_get_ipinfo(connman_service_t *service);

/**
 * Get all the proxy related information for a connected service
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the call to get properties failed, TRUE otherwise
 */
extern gboolean connman_service_get_proxyinfo(connman_service_t *service);

/**
 * Retrieve the list of properties for a service
 *
 * @param[IN] service A service instance
 *
 * @return GVariant pointer listing service properties, NULL if the call to
           get service properties failed
 */

extern GVariant *connman_service_fetch_properties(connman_service_t *service);

/**
 * Update service properties from the supplied variant
 *
 * @param[IN] service A service instance
 * @param[IN] service_v GVariant structure listing service properties
 */
extern void connman_service_update_properties(connman_service_t *service,
        GVariant *service_v);

/**
 * Register for service's property changed signal, calling the provided function whenever the callback function
 * for the signal is called and either the service state or online flag has changed
 *
 * @param[IN] service A service instance
 * @param[IN] func User function to register
 *
 */
extern void connman_service_register_property_changed_cb(
    connman_service_t *service, connman_property_changed_cb func);

/**
 * Register for incoming P2P requests, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] service A service instance
 * @param[IN] func User function to register
 *
 */
extern void connman_service_register_p2p_requests_cb(connman_service_t *service,
        connman_p2p_request_cb func);

/**
 * Gets hostroutes for the connman service
 *
 * @param[IN] service A service instance
 * @param[IN] hostroutes Hostroutes
 */
gboolean connman_service_set_hostroutes(connman_service_t *service, GStrv hostroutes);

/**
 * Create a new connman service instance and set its properties
 *
 * @param[IN] variant List of properties for a new service
 */
extern connman_service_t *connman_service_new(GVariant *variant);

/**
 * Free the connman service instance
 *
 * @param[IN] data Pointer to the service to be freed
 * @param[IN] user_data User data if any
 */
extern void connman_service_free(gpointer data, gpointer user_data);

extern void connman_service_unset_changed(connman_service_t *service,
        unsigned int category);
extern void connman_service_set_changed(connman_service_t *service,
                                        unsigned int category);
extern gboolean connman_service_is_changed(connman_service_t *service,
        unsigned int category);
extern void connman_service_update_display_name(connman_service_t *service);


extern gboolean connman_service_set_run_online_check(connman_service_t *service,
        gboolean value);
extern gboolean connman_service_set_passphrase(connman_service_t *service,
        gchar *passphrase);

extern gboolean connman_service_is_connected(connman_service_t *service);
extern gboolean connman_service_is_online(connman_service_t *service);

#endif /* CONNMAN_SERVICE_H_ */

