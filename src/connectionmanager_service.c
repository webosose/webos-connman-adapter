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
 * @file  connectionmanager_service.c
 *
 * @brief Implements all of the com.webos.service.connectionmanager methods using connman APIs
 * in the backend.
 */

/**
@page com_webos_connectionmanager com.webos.connectionmanager

@brief This service provides overall management of network connections.

Each call has a standard return response format in the case of a failure, as follows:

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | False to inidicate an error
errorCode | Yes | Integer | Error code
errorText | Yes | String | Error description

@{
@}
*/

#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <pbnjson.h>
#include <errno.h>

#include "common.h"
#include "connman_manager.h"
#include "connman_counter.h"
#include "connman_service.h"
#include "connectionmanager_service.h"
#include "lunaservice_utils.h"
#include "logging.h"
#include "errors.h"
#include "wifi_profile.h"
#include "utils.h"
#include "nyx.h"
#include "pacrunner_client.h"
#include "wan_service.h"
#include "pan_service.h"
#include "wifi_setting.h"

#define COUNTER_ACCURACY    10
#define COUNTER_PERIOD      1
#define GETINFO_UPDATE_INTERVAL_SECONDS 1

static LSHandle *pLsHandle;

connman_counter_t *counter = NULL;
connman_counter_data_t counter_data_new[CONNMAN_SERVICE_TYPE_MAX],
                       counter_data_old[CONNMAN_SERVICE_TYPE_MAX];

gboolean online_status = FALSE;
gboolean wired_online_checking_status = FALSE;
gboolean wifi_online_checking_status = FALSE;
gboolean wired_connected = FALSE;
gboolean wifi_connected = FALSE;
gboolean p2p_connected = FALSE;
gboolean cellular_powered = FALSE;
gboolean wan_connected = FALSE;
gboolean pan_connected = FALSE;
guint block_getstatus_response = 0;
gboolean old_wifi_tethering = FALSE;
gboolean old_pan_tethering = FALSE;
gboolean wired_plugged = FALSE;

char getinfo_cur_wifi_mac_address[MAC_ADDR_STRING_LEN]={0};
char getinfo_cur_wired_mac_address[MAC_ADDR_STRING_LEN]={0};

static void getinfo_update(void);

#define IS_WIRED_PLUGGED() g_slist_length(manager->wired_services)

static bool is_caller_using_new_interface(LSMessage *message)
{
	if (!message)
	{
		return false;
	}

	LSHandle *handle = LSMessageGetConnection(message);

	if (!handle)
	{
		return false;
	}

	const char *name = LSHandleGetName(handle);

	if (!name)
	{
		return false;
	}

	return (g_strcmp0(name, "com.webos.service.connectionmanager") == 0);
}

static gboolean set_ethernet_tethering_state(bool state)
{
	return connman_technology_set_tethering(
	           connman_manager_find_ethernet_technology(manager), state);
}

/**
 * @brief Fill in information about the system's connection status
 *
 * @param connected_service The connected connman service the status should be filled into
 * the supplied json status object
 * @param status json status object to fill with the service status
 */

static void update_connection_status(connman_service_t *connected_service,
                                     jvalue_ref *status)
{
	if (NULL == connected_service || NULL == status)
	{
		return;
	}

	int connman_state = 0;
	connman_state = connman_service_get_state(connected_service->state);

	if (connman_state == CONNMAN_SERVICE_STATE_ONLINE
		|| connman_state == CONNMAN_SERVICE_STATE_READY
		|| connman_state == CONNMAN_SERVICE_STATE_CONFIGURATION)
	{
		connman_service_get_ipinfo(connected_service);
		jobject_put(*status, J_CSTR_TO_JVAL("state"), jstring_create("connected"));

		if (NULL != connected_service->ipinfo.iface)
		{
			jobject_put(*status, J_CSTR_TO_JVAL("interfaceName"),
			            jstring_create(connected_service->ipinfo.iface));
		}

		if (NULL != connected_service->ipinfo.ipv4.address)
		{
			jobject_put(*status, J_CSTR_TO_JVAL("ipAddress"),
			            jstring_create(connected_service->ipinfo.ipv4.address));
		}

		if (NULL != connected_service->ipinfo.ipv4.netmask)
		{
			jobject_put(*status, J_CSTR_TO_JVAL("netmask"),
			            jstring_create(connected_service->ipinfo.ipv4.netmask));
		}

		if (NULL != connected_service->ipinfo.ipv4.gateway)
		{
			jobject_put(*status, J_CSTR_TO_JVAL("gateway"),
			            jstring_create(connected_service->ipinfo.ipv4.gateway));
		}

		gsize i;
		char dns_str[16];

		for (i = 0; i < g_strv_length(connected_service->ipinfo.dns); i++)
		{
			g_snprintf(dns_str, 16, "dns%d", i + 1);
			jobject_put(*status, jstring_create(dns_str),
			            jstring_create(connected_service->ipinfo.dns[i]));
		}

		if (NULL != connected_service->ipinfo.ipv4.method)
		{
			jobject_put(*status, J_CSTR_TO_JVAL("method"),
			            jstring_create(connected_service->ipinfo.ipv4.method));
		}

		if (connman_service_type_wifi(connected_service))
		{
			if (NULL != connected_service->name)
			{
				jobject_put(*status, J_CSTR_TO_JVAL("ssid"),
				            jstring_create(connected_service->name));
			}

			jobject_put(*status, J_CSTR_TO_JVAL("isWakeOnWifiEnabled"),
			            jboolean_create(false));
		}

		const char *s = connman_service_is_online(connected_service) ? "yes" : "no";
		jobject_put(*status, J_CSTR_TO_JVAL("onInternet"), jstring_create(s));
		jobject_put(*status, J_CSTR_TO_JVAL("checkingInternet"), jboolean_create(connected_service->online_checking));

		if (NULL != connected_service->ipinfo.ipv6.address)
		{
			jvalue_ref connected_ipv6_status = jobject_create();

			jobject_put(connected_ipv6_status, J_CSTR_TO_JVAL("ipAddress"),
			            jstring_create(connected_service->ipinfo.ipv6.address));

			if (connected_service->ipinfo.ipv6.prefix_length >= 0 &&
			        connected_service->ipinfo.ipv6.prefix_length <= 128)
			{
				jobject_put(connected_ipv6_status, J_CSTR_TO_JVAL("prefixLength"),
				            jnumber_create_i32(connected_service->ipinfo.ipv6.prefix_length));
			}

			if (NULL != connected_service->ipinfo.ipv6.gateway)
			{
				jobject_put(connected_ipv6_status, J_CSTR_TO_JVAL("gateway"),
				            jstring_create(connected_service->ipinfo.ipv6.gateway));
			}

			if (NULL != connected_service->ipinfo.ipv6.method)
			{
				jobject_put(connected_ipv6_status, J_CSTR_TO_JVAL("method"),
				            jstring_create(connected_service->ipinfo.ipv6.method));
			}

			jobject_put(*status, J_CSTR_TO_JVAL("ipv6"), connected_ipv6_status);
		}

		connman_service_get_proxyinfo(connected_service);

		if (NULL != connected_service->proxyinfo.method)
		{
			jvalue_ref connected_proxy_status = jobject_create();

			jobject_put(connected_proxy_status, J_CSTR_TO_JVAL("method"),
							jstring_create(connected_service->proxyinfo.method));

			if (!g_strcmp0(connected_service->proxyinfo.method, "auto"))
			{
				if (NULL != connected_service->proxyinfo.url)
				{
					jobject_put(connected_proxy_status, J_CSTR_TO_JVAL("url"),
								jstring_create(connected_service->proxyinfo.url));
				}
			}
			else if(!g_strcmp0(connected_service->proxyinfo.method, "manual"))
			{
				if (NULL != connected_service->proxyinfo.servers)
				{
					gsize i;
					jvalue_ref servers_obj = jarray_create(NULL);

					for (i = 0; i < g_strv_length(connected_service->proxyinfo.servers); i++)
					{
						jarray_append(servers_obj, jstring_create(connected_service->proxyinfo.servers[i]));
					}

					jobject_put(connected_proxy_status, J_CSTR_TO_JVAL("servers"), servers_obj);
				}

				if (NULL != connected_service->proxyinfo.excludes)
				{
					gsize i;
					jvalue_ref excludes_obj = jarray_create(NULL);

					for (i = 0; i < g_strv_length(connected_service->proxyinfo.excludes); i++)
					{
						jarray_append(excludes_obj, jstring_create(connected_service->proxyinfo.excludes[i]));
					}

					jobject_put(connected_proxy_status, J_CSTR_TO_JVAL("excludes"), excludes_obj);
				}
			}

			jobject_put(*status, J_CSTR_TO_JVAL("proxyinfo"), connected_proxy_status);
		}

	}
	else
	{
		jobject_put(*status, J_CSTR_TO_JVAL("state"), jstring_create("disconnected"));
	}
}

/**
 * @brief Handle the "PropertyChanged" signal for a net.connman.Group dbus object.
 *
 * @param data User context data
 * @param property Name of the property which has changed.
 * @param value Value of the changed property.
 */

static void group_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	if (!g_strcmp0(property, "LocalAddress"))
	{
		connman_service_t *connected_p2p_service =
		    connman_manager_get_connected_service(manager->p2p_services);

		if (NULL != connected_p2p_service)
		{
			connman_service_set_changed(connected_p2p_service,
			                            CONNMAN_SERVICE_CHANGE_CATEGORY_GETSTATUS);
			connectionmanager_send_status_to_subscribers();
		}
	}
}

/**
 * @brief Append the P2P connection status of a connman service object to a existing JSON
 * object.
 *
 * @param status JSON object where the P2P connection status should be appended to
 * @param connected_service Connman service object which status should be used
 */

static void append_p2p_connection_status(jvalue_ref *status,
        connman_service_t *connected_service)
{
	if (NULL == connected_service || NULL == status)
	{
		return;
	}

	int connman_state = 0;
	connman_state = connman_service_get_state(connected_service->state);

	if (connman_state == CONNMAN_SERVICE_STATE_ONLINE ||
	        connman_state == CONNMAN_SERVICE_STATE_READY)
	{
		jobject_put(*status, J_CSTR_TO_JVAL("state"), jstring_create("connected"));

		GSList *groupnode, *peernode;

		for (groupnode = manager->groups; groupnode ; groupnode = groupnode->next)
		{
			connman_group_t *group = (connman_group_t *)(groupnode->data);

			if (connman_manager_populate_group_peers(manager, group) == TRUE)
			{
				for (peernode = group->peer_list; peernode ; peernode = peernode->next)
				{
					connman_service_t *peer_service = (connman_service_t *) peernode->data;

					if (connected_service == peer_service)
					{
						/* to cover the case where the PropertyChanged signal for local address is missed */
						if (!group->local_address)
						{
							connman_group_get_local_address(group);
						}

						if (group->local_address)
						{
							jobject_put(*status, J_CSTR_TO_JVAL("localIp"),
							            jstring_create(group->local_address));
						}

						connman_group_register_property_changed_cb(group,
						        group_property_changed_callback);
					}
				}
			}
		}

		GSList *listnode;
		jvalue_ref peer_list = jarray_create(NULL);

		for (listnode = manager->p2p_services; listnode ; listnode = listnode->next)
		{
			connman_service_t *service = (connman_service_t *)(listnode->data);
			int service_state = connman_service_get_state(service->state);

			if (service_state == CONNMAN_SERVICE_STATE_ONLINE ||
			        service_state == CONNMAN_SERVICE_STATE_READY)
			{
				jvalue_ref peer_info = jobject_create();

				jobject_put(peer_info, J_CSTR_TO_JVAL("deviceName"),
				            jstring_create(service->name));

				if (service->peer.address)
				{
					jobject_put(peer_info, J_CSTR_TO_JVAL("deviceAddress"),
					            jstring_create(service->peer.address));
				}

				jobject_put(peer_info, J_CSTR_TO_JVAL("groupOwner"),
				            jboolean_create(service->peer.group_owner));

				if (service->peer.config_method)
				{
					jobject_put(peer_info, J_CSTR_TO_JVAL("configMethod"),
					            jnumber_create_i32(service->peer.config_method));
				}

				jobject_put(peer_info, J_CSTR_TO_JVAL("signalLevel"),
				            jnumber_create_i32(service->strength));

				if (NULL != service->ipinfo.ipv4.address)
				{
					jobject_put(peer_info, J_CSTR_TO_JVAL("peerIp"),
					            jstring_create(service->ipinfo.ipv4.address));
				}

				jvalue_ref peer_list_j = jobject_create();
				jobject_put(peer_list_j, J_CSTR_TO_JVAL("peerInfo"), peer_info);
				jarray_append(peer_list, peer_list_j);
			}
		}

		jobject_put(*status,  J_CSTR_TO_JVAL("connectedPeers"), peer_list);
	}
	else
	{
		jobject_put(*status, J_CSTR_TO_JVAL("state"), jstring_create("disconnected"));
	}
}

/**
 * @brief Append the current connection status to a supplied JSON object. The format
 * matches the response format for the com.webos.service.connectionmanager/getstatus method.
 *
 * @param reply JSON object where we will append the connection status to.
 */

static void append_connection_status(jvalue_ref *reply, bool subscribed,
                                     bool with_new_interface)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	gboolean online = connman_manager_is_manager_online(manager);
	jobject_put(*reply, J_CSTR_TO_JVAL("isInternetConnectionAvailable"),
	            jboolean_create(online));
	gboolean offlineMode = !connman_manager_is_manager_available(manager);
	jobject_put(*reply, J_CSTR_TO_JVAL("offlineMode"),
	            jstring_create(offlineMode ? "enabled" : "disabled"));

	jvalue_ref connected_wired_status = jobject_create();
	jvalue_ref disconnected_wired_status = jobject_create();
	jvalue_ref connected_wifi_status = jobject_create();
	jvalue_ref disconnected_wifi_status = jobject_create();
	jvalue_ref connected_p2p_status = jobject_create();
	jvalue_ref disconnected_p2p_status = jobject_create();

	jobject_put(disconnected_wired_status, J_CSTR_TO_JVAL("state"),
	            jstring_create("disconnected"));
	jobject_put(disconnected_wifi_status, J_CSTR_TO_JVAL("state"),
	            jstring_create("disconnected"));
	jobject_put(disconnected_wifi_status, J_CSTR_TO_JVAL("tetheringEnabled"),
	            jboolean_create(is_wifi_tethering()));
	jobject_put(disconnected_p2p_status, J_CSTR_TO_JVAL("state"),
	            jstring_create("disconnected"));

	/* get the service which is currently connecting or already in connected */
	connman_service_t *connected_wired_service =
	    connman_manager_get_connected_service(manager->wired_services);

	if (NULL != connected_wired_service)
	{
		update_connection_status(connected_wired_service, &connected_wired_status);
		jobject_put(connected_wired_status, J_CSTR_TO_JVAL("plugged"),
		            jboolean_create(true));
		jobject_put(*reply, J_CSTR_TO_JVAL("wired"), connected_wired_status);
		j_release(&disconnected_wired_status);
	}
	else
	{
		jobject_put(disconnected_wired_status, J_CSTR_TO_JVAL("plugged"),
		            jboolean_create(wired_plugged ? true : false));
		jobject_put(*reply, J_CSTR_TO_JVAL("wired"), disconnected_wired_status);
		j_release(&connected_wired_status);
	}

	connman_service_t *connected_wifi_service = NULL;

	if (is_wifi_powered())
	{
		connected_wifi_service = connman_manager_get_connected_service(
		                             manager->wifi_services);
	}

	if (NULL != connected_wifi_service)
	{
		update_connection_status(connected_wifi_service, &connected_wifi_status);

		// When we're connected to a WiFi service we can't have tethering enabled
		jobject_put(disconnected_wifi_status, J_CSTR_TO_JVAL("tetheringEnabled"),
		            jboolean_create(false));

		jobject_put(*reply, J_CSTR_TO_JVAL("wifi"), connected_wifi_status);
		j_release(&disconnected_wifi_status);
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("wifi"), disconnected_wifi_status);
		j_release(&connected_wifi_status);
	}

	connman_service_t *connected_p2p_service = NULL;

	if (is_wifi_powered())
	{
		connected_p2p_service = connman_manager_get_connected_service(
		                            manager->p2p_services);
	}

	if (NULL != connected_p2p_service)
	{
		append_p2p_connection_status(&connected_p2p_status, connected_p2p_service);
		jobject_put(*reply, J_CSTR_TO_JVAL("wifiDirect"), connected_p2p_status);
		j_release(&disconnected_p2p_status);
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("wifiDirect"), disconnected_p2p_status);
		j_release(&connected_p2p_status);
	}

	if (with_new_interface)
	{
		jvalue_ref cellular_obj = jobject_create();
		gboolean cellular_enabled = is_cellular_powered();

		jobject_put(cellular_obj, J_CSTR_TO_JVAL("enabled"),
		            jboolean_create(cellular_enabled));
		jobject_put(*reply, J_CSTR_TO_JVAL("cellular"), cellular_obj);

		jvalue_ref wan_obj = jobject_create();

		if (cellular_enabled)
		{
			append_wan_status(wan_obj);
		}
		else
		{
			jvalue_ref connected_contexts_obj = jarray_create(NULL);
			jobject_put(wan_obj, J_CSTR_TO_JVAL("connected"), jboolean_create(false));
			jobject_put(wan_obj, J_CSTR_TO_JVAL("connectedContexts"),
			            connected_contexts_obj);
		}

		jobject_put(*reply, J_CSTR_TO_JVAL("wan"), wan_obj);

		jvalue_ref connected_pan_status = jobject_create();
		jvalue_ref disconnected_pan_status = jobject_create();
		jobject_put(disconnected_pan_status, J_CSTR_TO_JVAL("state"),
		            jstring_create("disconnected"));
		jobject_put(disconnected_pan_status, J_CSTR_TO_JVAL("tetheringEnabled"),
		            jboolean_create(is_bluetooth_tethering()));

		connman_service_t *connected_pan_service =
		    connman_manager_get_connected_service(manager->bluetooth_services);

		if (NULL != connected_pan_service)
		{
			append_nap_info(&connected_pan_status);
			update_connection_status(connected_pan_service, &connected_pan_status);

			// When we're connected to a PAN service we can't have tethering enabled
			jobject_put(connected_pan_status, J_CSTR_TO_JVAL("tetheringEnabled"),
			            jboolean_create(false));

			jobject_put(*reply, J_CSTR_TO_JVAL("bluetooth"), connected_pan_status);
			j_release(&disconnected_pan_status);
		}
		else
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("bluetooth"), disconnected_pan_status);
			j_release(&connected_pan_status);
		}

	}
}

/**
 * @brief Check wether a connman service object was updated. This depends on the currently
 * implemented code inside the connman_service object which only sets the updated flag for
 * a limited number of service properties (those which are relevant for a response of the
 * com.webos.service.connectionmanager/getstatus method).
 *
 * @param service The connman service object to check
 * @param technology_connected The current connections status of the technology the supplied
 * service belongs to.
 *
 * @return TRUE if the service object was updated. FALSE otherwise.
 */

static gboolean check_service_for_update(connman_service_t *service,
        gboolean tech_connected)
{
	gboolean needed = FALSE;

	if ((service != NULL && !tech_connected) || (service == NULL && tech_connected))
	{
		needed = TRUE;
	}

	if (service != NULL &&
	        connman_service_is_changed(service, CONNMAN_SERVICE_CHANGE_CATEGORY_GETSTATUS))
	{
		needed = TRUE;
		/* mark service as unchanged to get notified about future updates */
		connman_service_unset_changed(service,
		                              CONNMAN_SERVICE_CHANGE_CATEGORY_GETSTATUS);
	}

	/* In case of P2P service, a service will be treated as connected only
	   if a group is present */
	if (service != NULL && service->type == CONNMAN_SERVICE_TYPE_P2P)
	{
		if (!tech_connected && manager->groups == NULL)
		{
			needed = FALSE;
		}
	}

	return needed;
}

/**
 * @brief Check whether a update needs to be send for subscribers of the
 * com.webos.service.connectionmanager/getstatus method.
 *
 * @return TRUE if a update needs to be send. FALSE otherwise.
 */

static gboolean check_update_is_needed(void)
{
	gboolean needed = FALSE;

	if (!manager)
	{
		return FALSE;
	}

	if (old_wifi_tethering != is_wifi_tethering())
	{
		old_wifi_tethering = is_wifi_tethering();
		needed = TRUE;
	}

	if (old_pan_tethering != is_bluetooth_tethering())
	{
		old_pan_tethering = is_bluetooth_tethering();
		needed = TRUE;
	}

	gboolean old_online_status = online_status;

	online_status = connman_manager_is_manager_online(manager);

	if (old_online_status != online_status)
	{
		needed = TRUE;
	}

	connman_service_t *connected_wifi_service = NULL;

	if (is_wifi_powered())
	{
		connected_wifi_service = connman_manager_get_connected_service(
		                             manager->wifi_services);
	}

	if (check_service_for_update(connected_wifi_service, wifi_connected))
	{
		needed = TRUE;
	}

	wifi_connected = (connected_wifi_service != NULL);

	connman_service_t *connected_wired_service =
	    connman_manager_get_connected_service(manager->wired_services);

	if (check_service_for_update(connected_wired_service, wired_connected))
	{
		needed = TRUE;
	}

	wired_connected = (connected_wired_service != NULL);

	if (IS_WIRED_PLUGGED() != wired_plugged)
	{
		needed = TRUE;
	}

	wired_plugged = IS_WIRED_PLUGGED();

	connman_service_t *connected_p2p_service = NULL;

	if (is_wifi_powered())
	{
		connected_p2p_service = connman_manager_get_connected_service(
		                            manager->p2p_services);
	}

	if (check_service_for_update(connected_p2p_service, p2p_connected))
	{
		needed = TRUE;
	}

	p2p_connected = (connected_p2p_service != NULL && manager->groups != NULL);

	if (cellular_powered != is_cellular_powered())
	{
		cellular_powered = is_cellular_powered();
		needed = TRUE;
	}

	connman_service_t *connected_pan_service =
	    connman_manager_get_connected_service(manager->bluetooth_services);

	if (check_service_for_update(connected_pan_service, pan_connected))
	{
		needed = TRUE;
	}

	pan_connected = (connected_pan_service != NULL);


	GSList *iter;
	guint num_connected = 0;

	for (iter = manager->cellular_services; iter != NULL; iter = iter->next)
	{
		connman_service_t *service = iter->data;

		if (!connman_service_is_connected(service))
		{
			continue;
		}

		num_connected++;

		if (check_service_for_update(service, wan_connected || (num_connected > 0)))
		{
			needed = TRUE;
		}
	}

	gboolean new_wan_connected = (num_connected > 0);

	if (wan_connected != new_wan_connected)
	{
		needed = TRUE;
	}

	wan_connected = new_wan_connected;

	WCALOG_INFO(MSGID_CONNECTION_INFO, 0, "needed: %d",needed);

	return needed;
}

/**
 *  @brief Callback function registered with connman manager whenever any of its properties changes.
 */

void connectionmanager_send_status_to_subscribers(void)
{
	bool wired_skip, wifi_skip = false;

	if (manager == NULL)
		return;

	if (block_getstatus_response || !check_update_is_needed())
	{
		// Retrieve the connected service for wired to check the online checking status
		connman_service_t *connected_wired_service =
				connman_manager_get_connected_service(manager->wired_services);

		// Retrieve the connected service for wifi to check the online checking sttaus
		connman_service_t *connected_wifi_service =
				connman_manager_get_connected_service(manager->wifi_services);

		if (connected_wired_service)
		{
			// "block_getstatus_response" blocks connectionmanager/getstatus for 1 seconds
			// While getstatus is blocked, "wired_skip" flag will be used to emit the
			// getstatus response if online_checking status is modified.
			if (connected_wired_service->online_checking == wired_online_checking_status)
				wired_skip = true;
			else
			{
				wired_online_checking_status = connected_wired_service->online_checking;
				wired_skip = false;
			}
		}

		if (connected_wifi_service)
		{
			// "block_getstatus_response" blocks connectionmanager/getstatus for 1 seconds
			// While getstatus is blocked, "wired_skip" flag will be used to emit the
			// getstatus response if online_checking status is modified.
			if (connected_wifi_service->online_checking == wifi_online_checking_status)
				wifi_skip = true;
			else
			{
				wifi_online_checking_status = connected_wifi_service->online_checking;
				wifi_skip = false;
			}
		}

		// This routine affects when connected service for both wired and wifi exists.
		if (connected_wired_service && connected_wifi_service)
		{
			/* If there is no change of online_checking status for both wired and wifi,
			 * getstatus will not be emitted. If there is a change of online_checking status
			 * for both wired and wifi, getstatus response will be emitted.
			 */
			if (wired_skip && wifi_skip)
				return;
		}
		// This routine affects when connected service for only wifi exists.
		else if (!connected_wired_service && connected_wifi_service)
		{
			if (wifi_skip)
				return;
		}
		// This routine affects when connected service for only wired exists.
		else if (connected_wired_service && !connected_wifi_service)
		{
			if (wired_skip)
				return;
		}
	}

	jvalue_ref reply = jobject_create();
	jvalue_ref reply_deprecated = jobject_create();
	append_connection_status(&reply, true, true);
	// Same but without mentioning WAN and PAN as we don't support it on the
	// com.webos.service.connectionmanager service face
	append_connection_status(&reply_deprecated, true, false);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		const char *payload_deprecated = jvalue_tostring(reply_deprecated,
		                                 response_schema);

		WCALOG_INFO(MSGID_CONNECTION_INFO, 0, "connectionmanager_send_status : %s",payload);

		LSError lserror;
		LSErrorInit(&lserror);

		// com.webos.service.connectionmanager/getstatus
		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_GETSTATUS,
		                        payload_deprecated, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		// com.webos.service.connectionmanager/getStatus
		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_GETSTATUS2,
		                        payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
	j_release(&reply_deprecated);
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_getstatus getstatus

Gets the current status of network connections (wifi, wired and wifi direct) on the system.

Callers of this method can subscribe to it so that they are notified whenever the
network status changes.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subcribe | no | Boolean | Subscribe to this method

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
isInternetConnectionAvailable | Yes | Boolean | Indicates if any internet connection is available
offlineMode | yes | String | "enabled" if manager is offline, "disabled" otherwise
wired | yes | Object | State of wired connection (see below)
wifi | yes | Object | State of wifi connection (see below)
wifiDirect | yes | Object | State of wifi direct connection (see below)

@par "wired" State Object

Optional fields are only present if "state" is "connected".

Name | Required | Type | Description
-----|--------|------|----------
state | yes | String | "connected" or "disconnected" to indicate status.
interfaceName | no | String | Interface name in use (e.g. "eth0")
ipAddress | no | String | IP address associated with the connection
netmask | no | String | Net mask value for the connection
gateway | no | String | IP address of network gateway
dns<n> | no | String | List of IP Addreses of dns servers for this connection
method | no | String | How the IP addressed was assigned (e.g. "Manual", "dhcp")
onInternet | no | String | "yes" or "no" to indicate if the service is "online"

@par "wifi" State Object

Optional fields are only present if "state" is "connected".

Name | Required | Type | Description
-----|--------|------|----------
state | yes | String | "connected" or "disconnected" to indicate status.
interfaceName | no | String | Interface name in use (e.g. "eth0")
ipAddress | no | String | IP address associated with the connection
netmask | no | String | Net mask value for the connection
gateway | no | String | IP address of network gateway
dns<n> | no | String | List of IP Addreses of dns servers for this connection
method | no | String | How the IP addressed was assigned (e.g. "Manual", "dhcp")
ssid | no | String | SSID of the connected service (if known)
isWakeOnWiFiEnabled | no | Boolean | True if "Wake on WIFI" is enabled
onInternet | no | String | "yes" or "no" to indicate if the service is "online"

@par "wifiDirect" State Object

Optional fields are only present if "state" is "connected".

Name | Required | Type | Description
-----|--------|------|----------
state | yes | String | "connected" or "disconnected"
localIp | no | String | IP address of the local connection endpoint
connectedPeers | no | Array | See "peer State Object".

@par "peer" State Object

Name | Required | Type | Description
-----|--------|------|----------
peerInfo | yes | Object | See "peerInfo State Object"

@par "peerInfo" State Obejct

Name | Required | Type | Description
-----|--------|------|----------
deviceName | yes | String | Name of the peer.
deviceAddress | yes | String | Address of the peer.
groupOwner | yes | Boolean | true, if the peer is the owner of the current active group. false otherwise
configMethod | yes | Integer | Configuration methods supported by the peer.
signalLevel | yes | Integer | Signal level of the peer.
peerIp | no | String | IP address of the peer if it's currently connected to our group.

@par Returns(Subscription)

The subcription update contains the same information as the initial call.

@}
*/
//->End of API documentation comment block

static bool handle_get_status_command(LSHandle *sh, LSMessage *message,
                                      void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	bool subscribed = false;
	jschema_ref response_schema = NULL;

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	// Adding the check for manager here, since we only want to error out in that case and not if manager is offline
	if (NULL == manager)
	{
		if (!connman_status_check_with_subscription(manager, sh, message, subscribed))
		{
			goto cleanup;
		}
	}

	append_connection_status(&reply, subscribed,
	                         is_caller_using_new_interface(message));

	response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);

	if (!response_schema)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema),
	                    &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	jschema_release(&response_schema);

cleanup:

	if (!jis_null(reply))
	{
		j_release(&reply);
	}

	if (!jis_null(parsedObj))
	{
		j_release(&parsedObj);
	}

	return true;
}

/**
 * @brief Loop through the manager's wifi services and match the one with the given ssid.
 * If 'ssid' is NULL then return the wired service on the system
 *
 * @param ssid SSID of the service object we're searching for. If NULL we will return the
 * first available wired network service.
 * @return Connman service object or NULL in case of a failure.
 */

static connman_service_t *retrieve_service_by_ssid(gchar *ssid)
{
	if (NULL != ssid)
	{
		GSList *ap;

		/* Look up for the service with the given ssid */
		for (ap = manager->wifi_services; ap; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);

			if (!g_strcmp0(service->name, ssid))
			{
				return service;
			}
		}
	}
	else
	{
		/* Return the first wired service (there will be just one on most systems) */
		GSList *ap = manager->wired_services;

		if (ap != NULL)
		{
			return (connman_service_t *) ap->data;
		}
	}

	return NULL;
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_setipv4 setipv4

Modify the parameters of an IPv4 connection (wired or WIFI)

If an SSID field is not provided in the request, the modifications are
applied to the wired connection.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
"method" | yes | String | "dhcp", "manual" or "off"
"address" | no | String | If specified, sets a new IP address (only when method is "manual")
"netmask" | no | String | If specified, sets a new netmask (only when method is "manual")
"gateway" | no | String | If specified, sets a new gateway IP address (only when method is "manual")
"ssid" | no | String | Select the wifi connection to modify. If absent, the wired connection is changed.

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True, when operation was successfull. False otherwise.

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_ipv4_command(LSHandle *sh, LSMessage *message,
                                    void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(method, string), PROP(address,
	                                     string),
	                                     PROP(netmask, string), PROP(gateway, string), PROP(ssid,
	                                             string)) REQUIRED_1(method))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0}, methodObj = {0}, addressObj = {0}, netmaskObj = {0},
	           gatewayObj = {0};
	ipv4info_t ipv4 = {0};
	gchar *ssid = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("method"), &methodObj))
	{
		raw_buffer method_buf = jstring_get(methodObj);
		ipv4.method = g_strdup(method_buf.m_str);
		jstring_free_buffer(method_buf);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		ipv4.address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!is_valid_ipaddress(ipv4.address))
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("netmask"), &netmaskObj))
	{
		raw_buffer netmask_buf = jstring_get(netmaskObj);
		ipv4.netmask = g_strdup(netmask_buf.m_str);
		jstring_free_buffer(netmask_buf);

		if (!is_valid_ipaddress(ipv4.netmask))
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("gateway"), &gatewayObj))
	{
		raw_buffer gateway_buf = jstring_get(gatewayObj);
		ipv4.gateway = g_strdup(gateway_buf.m_str);
		jstring_free_buffer(gateway_buf);

		if (!is_valid_ipaddress(ipv4.gateway))
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
	}

	connman_service_t *service = retrieve_service_by_ssid(ssid);

	if (NULL != service)
	{
		if (connman_service_set_ipv4(service, &ipv4))
		{
			LSMessageReplySuccess(sh, message);
		}
		else
		{
			LSMessageReplyErrorUnknown(sh, message);
		}
	}
	else
	{
		if (ssid)
		{
			wifi_profile_t *profile = get_profile_by_ssid(ssid);

			if (profile && profile->configured)
			{
				if (!g_strcmp0(ipv4.method, "manual"))
				{
					if (ipv4.address == NULL || ipv4.netmask == NULL || ipv4.gateway == NULL)
						LSMessageReplyCustomError(sh, message,
						                          "Address, netmask as well as gateway should be specified for out of range networks",
						                          WCA_API_ERROR_INVALID_PARAMETERS);
					else if (change_network_ipv4(profile->ssid, profile->security[0], ipv4.address,
					                             ipv4.netmask, ipv4.gateway))
					{
						LSMessageReplySuccess(sh, message);
					}
					else
					{
						LSMessageReplyErrorUnknown(sh, message);
					}
				}
				else if (!g_strcmp0(ipv4.method, "dhcp"))
				{
					if (change_network_remove_entry(profile->ssid, profile->security[0], "IPv4"))
					{
						LSMessageReplySuccess(sh, message);
					}
					else
					{
						LSMessageReplyErrorUnknown(sh, message);
					}
				}
				else
				{
					goto invalid_params;
				}

				goto exit;
			}
		}

		LSMessageReplyCustomError(sh, message, "Network not found",
		                          WCA_API_ERROR_NETWORK_NOT_FOUND);
	}

	goto exit;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
exit:
	g_free(ipv4.method);
	g_free(ipv4.address);
	g_free(ipv4.netmask);
	g_free(ipv4.gateway);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

static bool handle_set_ipv6_command(LSHandle *sh, LSMessage *message,
                                    void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(method, string), PROP(address,
	                                     string),
	                                     PROP(prefixLength, integer), PROP(gateway, string), PROP(ssid,
	                                             string)) REQUIRED_1(method))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0}, methodObj = {0}, addressObj = {0}, prefixLengthObj = {0},
	           gatewayObj = {0};
	ipv6info_t ipv6 = {0};
	gchar *ssid = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("method"), &methodObj))
	{
		raw_buffer method_buf = jstring_get(methodObj);
		ipv6.method = g_strdup(method_buf.m_str);
		jstring_free_buffer(method_buf);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		ipv6.address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!is_valid_ipv6address(ipv6.address))
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("prefixLength"),
	                       &prefixLengthObj))
	{
		int prefixLength_val = 0;
		jnumber_get_i32(prefixLengthObj, &prefixLength_val);
		ipv6.prefix_length = prefixLength_val;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("gateway"), &gatewayObj))
	{
		raw_buffer gateway_buf = jstring_get(gatewayObj);
		ipv6.gateway = g_strdup(gateway_buf.m_str);
		jstring_free_buffer(gateway_buf);

		if (!is_valid_ipv6address(ipv6.gateway))
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
	}

	connman_service_t *service = retrieve_service_by_ssid(ssid);

	if (NULL != service)
	{
		if (connman_service_set_ipv6(service, &ipv6))
		{
			LSMessageReplySuccess(sh, message);
		}
		else
		{
			LSMessageReplyErrorUnknown(sh, message);
		}
	}
	else
	{
		if (ssid)
		{
			wifi_profile_t *profile = get_profile_by_ssid(ssid);

			if (profile && profile->configured)
			{
				if (!g_strcmp0(ipv6.method, "manual"))
				{
					if (ipv6.address == NULL || ipv6.prefix_length == NULL || ipv6.gateway == NULL)
						LSMessageReplyCustomError(sh, message,
						                          "Address, prefix length as well as gateway should be specified for out of range networks",
						                          WCA_API_ERROR_INVALID_PARAMETERS);
					else if (change_network_ipv6(profile->ssid, profile->security[0], ipv6.address,
					                             ipv6.prefix_length, ipv6.gateway))
					{
						LSMessageReplySuccess(sh, message);
					}
					else
					{
						LSMessageReplyErrorUnknown(sh, message);
					}
				}
				else if (!g_strcmp0(ipv6.method, "dhcp"))
				{
					if (change_network_remove_entry(profile->ssid, profile->security[0], "IPv6"))
					{
						LSMessageReplySuccess(sh, message);
					}
					else
					{
						LSMessageReplyErrorUnknown(sh, message);
					}
				}
				else
				{
					goto invalid_params;
				}

				goto exit;
			}
		}

		LSMessageReplyCustomError(sh, message, "Network not found",
		                          WCA_API_ERROR_NETWORK_NOT_FOUND);
	}

	goto exit;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);

exit:
	g_free(ipv6.method);
	g_free(ipv6.address);
	g_free(ipv6.gateway);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_setdns setdns

Change the DNS servers for the network.

If an SSID field is not provided in the request, the modifications are
applied to the wired connection.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
dns | yes | Array of String | Each string provides the IP address of a dns server
ssid | no | String | SSID of wifi connection to be modified.

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True, when configuration has sucessfully applied. False otherwise.

@par Returns(Subscription)

Not applicable

@}
*/
//->End of API documentation comment block

static bool handle_set_dns_command(LSHandle *sh, LSMessage *message,
                                   void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(ARRAY(dns, string), PROP(ssid,
	                                     string)) REQUIRED_1(dns))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0}, dnsObj = {0};
	GStrv dns = NULL;
	gchar *ssid = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("dns"), &dnsObj))
	{
		int i, dns_arrsize = jarray_size(dnsObj);
		dns = (GStrv) g_new0(GStrv, dns_arrsize + 1);

		for (i = 0; i < dns_arrsize; i++)
		{
			raw_buffer dns_buf = jstring_get(jarray_get(dnsObj, i));
			dns[i] = g_strdup(dns_buf.m_str);
			jstring_free_buffer(dns_buf);

			if (!(is_valid_ipaddress(dns[i]) || is_valid_ipv6address(dns[i])))
			{
				goto invalid_params;
			}
		}

		dns[dns_arrsize] = NULL;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
	}

	connman_service_t *service = retrieve_service_by_ssid(ssid);

	if (NULL != service)
	{
		if (connman_service_set_nameservers(service, dns))
		{
			LSMessageReplySuccess(sh, message);
		}
		else
		{
			LSMessageReplyErrorUnknown(sh, message);
		}
	}
	else
	{
		if (ssid)
		{
			wifi_profile_t *profile = get_profile_by_ssid(ssid);

			if (profile && profile->configured)
			{
				if (change_network_dns(profile->ssid, profile->security[0], dns))
				{
					LSMessageReplySuccess(sh, message);
				}
				else
				{
					LSMessageReplyErrorUnknown(sh, message);
				}

				goto exit;
			}
		}

		LSMessageReplyCustomError(sh, message, "No connected network",
		                          WCA_API_ERROR_NO_CONNECTED_NW);
	}

	goto exit;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
exit:
	g_strfreev(dns);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

/**
 *  @brief Returns true if ethernet technology is powered on
 *
 *  @return TRUE if the the ethernet technology is powered. FALSE otherwise.
 */

static gboolean is_ethernet_powered(void)
{
	connman_technology_t *technology = connman_manager_find_ethernet_technology(
	                                       manager);

	if (NULL != technology)
	{
		return technology->powered;
	}

	return FALSE;
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_setstate setstate

Enable or disable the state of either or both wifi and wired technologies on the system

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
wifi | no | String | "enabled" or "disabled" to set status accordingly
wired | no | String | "enabled" or "disabled" to set status accordingly
offlineMode | no | String | "enabled" or "disabled" to set status accordingly

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@par Returns(Subscription)

Not Applicable

@}
*/
//->End of API documentation comment block

static bool handle_set_state_command(LSHandle *sh, LSMessage *message,
                                     void *context)
{
	// Adding the check for manager here, since we only want to error out in that case and not if manager is offline
	if (NULL == manager)
	{
		if (!connman_status_check(manager, sh, message))
		{
			return true;
		}
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_3(PROP(wifi, string), PROP(wired, string),
	                                     PROP(offlineMode, string)))), &parsedObj))
	{
		return true;
	}

	jvalue_ref wifiObj = {0}, wiredObj = {0}, offlineModeObj = {0};
	gboolean enable_wifi = FALSE, enable_wired = FALSE, enable_offline = FALSE;
	gboolean invalidArg = TRUE;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("offlineMode"),
	                       &offlineModeObj))
	{
		if (jstring_equal2(offlineModeObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_offline = TRUE;
		}
		else if (jstring_equal2(offlineModeObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_offline = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		gboolean offline = !connman_manager_is_manager_available(manager);

		if (enable_offline == offline)
		{
			WCALOG_DEBUG("Offline mode already set to the desired value");
		}
		else
		{
			if (enable_offline && is_wifi_tethering())
			{
				set_wifi_tethering(!enable_offline);
			}

			connman_manager_set_offlinemode(manager, enable_offline);
		}

		invalidArg = FALSE;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wifi"), &wifiObj))
	{
		if (jstring_equal2(wifiObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_wifi = TRUE;
		}
		else if (jstring_equal2(wifiObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_wifi = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		/* Check if we are enabling an already enabled service,
		 * or disabling an already disabled service */
		if ((enable_wifi && is_wifi_powered()) || (!enable_wifi && !is_wifi_powered()))
		{
			WCALOG_DEBUG("Wifi technology already enabled/disabled");
		}
		else
		{
			set_wifi_powered_status(enable_wifi);
		}

		invalidArg = FALSE;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wired"), &wiredObj))
	{
		if (jstring_equal2(wiredObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_wired = TRUE;
		}
		else if (jstring_equal2(wiredObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_wired = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		/* Check if we are enabling an already enabled service,
		 * or disabling an already disabled service */
		if ((enable_wired && is_ethernet_powered()) || (!enable_wired &&
		        !is_ethernet_powered()))
		{
			WCALOG_DEBUG("Wired technology already enabled/disabled");
		}
		else
		{
			connman_technology_t *technology = connman_manager_find_ethernet_technology(
			                                       manager);

			if (NULL != technology)
			{
				connman_technology_set_powered(technology, enable_wired, NULL);
			}
		}

		invalidArg = FALSE;
	}

	if (invalidArg == TRUE)
	{
		goto invalid_params;
	}

	LSMessageReplySuccess(sh, message);
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;

}

static void getinfo_add_response(jvalue_ref* reply, bool subscribed)
{
	jobject_put(*reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	if (getinfo_cur_wifi_mac_address[0])
	{
		jvalue_ref wifi_info = jobject_create();
		jobject_put(wifi_info,
		            J_CSTR_TO_JVAL("macAddress"),
		            jstring_create(getinfo_cur_wifi_mac_address));
		jobject_put(*reply, J_CSTR_TO_JVAL("wifiInfo"), wifi_info);
	}

	if (getinfo_cur_wired_mac_address[0])
	{
		jvalue_ref wired_info = jobject_create();
		jobject_put(wired_info,
		            J_CSTR_TO_JVAL("macAddress"),
		            jstring_create(getinfo_cur_wired_mac_address));
		jobject_put(*reply, J_CSTR_TO_JVAL("wiredInfo"), wired_info);
	}
}

void send_getinfo_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	getinfo_update();
	getinfo_add_response(&reply, true);

	const char *payload = jvalue_tostring(reply, jschema_all());
	LSError lserror;
	LSErrorInit(&lserror);
	if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_GETINFO, payload, &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply);
}

/**
 * Update mac address and send response to subscribers (if any).

 * Note that this method is called both on timer and
 * standalone, with subscribers and without.
 */
static void getinfo_update(void)
{
	WCALOG_INFO(MSGID_CM_GET_MAC_INFO, 0, "Updating Wi-Fi & Wired mac info");

	char wifi_mac_address[MAC_ADDR_STRING_LEN]={0};
	char wired_mac_address[MAC_ADDR_STRING_LEN]={0};

	if (retrieve_wifi_mac_address(wifi_mac_address, MAC_ADDR_STRING_LEN))
	{
		if (g_strcmp0(getinfo_cur_wifi_mac_address, wifi_mac_address))
		{
			g_strlcpy(getinfo_cur_wifi_mac_address, wifi_mac_address, MAC_ADDR_STRING_LEN);
		}
	}
	else
	{
		/** Mark as invalid */
		if (getinfo_cur_wifi_mac_address[0])
		{
			getinfo_cur_wifi_mac_address[0] = 0;
		}

		WCALOG_ERROR(MSGID_WIFI_MAC_ADDR_ERROR,0,"Error in fetching mac address for wifi interface");
	}

	if (retrieve_wired_mac_address(wired_mac_address, MAC_ADDR_STRING_LEN))
	{
		if (g_strcmp0(getinfo_cur_wired_mac_address, wired_mac_address))
		{
			g_strlcpy(getinfo_cur_wired_mac_address, wired_mac_address, MAC_ADDR_STRING_LEN);
		}
	}
	else
	{
		/** Mark as invalid */
		if (getinfo_cur_wired_mac_address[0])
		{
			getinfo_cur_wired_mac_address[0] = 0;
		}

		WCALOG_ERROR(MSGID_WIRED_MAC_ADDR_ERROR,0,"Error in fetching mac address for wired interface");
	}
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_getinfo getinfo

Lists information about the wifi and wired network interfaces.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subcribe to changes

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
subscribed | yes | Boolean | True when successfully subscribed. False not subscribed or subscription was not possible.
wiredInfo | no | Object | Object containing information for the current wired connection.
wifiInfo | no | Object | Object containing information for the current wifi connection.

@par Information Object

Name | Required | Type | Description
-----|--------|------|----------
macAddress | yes | String | MAC address of the controller for the connection

@par Returns(Subscription)

As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_get_info_command(LSHandle *sh, LSMessage *message,
                                    void *context)
{
	UNUSED(context);

	bool subscribed = false;
	jvalue_ref reply;
	LSError lserror;
	LSErrorInit(&lserror);
	jvalue_ref parsedObj;

	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
		return true;

	reply = jobject_create();

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	getinfo_add_response(&reply, subscribed);
	LSMessageReply(sh, message, jvalue_tostring(reply, jschema_all()), &lserror);

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply);
	j_release(&parsedObj);
	return true;
}

/* Blocking getstatus response for 1 sec for getting internet status*/
#define INTERNET_STATUS_TIMEOUT 1

/**
 * @brief Callback called after the delay set for getting internet status
 * for connected services. We have to make sure we send out a new status
 * regardless if anything has changed or not. Some of our users already
 * rely on this behaviour so we can't change it (see settings app).
 */
static gboolean send_updated_internet_status(gpointer data)
{
	block_getstatus_response = 0;
	return FALSE;
}

//->Start of API documentation comment block
/**
@page com_webos_connectionmanager com.webos.connectionmanager
@{
@section com_webos_connectionmanager_checkinternetstatus checkinternetstatus

Triggers online check for all connected interfaces.

@par Parameters

None

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_check_internet_status_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	LSError lserror;
	LSErrorInit(&lserror);
	gboolean wired_status = TRUE, wifi_status = TRUE;

	if (block_getstatus_response)
	{
		goto exit;
	}

	if (!connman_status_check(manager, sh, message))
		return true;

	connman_service_t *connected_wired_service =
	    connman_manager_get_connected_service(manager->wired_services);

	if (connected_wired_service)
	{
		wired_status = connman_service_set_run_online_check(connected_wired_service,
		               TRUE);
	}

	connman_service_t *connected_wifi_service =
	    connman_manager_get_connected_service(manager->wifi_services);

	if (connected_wifi_service)
	{
		wifi_status = connman_service_set_run_online_check(connected_wifi_service,
		              TRUE);
	}

	WCALOG_INFO(MSGID_CM_ONLINE_CHECK_INFO, 0, "internet check for connected wired service : %p, wifi service : %p",
		    connected_wired_service, connected_wifi_service);

	if (!connected_wired_service && !connected_wifi_service)
	{
		goto exit;
	}

	if (wired_status == TRUE || wifi_status == TRUE)
	{
		block_getstatus_response = g_timeout_add_seconds(INTERNET_STATUS_TIMEOUT,
		                           send_updated_internet_status, NULL);
	}

	if (!wired_status && !wifi_status)
		LSMessageReplyCustomError(sh, message,
		                          "Error in checking online status for both wired and wifi interfaces",
		                          WCA_API_ERROR_WIRED_WIFI_ONLINE);
	else if (!wired_status)
		LSMessageReplyCustomError(sh, message,
		                          "Error in checking online status for wired interface",
		                          WCA_API_ERROR_WIRED_ONLINE);
	else if (!wifi_status)
		LSMessageReplyCustomError(sh, message,
		                          "Error in checking online status for wifi interface",
		                          WCA_API_ERROR_WIFI_ONLINE);
	else
	{
		goto exit;
	}

	goto cleanup;

exit:
	LSMessageReplySuccess(sh, message);

cleanup:
	return true;
}

/**
 *  @brief Callback function registered with connman technology whenever any of its properties change
 *
 *  @param data User context data
 *  @param property Name of the property which has changed
 *  @param value Value of the changed property
 */

static void technology_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if (NULL == technology)
	{
		return;
	}

	/* Need to send getstatus method to all com.webos.service.connectionmanager subscribers whenever the
	   "powered" or "connected" state of the technology changes */

	if (!g_strcmp0(property, "Powered") || !g_strcmp0(property, "Connected"))
	{
		if (manager) {
			connman_service_t *connected_wifi_service = connman_manager_get_connected_service(manager->wifi_services);
			if (connected_wifi_service)
				connman_service_set_run_online_check(connected_wifi_service, TRUE);
		}
		connectionmanager_send_status_to_subscribers();
	}
}

static void increment_counter_statistics(connman_service_t *service,
        GVariant *home)
{
	connman_counter_data_t counter_data;

	int service_state = connman_service_get_state(service->state);

	if (!(service_state == CONNMAN_SERVICE_STATE_ONLINE ||
	        service_state == CONNMAN_SERVICE_STATE_READY))
	{
		return;
	}

	connman_service_types type = service->type;

	connman_counter_parse_counter_data(home, &counter_data);

	counter_data_new[type].rx_bytes += counter_data.rx_bytes;
	counter_data_new[type].tx_bytes += counter_data.tx_bytes;
	counter_data_new[type].rx_packet += counter_data.rx_packet;
	counter_data_new[type].tx_packet += counter_data.tx_packet;
	counter_data_new[type].rx_errors += counter_data.rx_errors;
	counter_data_new[type].tx_errors += counter_data.tx_errors;
	counter_data_new[type].rx_dropped += counter_data.rx_dropped;
	counter_data_new[type].tx_dropped += counter_data.tx_dropped;
}

static void counter_usage_callback(const gchar *path, GVariant *home,
                                   GVariant *roaming, gpointer user_data)
{
	if (!g_variant_is_container(home))
	{
		return;
	}

	connman_service_t *service = connman_manager_find_service_by_path(
	                                 manager->wired_services, path);

	if (NULL == service)
	{
		service = connman_manager_find_service_by_path(manager->wifi_services, path);

		if (NULL == service)
		{
			service = connman_manager_find_service_by_path(manager->cellular_services,
			          path);
		}
	}

	if (NULL == service)
	{
		return;
	}

	increment_counter_statistics(service, home);
}

static void counter_registered_callback(gpointer user_data)
{
	gchar *counter_path;

	counter_path = connman_counter_get_path(counter);

	if (!connman_manager_register_counter(manager, counter_path, COUNTER_ACCURACY,
	                                      COUNTER_PERIOD))
	{
		WCALOG_CRITICAL(MSGID_WIFI_COUNTER_ERROR, 0,
		                "Could not register our counter instance with connman; functionality will be limited!");
		return;
	}

	memset(counter_data_old, 0, sizeof(counter_data_old));
	memset(counter_data_new, 0, sizeof(counter_data_new));

	connman_counter_set_usage_callback(counter, counter_usage_callback, NULL);

}

#define CALCULATE_DIFFERENCE(name) (counter_data_new[type].name? abs(counter_data_new[type].name - counter_data_old[type].name): 0)

static void append_interface_data_activity(jvalue_ref *interface_stats,
        connman_service_types type)
{
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("rxPackets"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(rx_packet)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("rxBytes"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(rx_bytes)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("rxErrors"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(rx_errors)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("rxDropped"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(rx_dropped)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("txPackets"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(tx_packet)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("txBytes"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(tx_bytes)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("txErrors"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(tx_errors)));
	jobject_put(*interface_stats, J_CSTR_TO_JVAL("txDropped"),
	            jnumber_create_i32(CALCULATE_DIFFERENCE(rx_dropped)));
}

static void append_data_activity(jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(*reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	jobject_put(*reply, J_CSTR_TO_JVAL("sampleInterval"),
	            jnumber_create_i32(counter->timer->interval * 1000));

	jvalue_ref wired_stats = jobject_create();
	jvalue_ref wifi_stats = jobject_create();

	append_interface_data_activity(&wired_stats, CONNMAN_SERVICE_TYPE_ETHERNET);
	append_interface_data_activity(&wifi_stats, CONNMAN_SERVICE_TYPE_WIFI);

	jobject_put(*reply, J_CSTR_TO_JVAL("wired"), wired_stats);
	jobject_put(*reply, J_CSTR_TO_JVAL("wifi"), wifi_stats);

	jvalue_ref wan_stats = jobject_create();
	append_interface_data_activity(&wan_stats, CONNMAN_SERVICE_TYPE_CELLULAR);
	jobject_put(*reply, J_CSTR_TO_JVAL("wan"), wan_stats);

	memcpy(counter_data_old, counter_data_new, sizeof(counter_data_old));
	memset(counter_data_new, 0, sizeof(counter_data_new));
}


static void disable_counter(void)
{
	gchar *counter_path;

	counter_path = connman_counter_get_path(counter);

	if (!connman_manager_unregister_counter(manager, counter_path))
	{
		connman_counter_set_registered_callback(counter, NULL, NULL);
		connman_counter_free(counter);
		counter = NULL;
	}

	connman_counter_set_registered_callback(counter, NULL, NULL);
	connman_counter_free(counter);
	counter = NULL;

}

static gboolean notify_counter_statistics(void)
{
	if (counter->timer->timeout == 0)
	{
		return FALSE;
	}

	if (LSSubscriptionGetHandleSubscribersCount(pLsHandle,
	        LUNA_CATEGORY_ROOT LUNA_METHOD_MONITORACTIVITY) == 0)
	{
		disable_counter();
		return FALSE;
	}

	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	append_data_activity(&reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		WCALOG_DEBUG("Sending payload %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_MONITORACTIVITY, payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
	return true;
}


static bool handle_monitor_activity_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
		return true;
	}

	bool subscribed = false;
	LSError lserror;
	LSErrorInit(&lserror);
	jvalue_ref reply = jobject_create();

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

		if (!connman_manager_is_manager_available(manager))
		{
			jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
			jobject_put(reply, J_CSTR_TO_JVAL("errorText"),
			            jstring_create("Connman manager is not available"));
			goto response;
		}
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "Subscription is mandatory for this API",
		                          WCA_API_ERROR_SUBSCRIPTION_REQD);
		goto cleanup;
	}

	if (NULL == counter)
	{
		counter = connman_counter_new(notify_counter_statistics);

		if (NULL == counter)
		{
			LSMessageReplyCustomError(sh, message, "Error in setting counter",
			                          WCA_API_ERROR_COUNTER);
			goto cleanup;
		}

		connman_counter_set_registered_callback(counter, counter_registered_callback,
		                                        NULL);
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

response:
	{
		jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
		                              DOMOPT_NOOPT, NULL);

		if (!response_schema)
		{
			LSMessageReplyErrorUnknown(sh, message);
			goto cleanup;
		}

		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema),
		                    &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

cleanup:
	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

static bool handle_set_technology_state_command(LSHandle *sh,
        LSMessage *message, void *user_data)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(ARRAY(enabled, string), ARRAY(disabled,
	                                     string)))), &parsed_obj))
	{
		return true;
	}

	jvalue_ref enabled_obj = 0;
	jvalue_ref disabled_obj = 0;
	bool enabled_set = false;
	bool disabled_set = false;
	LSError lserror;
	LSErrorInit(&lserror);
	unsigned int n;
	bool success = TRUE;
	bool not_supported = FALSE;

	enabled_set = jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("enabled"),
	                                 &enabled_obj);
	disabled_set = jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("disabled"),
	                                  &disabled_obj);

	if (!enabled_set && !disabled_set)
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		return true;
	}

	for (n = 0; n < jarray_size(enabled_obj); n++)
	{
		jvalue_ref tech_obj = jarray_get(enabled_obj, n);

		raw_buffer name_buf = jstring_get(tech_obj);
		char *tech_name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);

		connman_technology_t *tech = connman_manager_find_technology_by_name(manager,
		                             tech_name);
		g_free(tech_name);

		if (!tech)
		{
			success &= FALSE;
			continue;
		}

		if (tech->powered)
		{
			continue;
		}

		success &= connman_technology_set_powered(tech, TRUE, &not_supported);
	}

	for (n = 0; n < jarray_size(disabled_obj); n++)
	{
		jvalue_ref tech_obj = jarray_get(disabled_obj, n);

		raw_buffer name_buf = jstring_get(tech_obj);
		char *tech_name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);

		connman_technology_t *tech = connman_manager_find_technology_by_name(manager,
		                             tech_name);
		g_free(tech_name);

		if (!tech)
		{
			success &= FALSE;
			continue;
		}

		if (!tech->powered)
		{
			continue;
		}

		success &= connman_technology_set_powered(tech, FALSE, &not_supported);
	}

	jvalue_ref reply_obj = jobject_create();

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(success));

	if (!success)
	{
		const char* error_string;
		int error_no;

		if (not_supported)
		{
			error_no = WCA_API_ERROR_SET_TECHNOLOGY_STATE_NOT_SUPPORTED;
			error_string = "Setting technology state of one or more technologies not supported";
		}
		else
		{
			error_no = WCA_API_ERROR_FAILED_TO_ENABLE_DISABLE_TECHNOLOGIES;
			error_string = "Failed to enable/disable one or more technologies";
		}

		jobject_put(reply_obj,
		            J_CSTR_TO_JVAL("errorCode"),
		            jnumber_create_i32(error_no));
		jobject_put(reply_obj,
		            J_CSTR_TO_JVAL("errorText"),
		            jstring_create(error_string));
	}

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (!response_schema)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply_obj, response_schema),
	                    &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	jschema_release(&response_schema);

cleanup:

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	if (!jis_null(reply_obj))
	{
		j_release(&reply_obj);
	}

	return true;
}

static bool handle_set_ethernet_tethering_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	if (!ethernet_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(state,
	                                     string))  REQUIRED_1(state))), &parsed_obj))
	{
		return true;
	}

	jvalue_ref state_obj = 0;
	gboolean enable_tethering = FALSE;

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("state"), &state_obj))
	{
		if (jstring_equal2(state_obj, J_CSTR_TO_BUF("enabled")))
		{
			enable_tethering = TRUE;
		}
		else if (jstring_equal2(state_obj, J_CSTR_TO_BUF("disabled")))
		{
			enable_tethering = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		if (enable_tethering && is_ethernet_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Ethernet tethering already enabled",
			                          WCA_API_ERROR_ETHERNET_TETHERING_ALREADY_ENABLED);
			goto cleanup;
		}
		else if (!enable_tethering && !is_ethernet_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Ethernet tethering already disabled",
			                          WCA_API_ERROR_ETHERNET_TETHERING_ALREADY_DISABLED);
			goto cleanup;
		}

		if (!set_ethernet_tethering_state(enable_tethering))
		{
			LSMessageReplyCustomError(sh, message, "Error in setting ethernet tethering",
			                          WCA_API_ERROR_ETHERNET_TETHERING_SET);
			goto cleanup;
		}

		LSMessageReplySuccess(sh, message);
		goto cleanup;
	}

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);

cleanup:

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	return true;
}

static bool handle_set_proxy_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(method, string), PROP(url,
	                                     string), ARRAY(servers, string), ARRAY(excludes, string), PROP(ssid, string)) REQUIRED_1(method))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0}, methodObj = {0}, urlObj = {0}, serversObj = {0}, excludesObj = {0};
	proxyinfo_t proxyinfo = {0};
	gchar *ssid = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("method"), &methodObj))
	{
		raw_buffer method_buf = jstring_get(methodObj);
		proxyinfo.method = g_strdup(method_buf.m_str);
		jstring_free_buffer(method_buf);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("url"), &urlObj))
	{
		raw_buffer url_buf = jstring_get(urlObj);
		proxyinfo.url = g_strdup(url_buf.m_str);
		jstring_free_buffer(url_buf);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("servers"), &serversObj))
	{
		int i, servers_arrsize = jarray_size(serversObj);
		proxyinfo.servers = (GStrv) g_new0(GStrv, servers_arrsize + 1);

		for (i = 0; i < servers_arrsize; i++)
		{
			raw_buffer servers_buf = jstring_get(jarray_get(serversObj, i));
			proxyinfo.servers[i] = g_strdup(servers_buf.m_str);
			jstring_free_buffer(servers_buf);
		}

		proxyinfo.servers[servers_arrsize] = NULL;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("excludes"), &excludesObj))
	{
		int i, excludes_arrsize = jarray_size(excludesObj);
		proxyinfo.excludes = (GStrv) g_new0(GStrv, excludes_arrsize + 1);

		for (i = 0; i < excludes_arrsize; i++)
		{
			raw_buffer excludes_buf = jstring_get(jarray_get(excludesObj, i));
			proxyinfo.excludes[i] = g_strdup(excludes_buf.m_str);
			jstring_free_buffer(excludes_buf);
		}

		proxyinfo.excludes[excludes_arrsize] = NULL;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
	}

	if (!g_strcmp0(proxyinfo.method, "manual"))
	{
		if (NULL == proxyinfo.servers)
			goto invalid_params;
	}

	connman_service_t *service = retrieve_service_by_ssid(ssid);

	if (NULL != service)
	{
		if (connman_service_set_proxy(service, &proxyinfo))
		{
			LSMessageReplySuccess(sh, message);
		}
		else
		{
			LSMessageReplyErrorUnknown(sh, message);
		}
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "No connected network",
		                          WCA_API_ERROR_NO_CONNECTED_NW);
	}

	goto exit;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
exit:
	g_free(proxyinfo.method);
	g_free(proxyinfo.url);
	g_strfreev(proxyinfo.servers);
	g_strfreev(proxyinfo.excludes);
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

static bool handle_find_proxy_for_url_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(url, string), PROP(host,
	                                     string)) REQUIRED_2(url,host))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	jvalue_ref urlObj = {0}, hostObj = {0};
	gchar *url = NULL, *host = NULL, *proxy = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("url"), &urlObj))
	{
		raw_buffer url_buf = jstring_get(urlObj);
		url = g_strdup(url_buf.m_str);
		jstring_free_buffer(url_buf);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("host"), &hostObj))
	{
		raw_buffer host_buf = jstring_get(hostObj);
		host = g_strdup(host_buf.m_str);
		jstring_free_buffer(host_buf);
	}

	pacrunner_client_t *client = pacrunner_client_new();

	proxy = pacrunner_client_find_proxy_for_url(client, url, host);
	if (NULL != proxy)
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply, J_CSTR_TO_JVAL("proxy"), jstring_create(proxy));

		jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
		                              DOMOPT_NOOPT, NULL);

		if (!response_schema)
		{
			LSMessageReplyErrorUnknown(sh, message);
			goto cleanup;
		}

		if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema),
		                    &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
		goto cleanup;
	}

	LSMessageReplyCustomError(sh, message, "Error in finding proxy for url",
									WCA_API_ERROR_PROXY_FIND_PROXY_FOR_URL_ERROR);

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(url);
	g_free(host);
	g_free(proxy);
	pacrunner_client_free(client);
	j_release(&reply);
	return true;
}

/**
 * @brief com.webos.service.connectionmanager service method table
 */

static LSMethod connectionmanager_methods[] =
{
	{ LUNA_METHOD_GETSTATUS,            handle_get_status_command },
	{ LUNA_METHOD_GETSTATUS2,           handle_get_status_command },
	{ LUNA_METHOD_SETIPV4,              handle_set_ipv4_command },
	{ LUNA_METHOD_SETDNS,               handle_set_dns_command },
	{ LUNA_METHOD_SETSTATE,             handle_set_state_command },
	{ LUNA_METHOD_GETINFO,              handle_get_info_command },
	{ LUNA_METHOD_SETIPV6,              handle_set_ipv6_command },
	{ LUNA_METHOD_MONITORACTIVITY,      handle_monitor_activity_command },
	{ LUNA_METHOD_SETTECHNOLOGYSTATE,   handle_set_technology_state_command },
	{ LUNA_METHOD_SETETHERNETTETHERING, handle_set_ethernet_tethering_command },
	{ LUNA_METHOD_SETPROXY,             handle_set_proxy_command },
	{ LUNA_METHOD_FINDPROXYFORURL,      handle_find_proxy_for_url_command },
	{ },
};

/**
 *  @brief Initialize the com.webos.service.connectionmanager service and register all provided
 *  service method on the luna service bus.
 *
 *  @param mainloop Reference to the used glib mainloop object
 *  @return 0 if service is initialized successfull. -1 otherwise.
 */

int initialize_connectionmanager_ls2_calls(GMainLoop *mainloop,
        LSHandle **cm_handle)
{
	LSError lserror;
	LSErrorInit(&lserror);
	pLsHandle = NULL;

	if (!mainloop)
	{
		goto exit;
	}

	if (!LSRegister(CONNECTIONMANAGER_LUNA_SERVICE_NAME, &pLsHandle, &lserror))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_CM_LUNA_BUS_ERROR, lserror.message);
		goto exit;
	}

	if (!LSRegisterCategory(pLsHandle, LUNA_CATEGORY_ROOT,
	                        connectionmanager_methods,
	                        NULL, NULL, &lserror))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_CM_METHODS_LUNA_ERROR, lserror.message);
		goto exit;
	}

	if (!LSGmainAttach(pLsHandle, mainloop, &lserror))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_CM_GLOOP_ATTACH_ERROR, lserror.message);
		goto exit;
	}

	*cm_handle = pLsHandle;

	return 0;

exit:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	if (pLsHandle)
	{
		LSErrorInit(&lserror);

		if (!LSUnregister(pLsHandle, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	return -1;
}
