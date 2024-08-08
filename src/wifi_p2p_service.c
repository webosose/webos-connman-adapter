/* @@@LICENSE
*
* Copyright (c) 2024 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/**
 * @file  wifi_p2p_service.c
 *
 * @brief Implements the com.webos.service.wifi/p2p service API with using connman in the backend.
 */

#include <glib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <pbnjson.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "wifi_service.h"
#include "wifi_profile.h"
#include "wifi_setting.h"
#include "wifi_p2p_service.h"
#include "wifi_scan.h"
#include "connman_manager.h"
#include "connman_service.h"
#include "connman_agent.h"
#include "connman_service_discovery.h"
#include "lunaservice_utils.h"
#include "common.h"
#include "connectionmanager_service.h"
#include "logging.h"
#include "errors.h"
#include "wfdsie/wfdinfoelemwrapper.h"

LSHandle *localpLSHandle = NULL;
bool subscribed_for_device_name = false;
static pthread_mutex_t callback_sequence_lock = PTHREAD_MUTEX_INITIALIZER;
static gboolean group_added_by_p2p_request = FALSE;
static gboolean group_added_pending = FALSE;

static char* p2p_get_state_prev_response = NULL;

void manager_groups_changed_callback(gpointer data, gboolean group_added);
void setPropertyUpdateCallback(connman_service_t *service);

/**
@page com_webos_wifi_p2p com.webos.wifi/p2p

@brief Manages connections to WiFi Direct (P2P) networks.

Each call has a standard return in the case of a failure, as follows:

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | False to inidicate an error
errorCode | Yes | Integer | Error code
errorText | Yes | String | Error description

@{
@}
*/


/**
 *  @brief Check whether p2p is enabled or not.
 *
 *  @return TRUE if P2P is enabled. FALSE otherwise.
 */

gboolean is_p2p_enabled(void)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);
	return (NULL != technology) && technology->powered;
}

/**
 * @brief Enable or disable P2P functionality by setting it's power state. This will not
 * turn of WiFi functionality but just P2P.
 *
 * @param state TRUE if P2P should be powered off. FALSE otherwise.
 * @return TRUE if the operation was successfull. FALSE otherwise.
 */

static gboolean set_p2p_power_state(gboolean state)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (technology)
	{
		return connman_technology_set_powered(technology, state, NULL);
	}
	else
	{
		return FALSE;
	}
}

/**
 *  @brief Check if the P2P listen state is enabled or not.
 *
 *  @return TRUE if P2P listen state is enabled. FALSE otherwise.
 */

gboolean is_p2p_listen_state_enabled(void)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);
	return (NULL != technology) && technology->p2p_listen;
}

/**
 *  @brief Enable or disable the P2P listen state.
 *
 *  @param state TRUE if P2P listen state should be enabled. FALSE otherwise.
 *  @return TRUE if the operation was successfull. FALSE otherwise.
 */

static gboolean set_p2p_listen_state(gboolean state)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (technology)
	{
		return connman_technology_set_p2p_listen_state(technology, state);
	}
	else
	{
		return FALSE;
	}
}

/**
 *  @brief Check if the P2P persistent mode is anbled or not.
 *
 *  @return TRUE if the P2P persistent mode is enabled. FALSE otherwise
 */

gboolean is_p2p_persistent_mode_enabled(void)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);
	return (NULL != technology) && technology->persistent_mode;
}

/**
 *  @brief Enable or disable the P2P persistent mode.
 *
 *  @param state TRUE to enable the P2P persistent mode. FALSE otherwise.
 *  @return TRUE if the operation was successfull. FALSE otherwise.
 */

static gboolean set_p2p_persistent_mode(gboolean state)
{
	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (technology)
	{
		return connman_technology_set_p2p_persistent_mode(technology, state);
	}
	else
	{
		return FALSE;
	}
}

/**
 * @brief Find a specific peer by it's address for the list of internally stored peer
 * objects.
 *
 * @param address The address of the peer to find. It's simply it's MAC address in the
 * format HH:HH:HH:HH:HH:HH (where H is one hex digit).
 * @return If a peer with the supplied address is found the object representation of the
 * peer. NULL otherwise.
 */

static connman_service_t *find_peer_by_address(const gchar *address)
{
	connman_service_t *service = NULL;
	GSList *listnode = NULL;

	for (listnode = manager->p2p_services; NULL != listnode ;
	        listnode = listnode->next)
	{
		service = (connman_service_t *)(listnode->data);

		if (!g_strcmp0(service->peer.address, address))
		{
			return service;
		}
	}

	return NULL;
}

/**
 * @brief Find a group by it's name (SSID) from the internal stored list of group objects.
 *
 * @param ssid SSID of the group to search for.
 * @return If a group for the supplied SSID is found the object representation of the
 * group. NULL otherwise.
 */

static connman_group_t *find_group_by_name(const char *ssid)
{
	connman_group_t *group = NULL;
	GSList *listnode = NULL;

	for (listnode = manager->groups; NULL != listnode ; listnode = listnode->next)
	{
		group = (connman_group_t *)(listnode->data);

		if (!g_strcmp0(group->name, ssid))
		{
			return group;
		}
	}

	return NULL;
}

/**
 * @brief Append the requested peer to the JSON object.
 *
 * @param reply JSON object to which the requested peeer should be appended,
 * if the device address is matched.
 */

static void append_requested_peer(jvalue_ref *reply,
                                  const gchar *device_address)
{
	if (NULL == reply)
	{
		return;
	}

	GSList *listnode;
	jvalue_ref wfd_info = jobject_create();

	for (listnode = manager->p2p_services; listnode ; listnode = listnode->next)
	{
		connman_service_t *service = (connman_service_t *)(listnode->data);

		if (!g_strcmp0(device_address, service->peer.address) &&
		        service->peer.wfd_enabled)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("deviceName"),
			            jstring_create(service->name));

			switch (service->peer.wfd_devtype)
			{
				case CONNMAN_WFD_DEV_TYPE_SOURCE:
					jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
					            jstring_create("source"));
					break;

				case CONNMAN_WFD_DEV_TYPE_PRIMARY_SINK:
					jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
					            jstring_create("primary-sink"));
					break;

				case CONNMAN_WFD_DEV_TYPE_SECONDARY_SINK:
					jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
					            jstring_create("secondary-sink"));
					break;

				case CONNMAN_WFD_DEV_TYPE_DUAL:
					jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
					            jstring_create("dual-role"));
					break;

				default:
					break;
			}

			jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdSessionAvail"),
			            jboolean_create(service->peer.wfd_sessionavail));
			jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdCpSupport"),
			            jboolean_create(service->peer.wfd_cpsupport));
			jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdRtspPort"),
			            jnumber_create_i32(service->peer.wfd_rtspport));
		}
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("wfdInfo"), wfd_info);
}


static void append_device_type(jvalue_ref *reply, const gchar *pri_dev_type)
{
	if (!g_strcmp0(pri_dev_type, "000a0050f2040005"))
			jobject_put(*reply, J_CSTR_TO_JVAL("deviceType"), jstring_create("phone"));
	/* 00010050f2000000 is win8.1 or win10, 00010050f2040000 is win8, 00010050f2040001 is win7 */
	else if (!g_strcmp0(pri_dev_type, "00010050f2000000") ||
			!g_strcmp0(pri_dev_type, "00010050f2040000") ||
			!g_strcmp0(pri_dev_type, "00010050f2040001"))
			jobject_put(*reply, J_CSTR_TO_JVAL("deviceType"), jstring_create("pc"));
	else
			jobject_put(*reply, J_CSTR_TO_JVAL("deviceType"),
					jstring_create(pri_dev_type));
}

/**
 * @brief Notify possible subscribers of the com.webos.service.wifi/p2p/getp2prequests method about
 * a new P2P connection request.
 *
 * @param data User context data.
 * @param wpstype The WPS type the other peers requests to use for the connection
 * establishment.
 * @param wpspin The WPS pin (if wpstype is WPS_DISPLAY) to use
 * @param goaddr The address of the group owner.
 */
static void notify_new_p2p_request(gpointer data, const int wpstype,
                                   const gchar *wpspin, const gchar *goaddr,
                                   const char *signal_name)
{
	connman_service_t *service = (connman_service_t *) data;

	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("deviceName"), jstring_create(service->name));
	jobject_put(reply, J_CSTR_TO_JVAL("deviceAddress"),
	            jstring_create(service->peer.address));
	jobject_put(reply, J_CSTR_TO_JVAL("signalName"), jstring_create(signal_name));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));

	switch (wpstype)
	{
		case WPS_PBC:
			jobject_put(reply, J_CSTR_TO_JVAL("wpsType"), jstring_create("pbc"));
			break;

		case WPS_KEYPAD:
			jobject_put(reply, J_CSTR_TO_JVAL("wpsType"), jstring_create("keypad"));
			break;

		case WPS_DISPLAY:
			jobject_put(reply, J_CSTR_TO_JVAL("wpsType"), jstring_create("display"));

			if (wpspin)
			{
				jobject_put(reply, J_CSTR_TO_JVAL("wpsPin"), jstring_create(wpspin));
			}

			break;

		default:
			if (goaddr)
			{
				jobject_put(reply, J_CSTR_TO_JVAL("groupOwner"), jstring_create(goaddr));
			}

			break;
	}

	if (service->peer.pri_dev_type)
		append_device_type(&reply, service->peer.pri_dev_type);
	append_requested_peer(&reply, service->peer.address);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		WCALOG_INFO(MSGID_P2P_CONNECT_PEER, 0, "Incoming P2P request : %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(localpLSHandle, "/p2p/getp2prequests",
		                        payload,
		                        &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);

	if (wpspin == NULL)
		manager_groups_changed_callback(NULL, TRUE);
}

/**
 * @brief Append peer specific information to a existing JSON object
 *
 * @param peer_info JSON object the peer information should be appended to
 * @param service The service object which represents the peer itself.
 */

static void append_peer_information(jvalue_ref *peer_info,
                                    connman_service_t *service)
{
	jobject_put(*peer_info, J_CSTR_TO_JVAL("deviceName"),
	            jstring_create(service->name));

	if (service->peer.address)
	{
		jobject_put(*peer_info, J_CSTR_TO_JVAL("deviceAddress"),
		            jstring_create(service->peer.address));
	}

	jobject_put(*peer_info, J_CSTR_TO_JVAL("groupOwner"),
	            jboolean_create(service->peer.group_owner));

	if (service->peer.config_method)
	{
		jobject_put(*peer_info, J_CSTR_TO_JVAL("configMethod"),
		            jnumber_create_i32(service->peer.config_method));
	}

	if (service->peer.pri_dev_type)
		append_device_type(peer_info, service->peer.pri_dev_type);

	jobject_put(*peer_info, J_CSTR_TO_JVAL("signalLevel"),
	            jnumber_create_i32(service->strength));

	if (service->peer.wfd_enabled)
	{
		jvalue_ref wfd_info = jobject_create();

		switch (service->peer.wfd_devtype)
		{
			case CONNMAN_WFD_DEV_TYPE_SOURCE:
				jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("source"));
				break;

			case CONNMAN_WFD_DEV_TYPE_PRIMARY_SINK:
				jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("primary-sink"));
				break;

			case CONNMAN_WFD_DEV_TYPE_SECONDARY_SINK:
				jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("secondary-sink"));
				break;

			case CONNMAN_WFD_DEV_TYPE_DUAL:
				jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("dual-role"));
				break;

			default:
				break;
		}

		jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdSessionAvail"),
		            jboolean_create(service->peer.wfd_sessionavail));
		jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdCpSupport"),
		            jboolean_create(service->peer.wfd_cpsupport));
		jobject_put(wfd_info, J_CSTR_TO_JVAL("wfdRtspPort"),
		            jnumber_create_i32(service->peer.wfd_rtspport));
		jobject_put(*peer_info, J_CSTR_TO_JVAL("wfdInfo"), wfd_info);
	}

	bool connection_state = ((connman_service_get_state(service->state) ==
	                          CONNMAN_SERVICE_STATE_READY) ||
	                         (connman_service_get_state(service->state) == CONNMAN_SERVICE_STATE_ONLINE));
	jobject_put(*peer_info, J_CSTR_TO_JVAL("connected"),
	            jboolean_create(connection_state));

	if (NULL != service->ipinfo.ipv4.address)
	{
		jobject_put(*peer_info, J_CSTR_TO_JVAL("peerIp"),
		            jstring_create(service->ipinfo.ipv4.address));
	}

	if (connman_service_get_state(service->state) ==
	        CONNMAN_SERVICE_STATE_ASSOCIATION)
	{
		jobject_put(*peer_info, J_CSTR_TO_JVAL("invited"), jboolean_create(true));
	}

	if (connman_service_get_state(service->state) == CONNMAN_SERVICE_STATE_FAILURE)
	{
		jobject_put(*peer_info, J_CSTR_TO_JVAL("invited"), jboolean_create(false));
	}

	if (service->peer.service_discovery_response)
	{
		/* Send service discovery response only once, and then free the field so that its not sent again */
		jobject_put(*peer_info, J_CSTR_TO_JVAL("serviceDiscoveryResponse"),
		            jstring_create(service->peer.service_discovery_response));
		g_free(service->peer.service_discovery_response);
		service->peer.service_discovery_response = NULL;
	}
}

static gboolean is_connected_state(connman_service_t *service)
{
	return ((connman_service_get_state(service->state) == CONNMAN_SERVICE_STATE_READY) ||
			(connman_service_get_state(service->state) == CONNMAN_SERVICE_STATE_ONLINE));
}

static void updatepeers_propertychanged_callback()
{
	GSList *listnode;

	if(manager)
	{
		for (listnode = manager->p2p_services; listnode ; listnode = listnode->next)
		{
			connman_service_t *service = (connman_service_t *)(listnode->data);
			setPropertyUpdateCallback(service);
		}
	}
}

/**
 * @brief Append all available peers to the JSON object with their specific information.
 *
 * @param reply JSON object to which the peers should be appended.
 */

static gboolean append_peers(jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return FALSE;
	}

	GSList *listnode;
	gboolean peer_found = FALSE;
	gboolean connected_peer_found = FALSE;

	jvalue_ref peer_list = jarray_create(NULL);
	jvalue_ref connected_peer = jarray_create(NULL);

	for (listnode = manager->p2p_services; listnode ; listnode = listnode->next)
	{
		connman_service_t *service = (connman_service_t *)(listnode->data);

		jvalue_ref peer_info = jobject_create();

		append_peer_information(&peer_info, service);

		jvalue_ref peer_list_j = jobject_create();
		jobject_put(peer_list_j, J_CSTR_TO_JVAL("peerInfo"), peer_info);

		/* FIXME we're doing things which are unrelated to populating the peer
		 * information as part of the JSON object. This needs to be moved
		 * somewhere else */
		connman_service_register_p2p_requests_cb(service, notify_new_p2p_request);

		peer_found = TRUE;
		if (is_connected_state(service))
		{
			jarray_append(connected_peer, peer_list_j);
			connected_peer_found = TRUE;
			continue;
		}
		else
			jarray_append(peer_list, peer_list_j);
	}

	if (connected_peer_found)
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("peers"), connected_peer);
		j_release(&peer_list);
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("peers"), peer_list);
		j_release(&connected_peer);
	}

	return peer_found;
}

gboolean is_connected_peer(void)
{
	GSList *listnode;

	for (listnode = manager->p2p_services; listnode ; listnode = listnode->next)
	{
		connman_service_t *service = (connman_service_t *)(listnode->data);

		if (is_connected_state(service))
		{
			WCALOG_DEBUG("Connected peer is found. p2p scan will be blocked.");
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief Send an update to subscribers for com.webos.service.wifi/p2p/getpeers about changes to
 * the list of available peers.
 */

void send_peer_information_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	append_peers(&reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		WCALOG_DEBUG("Sending payload %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(localpLSHandle, "/p2p/getpeers",
		                        payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
}

/**
 * @brief Callback function registered with the connman service object which
 * represents the peer and is called whenever the any service property
 * changes.
 *
 * @param data User context data
 * @param new_state Name of the new state the peer switched to
 */

static void peer_service_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	connman_service_t *service = (connman_service_t *) data;

	if (NULL == service)
	{
		return;
	}

	if (!g_strcmp0(property, "State"))
	{
		WCALOG_DEBUG("Service %s state changed to %s", service->name, service->state);

		int service_state = connman_service_get_state(service->state);

		switch (service_state)
		{
			case CONNMAN_SERVICE_STATE_IDLE:
				connectionmanager_send_status_to_subscribers();
				send_peer_information_to_subscribers();
				break;

			case CONNMAN_SERVICE_STATE_ASSOCIATION:
				send_peer_information_to_subscribers();
				break;

			case CONNMAN_SERVICE_STATE_READY:
			case CONNMAN_SERVICE_STATE_ONLINE:
				connectionmanager_send_status_to_subscribers();
				send_peer_information_to_subscribers();
				/* Unset agent callback as we no longer have any valid input for connman available */
				connman_agent_set_request_input_callback(agent, NULL, NULL);
				break;
		}
	}

	if (!g_strcmp0(property, "IPv4"))
	{
		gsize j;
		for (j = 0; j < g_variant_n_children(value); j++)
		{
			GVariant *ipv4 = g_variant_get_child_value(value, j);
			GVariant *ikey_v = g_variant_get_child_value(ipv4, 0);
			const gchar *ikey = g_variant_get_string(ikey_v, NULL);

			if (!g_strcmp0(ikey, "Remote"))
			{
				GVariant *addressv = g_variant_get_child_value(ipv4, 1);
				GVariant *addressva = g_variant_get_variant(addressv);
				const gchar *new_addressva = g_variant_get_string(addressva, NULL);

				if (g_strcmp0(new_addressva, service->ipinfo.ipv4.address)){
					g_free(service->ipinfo.ipv4.address);
					service->ipinfo.ipv4.address = g_variant_dup_string(addressva, NULL);
					send_peer_information_to_subscribers();
				}

				g_variant_unref(addressv);
				g_variant_unref(addressva);
			}

			g_variant_unref(ipv4);
			g_variant_unref(ikey_v);
		}
	}
}

/**
 * @brief Append information about the available P2P groups to a existing JSON object.
 *
 * @param reply The JSON object the group information should be appended to.
 */

static gboolean append_groups(jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return FALSE;
	}

	GSList *listnode;
	gboolean group_found = FALSE;
	jvalue_ref group_list = jarray_create(NULL);

	for (listnode = manager->groups; listnode ; listnode = listnode->next)
	{
		connman_group_t *group = (connman_group_t *)(listnode->data);
		jvalue_ref group_info = jobject_create();

		jobject_put(group_info, J_CSTR_TO_JVAL("ssid"), jstring_create(group->name));
		jobject_put(group_info, J_CSTR_TO_JVAL("owner"),
		            jboolean_create(group->is_group_owner));
		jobject_put(group_info, J_CSTR_TO_JVAL("persistent"),
		            jboolean_create(group->is_persistent));
		jobject_put(group_info, J_CSTR_TO_JVAL("tethering"),
		            jboolean_create(group->tethering));
		jobject_put(group_info, J_CSTR_TO_JVAL("frequency"),
		            jnumber_create_i32(group->freq));

		jvalue_ref group_list_j = jobject_create();
		jobject_put(group_list_j, J_CSTR_TO_JVAL("groupInfo"), group_info);
		jarray_append(group_list, group_list_j);

		group_found = TRUE;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("groups"), group_list);

	return group_found;
}

/**
 * @brief Callback called from connman when any of the available group objects changes. As
 * consequence this will send an update to all subscribers of the
 * com.webos.service.wifi/p2p/getgroups method.
 *
 * @param data User context data
 */

void manager_groups_changed_callback(gpointer data, gboolean group_added)
{
	if (group_added)
	{
                if (pthread_mutex_lock(&callback_sequence_lock)!=0)
                {
                        return;
                }

		if (!group_added_by_p2p_request && !group_added_pending)
		{
			if (data)
				group_added_pending = TRUE;

			group_added_by_p2p_request = TRUE;
			pthread_mutex_unlock(&callback_sequence_lock);
			return;
		}

		if (!group_added_pending && !data) {
			pthread_mutex_unlock(&callback_sequence_lock);
			return;
		}

		group_added_by_p2p_request = FALSE;
		group_added_pending = FALSE;
		pthread_mutex_unlock(&callback_sequence_lock);
	}

	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	append_groups(&reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		WCALOG_DEBUG("Sending payload %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(localpLSHandle, "/p2p/getgroups", payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
}

static gboolean set_p2p_persistent_callback(gpointer user_data)
{
	gboolean enable_persistent_mode = user_data;

	set_p2p_persistent_mode(enable_persistent_mode);

	return FALSE;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setstate setstate

Enables/disables Wi-Fi Direct technology

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
P2P | No | String | "enabled" or "disabled" to control P2P state accordingly
listenState | No | String | "enabled" or "disabled" to control P2P listen state accordingly
persistentMode | No | String | "enabled" or "disabled" to control P2P persistent mode accordingly

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_state_command(LSHandle *sh, LSMessage *message,
                                     void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_3(PROP(P2P, string),
	                                     PROP(listenState, string), PROP(persistentMode, string)))), &parsedObj))
	{
		return true;
	}

	gboolean enable_p2p = TRUE, enable_p2p_listen = FALSE,
	         enable_persistent_mode = FALSE, error = FALSE;

        int lock_result = pthread_mutex_lock(&callback_sequence_lock);
        if (lock_result != 0)
        {
           goto cleanup;
        }
	group_added_by_p2p_request = FALSE;
	group_added_pending = FALSE;
	pthread_mutex_unlock(&callback_sequence_lock);

	jvalue_ref stateObj = {0};

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("P2P"), &stateObj))
	{
		if (jstring_equal2(stateObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_p2p = TRUE;
			if (!(enable_p2p == is_p2p_enabled()) && !set_p2p_power_state(enable_p2p))
			{
				LSMessageReplyCustomError(sh, message, "Error in changing P2P state",
				                          WCA_API_ERROR_P2P_STATE_CHANGE);
				error = TRUE;
				goto cleanup;
			}
		}
		else if (jstring_equal2(stateObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_p2p = FALSE;
		}
		else
		{
			goto invalid_params;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("listenState"), &stateObj))
	{
		if (jstring_equal2(stateObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_p2p_listen = TRUE;
		}
		else if (jstring_equal2(stateObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_p2p_listen = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		if (!is_p2p_enabled())
		{
			LSMessageReplyCustomError(sh, message,
			                          "P2P disabled, so cannot changing listen state",
			                          WCA_API_ERROR_P2P_DISABLED);
			goto cleanup;
		}
		else if (!set_p2p_listen_state(enable_p2p_listen))
		{
			LSMessageReplyCustomError(sh, message, "Error in changing listen state",
			                          WCA_API_ERROR_LISTEN_STATE);
			goto cleanup;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("persistentMode"), &stateObj))
	{
		if (jstring_equal2(stateObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_persistent_mode = TRUE;
		}
		else if (jstring_equal2(stateObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_persistent_mode = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		if (!is_p2p_enabled())
		{
			LSMessageReplyCustomError(sh, message,
			                          "P2P disabled, so cannot changing persistent mode",
			                          WCA_API_ERROR_P2P_DISABLED);
			goto cleanup;
		}

		if (!enable_p2p)
		{
				if (!set_p2p_persistent_mode(enable_persistent_mode))
				{
					LSMessageReplyCustomError(sh, message, "Error in changing persistent mode",
							WCA_API_ERROR_PERSISTENT_STATE);
					goto cleanup;
				}
		}
		else
			g_timeout_add(500, set_p2p_persistent_callback, enable_persistent_mode);
	}

	if (!enable_p2p && !(enable_p2p == is_p2p_enabled()) && !set_p2p_power_state(enable_p2p))
	{
		LSMessageReplyCustomError(sh, message, "Error in changing P2P state",
								  WCA_API_ERROR_P2P_STATE_CHANGE);
		error = TRUE;
	}

	if (!error)
	{
		LSMessageReplySuccess(sh, message);
	}

	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;
}

/**
 * @brief Fill in all status information to be sent with '/p2p/getstate' method
 */

static void create_wifi_p2p_get_state_response(jvalue_ref *reply, bool subscribed)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(*reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	if (is_p2p_enabled())
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("P2P"), jstring_create("enabled"));
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("P2P"), jstring_create("disabled"));
	}

	if (is_p2p_listen_state_enabled())
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("listenState"), jstring_create("enabled"));
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("listenState"), jstring_create("disabled"));
	}

	if (is_p2p_persistent_mode_enabled())
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("persistentMode"),
		            jstring_create("enabled"));
	}
	else
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("persistentMode"),
		            jstring_create("disabled"));
	}
}

void send_p2p_get_state_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();

	create_wifi_p2p_get_state_response(&reply, true);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		/*
		 * Do not send identical responses back.
		 * Check if the payload is different from previous payload.
		 * Note this is executed also when there are no subscribers, keeping
		 * prev_response always up to date with current situation.
		 **/
		 if (g_strcmp0(payload, p2p_get_state_prev_response) != 0)
		 {
			g_free(p2p_get_state_prev_response);
			p2p_get_state_prev_response = g_strdup(payload);

			WCALOG_DEBUG("Sending payload : %s", payload);

			LSError lserror;
			LSErrorInit(&lserror);

			if (!LSSubscriptionReply(localpLSHandle, "/p2p/getstate", payload, &lserror))
			{
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}
		}
			jschema_release(&response_schema);
	}

	j_release(&reply);
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_getstate getstate

Gets the state for Wi-Fi Direct technology

@par Parameters

None required

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
P2P | Yes | String | "enabled" or "disabled"
listenState | Yes | String | "enabled" or "disabled"
persistentMode | Yes | String | "enabled" or "disabled"

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_state_command(LSHandle *sh, LSMessage *message,
                                     void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialize
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

	if (!connman_status_check_with_subscription(manager, sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!p2p_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	create_wifi_p2p_get_state_response(&reply, subscribed);

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_getpeers getpeers

Gets the information about the Wi-Fi Direct peers

Callers can subscribe to this method to be notified of any changes
in the list of neighbouring peers.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
peers | No | Array of Objects | List of p2p peers (see "peerInfo" Object)

@par "peerInfo" Object

Each entry in the "peers" array is of the form "peerInfo":{...}

Name | Required | Type | Description
-----|--------|------|----------
deviceName | Yes | String | Name of the peer
deviceAddress | Yes | String | Hardware (MAC) address of the peer
groupOwner | Yes | Boolean | True if this peer is owner of a group
configMethod | Yes | Integer | Authentication method that peer supports "PIN" or "PBC"
signalLevel | Yes | Integer | Signal strength of the peer

@par Returns(Subscription)

As for a successful call
@}
*/
//->End of API documentation comment block

static bool handle_get_peers_command(LSHandle *sh, LSMessage *message,
                                     void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(subscribe, boolean),
		PROP(scan, boolean)))), &parsedObj))
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

	jvalue_ref scanObj = NULL;
	gboolean scan = TRUE;

	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("scan"), &scanObj))
	{
		bool value;
		jboolean_get(scanObj, &value);
		scan = value? TRUE : FALSE;
	}

	if (!connman_status_check_with_subscription(manager, sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!p2p_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message, "P2P is not enabled",
		        WCA_API_ERROR_P2P_DISABLED, subscribed);
		return true;
	}

	if (subscribed && scan)
	{
		if (!wifi_scan_now_p2p())
		{
			LSMessageReplyCustomErrorWithSubscription(sh, message,
			        "Error in scanning network", WCA_API_ERROR_SCANNING, subscribed);
			return true;
		}
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	append_peers(&reply);
	updatepeers_propertychanged_callback();

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

static void service_connect_callback(gboolean success, gpointer user_data)
{
	luna_service_request_t *service_req = user_data;

	if (success)
	{
		LSMessageReplySuccess(service_req->handle, service_req->message);
	}
	else
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Failed to connect",
		                          WCA_API_ERROR_FAILED_TO_CONNECT);
	}

	luna_service_request_free(service_req);
}


//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_connect connect

Connect to a given p2p peer

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
peerAddress | Yes | String | Device address of the peer that we want to connect to
wpsInfo | Yes | Object | WPS information to connect to the peer

@par "wpsInfo" Object

Name | Required | Type | Description
-----|--------|------|----------
wps | Yes | Boolean | true to enable wps mode
wpspin | No | String | WPS PIN if using WPS-PIN mode

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_connect_command(LSHandle *sh, LSMessage *message,
                                   void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(peerAddress, string),
	                                     OBJECT(wpsInfo, OBJSCHEMA_2(PROP(wps, boolean), PROP(wpsPin,
	                                             string)))) REQUIRED_2(peerAddress, wpsInfo))), &parsedObj))
	{
		return true;
	}

	jvalue_ref peerAddressObj = {0};
	char *peerAddress = NULL;
	jvalue_ref wpsinfo_obj = NULL;
	jvalue_ref wps_obj = NULL;
	jvalue_ref wpspin_obj = NULL;
	raw_buffer wpspin_buf;
	connman_service_t *service = NULL;

	connection_settings_t *settings = NULL;
	luna_service_request_t *service_req = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("peerAddress"),
	                       &peerAddressObj))
	{
		raw_buffer address_buf = jstring_get(peerAddressObj);
		peerAddress = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the service with the given peer address */
	service = find_peer_by_address(peerAddress);

	if (service == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Peer not found",
		                          WCA_API_ERROR_PEER_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_ADDR_INFOMSG(MSGID_P2P_CONNECT_PEER, "Peer", service);

	/* Register for 'state changed' signal for this service to update its connection status */
	connman_service_register_property_changed_cb(service,
	        peer_service_property_changed_callback);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wpsInfo"), &wpsinfo_obj))
	{
		settings = connection_settings_new();
		settings->ssid = strdup(service->name);

		if (jobject_get_exists(wpsinfo_obj, J_CSTR_TO_BUF("wps"), &wps_obj))
		{
			jboolean_get(wps_obj, &settings->wpsmode);

			if (jobject_get_exists(wpsinfo_obj, J_CSTR_TO_BUF("wpsPin"), &wpspin_obj))
			{
				wpspin_buf = jstring_get(wpspin_obj);
				settings->wpspin = strdup(wpspin_buf.m_str);
				jstring_free_buffer(wpspin_buf);
			}
			else
			{
				settings->wpspin = strdup("");
			}
		}
                int lock_result = pthread_mutex_lock(&callback_sequence_lock);
                if(lock_result!=0)
                {
                    goto cleanup;
                }

		group_added_by_p2p_request = TRUE;
		pthread_mutex_unlock(&callback_sequence_lock);
		WCALOG_DEBUG("Setup for connecting with secured network");
		connman_agent_set_request_input_callback(agent, agent_request_input_callback,
		        settings);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (connman_service_get_state(service->state) ==
	        CONNMAN_SERVICE_STATE_ASSOCIATION)
	{
		LSMessageReplyCustomError(sh, message, "Peer still in association state",
		                          WCA_API_ERROR_PEER_IN_ASSOC);
		goto cleanup;
	}

	service_req = luna_service_request_new(sh, message);

	if (!connman_peer_connect(service, service_connect_callback, service_req))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

cleanup:
	g_free(peerAddress);
	j_release(&parsedObj);
	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_disconnect disconnect

Disconnect the given p2p peer

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
peerAddress | Yes | String | Device address of the peer that we want to connect to

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_disconnect_command(LSHandle *sh, LSMessage *message,
                                      void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(peerAddress,
	                                     string)) REQUIRED_1(peerAddress))), &parsedObj))
	{
		return true;
	}

	jvalue_ref peerAddressObj = {0};
	char *peerAddress = NULL;
	int service_state;
	connman_service_t *service = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("peerAddress"),
	                       &peerAddressObj))
	{
		raw_buffer address_buf = jstring_get(peerAddressObj);
		peerAddress = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the service with the given peer address */
	service = find_peer_by_address(peerAddress);
	if (service == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Peer not found",
		                          WCA_API_ERROR_PEER_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_ADDR_INFOMSG(MSGID_P2P_DISCONNECT_PEER, "Peer", service);

	service_state = connman_service_get_state(service->state);

	if (service_state != CONNMAN_SERVICE_STATE_READY)
	{
		LSMessageReplyCustomError(sh, message, "Not connected",
		                          WCA_API_ERROR_NOT_CONNECTED);
		goto cleanup;
	}

	if (!connman_peer_disconnect(service))
	{
		LSMessageReplyCustomError(sh, message, "Error in disconnecting peer",
			                          WCA_API_ERROR_DISCONNECT_FAILED);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(peerAddress);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_invite invite

Invite a p2p peer to the group that this device belongs to

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
peerAddress | Yes | String | Device address of the peer that we want to invite

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_invite_command(LSHandle *sh, LSMessage *message,
                                  void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(peerAddress,
	                                     string)) REQUIRED_1(peerAddress))), &parsedObj))
	{
		return true;
	}

	jvalue_ref peerAddressObj = {0};
	char *peerAddress = NULL;
	connman_service_t *service = NULL;
	connman_group_t *group = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("peerAddress"),
	                       &peerAddressObj))
	{
		raw_buffer address_buf = jstring_get(peerAddressObj);
		peerAddress = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the service with the given peer address */
	service = find_peer_by_address(peerAddress);

	if (service == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Peer not found",
		                          WCA_API_ERROR_PEER_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_ADDR_INFOMSG(MSGID_P2P_INVITE_PEER, "Peer", service);

	// As of now connman supports just one group on the dbus, so use that group
	if (manager->groups == NULL)
	{
		LSMessageReplyCustomError(sh, message, "No active group found",
		                          WCA_API_ERROR_NO_ACTIVE_GRP);
		goto cleanup;
	}

	group = (connman_group_t *)(manager->groups->data);

	if (!connman_group_invite_peer(group, service))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(peerAddress);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_creategroup creategroup

Create an autonomous group

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | Name of the new group we want to create
passPhrase | Yes | String | Passphrase for connecting to this group

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_create_group_command(LSHandle *sh, LSMessage *message,
                                        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(ssid, string),
	                                     PROP(passPhrase, string)) REQUIRED_2(ssid, passPhrase))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0}, passPhraseObj = {0};
	char *ssid = NULL, *passphrase = NULL;
	int passphrase_length;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer address_buf = jstring_get(ssidObj);
		ssid = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("passPhrase"), &passPhraseObj))
	{
		raw_buffer address_buf = jstring_get(passPhraseObj);
		passphrase = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	passphrase_length = strlen(passphrase);

	if (passphrase_length < 8 || passphrase_length > 63)
	{
		LSMessageReplyCustomError(sh,
		                          message,
		                          "Passphrase doesn't match the requirements",
		                          WCA_API_ERROR_P2P_PASSPHRASE_INVALID);
		goto cleanup;
	}

	if (manager->groups)
	{
		LSMessageReplyCustomError(sh,
		                          message,
		                          "Only one group can be created at a time",
		                          WCA_API_ERROR_P2P_MULTIPLE_GROUPS_NOT_ALLOWED);
		goto cleanup;
	}

	if (!connman_manager_create_group(manager, ssid, passphrase))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(ssid);
	g_free(passphrase);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_disconnectgroup disconnectgroup

Disconnect a group.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | Name of the group we want to disconnect

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_disconnect_group_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(ssid, string)) REQUIRED_1(ssid))),
	                             &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0};
	char *ssid = NULL;
	connman_group_t *group = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer address_buf = jstring_get(ssidObj);
		ssid = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the group with the given ssid */
	group = find_group_by_name(ssid);

	if (group == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Group not found",
		                          WCA_API_ERROR_GRP_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_INFO(MSGID_P2P_DISCONNECT_GROUP, 1, PMLOGKS("Group", group->name), "");

	if (!connman_group_disconnect(group))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_getgroups getgroups

Gets the information about all the Wi-Fi Direct groups

Callers can subscribe to this method to be notified of any changes
in the list of groups.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
groups | Yes | Array of Objects | List of groups.

@par "groupInfo" Object

Each entry in the "groups" array is of the form "groupInfo":{...}

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | Name of the group
owner | Yes | Boolean | True if this group is an owner
persistent | Yes | Boolean | True if this group is a persistent group
tethering | Yes | Boolean | True if this group allows tethering

@par Returns(Subscription)

As for a successful call
@}
*/
//->End of API documentation comment block

static bool handle_get_groups_command(LSHandle *sh, LSMessage *message,
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

	if (!connman_status_check_with_subscription(manager, sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!p2p_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message, "P2P is not enabled",
		        WCA_API_ERROR_P2P_DISABLED, subscribed);
		return true;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	append_groups(&reply);

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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
cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_settethering settethering

Enable/disable a group's tethering property

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | Name of the group
tethering | Yes | Boolean | "true" to enable, "false" to disable

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_tethering_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(ssid, string),
	                                     PROP(tethering, boolean)) REQUIRED_2(ssid, tethering))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = NULL, tetheringObj = NULL;
	char *ssid = NULL;
	gboolean tethering = FALSE;
	connman_group_t *group = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer address_buf = jstring_get(ssidObj);
		ssid = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("tethering"), &tetheringObj))
	{
		bool value;
		jboolean_get(tetheringObj, &value);
		tethering = value ? TRUE : FALSE;
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the group with the given ssid */
	group = find_group_by_name(ssid);

	if (group == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Group not found",
		                          WCA_API_ERROR_GRP_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_INFO(MSGID_P2P_SET_TETHERING, 2, PMLOGKS("Group", group->name),
	            PMLOGKS("Tethering", tethering ? "true" : "false"), "");

	if (group->tethering == tethering)
	{
		if (tethering == TRUE)
		{
			LSMessageReplyCustomError(sh, message, "Already enabled",
			                          WCA_API_ERROR_ALREADY_ENABLED);
		}
		else
		{
			LSMessageReplyCustomError(sh, message, "Already disabled",
			                          WCA_API_ERROR_ALREADY_DISABLED);
		}

		goto cleanup;
	}
	else if (!connman_group_set_tethering(group, tethering))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(ssid);
	j_release(&parsedObj);
	return true;
}

static gboolean send_group_peers_information(connman_group_t *group,
        jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return FALSE;
	}

	GSList *listnode;
	gboolean peer_found = FALSE;

	jvalue_ref peer_list = jarray_create(NULL);

	for (listnode = group->peer_list; listnode ; listnode = listnode->next)
	{
		connman_service_t *service = (connman_service_t *)(listnode->data);

		jvalue_ref peer_info = jobject_create();

		append_peer_information(&peer_info, service);

		jvalue_ref peer_list_j = jobject_create();
		jobject_put(peer_list_j, J_CSTR_TO_JVAL("peerInfo"), peer_info);
		jarray_append(peer_list, peer_list_j);

		peer_found = TRUE;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("peers"), peer_list);

	return peer_found;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_getgrouppeers getgrouppeers

Gets the list of peers for a group.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | Name of the group

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
peers | Yes | Array | List of peers in the group (see "peerInfo" Object)

@par Returns(Subscription)

Not applicable.

@par "peerInfo" Object

Each entry in the "peers" array is of the form "peerInfo":{...}

Name | Required | Type | Description
-----|--------|------|----------
deviceName | Yes | String | Name of the peer
deviceAddress | Yes | String | Hardware (MAC) address of the peer
groupOwner | Yes | Boolean | True if this peer is owner of a group
configMethod | Yes | Integer | Authentication method that peer supports "PIN" or "PBC"
signalLevel | Yes | Integer | Signal strength of the peer

@}
*/
//->End of API documentation comment block

static bool handle_get_group_peers_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(ssid, string)) REQUIRED_1(ssid))),
	                             &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0};
	char *ssid = NULL;
	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	connman_group_t *group = NULL;
	jschema_ref response_schema = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer address_buf = jstring_get(ssidObj);
		ssid = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the group with the given ssid */
	group = find_group_by_name(ssid);

	if (group == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Group not found",
		                          WCA_API_ERROR_GRP_NOT_FOUND);
		goto cleanup;
	}

	WCALOG_DEBUG("Listing peers for group %s", group->name);

	if (!connman_manager_populate_group_peers(manager, group))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	send_group_peers_information(group, &reply);

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(ssid);
	j_release(&reply);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setdevicename setdevicename

Set the device name for p2p communication

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
deviceName | Yes | String | Device name to be used

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_device_name_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(deviceName,
	                                     string)) REQUIRED_1(deviceName))), &parsedObj))
	{
		return true;
	}

	jvalue_ref nameObj = NULL;
	char *name = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("deviceName"), &nameObj))
	{
		raw_buffer address_buf = jstring_get(nameObj);
		name = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	WCALOG_DEBUG("Setting new P2P identifier : %s", name);

	if (!connman_technology_set_p2p_identifier(connman_manager_find_p2p_technology(
	            manager), name))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(name);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_getdevicename getdevicename

Gets the device name used for P2P communication

@par Parameters

None required

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
deviceName | Yes | String | P2P device name

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_device_name_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	jschema_ref response_schema = NULL;

	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

        if ((NULL != technology) && (technology->p2p_identifier))
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply, J_CSTR_TO_JVAL("deviceName"),
		            jstring_create(technology->p2p_identifier));
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "Device name not set",
		                          WCA_API_ERROR_DEVICE_NAME_UNSET);
		goto cleanup;
	}

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setwifidisplayinfo setwifidisplayinfo

Set the wifi display parameters.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
enabled | No | Boolean | Enable/disable WiFi Display feature
deviceType | No | String | Set the device type : Should be one of source/primary-sink/secondary-sink/dual-role
sessionAvailable | No | Boolean | WFD Session Available
rtspPort | No | Integer | Session management control port
cpSupport | No | Boolean | Content Protection using HDCP System 2.0/2.1

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_wifidisplay_info_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(enabled, boolean),
	                                     PROP(deviceType, string), PROP(sessionAvailable, boolean), PROP(rtspPort,
	                                             integer), PROP(cpSupport, boolean)))), &parsedObj))
	{
		return true;
	}

	jvalue_ref deviceTypeObj = NULL, enabledObj = NULL, sessionAvailableObj = NULL,
	           cpSupportObj = NULL, rtspPortObj = NULL;
	gchar *deviceType = NULL;
	gboolean sessionAvailable = FALSE, cpSupport = FALSE, enabled = FALSE;
	bool value = false;
	int rtspPort = 0;
	bool is_master = FALSE;
	guint16 devtype = SOURCE;
	InformationElementArray* array = NULL;

	struct InformationElement* infoelem = newInformationElement();
	Subelement *newsubElement = new_subelement(DEVICE_INFORMATION);
	DeviceInformationSubelement* newDeviceInfo = (DeviceInformationSubelement *) newsubElement;

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("enabled"), &enabledObj))
	{
		jboolean_get(enabledObj, &value);
		enabled = value ? TRUE : FALSE;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("deviceType"), &deviceTypeObj))
	{
		raw_buffer address_buf = jstring_get(deviceTypeObj);
		deviceType = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!g_strcmp0(deviceType, "source"))
		{
			devtype = SOURCE;
			is_master = TRUE;
		}
		else if (!g_strcmp0(deviceType, "primary-sink"))
		{
			devtype = PRIMARY_SINK;
		}
		else if (!g_strcmp0(deviceType, "secondary-sink"))
		{
			devtype = SECONDARY_SINK;
		}
		else if (!g_strcmp0(deviceType, "dual-role"))
		{
			devtype = DUAL_ROLE;
		}
		else
		{
			LSMessageReplyCustomError(sh, message,
			                          "Invalid value for deviceType (should be one of source/primary-sink/secondary-sink/dual-role",
			                          WCA_API_ERROR_DEVICETYPE_INVALID);
			goto cleanup;
		}

		newDeviceInfo->field1.device_type = devtype;

	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("sessionAvailable"),
	                       &sessionAvailableObj))
	{
		jboolean_get(sessionAvailableObj, &value);
		sessionAvailable = value ? TRUE : FALSE;

		newDeviceInfo->field1.session_availability = sessionAvailable;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("cpSupport"), &cpSupportObj))
	{
		jboolean_get(cpSupportObj, &value);
		cpSupport = value ? TRUE : FALSE;

		newDeviceInfo->field2.hdcp_support = cpSupport;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("rtspPort"), &rtspPortObj))
	{
		jnumber_get_i32(rtspPortObj, &rtspPort);

		newDeviceInfo->session_management_control_port =  htons(rtspPort);
		newDeviceInfo->maximum_throughput = htons(50);

	}

	wfdinfoelem_add_subelement(infoelem, newsubElement);
	array = wfdinfoelem_serialize(infoelem);

	if(technology->wfd & enabled)
	{

		if(technology->wfd == enabled && technology->wfd_sessionavail == sessionAvailable
			&& technology->wfd_cpsupport == cpSupport &&
			technology->wfd_rtspport == rtspPort && technology->wfd_devtype == devtype)
		{
			WCALOG_DEBUG("Activate Request is same as old one, so Return Just True");
			LSMessageReplySuccess(sh, message);
			goto cleanup;
		}

		struct InformationElement* tempinfoelem = newInformationElement();
		Subelement *tempnewsubElement = new_subelement(DEVICE_INFORMATION);
		DeviceInformationSubelement* tempnewDeviceInfo = (DeviceInformationSubelement *) tempnewsubElement;

		tempnewDeviceInfo->field1.device_type = technology->wfd_devtype;
		tempnewDeviceInfo->field1.session_availability = technology->wfd_sessionavail;
		tempnewDeviceInfo->field2.hdcp_support = technology->wfd_cpsupport;
		tempnewDeviceInfo->session_management_control_port =  htons(technology->wfd_rtspport);
		tempnewDeviceInfo->maximum_throughput = htons(50);

		wfdinfoelem_add_subelement(tempinfoelem, tempnewsubElement);
		InformationElementArray* temparray = wfdinfoelem_serialize(tempinfoelem);

		if (!connman_manager_p2p_service_unregister(manager, CONNMAN_SERVICE_TYPE_WiFiDisplayIEs, NULL, NULL, temparray))
		{
				LSMessageReplyCustomError(sh, message, "Internal Error", WCA_API_ERROR_INTERNAL);
				deleteInformationElement(tempinfoelem);
				deleteInformationElementArray(temparray);
				goto cleanup;
		}

		deleteInformationElement(tempinfoelem);
		deleteInformationElementArray(temparray);
	}

	if (enabled)
	{
		if (!connman_manager_p2p_service_register(manager, CONNMAN_SERVICE_TYPE_WiFiDisplayIEs, NULL, NULL, NULL, array, is_master))
		{
			LSMessageReplyCustomError(sh, message, "Error in register servie", WCA_API_ERROR_ADDSERVICE);
			goto cleanup;
		}
	}
	else
	{
		if (!connman_manager_p2p_service_unregister(manager, CONNMAN_SERVICE_TYPE_WiFiDisplayIEs, NULL, NULL, array))
		{
			LSMessageReplyCustomError(sh, message, "Error in unregister service", WCA_API_ERROR_ADDSERVICE);
			goto cleanup;
		}
	}

	if (enabled != technology->wfd &&
		        !connman_technology_set_wfd(technology, enabled))
	{
			LSMessageReplyCustomError(sh, message, "Error in changing WFD state",
			                          WCA_API_ERROR_WFD_STATE);
			goto cleanup;
	}


	if (devtype != technology->wfd_devtype &&
		        !connman_technology_set_wfd_devtype(technology, (connman_wfd_dev_type) devtype))
	{
			LSMessageReplyCustomError(sh, message, "Error in changing WFD device type",
			                          WCA_API_ERROR_DEVICETYPE);
			goto cleanup;
	}

	if (sessionAvailable != technology->wfd_sessionavail &&
		        !connman_technology_set_wfd_sessionavail(technology, sessionAvailable))
	{
			LSMessageReplyCustomError(sh, message,
			                          "Error in changing WFD session available bit", WCA_API_ERROR_SESSION_AVAIL_BIT);
			goto cleanup;
	}

	if (cpSupport != technology->wfd_cpsupport &&
		        !connman_technology_set_wfd_cpsupport(technology, cpSupport))
	{
			LSMessageReplyCustomError(sh, message, "Error in changing WFD cp support bit",
			                          WCA_API_ERROR_CP_SUPPORT_BIT);
			goto cleanup;
	}

	if (rtspPort != technology->wfd_rtspport &&
		        !connman_technology_set_wfd_rtspport(technology, rtspPort))
	{
			LSMessageReplyCustomError(sh, message, "Error in changing WFD rtsp port",
			                          WCA_API_ERROR_RTSP_PORT);
			goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(deviceType);
	deleteInformationElement(infoelem);
	if (array)
		deleteInformationElementArray(array);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_getwifidisplayinfo getwifidisplayinfo

Gets the wifi display parameters

@par Parameters

None required

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
enabled | Yes | Boolean | WiFi Display feature status
deviceType | Yes | String | WFD Device type : source/primary-sink/secondary-sink/dual-role
sessionAvailable | Yes | Boolean | WFD Session Available
rtspPort | Yes | Integer | Session management control port
cpSupport | Yes | Boolean | Content Protection using HDCP System 2.0/2.1

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_wifidisplay_info_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);
	jobject_put(reply, J_CSTR_TO_JVAL("enabled"), jboolean_create(technology->wfd));

	if (technology->wfd)
	{
		switch (technology->wfd_devtype)
		{
			case CONNMAN_WFD_DEV_TYPE_SOURCE:
				jobject_put(reply, J_CSTR_TO_JVAL("wfdDeviceType"), jstring_create("source"));
				break;

			case CONNMAN_WFD_DEV_TYPE_PRIMARY_SINK:
				jobject_put(reply, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("primary-sink"));
				break;

			case CONNMAN_WFD_DEV_TYPE_SECONDARY_SINK:
				jobject_put(reply, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("secondary-sink"));
				break;

			case CONNMAN_WFD_DEV_TYPE_DUAL:
				jobject_put(reply, J_CSTR_TO_JVAL("wfdDeviceType"),
				            jstring_create("dual-role"));
				break;

		}

		jobject_put(reply, J_CSTR_TO_JVAL("wfdSessionAvail"),
		            jboolean_create(technology->wfd_sessionavail));
		jobject_put(reply, J_CSTR_TO_JVAL("wfdCpSupport"),
		            jboolean_create(technology->wfd_cpsupport));
		jobject_put(reply, J_CSTR_TO_JVAL("wfdRtspPort"),
		            jnumber_create_i32(technology->wfd_rtspport));
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
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

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_getp2prequests getp2prequests

Subscribes the caller for incoming p2p request notification

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_get_p2p_requests_command(LSHandle *sh, LSMessage *message,
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

		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "Subscription is mandatory for this API",
		                          WCA_API_ERROR_SUBSCRIPTION_REQD);
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	response_schema = jschema_parse(j_cstr_to_buffer("{}"),
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
cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_findservice findservice

Finds all Wi-Fi Direct services or a specific service based on
service type. Once this API is triggered, the response will be
received to the subscriber of the getpeers API.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
type | yes | String | Should be one of "upnp" or "bonjour"
address | no | String | If not set will look for all peers
version | no | Integer | Version number for "upnp"
description | no | String | Description for "upnp"
query | no | String | Query for "bonjour"

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par
As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_find_service_command(LSHandle *sh, LSMessage *message,
                                        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(type, string),
	                                     PROP(address, string), PROP(version, integer), PROP(description, string),
	                                     PROP(query, string)) REQUIRED_1(type))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	jvalue_ref typeObj = NULL, addressObj = NULL, versionObj = NULL,
	           descriptionObj = NULL, queryObj = NULL;
	gchar *type = NULL, *address = NULL, *description = NULL, *query = NULL;
	gint version = 0;
	connman_service_type service_type;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("type"), &typeObj))
	{
		raw_buffer address_buf = jstring_get(typeObj);
		type = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!g_strcmp0(type, "upnp"))
		{
			service_type = CONNMAN_SERVICE_TYPE_UPNP;
		}
		else if (!g_strcmp0(type, "bonjour"))
		{
			service_type = CONNMAN_SERVICE_TYPE_BONJOUR;
		}
		else
		{
			goto invalid_params;
		}
	}
	else
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		address = g_strdup("00:00:00:00:00:00");
	}


	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("version"), &versionObj))
	{
		jnumber_get_i32(versionObj, &version);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_UPNP)
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("description"),
	                       &descriptionObj))
	{
		raw_buffer address_buf = jstring_get(descriptionObj);
		description = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_UPNP)
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("query"), &queryObj))
	{
		raw_buffer address_buf = jstring_get(queryObj);
		query = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_BONJOUR)
	{
		goto invalid_params;
	}

	if (!connman_service_discovery_request(service_type, address, version,
	                                       description, query))
	{
		LSMessageReplyCustomError(sh, message, "Error in findservice",
		                          WCA_API_ERROR_FINDSERVICE);
		goto cleanup;
	}


	LSMessageReplySuccess(sh, message);
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	g_free(type);
	g_free(address);
	g_free(description);
	g_free(query);
	j_release(&reply);

	if (!jis_null(parsedObj))
	{
		j_release(&parsedObj);
	}
	return true;
}



//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_addservice addservice

Adds a Wi-Fi Direct service.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
type | yes | String | Should be one of "upnp" or "bonjour"
description | no | String | Description for "upnp"
query | no | String | Query for "bonjour"
response | no | String | Response for "bonjour"

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par
As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_add_service_command(LSHandle *sh, LSMessage *message,
                                       void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_4(PROP(type, string),
	                                     PROP(description, string), PROP(query, string), PROP(response,
	                                             string)) REQUIRED_1(type))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	jvalue_ref typeObj = NULL, descriptionObj = NULL, queryObj = NULL,
	           *responseObj = NULL;
	gchar *type = NULL, *description = NULL, *query = NULL, *response = NULL;
	connman_service_type service_type;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("type"), &typeObj))
	{
		raw_buffer address_buf = jstring_get(typeObj);
		type = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!g_strcmp0(type, "upnp"))
		{
			service_type = CONNMAN_SERVICE_TYPE_UPNP;
		}
		else if (!g_strcmp0(type, "bonjour"))
		{
			service_type = CONNMAN_SERVICE_TYPE_BONJOUR;
		}
		else
		{
			goto invalid_params;
		}
	}
	else
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("description"),
	                       &descriptionObj))
	{
		raw_buffer address_buf = jstring_get(descriptionObj);
		description = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_UPNP)
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("query"), &queryObj))
	{
		raw_buffer address_buf = jstring_get(queryObj);
		query = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_BONJOUR)
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("response"), &responseObj))
	{
		raw_buffer address_buf = jstring_get(responseObj);
		response = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_BONJOUR)
	{
		goto invalid_params;
	}

	if (!connman_manager_p2p_service_register(manager, service_type, description, query,
	                                        response, NULL, FALSE))
	{
		LSMessageReplyCustomError(sh, message, "Error in addservice",
		                          WCA_API_ERROR_ADDSERVICE);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	g_free(type);
	g_free(description);
	g_free(query);
	g_free(response);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_deleteservice deleteservice

Deletes a Wi-Fi Direct service.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
serviceType | yes | String | Should be one of "upnp" or "bonjour"
description | no | String | Description for "upnp"
query | no | String | Query for "bonjour"

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par
As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_delete_service_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_3(PROP(type, string),
	                                     PROP(description, string), PROP(query, string)) REQUIRED_1(type))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	jvalue_ref typeObj = NULL, descriptionObj = NULL, queryObj = NULL;
	gchar *type = NULL, *description = NULL, *query = NULL;
	connman_service_type service_type;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("type"), &typeObj))
	{
		raw_buffer address_buf = jstring_get(typeObj);
		type = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);

		if (!g_strcmp0(type, "upnp"))
		{
			service_type = CONNMAN_SERVICE_TYPE_UPNP;
		}
		else if (!g_strcmp0(type, "bonjour"))
		{
			service_type = CONNMAN_SERVICE_TYPE_BONJOUR;
		}
		else
		{
			goto invalid_params;
		}
	}
	else
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("description"),
	                       &descriptionObj))
	{
		raw_buffer address_buf = jstring_get(descriptionObj);
		description = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_UPNP)
	{
		goto invalid_params;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("query"), &queryObj))
	{
		raw_buffer address_buf = jstring_get(queryObj);
		query = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else if (service_type == CONNMAN_SERVICE_TYPE_BONJOUR)
	{
		goto invalid_params;
	}

	if (!connman_manager_p2p_service_unregister(manager, service_type, description, query, NULL))
	{
		LSMessageReplyCustomError(sh, message, "Error in deleteservice",
		                          WCA_API_ERROR_DELETESERVICE);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	g_free(type);
	g_free(description);
	g_free(query);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_cancel cancel

Cancel any ongoing P2P connection.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
None

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_cancel_command(LSHandle *sh, LSMessage *message,
                                  void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

        (void)pthread_mutex_lock(&callback_sequence_lock);
	group_added_by_p2p_request = FALSE;
	group_added_pending = FALSE;
	pthread_mutex_unlock(&callback_sequence_lock);

	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (!connman_technology_cancel_p2p(technology))
	{
		LSMessageReplyCustomError(sh, message, "Error in cancelling P2P connection",
		                          WCA_API_ERROR_CANCEL_P2P_CONN);
		return true;
	}

	LSMessageReplySuccess(sh, message);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_rejectPeer rejectPeer

Reject any incoming P2P connection.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
peerAddress | Yes | String | Device address of the peer that we want to reject

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_reject_peer_command(LSHandle *sh, LSMessage *message,
                                       void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(peerAddress,
	                                     string)) REQUIRED_1(peerAddress))), &parsedObj))
	{
		return true;
	}

	jvalue_ref peerAddressObj = {0};
	char *peerAddress = NULL;
	connman_service_t *service = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("peerAddress"),
	                       &peerAddressObj))
	{
		raw_buffer address_buf = jstring_get(peerAddressObj);
		peerAddress = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Look up for the service with the given peer address */
	service = find_peer_by_address(peerAddress);

	if (service == NULL)
	{
		LSMessageReplyCustomError(sh, message, "Peer not found",
		                          WCA_API_ERROR_PEER_NOT_FOUND);
		goto cleanup;
	}

	if (!connman_service_reject_peer(service))
	{
		LSMessageReplyCustomError(sh, message, "Error in rejecting peer",
		                          WCA_API_ERROR_REJECT_PEER);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(peerAddress);
	j_release(&parsedObj);
	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_deleteprofile deleteprofile

Delete persistent profile for a specific mac address or all
profiles and also disconnect the peer(s) if connected.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
deviceAddress | Yes | String | Device address or "all"

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_delete_profile_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(deviceAddress,
	                                     string)) REQUIRED_1(deviceAddress))), &parsedObj))
	{
		return true;
	}

	jvalue_ref addressObj = NULL;
	char *address = NULL;
	connman_service_t *service = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("deviceAddress"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	/* Disconnect the peer(s) if they are already connected */

	if (!g_strcmp0(address, "all"))
	{
		service = connman_manager_get_connected_service(manager->p2p_services);
	}
	else
	{
		service = find_peer_by_address(address);
	}

	if (service != NULL)
	{
		WCALOG_ADDR_INFOMSG(MSGID_P2P_DELETE_PROFILE, "Peer", service);

		int service_state = connman_service_get_state(service->state);

		if (service_state == CONNMAN_SERVICE_STATE_READY ||
		        service_state == CONNMAN_SERVICE_STATE_ONLINE)
		{
			connman_group_t *group = NULL;
			GSList *listnode = NULL;

			// Since net.connman.Service.Disconnect API is not valid for a p2p service,
			// we will just disconnect all the groups which will effectively disconnect
			// the p2p connections associated with them (currently connman just
			// supports one group)
			for (listnode = manager->groups; NULL != listnode ; listnode = listnode->next)
			{
				group = (connman_group_t *)(listnode->data);

				/* Disconnecting the group will disconnect all connected peers */
				if (!connman_group_disconnect(group))
				{
					LSMessageReplyCustomError(sh, message, "Error in disconnecting group",
					                          WCA_API_ERROR_DISC_GROUP);
					goto cleanup;
				}
			}
		}
	}

	if (!connman_technology_delete_profile(connman_manager_find_p2p_technology(
	        manager), address))
	{
		LSMessageReplyCustomError(sh, message, "Error in deleting profile",
		                          WCA_API_ERROR_DELETING_PROFILE);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(address);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setlistenparams setlistenparams

Set the wifi display listen parameters.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
period | Yes | Integer | Set listen state period
interval | Yes | Integer | Set listen state interval

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block
static bool handle_set_listen_params_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(period, integer),
	                                     PROP(interval, integer)) REQUIRED_2(period, interval))), &parsedObj))
	{
		return true;
	}

	jvalue_ref periodObj = NULL, intervalObj = NULL;
	int period = 0, interval = 0;

	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("period"), &periodObj))
	{
		jnumber_get_i32(periodObj, &period);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("interval"), &intervalObj))
	{
		jnumber_get_i32(intervalObj, &interval);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (period <= 0 || interval <= 0)
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (period > interval)
	{
		LSMessageReplyCustomError(sh, message, "Period cannot be larger than interval",
		                          WCA_API_ERROR_LISTEN_PARAMS_INVALID_VALUES);
		goto cleanup;
	}

	if (!connman_technology_set_listen_params(technology, period, interval))
	{
		LSMessageReplyCustomError(sh, message, "Error in setting listen parameters",
		                          WCA_API_ERROR_LISTEN_PARAMS);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setlistenchannel setlistenchannel

Set the wifi display listen channel.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
listenChannel | Yes | Integer | Set listen channel

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block
static bool handle_set_listen_channel_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!p2p_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh, message, "P2P is not enabled",
		                          WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(listenChannel,
	                                     integer)) REQUIRED_1(listenChannel))), &parsedObj))
	{
		return true;
	}

	jvalue_ref channelObj = NULL;
	int listen_channel = 0;

	connman_technology_t *technology = connman_manager_find_p2p_technology(
	                                       manager);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("listenChannel"), &channelObj))
	{
		jnumber_get_i32(channelObj, &listen_channel);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (listen_channel <= 0)
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if (!connman_technology_set_listen_channel(technology, listen_channel))
	{
		LSMessageReplyCustomError(sh, message, "Error in changing listen channel",
		                          WCA_API_ERROR_FAILED_TO_SET_LISTEN_CHANNEL);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);

cleanup:
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi_p2p com.webos.wifi/p2p
@{
@section com_webos_wifi_p2p_setgointent setgointent

Set the group owner intent value.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
GoIntent | Yes | Integer | Set GO intent value

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_go_intent_command(LSHandle *sh, LSMessage *message, void* context)
{
	if(!connman_status_check(manager, sh, message))
		return true;

	if(!p2p_technology_status_check(sh, message))
		return true;

	if(!is_p2p_enabled())
	{
		LSMessageReplyCustomError(sh,message,"P2P is not enabled", WCA_API_ERROR_P2P_DISABLED);
		return true;
	}

	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(GOIntent, integer)) REQUIRED_1(GOIntent))), &parsedObj))
		return true;

	jvalue_ref channelObj = NULL;
	int go_intent = 0;

	connman_technology_t *technology = connman_manager_find_p2p_technology(manager);
	if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("GOIntent"), &channelObj))
	{
		jnumber_get_i32(channelObj, &go_intent);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	if(!connman_technology_set_go_intent(technology, go_intent))
	{
		LSMessageReplyCustomError(sh, message, "Error in changing go intent value", WCA_API_ERROR_FAILED_TO_SET_GO_INTENT);
		goto cleanup;
	}

	LSMessageReplySuccess(sh,message);

cleanup:
	j_release(&parsedObj);
	return true;
}

static bool new_device_name_cb(LSHandle *sh, LSMessage *message, void *ctx)
{
	connman_technology_t *p2p_tech = connman_manager_find_p2p_technology(manager);

	if (!connman_manager_is_manager_available(manager) && !p2p_tech)
	{
		return true;
	}

	jvalue_ref parsedObj = {0};
	jschema_ref input_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT,
	                           NULL);

	if (!input_schema)
	{
		return false;
	}

	JSchemaInfo schemaInfo;
	jschema_info_init(&schemaInfo, input_schema, NULL,
	                  NULL); // no external refs & no error handlers
	parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)),
	                       DOMOPT_NOOPT, &schemaInfo);
	jschema_release(&input_schema);

	if (jis_null(parsedObj))
	{
		return true;
	}

	jvalue_ref settingsObj = {0}, deviceNameObj = {0}, subscribedObj = {0},
	           returnValueObj = {0};
	gchar *device_name = NULL;
	bool returnValue = false;
	raw_buffer address_buf = {0};

	if (!jobject_get_exists(parsedObj, J_CSTR_TO_BUF("returnValue"),
	                        &returnValueObj))
	{
		goto cleanup;
	}

	jboolean_get(returnValueObj, &returnValue);

	if (!returnValue)
	{
		goto cleanup;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("subscribed"), &subscribedObj))
	{
		jboolean_get(subscribedObj, &subscribed_for_device_name);
	}

	if (!jobject_get_exists(parsedObj, J_CSTR_TO_BUF("settings"), &settingsObj))
	{
		goto cleanup;
	}

	if (!jobject_get_exists(settingsObj, J_CSTR_TO_BUF("deviceName"),
	                        &deviceNameObj))
	{
		goto cleanup;
	}

	address_buf = jstring_get(deviceNameObj);
	device_name = g_strdup(address_buf.m_str);
	jstring_free_buffer(address_buf);

	connman_technology_set_p2p_identifier(p2p_tech, device_name);

cleanup:
	g_free(device_name);
	j_release(&parsedObj);

	return true;
}


/**
 * com.webos.service.wifi/p2p service Luna Method Table
 */

static LSMethod wifi_p2p_methods[] =
{
	{ LUNA_METHOD_P2P_SETSTATE,              handle_set_state_command },
	{ LUNA_METHOD_P2P_GETSTATE,              handle_get_state_command },
	{ LUNA_METHOD_P2P_GETPEERS,              handle_get_peers_command },
	{ LUNA_METHOD_P2P_CONNECT,               handle_connect_command },
	{ LUNA_METHOD_P2P_DISCONNECT,            handle_disconnect_command },
	{ LUNA_METHOD_P2P_INVITE,                handle_invite_command },
	{ LUNA_METHOD_P2P_CREATEGROUP,           handle_create_group_command },
	{ LUNA_METHOD_P2P_DISCONNECTGROUP,       handle_disconnect_group_command },
	{ LUNA_METHOD_P2P_GETGROUPS,             handle_get_groups_command },
	{ LUNA_METHOD_P2P_SETTETHERING,          handle_set_tethering_command },
	{ LUNA_METHOD_P2P_GETGROUPPEERS,         handle_get_group_peers_command },
	{ LUNA_METHOD_P2P_SETDEVICENAME,         handle_set_device_name_command },
	{ LUNA_METHOD_P2P_GETDEVICENAME,         handle_get_device_name_command },
	{ LUNA_METHOD_P2P_SETWIFIDISPLAYINFO,    handle_set_wifidisplay_info_command },
	{ LUNA_METHOD_P2P_GETWIFIDISPLAYINFO,    handle_get_wifidisplay_info_command },
	{ LUNA_METHOD_P2P_GETP2PREQUESTS,        handle_get_p2p_requests_command },
	{ LUNA_METHOD_P2P_FINDSERVICE,           handle_find_service_command },
	{ LUNA_METHOD_P2P_ADDSERVICE,            handle_add_service_command },
	{ LUNA_METHOD_P2P_DELETESERVICE,         handle_delete_service_command },
	{ LUNA_METHOD_P2P_CANCEL,                handle_cancel_command },
	{ LUNA_METHOD_P2P_REJECTPEER,                handle_reject_peer_command },
	{ LUNA_METHOD_P2P_DELETE_PROFILE,        handle_delete_profile_command },
	{ LUNA_METHOD_P2P_SETLISTENPARAMS,     handle_set_listen_params_command },
	{ LUNA_METHOD_P2P_SETLISTENCHANNEL,     handle_set_listen_channel_command },
	{ LUNA_METHOD_P2P_SETGOINTENT,          handle_set_go_intent_command },
	{ },
};

gboolean settingsservice_started = FALSE;

void update_p2p_device_name(void)
{
	if (settingsservice_started && connman_manager_find_wifi_technology(manager))
	{
		if (!subscribed_for_device_name)
		{
			if (!LSCall(localpLSHandle, "palm://com.webos.settingsservice/getSystemSettings",
			       "{\"keys\":[\"deviceName\"],"
			       "\"category\":\"network\",\"subscribe\":true}", new_device_name_cb, NULL, NULL,
			       NULL))
				WCALOG_DEBUG("Failed to get system device name from com.webos.settigsservice");
		}
		else
		{
			LSCallOneReply(localpLSHandle,
			               "palm://com.webos.settingsservice/getSystemSettings",
			               "{\"keys\":[\"deviceName\"],"
			               "\"category\":\"network\"}", new_device_name_cb, NULL, NULL, NULL);
		}
	}
}


static gboolean register_settingsservice_status_cb(LSHandle *sh,
        const char *service, gboolean connected, void *ctx)
{
	if (connected)
	{
		settingsservice_started = TRUE;
		retrieve_system_locale_info(sh);
		update_p2p_device_name();
	}

	return TRUE;
}

void setPropertyUpdateCallback(connman_service_t *service)
{
	if(service==NULL)
		return;
	connman_service_register_property_changed_cb(service, peer_service_property_changed_callback);
}

/**
 *  @brief Initialize com.webos.service.wifi/p2p service and all of its methods
 */

int initialize_wifi_p2p_ls2_calls(GMainLoop *mainloop, LSHandle *pLsHandle)
{
	LSError lserror;
	LSErrorInit(&lserror);

	if (NULL == mainloop)
	{
		goto Exit;
	}

	localpLSHandle = pLsHandle;

	if (LSRegisterCategory(pLsHandle, LUNA_CATEGORY_P2P, wifi_p2p_methods, NULL,
	                       NULL,
	                       &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_P2P_METHODS_LUNA_ERROR, lserror.message);
		goto Exit;
	}

	if (LSRegisterServerStatusEx(pLsHandle, "com.webos.settingsservice",
	                             (LSServerStatusFunc)register_settingsservice_status_cb, NULL, NULL,
	                             &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_SETTINGS_SERVICE_REG_ERROR, lserror.message);
		goto Exit;
	}

	return 0;
Exit:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return -1;
}
