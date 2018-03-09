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
 * @file  wifi_service.c
 *
 * @brief Implements all of the com.webos.service.wifi methods using connman APIs
 * in the backend
 */

/**
@page com_webos_wifi com.webos.wifi

@brief Manages connections to Wireless Networks

Each call has a standard return in the case of a failure, as follows:

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
#include <string.h>
#include <pbnjson.h>

#include <wca-support.h>

#include "wifi_service.h"
#include "wifi_profile.h"
#include "wifi_setting.h"
#include "wifi_scan.h"
#include "connman_manager.h"
#include "connman_agent.h"
#include "lunaservice_utils.h"
#include "utils.h"
#include "common.h"
#include "connectionmanager_service.h"
#include "logging.h"
#include "wifi_tethering_service.h"
#include "wan_service.h"
#include "pan_service.h"
#include "errors.h"
#include "nyx.h"

/* Range for converting signal strength to signal bars */
#define MID_SIGNAL_RANGE_LOW    55
#define MID_SIGNAL_RANGE_HIGH   65

/* Schedule a scan every 15 seconds */
#define WIFI_DEFAULT_SCAN_INTERVAL   15000

#define MAX_PREFIX_LENGTH   128

static LSHandle *pLsHandle;

connman_manager_t *manager = NULL;
connman_agent_t *agent = NULL;

/* Default scan interval. Used if no interval specified. */
static gint findnetworks_default_scan_interval = WIFI_DEFAULT_SCAN_INTERVAL;

static guint signal_polling_timeout_source = 0;

static char* wifi_getstatus_prev_response = NULL;

luna_service_request_t *current_connect_req;
typedef struct current_service_data
{
	connman_service_t *service;
	connection_settings_t *settings;
} current_service_data_t;


static gboolean check_wifi_services_for_updates(void);

connection_settings_t *connection_settings_new(void)
{
	connection_settings_t *settings = NULL;

	settings = g_new0(connection_settings_t, 1);

	return settings;
}

static void connection_settings_free(connection_settings_t *settings)
{
	g_free(settings->passkey);
	g_free(settings->ssid);
	g_free(settings->wpspin);
	g_free(settings->identity);
	g_free(settings->eap_type);
	g_free(settings->ca_cert_file);
	g_free(settings->client_cert_file);
	g_free(settings->private_key_file);
	g_free(settings->private_key_passphrase);
	g_free(settings->phase2);
	g_free(settings->passphrase);

	g_free(settings);
}

static void connect_req_free(luna_service_request_t *request)
{
	current_service_data_t *service_data = request->user_data;

	if (service_data)
	{
		connection_settings_t *settings = service_data->settings;

		if (settings)
		{
			connection_settings_free(settings);
		}

		g_free(service_data);
	}

	luna_service_request_free(request);
}

static void current_connect_req_free()
{
	connect_req_free(current_connect_req);
	current_connect_req = NULL;
}

/**
 * Compare the signal strengths of services and sort the list based on decreasing
 * signal strength. However the hidden service (if any) will always be put at the end of the list.
 */

static gint compare_signal_strength(connman_service_t *service1,
                                    connman_service_t *service2)
{
	if (service2->name == NULL)
	{
		return -1;    // let the hidden service be added to the list
	}
		// after all non-hidden services
	else if (service1->name == NULL)
	{
		return 1;    // insert non-hidden service2 before hidden service1
	}

	return (service2->strength - service1->strength);
}

/**
 *  @brief Sets the wifi technologies powered state
 *
 *  @param state
 */

static gboolean set_wifi_powered_state(bool state)
{
	/* if scan is still scheduled abort it */
	if (state == FALSE)
	{
		wifi_scan_stop();
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (wifi_tech)
	{
		return connman_technology_set_powered(wifi_tech, state, NULL);
	}
	else
	{
		return FALSE;
	}
}

/**
 * Convert signal strength to signal bars
 *
 * @param[IN] strength Signal strength
 *
 * @return Mapped signal strength in bars
 */

static int signal_strength_to_bars(int strength)
{
	if (strength > 0 && strength < MID_SIGNAL_RANGE_LOW)
	{
		return 1;
	}
	else if (strength >= MID_SIGNAL_RANGE_LOW && strength < MID_SIGNAL_RANGE_HIGH)
	{
		return 2;
	}
	else if (strength >= MID_SIGNAL_RANGE_HIGH)
	{
		return 3;
	}

	return 0;
}

/**
 *  @brief Add details about the connected service
 *
 *  @param reply
 *  @param connected_service
 *
 */

static void add_connected_network_status(jvalue_ref *reply,
        connman_service_t *connected_service)
{
	if (NULL == reply || NULL == connected_service)
	{
		return;
	}
	int connman_state = 0;

	jvalue_ref network_info = jobject_create();

	/* Fill in details about the service access point */
	if (connected_service->display_name != NULL)
	{
		jobject_put(network_info, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(connected_service->display_name));
	}
	else
	{
		jobject_put(network_info, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(connected_service->name));
	}

	jobject_put(network_info, J_CSTR_TO_JVAL("ssid"),
	            jstring_create(connected_service->name));

	wifi_profile_t *profile = NULL;

	if (connected_service->security != NULL)
	{
		profile = get_profile_by_ssid_security(connected_service->name,
		                                       connected_service->security[0]);
	}

	if (NULL != profile)
	{
		jobject_put(network_info, J_CSTR_TO_JVAL("profileId"),
		            jnumber_create_i32(profile->profile_id));
	}

	if (connected_service->state != NULL)
	{
		connman_state = connman_service_get_state(connected_service->state);
		jobject_put(network_info, J_CSTR_TO_JVAL("connectState"),
		            jstring_create(connman_service_get_webos_state(connman_state)));
	}

	jobject_put(network_info, J_CSTR_TO_JVAL("signalBars"),
	            jnumber_create_i32(signal_strength_to_bars(connected_service->strength)));
	jobject_put(network_info, J_CSTR_TO_JVAL("signalLevel"),
	            jnumber_create_i32(connected_service->strength));

	jobject_put(*reply,  J_CSTR_TO_JVAL("networkInfo"), network_info);

	/* Fill in ip information only for a service which is online (fully connected) */
	if (connman_state == CONNMAN_SERVICE_STATE_ONLINE
	        || connman_state == CONNMAN_SERVICE_STATE_READY)
	{
		connman_service_get_ipinfo(connected_service);
		jvalue_ref ip_info = jobject_create();

		if (connected_service->ipinfo.iface)
		{
			jobject_put(ip_info, J_CSTR_TO_JVAL("interface"),
			            jstring_create(connected_service->ipinfo.iface));
		}

		if (connected_service->ipinfo.ipv4.address)
		{
			jobject_put(ip_info, J_CSTR_TO_JVAL("ip"),
			            jstring_create(connected_service->ipinfo.ipv4.address));
		}

		if (connected_service->ipinfo.ipv4.netmask)
		{
			jobject_put(ip_info, J_CSTR_TO_JVAL("subnet"),
			            jstring_create(connected_service->ipinfo.ipv4.netmask));
		}

		if (connected_service->ipinfo.ipv4.gateway)
		{
			jobject_put(ip_info, J_CSTR_TO_JVAL("gateway"),
			            jstring_create(connected_service->ipinfo.ipv4.gateway));
		}

		if (connected_service->ipinfo.dns != NULL)
		{
			gsize i;
			char dns_str[16];

			for (i = 0; i < g_strv_length(connected_service->ipinfo.dns); i++)
			{
				g_snprintf(dns_str, 16, "dns%d", i + 1);
				jobject_put(ip_info, jstring_create(dns_str),
				            jstring_create(connected_service->ipinfo.dns[i]));
			}
		}

		if (connected_service->ipinfo.ipv4.method)
		{
			jobject_put(ip_info, J_CSTR_TO_JVAL("method"),
			            jstring_create(connected_service->ipinfo.ipv4.method));
		}

		if (NULL != connected_service->ipinfo.ipv6.address)
		{
			jvalue_ref connected_ipv6_status = jobject_create();

			jobject_put(connected_ipv6_status, J_CSTR_TO_JVAL("ip"),
			            jstring_create(connected_service->ipinfo.ipv6.address));

			if (connected_service->ipinfo.ipv6.prefix_length >= 0 &&
			        connected_service->ipinfo.ipv6.prefix_length <= MAX_PREFIX_LENGTH)
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

			jobject_put(ip_info, J_CSTR_TO_JVAL("ipv6"), connected_ipv6_status);
		}

		jobject_put(*reply,  J_CSTR_TO_JVAL("ipInfo"), ip_info);
	}
}


/**
 * @brief Fill in all status information to be sent with 'getstatus' method
 */

static void create_wifi_getstatus_response(jvalue_ref *reply, bool subscribed)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(*reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	jobject_put(*reply, J_CSTR_TO_JVAL("wakeOnWlan"), jstring_create("disabled"));

	jobject_put(*reply, J_CSTR_TO_JVAL("tetheringEnabled"),
	            jboolean_create(is_wifi_tethering()));

	gboolean powered = is_wifi_powered() && !is_wifi_tethering();

	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(
			manager->wifi_services);

	const char* status;

	if (connected_service != NULL)
	{
		status = "connectionStateChanged";
	}
	else if (powered)
	{
		status = "serviceEnabled";
	}
	else
	{
		status = "serviceDisabled";
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("status"), jstring_create(status));

	if (connected_service != NULL)
	{
		add_connected_network_status(reply, connected_service);
	}
}

static void wifi_send_status_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	create_wifi_getstatus_response(&reply, true);

	const char *payload = jvalue_tostring(reply, jschema_all());

	/*
	 * Do not send identical responses back.
	 * Check if the payload is different from previous payload.
	 * Note this is executed also when there are no subscribers, keeping
	 * prev_response always up to date with current situation.
	 **/
	if (g_strcmp0(payload, wifi_getstatus_prev_response) != 0)
	{
		g_free(wifi_getstatus_prev_response);
		wifi_getstatus_prev_response = g_strdup(payload);

		WCALOG_DEBUG("Sending payload : %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		// com.webos.service.wifi/getstatus
		if (!LSSubscriptionReply(pLsHandle,
		                        LUNA_CATEGORY_ROOT LUNA_METHOD_GETSTATUS,
		                        payload,
		                        &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		// com.webos.service.wifi/getStatus
		if (!LSSubscriptionReply(pLsHandle,
		                        LUNA_CATEGORY_ROOT LUNA_METHOD_GETSTATUS2,
		                        payload,
		                        &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	j_release(&reply);

	connectionmanager_send_status_to_subscribers();
}

/**
 * Timer callback method to delete profile.
 * @param - user_data - service path, owned by the callback method.
 */
static gboolean delete_profile_if_not_connected(gpointer user_data)
{
	char* service_path = (char*) user_data;

	if (NULL == manager)
	{
		goto cleanup;
	}

	connman_service_t *service = connman_manager_find_service_by_path(
			manager->wifi_services,
			service_path);

	if (NULL == service)
	{
		WCALOG_INFO(MSGID_WIFI_SERVICE_NOT_EXIST, 0, "Service %s doesn't exist",
		            service_path);
		goto cleanup;
	}

	connman_service_t *connected_service = connman_manager_get_connected_service(
	        manager->wifi_services);

	if (NULL != connected_service || (connected_service != service))
	{
		wifi_profile_t *profile = get_profile_by_ssid_security(service->name,
		                          service->security[0]);

		if (NULL != profile)
		{
			delete_profile(profile);
		}

		connman_service_remove(service);
		connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);
		if(wifi_tech)
			connman_technology_remove_saved_profiles(wifi_tech, "all");
	}

cleanup:
	g_free(user_data);
	return FALSE;
}

/**
 * When the user requests a connection to a network and the connection establishment
 * process fails we don't immediately report this to the user but waiting until the
 * service object enters the failure state in order to analyze why things went wrong.

 * By doing this we can provide a appropiate error message to the user an not simply
 * failing with a common error message.
 *
 * Currently we're handling all known errors connman returns. See method error2string
 * in src/service.c of the connman source tree for all currently handled errors.
 */

static void handle_failed_connection_request(gpointer user_data)
{
	const char *error_message = "Unknown error";
	unsigned int error_code = WCA_API_ERROR_UNKNOWN;

	if (NULL == manager)
	{
		return;
	}

	if (NULL == current_connect_req)
	{
		return;
	}

	current_service_data_t *service_data = current_connect_req->user_data;

	if (NULL == service_data)
	{
		goto cleanup;
	}

	connman_service_t *service = service_data->service;
	connection_settings_t *settings = service_data->settings;

	if (NULL == service || NULL == g_slist_find(manager->wifi_services, service))
	{
		LSMessageReplyCustomError(current_connect_req->handle,
		                          current_connect_req->message,
		                          error_message, error_code);
		goto cleanup;
	}

	if (NULL == service->path)
	{
		WCALOG_INFO(MSGID_WIFI_SKIPPING_FETCH_PROPERTIES, 0,
		            "Skipping fetch properties");
		goto cleanup;
	}

	if (NULL == connman_manager_find_service_by_path(manager->wifi_services,
	        service->path))
	{
		WCALOG_INFO(MSGID_WIFI_SERVICE_NOT_EXIST, 0, "Service %s doesn't exist",
		            service->name);
		LSMessageReplyCustomError(current_connect_req->handle,
		                          current_connect_req->message,
		                          error_message, error_code);
		goto cleanup;
	}

	GVariant *properties = connman_service_fetch_properties(service);

	if (NULL == properties)
	{
		goto cleanup;
	}

	connman_service_update_properties(service, properties);
	g_variant_unref(properties);

	if (g_strcmp0(service->error, "invalid-key") == 0)
	{
		error_message = "The supplied password is incorrect";
		error_code = WCA_API_ERROR_INVALID_KEY;
	}
	else if (g_strcmp0(service->error, "auth-failed") == 0)
	{
		error_message = "Authentication with access point failed";
		error_code = WCA_API_ERROR_AUTH_FAILED;
	}
	else if (g_strcmp0(service->error, "login-failed") == 0)
	{
		error_message = "Login failed";
		error_code = WCA_API_ERROR_LOGIN_FAILED;
	}
	else if (g_strcmp0(service->error, "connect-failed") == 0)
	{
		error_message = "Could not establish a connection to access point";
		error_code = WCA_API_ERROR_CONNECT_FAILED;
	}
	else if (g_strcmp0(service->error, "dhcp-failed") == 0)
	{
		error_message = "Could not retrieve a valid IP address by using DHCP";
		error_code = WCA_API_ERROR_DHCP_FAILED;
	}
	else if (g_strcmp0(service->error, "pin-missing") == 0)
	{
		error_message = "PIN is missing";
		error_code = WCA_API_ERROR_PIN_MISSING;
	}
	else if (g_strcmp0(service->error, "out-of-range") == 0)
	{
		error_message = "Out of range";
		error_code = WCA_API_ERROR_OUT_OF_RANGE;
	}

	LSMessageReplyCustomError(current_connect_req->handle,
	                          current_connect_req->message,
	                          error_message, error_code);

	if (settings && !settings->store)
	{
		// In case of enterprise networks we always create a profile (even before connecting to it),
		// so in case the connection fails, we should delete the profile and the corresponding config file
		// Give it 2 sec for service to auto-connect
		char* service_name = g_strdup(service->path);
		g_timeout_add_seconds(5, delete_profile_if_not_connected, service_name);
	}

#ifndef ENABLE_SINGLE_PROFILE

	if (settings && settings->store)
	{
		store_network_config(settings, service->security[0]);
	}

#endif
cleanup:

	if (current_connect_req != NULL)
	{
		current_connect_req_free();
	}
}

/**
 * @brief Remove a single service per SSID or all other services which don't
 *        match the SSID but are marked as autoconnectable or as favorite.
 *
 * @param ssid
 * @param others
 */
static void remove_service_or_all_other(const gchar *ssid, gboolean others)
{
	GSList *ap = NULL;

	/* Look up for any existing service with ssid same as this profile*/
	for (ap = manager->wifi_services; ap; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);

		if ((others == FALSE && !g_strcmp0(service->name, ssid)) ||
		        (others == TRUE  &&  g_strcmp0(service->name, ssid)))
		{
			if (service->state == NULL)
			{
				continue;
			}

			if (!service->favorite && !service->auto_connect)
			{
				continue;
			}

			/* We can't really change immutable services this way so don't try it */
			if (service->immutable)
			{
				continue;
			}

			/* Deleting profile for this ssid, so set autoconnect property for this
			   service to FALSE so that connman doesn't autoconnect to this service next time */
			connman_service_set_autoconnect(service, FALSE);

			/* Remove the service from connman (will disconnect it first if connected) */
			connman_service_remove(service);

			WCALOG_ADDR_INFOMSG(MSGID_WIFI_DISCONNECT_SERVICE, "Service", service);
		}
	}
}

/**
 *  @brief Callback function registered with connman service whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void service_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	if (!g_strcmp0(property, "State"))
	{
		connman_service_t *service = (connman_service_t *)data;

		if (NULL == service)
		{
			return;
		}

		WCALOG_INFO(MSGID_WIFI_CONNECT_SERVICE,2,PMLOGKS("Service", service->name),PMLOGKS("state changed to",service->state),"");

		bool is_wifi_service = (CONNMAN_SERVICE_TYPE_WIFI == service->type);

		if (is_wifi_service && check_wifi_services_for_updates())
		{
			send_findnetworks_status_to_subscribers();
		}

		send_getnetworks_status_to_subscribers();

		int service_state = connman_service_get_state(service->state);

		switch (service_state)
		{
			case  CONNMAN_SERVICE_STATE_CONFIGURATION:
				break;

			case  CONNMAN_SERVICE_STATE_READY:
			case  CONNMAN_SERVICE_STATE_ONLINE:
				wifi_send_status_to_subscribers();
				connman_service_set_autoconnect(service, TRUE);
				break;

			case CONNMAN_SERVICE_STATE_IDLE:
				wifi_send_status_to_subscribers();
				return;

			case CONNMAN_SERVICE_STATE_FAILURE:

				/* When the service object the state has changed for is not the one we're
				 * currently connecting to then we do nothing here. */
				if (!current_connect_req)
				{
					return;
				}

				current_service_data_t *service_data = current_connect_req->user_data;

				if (service_data)
				{
					connman_service_t *curr_service = service_data->service;

					// In case of hidden networks the original service never matches with the new service added
					if (service != curr_service)
					{
						service_data->service = service;
					}
				}

				handle_failed_connection_request(NULL);
				return;

			default:
				return;
		}

		if (NULL == service->name)
		{
			// Hidden network.
			return;
		}

		wifi_profile_t *profile = NULL;

		if (service->security != NULL)
		{
			profile = get_profile_by_ssid_security(service->name, service->security[0]);
		}

		if (NULL != profile)
		{
			/* If profile already exists, move it to top of the list */
			move_profile_to_head(profile);
		}
		else
		{
			/* Else, create a new profile */
			if (service->security == NULL)
			{
				profile = create_new_profile(service->name, NULL, service->hidden, FALSE);
			}
			else
			{
				profile = create_new_profile(service->name, service->security, service->hidden,
				                             FALSE);
			}
		}

#ifdef ENABLE_SINGLE_PROFILE

		if (profile && is_wifi_service)
		{
			/* TODO: Only wifi profiles should be removed?
			   Check with requirements and possibly update.
			*/

			/* Remove adapter stored services */
			remove_service_or_all_other(profile->ssid, TRUE);

			/* Remove all services connman has reported to adapter */
			delete_all_profiles_except_one(profile->profile_id);

			/* Ask connman to remove profiles it has in it's config files */
			connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

			if (wifi_tech)
			{
				connman_technology_remove_saved_profiles(wifi_tech, service->identifier);
			}
		}

#endif
		/* Unset agent callback as we no longer have any valid input for connman available */
		connman_agent_set_request_input_callback(agent, NULL, NULL);
	}
	else if (!g_strcmp0(property, "Online"))
	{
		connman_service_t *service = (connman_service_t *)data;

		if (NULL == service)
		{
			return;
		}

		WCALOG_INFO(MSGID_WIFI_CONNECT_SERVICE,2,PMLOGKS("Service", service->name),PMLOGKS("online flag changed to",service->online?"TRUE":"FALSE"),"");
		wifi_send_status_to_subscribers();
		send_findnetworks_status_to_subscribers();
	}
}

/**  @brief Add details about the given service representing a wifi access point
 *
 *  @param service
 *  @param network
 *
 */

static bool add_service(connman_service_t *service, jvalue_ref *network,
                        gboolean available)
{
	if (NULL == service || NULL == network || NULL == service->name)
	{
		/* Service->name is null for hidden wifi networks. Do not include those */
		return false;
	}

	bool supported = true;

	if (service->display_name)
	{
		jobject_put(*network, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(service->display_name));
	}
	else
	{
		jobject_put(*network, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(service->name));
	}

	jobject_put(*network, J_CSTR_TO_JVAL("ssid"), jstring_create(service->name));

	wifi_profile_t *profile = NULL;

	if (service->security != NULL)
	{
		profile = get_profile_by_ssid_security(service->name, service->security[0]);
	}

	if (NULL != profile)
	{
		jobject_put(*network, J_CSTR_TO_JVAL("profileId"),
		            jnumber_create_i32(profile->profile_id));
	}

	if (available == TRUE)
	{
		if ((service->security != NULL) && g_strv_length(service->security))
		{
			gsize i;
			jvalue_ref security_list = jarray_create(NULL);

			for (i = 0; i < g_strv_length(service->security); i++)
			{
				jarray_append(security_list, jstring_create(service->security[i]));
			}

			jobject_put(*network, J_CSTR_TO_JVAL("availableSecurityTypes"), security_list);
		}

		if (service->strength != NULL)
		{
			jobject_put(*network, J_CSTR_TO_JVAL("signalBars"),
			            jnumber_create_i32(signal_strength_to_bars(service->strength)));
			jobject_put(*network, J_CSTR_TO_JVAL("signalLevel"),
			            jnumber_create_i32(service->strength));
		}

		//Add BSS
		if (service->bss != NULL)
		{
			jvalue_ref bss_array = jarray_create(NULL);
			guint length = service->bss->len;
			guint j;
			for (j = 0; j < length; j++)
			{
				bssinfo_t* bss_info = &g_array_index(service->bss, bssinfo_t, j);
				jvalue_ref bss_val = jobject_create();

				jobject_put(bss_val, J_CSTR_TO_JVAL("bssid"),
				            jstring_create(bss_info->bssid));
				jobject_put(bss_val, J_CSTR_TO_JVAL("signal"),
				            jnumber_create_i32(bss_info->signal));
				jobject_put(bss_val, J_CSTR_TO_JVAL("frequency"),
				            jnumber_create_i32(bss_info->frequency));

				jarray_append(bss_array, bss_val);
			}

			jobject_put(*network, J_CSTR_TO_JVAL("bssInfo"), bss_array);
		}
	}

	jobject_put(*network, J_CSTR_TO_JVAL("supported"), jboolean_create(supported));

	jobject_put(*network, J_CSTR_TO_JVAL("available"), jboolean_create(available));

	if (service->state != NULL)
	{
		if (connman_service_get_state(service->state) != CONNMAN_SERVICE_STATE_IDLE)
		{
			jobject_put(*network, J_CSTR_TO_JVAL("connectState"),
			            jstring_create(connman_service_get_webos_state(connman_service_get_state(
			                               service->state))));
			/* Register for 'PropertyChanged' signal for this service to update its connection status */
			/* The hidden services, once connected, get added as a new service in "association" state */
			connman_service_register_property_changed_cb(service,
			        service_property_changed_callback);
		}
	}

	return true;
}

static void add_service_from_profile(wifi_profile_t *profile,
                                     jvalue_ref *network)
{
	if (NULL == profile || NULL == network)
	{
		return;
	}

	gboolean supported = TRUE;

	jobject_put(*network, J_CSTR_TO_JVAL("ssid"), jstring_create(profile->ssid));

	jobject_put(*network, J_CSTR_TO_JVAL("profileId"),
	            jnumber_create_i32(profile->profile_id));

	if ((profile->security != NULL) && g_strv_length(profile->security))
	{
		gsize i;
		jvalue_ref security_list = jarray_create(NULL);

		for (i = 0; i < g_strv_length(profile->security); i++)
		{
			jarray_append(security_list, jstring_create(profile->security[i]));
		}

		jobject_put(*network, J_CSTR_TO_JVAL("availableSecurityTypes"), security_list);
	}

	jobject_put(*network, J_CSTR_TO_JVAL("supported"), jboolean_create(supported));

	jobject_put(*network, J_CSTR_TO_JVAL("available"), jboolean_create(false));
}


/**
 * @brief Check if a profile is present in the saved_services list,
 * return TRUE if its present, FALSE otherwise
 */
static gboolean find_saved_service_by_profile(wifi_profile_t *profile)
{
	GSList *ap;

	for (ap = manager->saved_services; NULL != ap ; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);

		if (NULL == service->name)
		{
			continue;
		}

		if (g_strcmp0(service->name, profile->ssid) != 0)
		{
			continue;
		}

		if (service->security[0] != NULL &&
		        g_strcmp0(service->security[0], profile->security[0]) != 0)
		{
			continue;
		}

		return TRUE;
	}

	return FALSE;
}


/**
 *  @brief Populate information about all the found networks
 *
 *  @param reply
 *  @param show_saved_nw
 *
 */

static void populate_wifi_networks(jvalue_ref *reply, gboolean show_saved_nw)
{
	if (NULL == reply)
	{
		return;
	}

	jvalue_ref network_list = jarray_create(NULL);

	manager->wifi_services = g_slist_sort(manager->wifi_services, (GCompareFunc) compare_signal_strength);

	GSList *ap;

	/* Go through the manager's services list and fill in details
	 * for each one of them */
	for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);

		jvalue_ref network = jobject_create();

		if (add_service(service, &network, TRUE))
		{
			jvalue_ref network_list_j = jobject_create();
			jobject_put(network_list_j, J_CSTR_TO_JVAL("networkInfo"), network);
			jarray_append(network_list, network_list_j);
		}
		else
		{
			j_release(&network);
		}
	}

	// Populate out of range networks only if saved flag is TRUE
	if (show_saved_nw == TRUE)
	{
		wifi_profile_t *profile = NULL;

		/* Go through the manager's saved services list and if its a wifi service
		   not in the wifi_services list, then list the service as not available */
		for (ap = manager->saved_services; NULL != ap ; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);
			jvalue_ref network;

			/* Consider only wifi services */
			if (service->type != CONNMAN_SERVICE_TYPE_WIFI)
			{
				continue;
			}

			/** Skip services already present in wifi - we do not want duplicate
			 *  services */
			if (NULL != connman_manager_find_service_by_path(
			        manager->wifi_services,
			        service->path))
			{
				continue;
			}

			network = jobject_create();

			if (add_service(service, &network, FALSE))
			{
				jvalue_ref network_list_j = jobject_create();
				jobject_put(network_list_j, J_CSTR_TO_JVAL("networkInfo"), network);
				jarray_append(network_list, network_list_j);
			}
			else
			{
				j_release(&network);
			}
		}

		profile = NULL;

		/** Add services that are not in connman saved services list but are
		 * in adapter's profile list.
		 */
		while (NULL != (profile = get_next_profile(profile)))
		{
			if (!profile->configured)
			{
				continue;
			}

			if (find_saved_service_by_profile(profile) == FALSE)
			{
				jvalue_ref network = jobject_create();
				add_service_from_profile(profile, &network);

				jvalue_ref network_list_j = jobject_create();
				jobject_put(network_list_j, J_CSTR_TO_JVAL("networkInfo"), network);
				jarray_append(network_list, network_list_j);
			}
		}
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("foundNetworks"), network_list);
}


GVariant *agent_request_input_callback(GVariant *fields, gpointer data)
{
	connection_settings_t *settings = data;
	GVariant *response = NULL;
	GVariantBuilder *vabuilder;
	GVariantIter iter;
	gchar *key;
	GVariant *value;

	if (!g_variant_is_container(fields))
	{
		connection_settings_free(settings);
		return NULL;
	}

	vabuilder = g_variant_builder_new((const GVariantType *)"a{sv}");

	g_variant_iter_init(&iter, fields);

	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{
		if (!strncmp(key, "Name", 10))
		{
			if (NULL != settings->ssid)
			{
				g_variant_builder_add(vabuilder, "{sv}", "Name",
				                      g_variant_new("s", settings->ssid));
			}
		}
		else if (!strncmp(key, "Passphrase", 10))
		{
			/* FIXME we're ignoring the other fields here as we're only connecting to
			 * psk secured networks at the moment */
			if (NULL != settings->passkey)
			{
				g_variant_builder_add(vabuilder, "{sv}", "Passphrase",
				                      g_variant_new("s", settings->passkey));
			}
		}
		else if (!strncmp(key, "WPS", 10))
		{
			if (settings->wpsmode)
			{
				if (settings->wpspin != NULL)
				{
					g_variant_builder_add(vabuilder, "{sv}", "WPS",
					                      g_variant_new("s", settings->wpspin));
				}
			}
		}

		g_variant_unref(value);
		g_free(key);
	}

	response = g_variant_builder_end(vabuilder);
	g_variant_builder_unref(vabuilder);

	//  connection_settings_free(settings);

	connman_agent_set_request_input_callback(agent, NULL, NULL);
	return response;
}

static void service_connect_callback(gboolean success, gpointer user_data)
{
	UNUSED(user_data);

	if (!current_connect_req)
	{
		// Something is wrong. It should have been there. There is no luna call to respond to. Log an error.
		WCALOG_ESCAPED_ERRMSG(MSGID_WIFI_CONNECT_SERVICE,
		                      "Missing connect request on connect callback!");
		return;
	}

	luna_service_request_t *service_req = current_connect_req;

	/* if the connection could not be established we're waiting for the service to switch
	 * it's state to failure until we report the failed connection request to the user */
	if (!success)
	{
		g_timeout_add_seconds(2, handle_failed_connection_request, NULL);
		return;
	}

	LSMessageReplySuccess(service_req->handle, service_req->message);

	current_connect_req_free();
}

bool check_service_security(connman_service_t *service, const char *security)
{
	int n = 0;

	if (!service->security || !security)
	{
		return false;
	}

	for (n = 0; n < g_strv_length(service->security); n++)
		if (!g_strcmp0(service->security[n], security))
		{
			return true;
		}

	return false;
}

void connect_after_scan_cb(gpointer user_data)
{
	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (!wifi_tech || !current_connect_req)
	{
		return;
	}

	current_service_data_t *service_data = current_connect_req->user_data;
	connman_service_t *service = NULL;

	if (service_data)
	{
		service = service_data->service;
	}

	if (!wifi_tech || !service)
	{
		goto error;
	}

	if (!connman_service_connect(service, service_connect_callback, NULL))
	{
		LSMessageReplyErrorUnknown(current_connect_req->handle,
		                           current_connect_req->message);
		goto cleanup;
	}

	return;

error:
	LSMessageReplyCustomError(current_connect_req->handle,
	                          current_connect_req->message,
	                          "Internal error", WCA_API_ERROR_INTERNAL);
cleanup:
	current_connect_req_free();
}

/**
 *  @brief Connect to a access point with the given ssid
 *
 *  @param ssid
 */

static void connect_wifi_with_ssid(const char *ssid, wifi_profile_t *profile,
                                   jvalue_ref req_object, luna_service_request_t *service_req)
{
	jvalue_ref security_obj = NULL;
	jvalue_ref simple_security_obj = NULL;
	jvalue_ref enterprise_security_obj = NULL;
	jvalue_ref passkey_obj = NULL;
	jvalue_ref hidden_obj = NULL;
	jvalue_ref wps_obj = NULL;
	jvalue_ref wpspin_obj = NULL;
	jvalue_ref type_obj = NULL;
	jvalue_ref store_profile_obj = NULL;
	jvalue_ref identity_obj = NULL;
	jvalue_ref eap_type_obj = NULL;
	jvalue_ref ca_cert_file_obj = NULL;
	jvalue_ref client_cert_file_obj = NULL;
	jvalue_ref private_key_file_obj = NULL;
	jvalue_ref private_key_passphrase_obj = NULL;
	jvalue_ref phase2_obj = NULL;
	jvalue_ref passphrase_obj = NULL;
	jvalue_ref fast_provisioning_obj = NULL;
	jvalue_ref pac_file_obj = NULL;


	raw_buffer passkey_buf, wpspin_buf;
	GSList *ap;
	gboolean found_service = FALSE;
	connection_settings_t *settings = NULL;
	connman_service_t *service = NULL;
	bool hidden = false, store_profile = false;
	gchar *security = NULL;
	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (NULL == ssid || NULL == wifi_tech)
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Internal error", WCA_API_ERROR_INTERNAL);
		goto cleanup;
	}

	if (current_connect_req)
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Already connecting to a network", WCA_API_ERROR_ALREADY_CONNECTING);
		goto cleanup;
	}

	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("wasCreatedWithJoinOther"),
	                       &hidden_obj))
	{
		jboolean_get(hidden_obj, &hidden);
	}

	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("storeProfile"),
	                       &store_profile_obj))
	{
		jboolean_get(store_profile_obj, &store_profile);
	}

	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("security"), &security_obj))
	{
		if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("securityType"), &type_obj))
		{
			raw_buffer type_buf = jstring_get(type_obj);
			security = strdup(type_buf.m_str);
			jstring_free_buffer(type_buf);

			if (g_strcmp0(security, "none") &&
					g_strcmp0(security, "wep") &&
					g_strcmp0(security, "psk") &&
					g_strcmp0(security, "ieee8021x"))
			{
				LSMessageReplyCustomError(service_req->handle, service_req->message,
				                          "Invalid securityType",
				                          WCA_API_ERROR_WIFI_SECURITY_TYPE_INVALID);
				goto cleanup;
			}
		}
	}
	else if (profile != NULL && profile->security != NULL)
	{
		security = strdup(profile->security[0]);
	}

	if (security == NULL)
	{
		security = strdup("none");
	}

	/* Look up for the service with the given ssid */
	for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
		service = (connman_service_t *)(ap->data);

		if (NULL == service->name)
		{
			if (hidden)
			{
				if (check_service_security(service, security))
				{
					found_service = TRUE;
				}
			}
		}

		if (found_service || (!g_strcmp0(service->name, ssid) &&
		                      check_service_security(service, security)))
		{
			connman_service_t *connected_service = connman_manager_get_connected_service(
			        manager->wifi_services);
			wifi_profile_t *current_connected_profile = NULL;

			if (NULL == service->name)
			{
				WCALOG_INFO(MSGID_WIFI_CONNECT_HIDDEN_SERVICE, 0, "");
			}
			else
			{
				/* For the case that the hidden network name the user specified matches
				 * with one of the known networks we need to validate that the security
				 * for matches for both */
				if (hidden && !check_service_security(service, security))
				{
					continue;
				}
				else if (hidden && check_service_security(service, security))
				{
					/* If user input is same with the current service,
					 * return the error msg before connecting to same network */
					if (connected_service)
					{
						current_connected_profile = get_profile_by_ssid(connected_service->name);

						if ((NULL != current_connected_profile) &&
						        !g_strcmp0(ssid, connected_service->name))
						{
							WCALOG_DEBUG("Already connected via hidden network");
							LSMessageReplyCustomError(service_req->handle, service_req->message,
							                          "Already connected via hidden network", WCA_API_ERROR_ALREADY_CONNECTED);
							goto cleanup;
						}
					}
				}

				WCALOG_ADDR_INFOMSG(MSGID_WIFI_CONNECT_SERVICE, "Service", service);
			}

			found_service = TRUE;

			/* For the connection to hidden network, User input has higher priority
			 * than status of connected service. So ignore former condition */
			if (NULL != connected_service && (connected_service == service))
			{
				/* Already connected so connection was successful */
				LSMessageReplySuccess(service_req->handle, service_req->message);
				WCALOG_DEBUG("Already connected with network");
				goto cleanup;
			}

			/* Register for 'PropertyChanged' signal for this service to update its connection status */
			connman_service_register_property_changed_cb(service,
			        service_property_changed_callback);
			break;
		}
	}


	if (jobject_get_exists(req_object, J_CSTR_TO_BUF("security"), &security_obj))
	{
		settings = connection_settings_new();
		if (NULL == settings)
			goto cleanup;

		settings->ssid = strdup(ssid);

		/* parse security parameters and set connection settings accordingly */
		if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("simpleSecurity"),
		                       &simple_security_obj) &&
		        jobject_get_exists(simple_security_obj, J_CSTR_TO_BUF("passKey"), &passkey_obj))
		{
			passkey_buf = jstring_get(passkey_obj);
			settings->passkey = strdup(passkey_buf.m_str);
			jstring_free_buffer(passkey_buf);

			if (!is_valid_wifi_passphrase(settings->passkey, security))
			{
				LSMessageReplyCustomError(service_req->handle, service_req->message,
				                          "Passphrase doesn't match the requirements",
				                          WCA_API_ERROR_WIFI_PASSPHRASE_INVALID);
				goto cleanup;
			}
		}
		else if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("enterpriseSecurity"),
		                            &enterprise_security_obj))
		{
			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("eapType"),
			                       &eap_type_obj))
			{
				raw_buffer eap_type_buf = jstring_get(eap_type_obj);
				settings->eap_type = g_strdup(eap_type_buf.m_str);
				jstring_free_buffer(eap_type_buf);

				if (g_strcmp0(settings->eap_type, "peap") &&
				        g_strcmp0(settings->eap_type, "ttls") && g_strcmp0(settings->eap_type, "tls"))
				{
					LSMessageReplyCustomError(service_req->handle, service_req->message,
					                          "Invalid eapType", WCA_API_ERROR_INVALID_PARAMETERS);
					goto cleanup;
				}
			}
			else
			{
				LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
				goto cleanup;
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("identity"),
			                       &identity_obj))
			{
				raw_buffer identity_buf = jstring_get(identity_obj);
				settings->identity = g_strdup(identity_buf.m_str);
				jstring_free_buffer(identity_buf);
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("caCertFile"),
			                       &ca_cert_file_obj))
			{
				raw_buffer ca_cert_file_buf = jstring_get(ca_cert_file_obj);
				settings->ca_cert_file = g_strdup(ca_cert_file_buf.m_str);
				jstring_free_buffer(ca_cert_file_buf);
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("clientCertFile"),
			                       &client_cert_file_obj))
			{
				raw_buffer client_cert_file_buf = jstring_get(client_cert_file_obj);
				settings->client_cert_file = g_strdup(client_cert_file_buf.m_str);
				jstring_free_buffer(client_cert_file_buf);
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("privateKeyFile"),
			                       &private_key_file_obj))
			{
				raw_buffer private_key_file_buf = jstring_get(private_key_file_obj);
				settings->private_key_file = g_strdup(private_key_file_buf.m_str);
				jstring_free_buffer(private_key_file_buf);
			}

			if (jobject_get_exists(enterprise_security_obj,
			                       J_CSTR_TO_BUF("privateKeyPassphrase"), &private_key_passphrase_obj))
			{
				raw_buffer private_key_passphrase_buf = jstring_get(private_key_passphrase_obj);
				settings->private_key_passphrase = g_strdup(private_key_passphrase_buf.m_str);
				jstring_free_buffer(private_key_passphrase_buf);
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("phase2"),
			                       &phase2_obj))
			{
				raw_buffer phase2_buf = jstring_get(phase2_obj);
				settings->phase2 = g_strdup(phase2_buf.m_str);
				jstring_free_buffer(phase2_buf);
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("passphrase"),
			                       &passphrase_obj))
			{
				raw_buffer passphrase_buf = jstring_get(passphrase_obj);
				settings->passphrase = g_strdup(passphrase_buf.m_str);
				jstring_free_buffer(passphrase_buf);
			}

			if (jobject_get_exists(enterprise_security_obj,
			                       J_CSTR_TO_BUF("fastProvisioning"), &fast_provisioning_obj))
			{
				LSMessageReplyCustomError(service_req->handle, service_req->message,
				                          "This option is not implemented", WCA_API_ERROR_NOT_IMPLEMENTED);
				goto cleanup;
			}

			if (jobject_get_exists(enterprise_security_obj, J_CSTR_TO_BUF("pacFile"),
			                       &pac_file_obj))
			{
				LSMessageReplyCustomError(service_req->handle, service_req->message,
				                          "This option is not implemented", WCA_API_ERROR_NOT_IMPLEMENTED);
				goto cleanup;
			}
		}
		else if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("wps"), &wps_obj))
		{
			jboolean_get(wps_obj, &settings->wpsmode);

			if (jobject_get_exists(security_obj, J_CSTR_TO_BUF("wpsPin"), &wpspin_obj))
			{
				if (!jis_string(wpspin_obj))
				{
					LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
					goto cleanup;
				}

				wpspin_buf = jstring_get(wpspin_obj);
				settings->wpspin = strdup(wpspin_buf.m_str);
				jstring_free_buffer(wpspin_buf);
			}
			else
			{
				settings->wpspin = strdup("");
			}
		}
		else
		{
			LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
			goto cleanup;
		}

		WCALOG_DEBUG("Setup for connecting with secured network");

		if (!g_strcmp0(security, WIFI_ENTERPRISE_SECURITY_TYPE))
		{
			if (found_service)
			{
				settings->store = FALSE; // ignore "storeProfile" field for enterprise networks
				store_network_config(settings, security);
			}
		}
		else
		{
			connman_agent_set_request_input_callback(agent, agent_request_input_callback,
			        settings);
		}
	}
	else //open network
	{
		settings = connection_settings_new();
		if (NULL == settings)
			goto cleanup;

		settings->ssid = strdup(ssid);

		if (hidden) //unsecure hidden network
		{
			connman_agent_set_request_input_callback(agent, agent_request_input_callback,
			        settings);
		}
	}

	if (settings && store_profile)
	{
		settings->store = true;
	}

	if (settings && hidden)
	{
		settings->hidden = true;
	}

	if (!found_service)
	{
#ifndef ENABLE_SINGLE_PROFILE

		if (settings && settings->store)
		{
			store_network_config(settings, security);
		}

#endif
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Network not found", WCA_API_ERROR_NETWORK_NOT_FOUND);
		goto cleanup;
	}

	current_service_data_t *service_data;
	service_data = g_new0(current_service_data_t, 1);
	service_data->service = service;

	if (settings)
	{
		service_data->settings = settings;
	}

	service_req->user_data = service_data;

	current_connect_req = service_req;

	/* If we're going to connect to a hidden network and a scan is already running we
	 * have to wait until the scan has finished as connman needs to issue another one
	 * for the hidden network to be able to connect it */

	if (hidden)
	{
		wifi_scan_execute_when_scan_done(connect_after_scan_cb, NULL);
	}
	else if (!connman_service_connect(service, service_connect_callback,
	                                  service_req))
	{
		current_connect_req = NULL;
		LSMessageReplyErrorUnknown(service_req->handle, service_req->message);
		goto cleanup;
	}

	goto exit;

cleanup:

	connect_req_free(service_req);

	if (settings)
	{
		connection_settings_free(settings);
	}

exit:
	g_free(security);
	return;
}

/**
 *  @brief Callback function registered with connman manager whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void manager_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	/* Send getstatus method to all is subscribers whenever manager's state changes */
	if (!g_strcmp0(property, "State"))
	{
		connectionmanager_send_status_to_subscribers();
	}
}

/**
 * @brief Check all wifi services if we have to send an update to all subscribers of the
 * com.webos.service.wifi/findnetworks API method
 *
 * @return TRUE if an update should be send. FALSE otherwise.
 */

static gboolean check_wifi_services_for_updates(void)
{
	GSList *ap;

	for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);

		if (connman_service_is_changed(service,
		                               CONNMAN_SERVICE_CHANGE_CATEGORY_FINDNETWORKS))
		{
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief Mark all wifi services as unchanged for the findnetworks category
 */

static void mark_all_wifi_services_as_unchanged(void)
{
	GSList *ap;

	for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);
		connman_service_unset_changed(service,
		                              CONNMAN_SERVICE_CHANGE_CATEGORY_FINDNETWORKS);
	}
}

/**
 *  @brief Callback function registered with connman manager whenever any of its services change
 *  This would happen whenever any existing service is changed/deleted, or a new service is added
 *
 *  @param data
 */

static void manager_services_changed_callback(gpointer data,
        unsigned char service_type)
{
	if ((service_type & WIFI_SERVICES_CHANGED) && check_wifi_services_for_updates())
	{
		/* Send the latest WiFi network list to subscribers of 'findnetworks'/'getNetworks' method */
		send_findnetworks_status_to_subscribers();
		send_getnetworks_status_to_subscribers();

		/* We processed the update for the changed wifi networks so mark them as unchanged
		 * again */
		mark_all_wifi_services_as_unchanged();
	}

	if (service_type & ETHERNET_SERVICES_CHANGED)
	{
		connectionmanager_send_status_to_subscribers();
	}

	if (service_type & CELLULAR_SERVICES_CHANGED)
	{
		connectionmanager_send_status_to_subscribers();
		send_wan_connection_status_to_subscribers();
		send_wan_contexts_update_to_subscribers();
	}

	if (service_type & BLUETOOTH_SERVICES_CHANGED)
	{
		connectionmanager_send_status_to_subscribers();
	}
}

void send_getnetworks_status_to_subscribers()
{
	jvalue_ref getNetworks_reply = jobject_create();
	jobject_put(getNetworks_reply, J_CSTR_TO_JVAL("subscribed"),
	            jboolean_create(true));
	jobject_put(getNetworks_reply, J_CSTR_TO_JVAL("returnValue"),
	            jboolean_create(true));
	populate_wifi_networks(&getNetworks_reply, TRUE);

	const char *getNetworks_payload = jvalue_tostring(getNetworks_reply, jschema_all());
	LSError lserror;
	LSErrorInit(&lserror);

	if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_GETNETWORKS,
	                        getNetworks_payload,
	                        &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&getNetworks_reply);
}

void send_findnetworks_status_to_subscribers()
{
	jvalue_ref findnetworks_reply = jobject_create();
	jobject_put(findnetworks_reply, J_CSTR_TO_JVAL("subscribed"),
	            jboolean_create(true));
	jobject_put(findnetworks_reply, J_CSTR_TO_JVAL("returnValue"),
	            jboolean_create(true));
	populate_wifi_networks(&findnetworks_reply, FALSE);

	const char *findnetworks_payload = jvalue_tostring(findnetworks_reply, jschema_all());
	LSError lserror;
	LSErrorInit(&lserror);

	if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_FINDNETWORKS,
	                        findnetworks_payload,
	                        &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&findnetworks_reply);
}

static int convert_frequency_to_channel(int freq)
{
	if (freq >= 2412 && freq <= 2484)
	{
		return (freq - 2412) / 5 + 1;
	}
	else if (freq >= 5170 && freq <= 5825)
	{
		return (freq - 5170) / 5 + 34;
	}
	else
	{
		return -1;
	}
}

#define add_diagnostic_info_field(reply, info, name) ({ \
    if(info) { \
        gchar **value_str = g_strsplit(g_strstrip(info), ":", 2); \
        if(value_str) { \
            jobject_put(*reply, J_CSTR_TO_JVAL(name), jstring_create(g_strstrip(value_str[1]))); \
            g_strfreev(value_str); \
        } \
    }\
})

/**
 * Populate the wifi diagnostics information
 * Split the technology->diagnostic_info variable if available and add all the values to an existing json object
 * Or get the interface properties for the wifi interface "wlan0"
 *
 * @param technoolgy A technology instance
 * @param reply The json object which needs to be updated
 */

static gboolean make_wifi_diagnostics_payload(connman_technology_t *technology,
        jvalue_ref *reply)
{
	jobject_put(*reply, J_CSTR_TO_JVAL("ssid"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("macAddress"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("state"), jstring_create("Power off"));
	jobject_put(*reply, J_CSTR_TO_JVAL("amac"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("hi_op"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("ipAddress"), jstring_create("N/A"));

	jobject_put(*reply, J_CSTR_TO_JVAL("version"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("ccode"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("ccodeRev"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("channel"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("MCS"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("MIMO"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("rate"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("RSSI"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("noise"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("txpwr"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("NSS"), jstring_create("N/A"));
	jobject_put(*reply, J_CSTR_TO_JVAL("BW"), jstring_create("N/A"));

	if (technology->diagnostic_info)
	{
		gchar **split_str = g_strsplit(g_strstrip(technology->diagnostic_info),
		                               "\n\t\t", 13);

		if(split_str)
		{
			int i;
			int diagnostic_len = g_strv_length(split_str);

			for (i = 1; i < diagnostic_len; i++)
			{
				if (i == 1)
				{
					add_diagnostic_info_field(reply, split_str[1], "version");
				}
				else if (i == 2)
				{
					add_diagnostic_info_field(reply, split_str[2], "ccode");
				}
				else if (i == 3)
				{
					add_diagnostic_info_field(reply, split_str[3], "ccodeRev");
				}
				else if (i == 4)
				{
					add_diagnostic_info_field(reply, split_str[4], "channel");
				}
				else if (i == 5)
				{
					add_diagnostic_info_field(reply, split_str[5], "MCS");
				}
				else if (i == 6)
				{
					add_diagnostic_info_field(reply, split_str[6], "MIMO");
				}
				else if (i == 7)
				{
					add_diagnostic_info_field(reply, split_str[7], "rate");
				}
				else if (i == 8)
				{
					add_diagnostic_info_field(reply, split_str[8], "RSSI");
				}
				else if (i == 9)
				{
					add_diagnostic_info_field(reply, split_str[9], "noise");
				}
				else if (i == 10)
				{
					add_diagnostic_info_field(reply, split_str[10], "txpwr");
				}
				else if (i == 11)
				{
					add_diagnostic_info_field(reply, split_str[11], "NSS");
				}
				else if(i == 12)
				{
					add_diagnostic_info_field(reply, split_str[12], "BW");
				}
			}

			g_strfreev(split_str);
		}
	}
	else
	{
		connman_technology_t *wifi_technology = connman_manager_find_wifi_technology(
		        manager);
		connman_technology_interface_t interface_properties;

		if (connman_technology_get_interface_properties(wifi_technology,
		        CONNMAN_WIFI_INTERFACE_NAME, &interface_properties) == TRUE)
		{
			gchar *rssi = g_strdup_printf("%ddbm", interface_properties.rssi);
			jobject_put(*reply, J_CSTR_TO_JVAL("RSSI"), jstring_create(rssi));
			g_free(rssi);

			jobject_put(*reply, J_CSTR_TO_JVAL("linkSpeed"),
			            jnumber_create_i32(interface_properties.link_speed));

			if (interface_properties.link_speed < 6 ||
			        interface_properties.link_speed == 11)
			{
				jobject_put(*reply, J_CSTR_TO_JVAL("txpwr"), jstring_create("17 dBm"));
			}
			else
			{
				jobject_put(*reply, J_CSTR_TO_JVAL("txpwr"), jstring_create("14 dBm"));
			}

			int ch = convert_frequency_to_channel(interface_properties.frequency);

			if (ch > 0)
			{
				gchar *channel =  g_strdup_printf("%d", ch);
				jobject_put(*reply, J_CSTR_TO_JVAL("channel"), jstring_create(channel));
				g_free(channel);
			}
		}
	}

	if (is_wifi_powered())
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("state"), jstring_create("Power on"));
	}

	gchar wifi_mac_address[MAC_ADDR_STRING_LEN];

	if (retrieve_wifi_mac_address(wifi_mac_address, MAC_ADDR_STRING_LEN))
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("macAddress"),
		            jstring_create(wifi_mac_address));
	}

	connman_service_t *connected_service = connman_manager_get_connected_service(
	        manager->wifi_services);

	if (connected_service != NULL)
	{
		if (connected_service->name != NULL)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("ssid"),
			            jstring_create(connected_service->name));
		}

		int wifi_state = connman_service_get_state(connected_service->state);

		if (wifi_state == CONNMAN_SERVICE_STATE_ONLINE ||
		        wifi_state == CONNMAN_SERVICE_STATE_READY)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("state"), jstring_create("CONNECTED"));

			if (connected_service->ipinfo.ipv4.address)
			{
				jobject_put(*reply, J_CSTR_TO_JVAL("ipAddress"),
				            jstring_create(connected_service->ipinfo.ipv4.address));
			}
		}
		else if (wifi_state == CONNMAN_SERVICE_STATE_ASSOCIATION ||
		         wifi_state == CONNMAN_SERVICE_STATE_CONFIGURATION)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("state"), jstring_create("CONNECTING"));
		}

		if (connected_service->hidden)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("hi_op"), jstring_create("Hidden"));
		}
		else
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("hi_op"), jstring_create("Open"));
		}

		if (connected_service->address != NULL)
		{
			jobject_put(*reply, J_CSTR_TO_JVAL("amac"),
			            jstring_create(connected_service->address));
		}

	}

	return TRUE;
}


static void send_wifi_diagnostics_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	connman_technology_t *wifi_technology = connman_manager_find_wifi_technology(
	        manager);

	if (make_wifi_diagnostics_payload(wifi_technology, &reply) == TRUE)
	{
		jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
		                              DOMOPT_NOOPT, NULL);

		if (response_schema)
		{
			const char *payload = jvalue_tostring(reply, response_schema);
			LSError lserror;
			LSErrorInit(&lserror);

			if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_GET_WIFI_DIAGNOSTICS,
                                                 payload,
			                         &lserror))
			{
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}

			jschema_release(&response_schema);
		}
	}

	j_release(&reply);
}

static gboolean signal_polling_cb(gpointer user_data)
{
	connman_service_t *connected_service = connman_manager_get_connected_service(
	        manager->wifi_services);

	if (!is_wifi_powered() || NULL == connected_service)
	{
		g_source_remove(signal_polling_timeout_source);
		signal_polling_timeout_source = 0;

		return FALSE;
	}

	connman_technology_t *wifi_technology = connman_manager_find_wifi_technology(
	        manager);
	connman_technology_interface_t interface_properties;

	if (connman_technology_get_interface_properties(wifi_technology,
	        CONNMAN_WIFI_INTERFACE_NAME, &interface_properties) == TRUE)
	{

		guchar old_strength = connected_service->strength;
		connected_service->strength = interface_properties.rssi + 120;

		if (old_strength != connected_service->strength)
		{
			send_wifi_diagnostics_to_subscribers();
		}

		if (signal_strength_to_bars(old_strength) != signal_strength_to_bars(
		            connected_service->strength))
		{
			wifi_send_status_to_subscribers();
			send_findnetworks_status_to_subscribers();
			send_getnetworks_status_to_subscribers();
		}
	}

	return TRUE;
}

static void start_signal_polling()
{
	// start signal polling only if there are subscribers for "getwifidiagnositcs" and
	// the wifi technology interface doesn't support diagnostic info
	if ((LSSubscriptionGetHandleSubscribersCount(pLsHandle,
	        LUNA_CATEGORY_ROOT LUNA_METHOD_GET_WIFI_DIAGNOSTICS) == 0)
	        && (LSSubscriptionGetHandleSubscribersCount(pLsHandle,
	                LUNA_CATEGORY_ROOT LUNA_METHOD_GET_WIFI_DIAGNOSTICS) == 0))
	{
		return;
	}

	connman_technology_t *wifi_technology = connman_manager_find_wifi_technology(
	        manager);

	if (!wifi_technology->diagnostic_info && 0 == signal_polling_timeout_source)
	{
		signal_polling_timeout_source = g_timeout_add_seconds(3, signal_polling_cb,
		                                NULL);
	}
}

static void stop_signal_polling()
{
	if (0 < signal_polling_timeout_source)
	{
		g_source_remove(signal_polling_timeout_source);
		signal_polling_timeout_source = 0;
	}
}


/**
 *  @brief Callback function registered with connman technology whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void technology_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if (NULL == technology)
	{
		return;
	}

	connman_technology_t *wifi_technology = connman_manager_find_wifi_technology(
	        manager);

	/* Need to send getstatus method to all its subscribers whenever the "powered" state for
	   WiFi technology changes and "powered" / "connected" state for ethernet technology changes */
	if (technology == wifi_technology)
	{
		if (!g_strcmp0(property, "Powered") || !g_strcmp0(property, "Connected"))
		{
			wifi_send_status_to_subscribers();

			if (wifi_technology->powered)
			{
				wifi_scan_start(technology);
			}
			else
			{
				wifi_scan_stop();
			}

			if (wifi_technology->connected)
			{
				start_signal_polling();
			}
			else
			{
				stop_signal_polling();
			}

			/** Force update to get new Diagnostic Info and send to subscribers */
			connman_technology_update_properties(technology);

		}

		if (g_strcmp0(property, "Tethering") == 0 ||
		    g_strcmp0(property, "TetheringIdentifier") == 0 ||
		    g_strcmp0(property, "TetheringPassphrase") == 0)
		{
			send_tethering_state_to_subscribers();
			connectionmanager_send_status_to_subscribers();
			wifi_send_status_to_subscribers();
		}

		if(g_strcmp0(property, "StaCount") == 0) {
			send_sta_count_to_subscribers();
		}

		if (!g_strcmp0(property, "DiagnosticInfo"))
		{
			send_wifi_diagnostics_to_subscribers();
		}
	}
	else if (technology == connman_manager_find_ethernet_technology(manager))
	{
		if (!g_strcmp0(property, "Powered") || !g_strcmp0(property, "Connected"))
		{
			connectionmanager_send_status_to_subscribers();
		}
	}
}

static void support_configure_country_code_cb(bool success, void *user_data)
{
	if (success)
	{
		WCALOG_INFO(MSGID_COUNTRY_CODE_INFO, 0, "Success in setting country code");
	}
	else
	{
		WCALOG_ERROR(MSGID_COUNTRY_CODE_FAILED, 0, "Failed to set country code");
	}
}

static void check_and_initialize_ethernet_technology(void)
{

	connman_technology_t *technology = connman_manager_find_ethernet_technology(
			manager);

	if (technology)
	{
		connman_technology_register_property_changed_cb(technology,
		                                                technology_property_changed_callback);
	}
}

static void check_and_initialize_wifi_technology(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);
	/** TODO: this needs to be done only when wifi technology is changed:
	 * The method is called whenever technology list changes.
	 * */

	if (technology)
	{
		connman_technology_register_property_changed_cb(technology,
		        technology_property_changed_callback);

		if (technology->powered)
		{
			wifi_scan_start(technology);
		}
		else
		{
			wifi_scan_stop();
		}
	}
	else
	{
		/* Technology removed */
		wifi_scan_stop();
	}

	send_getinfo_to_subscribers();
}

/* Most likely this callback will be called when wifi dongle is added/removed */
static void manager_technologies_changed_callback(gpointer data)
{
	check_and_initialize_wifi_technology();
	check_and_initialize_cellular_technology();
	check_and_initialize_bluetooth_technology();
	check_and_initialize_ethernet_technology();
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_setstate setstate

Enable or Disable WIFI support


@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
state | Yes | String | "enabled" or "disabled" to control WIFI accordingly

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

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

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(state, string)) REQUIRED_1(state))),
	                             &parsedObj))
	{
		return true;
	}

	jvalue_ref stateObj = {0};
	gboolean enable_wifi = FALSE;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("state"), &stateObj))
	{
		if (jstring_equal2(stateObj, J_CSTR_TO_BUF("enabled")))
		{
			enable_wifi = TRUE;
		}
		else if (jstring_equal2(stateObj, J_CSTR_TO_BUF("disabled")))
		{
			enable_wifi = FALSE;

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

	/*
	 *  Check if we are enabling an already enabled service,
	 *  or disabling an already disabled service
	 */

	if (enable_wifi && is_wifi_powered())
	{
		LSMessageReplyCustomError(sh, message, "Already Enabled",
		                          WCA_API_ERROR_ALREADY_ENABLED);
		goto cleanup;
	}
	else if (!enable_wifi && !is_wifi_powered())
	{
		LSMessageReplyCustomError(sh, message, "Already Disabled",
		                          WCA_API_ERROR_ALREADY_DISABLED);
		goto cleanup;
	}

	set_wifi_powered_state(enable_wifi);

	LSMessageReplySuccess(sh, message);
	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;

}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_connect connect

@par To Connect to open, hidden or secure networks

Connects to the given ssid , which can be an open network (requiring
no passphrase i.e no 'security' field in its argument), hidden
(requiring 'wasCreatedWithJoinOther' field set to true in its argument),
or secure networks (authenticating with provided passphrase).

Note: webos-connman-adapter only supports simple security using psk,
it doesn't support "enterprise" security.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of desired network
wasCreatedWithJoinOther | Yes | String | Set True for a hidden network
security | Only for secure networks | Object | Security information for establishing a connection

@par "security" Object

Name | Required | Type | Description
-----|--------|------|----------
securityType | Yes | String | Connection type, e.g. wpa-personal, wep, or psk
simpleSecurity | Yes | Object | Connection information for a simple connection

@par "simpleSecurity" Object

Name | Required | Type | Description
-----|--------|------|----------
passKey | Yes | String | Passkey for connection to network

@par To connect to wps enabled networks:

Connects to the given ssid with wps setup, for WPS-PBC mode or WPS-PIN mode with
pin to be entered at AP, you just need to set the "wps" field set to true, for
WPS-PIN mode where pin needs to be entered on the device, you need to also enter
the "wpspin" value

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of desired network
security | Yes | Object | Security information for establishing a connection

@par "security" Object

Name | Required | Type | Description
-----|--------|------|----------
wps | Yes | Boolean | true to enable wps mode
wpspin | No | String | WPS PIN if using WPS-PIN mode

@par To connect to a known profile

Connects to an AP using its profileId which is listed in 'getprofilelist' method.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
profileId | Yes | Integer | Name of desired profile

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

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

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_wifi_powered())
	{
		LSMessageReplyCustomError(sh, message, "WiFi switched off",
		                          WCA_API_ERROR_WIFI_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(ssid, string),
	                                     PROP(profileId, integer), PROP(wasCreatedWithJoinOther, boolean),
	                                     PROP(storeProfile, boolean),
	                                     OBJECT(security, OBJSCHEMA_4(PROP(securityType, string), OBJECT(simpleSecurity,
	                                             OBJSCHEMA_1(PROP(passKey, string))),
	                                             PROP(wps, boolean), PROP(wpsPin, string)))))), &parsedObj))
	{
		return true;
	}

	jvalue_ref ssidObj = {0};
	jvalue_ref profileIdObj = {0};
	char *ssid;
	wifi_profile_t *profile = NULL;
	luna_service_request_t *service_req;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);
	}
	else if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"),
	                            &profileIdObj))
	{
		int profile_id = 0;
		jnumber_get_i32(profileIdObj, &profile_id);
		profile = get_profile_by_id(profile_id);

		if (NULL == profile)
		{
			LSMessageReplyCustomError(sh, message, "Profile not found",
			                          WCA_API_ERROR_PROFILE_NOT_FOUND);
			goto cleanup;
		}

		ssid = g_strdup(profile->ssid);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	service_req = luna_service_request_new(sh, message);

	connect_wifi_with_ssid(ssid, profile, parsedObj, service_req);

	g_free(ssid);
cleanup:
	j_release(&parsedObj);
	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_cancel

Cancel an currently ongoing connection attempt.

Callers can cancel and previously initiated connection attempt with calling this method. Internally
the wifi service will figure out the currently connecting service and cancel the attempt.

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@}
*/
//->End of API documentation comment block

static bool handle_cancel_command(LSHandle *handle, LSMessage *message,
                                  void *user_data)
{
	connman_service_t *connecting_service;

	if (!connman_status_check(manager, handle, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(handle, message))
	{
		return true;
	}

	connecting_service = connman_manager_get_connecting_service(
	                         manager->wifi_services);

	if (!connecting_service)
	{
		LSMessageReplyCustomError(handle, message, "No service is connecting currently",
		                          WCA_API_ERROR_NO_SERVICE_CONNECTING);
		return true;
	}

	if (!connman_service_disconnect(connecting_service))
	{
		LSMessageReplyCustomError(handle, message,
		                          "Failed to disconnect currently connecting service",
		                          WCA_API_ERROR_DISCONNECT_FAILED);
		return true;
	}

	LSMessageReplySuccess(handle, message);

	return true;
}


//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_findnetworks

List all available wifi access points found in the area.

Callers can subscribe to this method to be notified of any changes. If a
caller subscribes to further results he has to unsubscribe once it doesn't
need fresh results any more. Once more than one client is subscribed a
scan for available wifi networks is scheduled every 30 seconds until no
client is subscribed anymore.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subcribe to changes
interval | No | Number | Number of seconds to use as scan interval

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
foundNetworks | Yes | Array of Objects | List of networkInfo objects

@par "networkInfo" Object

Each entry in the "foundNetworks" array is of the form "networkInfo":{...}

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of discovered AP
availableSecurityTypes | Yes | Array of String | List of supported security mechanisms
signalBars | Yes | Integer | Coarse indication of signal strength
signalLevel | Yes | Integer | Fine indication of signal strength

@par Returns(Subscription)

As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_findnetworks_command(LSHandle *sh, LSMessage *message,
                                        void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(subscribe, boolean), PROP(interval,
	                                     number)))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	jvalue_ref intervalObj = 0;
	bool subscribed = false;
	gint interval = findnetworks_default_scan_interval;
	gboolean result;
	LSError lserror;
	LSErrorInit(&lserror);

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

	if (!wifi_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!is_wifi_powered())
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message, "WiFi switched off",
		        WCA_API_ERROR_WIFI_SWITCHED_OFF, subscribed);
		goto cleanup;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("interval"), &intervalObj))
	{
		jnumber_get_i32(intervalObj, &interval);

		if (interval <= 0)
		{
			LSMessageReplyErrorInvalidParams(sh, message);
			goto cleanup;
		}

		/**If not subscribed, set default interval value. */
		if (!subscribed)
		{
			findnetworks_default_scan_interval = interval;
		}
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (NULL == wifi_tech)
	{
		LSMessageReplyCustomError(sh, message, "WiFi technology unavailable",
		                          WCA_API_ERROR_WIFI_TECH_UNAVAILABLE);
		goto cleanup;
	}

	if (subscribed)
	{
		result = wifi_scan_add_interval(LSMessageGetUniqueToken(message),
		                                (guint) interval);
	}
	else
	{
		result = wifi_scan_now();
	}

	if (!result)
	{
		LSMessageReplyCustomError(sh, message, "Error in scanning network",
		                          WCA_API_ERROR_SCANNING);
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	populate_wifi_networks(&reply, FALSE);

	LSMessageReply(sh, message, jvalue_tostring(reply, jschema_all()), &lserror);

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

static bool handle_scan_command(LSHandle *sh, LSMessage *message,
                                void *user_data)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_wifi_powered())
	{
		LSMessageReplyCustomError(sh, message, "WiFi switched off",
		                          WCA_API_ERROR_WIFI_SWITCHED_OFF);
		return true;
	}

	if (!wifi_scan_now())
	{
		LSMessageReplyCustomError(sh, message, "Error in scanning network",
		                          WCA_API_ERROR_SCANNING);
		return true;
	}

	LSMessageReplySuccess(sh, message);
	return true;
}

static bool handle_get_networks_command(LSHandle *sh, LSMessage *message,
                                        void *user_data)
{
	jvalue_ref replyObj = 0;
	bool subscribed = false;
	LSError lserror;
	LSErrorInit(&lserror);

	replyObj = jobject_create();

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

	if (!wifi_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!is_wifi_powered())
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message, "WiFi switched off",
		        WCA_API_ERROR_WIFI_SWITCHED_OFF, subscribed);
		goto cleanup;
	}

	jobject_put(replyObj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(replyObj, J_CSTR_TO_JVAL("subscribed"),
	            jboolean_create(subscribed));

	populate_wifi_networks(&replyObj, TRUE);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (!response_schema)
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(replyObj, response_schema),
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

	if (replyObj)
	{
		j_release(&replyObj);
	}

	return true;
}

static bool handle_change_network_command(LSHandle *sh, LSMessage *message,
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

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(PROP(profileId, integer), PROP(passKey,
	                                     string)) REQUIRED_2(profileId, passKey))), &parsedObj))
	{
		return true;
	}

	jvalue_ref profileIdObj = {0}, passKeyObj = {0};
	int profile_id = 0;
	gchar *passKey = NULL;
	LSError lserror;
	LSErrorInit(&lserror);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		jnumber_get_i32(profileIdObj, &profile_id);
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("passKey"), &passKeyObj))
	{
		raw_buffer passKey_buf = jstring_get(passKeyObj);
		passKey = g_strdup(passKey_buf.m_str);
		jstring_free_buffer(passKey_buf);
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);

	if (NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found",
		                          WCA_API_ERROR_PROFILE_NOT_FOUND);
		goto cleanup;
	}

	if (!is_valid_wifi_passphrase(passKey, profile->security[0]))
	{
		LSMessageReplyCustomError(sh, message,
		                          "Passphrase doesn't match the requirements",
		                          WCA_API_ERROR_WIFI_PASSPHRASE_INVALID);
		goto cleanup;
	}

	if (profile->configured)
	{
		// for out of range configured but not provisioned networks
		change_network_passphrase(profile->ssid, profile->security[0], passKey);
	}
	else
	{
		GSList *ap = NULL;

		for (ap = manager->saved_services; NULL != ap ; ap = ap->next)
		{
			connman_service_t *service = (connman_service_t *)(ap->data);

			if (g_strcmp0(service->name, profile->ssid) ||
			        check_service_security(service, profile->security))
			{
				continue;
			}

			gboolean ret = FALSE;

			if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			        NULL == connman_manager_find_service_by_path(manager->wifi_services,
			                service->path))
			{
				// for out of range but not provisioned by a .config file networks
				ret = connman_manager_change_saved_passphrase(manager, service, passKey);
			}
			else
			{
				// for currently available but not provisioned by a .config networks
				ret = connman_service_set_passphrase(service, passKey);
			}

			if (!ret)
			{
				LSMessageReplyErrorUnknown(sh, message);
				goto cleanup;
			}

			goto out;

		}
	}

out:
	LSMessageReplySuccess(sh, message);

cleanup:
	g_free(passKey);
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getstatus getstatus

Gets the current status of wifi connection on the system.

Callers can subscribe to this method to be notified of any changes
in the wifi connection status.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)

All optional fields are absent if WIFI is not connected

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
wakeOnWlan | No | String | provided for backwards compatibility and always set to "disabled"
status | No | String | Set to "connectedStateChanged" for backwards compatibility
networkInfo | No | Object | A single object describing the current connection

@par "networkInfo" Object

Name | Required | Type | Description
-----|--------|------|----------
ssid | Yes | String | SSID of AP
connectState | Yes | String | One of {notAssociated, associating, associated, ipConfigured, ipFailed}
signalBars | Yes | Integer | Coarse indication of signal strength (1..3)
signalLevel | Yes | Integer | Absolute indication of signal strength
ipInfo | Yes | Object | See below

@par "ipInfo" Object

Name | Required | Type | Description
-----|--------|------|----------
interface | Yes | String |
ip | Yes | String | IP Address
subnet | Yes | String | Subnet mask value
gateway | Yes | String |IP Address of network gateway
dns | Yes | Array of String | List of DNS server IP addresses

@par Returns(Subscription)

As for a successful call
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

	if (!wifi_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	create_wifi_getstatus_response(&reply, subscribed);

	LSMessageReply(sh, message, jvalue_tostring(reply, jschema_all()),
	                    &lserror);

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

static void add_wifi_profile(jvalue_ref *profile_j, wifi_profile_t *profile)
{
	jvalue_ref profile_details_j = jobject_create();
	jobject_put(profile_details_j, J_CSTR_TO_JVAL("ssid"),
	            jstring_create(profile->ssid));
	jobject_put(profile_details_j, J_CSTR_TO_JVAL("profileId"),
	            jnumber_create_i32(profile->profile_id));

	if (profile->hidden)
	{
		jobject_put(profile_details_j, J_CSTR_TO_JVAL("wasCreatedWithJoinOther"),
		            jboolean_create(profile->hidden));
	}

	if (profile->security != NULL)
	{
		jvalue_ref security = jobject_create();
		jvalue_ref security_list = jarray_create(NULL);
		int i;

		for (i = 0; i < g_strv_length(profile->security); i++)
		{
			jarray_append(security_list, jstring_create(profile->security[i]));
		}

		jobject_put(security, J_CSTR_TO_JVAL("securityType"), security_list);
		jobject_put(profile_details_j, J_CSTR_TO_JVAL("security"), security);
	}

	jobject_put(*profile_j, J_CSTR_TO_JVAL("wifiProfile"), profile_details_j);
}

static void add_wifi_profile_list(jvalue_ref *reply)
{
	if (profile_list_is_empty())
	{
		return;
	}

	jvalue_ref profile_list_j = jarray_create(NULL);

	wifi_profile_t *profile = NULL;

	while (NULL != (profile = get_next_profile(profile)))
	{
		jvalue_ref profile_j = jobject_create();
		add_wifi_profile(&profile_j, profile);
		jarray_append(profile_list_j, profile_j);
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("profileList"), profile_list_j);
}



//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getprofilelist getprofilelist

Lists all the stored wifi profiles on the system.

@Note If the wifi AP is an open network with no security, it
      won't list the "security" field.

@par Parameters

None

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
profileList | yes | Array of Object | Array of wifiProfile objects

@par "wifiProfile" Object

Name | Required | Type | Description
-----|--------|------|----------
ssid | yes | String | SSID associated with the profile
profileId | yes | String | ID string naming the profile (can be used with connect method)
security | no | Object | Contains a "securityType" object, which is an Array of String

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_profilelist_command(LSHandle *sh, LSMessage *message,
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

	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);

	if (profile_list_is_empty())
	{
		LSMessageReplyCustomError(sh, message, "Profile not found",
		                          WCA_API_ERROR_PROFILE_NOT_FOUND);
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	add_wifi_profile_list(&reply);

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
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getprofile getprofile

Lists the profile with the given profile ID on the system.

@Note As in getprofilelist, even here the open networks won't list
      the "security" field.


@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
profileId | yes | Integer | Name of profile required

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
wifiProfile | yes | Object | A "wifiProfile" object as described for the getprofilelist method

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_profile_command(LSHandle *sh, LSMessage *message,
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

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(profileId,
	                                     integer)) REQUIRED_1(profileId))), &parsedObj))
	{
		return true;
	}

	jvalue_ref profileIdObj = {0};
	jvalue_ref reply = jobject_create();
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		jnumber_get_i32(profileIdObj, &profile_id);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);

	if (NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found",
		                          WCA_API_ERROR_PROFILE_NOT_FOUND);
		goto cleanup;
	}
	else
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		add_wifi_profile(&reply, profile);
	}

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

	j_release(&parsedObj);
	j_release(&reply);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_deleteprofile deleteprofile

Deletes the profile with the given profile ID

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
profileId | Yes | Integer | Name of profile to be deleted

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

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

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(profileId,
	                                     integer)) REQUIRED_1(profileId))), &parsedObj))
	{
		return true;
	}

	jvalue_ref profileIdObj = {0};
	int profile_id = 0;
	LSError lserror;
	LSErrorInit(&lserror);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("profileId"), &profileIdObj))
	{
		jnumber_get_i32(profileIdObj, &profile_id);
	}
	else
	{

		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	wifi_profile_t *profile = get_profile_by_id(profile_id);

	if (NULL == profile)
	{
		LSMessageReplyCustomError(sh, message, "Profile not found",
		                          WCA_API_ERROR_PROFILE_NOT_FOUND);
		goto cleanup;
	}
	else
	{
		remove_service_or_all_other(profile->ssid, FALSE);
		delete_profile(profile);
		LSMessageReplySuccess(sh, message);
	}

cleanup:
	j_release(&parsedObj);
	return true;
}


gint generate_new_wpspin(void)
{
	FILE *f = fopen("/dev/urandom", "rb");

	if (f == NULL)
	{
		return -1;
	}

	//Generate 7 random digits
	gint pin = 0;
	int count = 0;

	do
	{
		count = fread(&pin, sizeof(pin), 1, f);
	}
	while(count == -1 || pin < 0);

	pin %= 10000000;
	pin *= 10;

	fclose(f);

	// Append checksum digit in the end

	unsigned int tmppin =  pin / 10;
	unsigned int accum = 0;

	while (tmppin)
	{
		accum += 3 * (tmppin % 10);
		tmppin /= 10;
		accum += tmppin % 10;
		tmppin /= 10;
	}

	pin += ((10 - accum % 10) % 10);

	return pin;
}



//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_createwpspin createwpspin

Generates an 8 digit random wps pin

@par Parameters

None

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
wpspin | yes | String | 8 digit random wps pin number

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_create_wpspin_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);

	gint wpspin = generate_new_wpspin();

	if (wpspin < 0)
	{
		goto error;
	}

	char wpspin_str[9];
	snprintf(wpspin_str, 9, "%08i", wpspin);

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("wpspin"), jstring_create(wpspin_str));

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
error:
	LSMessageReplyCustomError(sh, message, "Error in generating wps pin",
	                          WCA_API_ERROR_WPS_PIN);
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
@page com_webos_wifi com.webos.wifi/p2p
@{
@section com_webos_wifi_startwps startwps

Start WPS authentication process. If no wpsPin argument is supplied
the WPS-PBC method will be used, else it will be WPS-PIN method.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
wpsPin | No | String | Pin for WPS-PIN mode

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_start_wps_command(LSHandle *sh, LSMessage *message,
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

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(wpsPin, string)))), &parsedObj))
	{
		return true;
	}

	jvalue_ref wpsPinObj = NULL;
	char *wpspin = NULL;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wpsPin"), &wpsPinObj))
	{
		raw_buffer address_buf = jstring_get(wpsPinObj);
		wpspin = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		wpspin = g_strdup("");
	}

	if (!connman_technology_start_wps(connman_manager_find_wifi_technology(manager),
	                                  wpspin))
	{
		LSMessageReplyErrorUnknown(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	g_free(wpspin);
	j_release(&parsedObj);
	return true;
}



//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_cancelwps cancelwps

Cancel any ongoing WPS connection.

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

static bool handle_cancel_wps_command(LSHandle *sh, LSMessage *message,
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

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);

	if (!connman_technology_cancel_wps(technology))
	{
		LSMessageReplyCustomError(sh, message, "Error in cancelling WPS connection",
		                          WCA_API_ERROR_CANCEL_WPS);
		return true;
	}

	LSMessageReplySuccess(sh, message);
	return true;
}



//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_setmultichannelschedmode setmultichannelschedmode

Set the multi channel scheduling mode for wifi technology

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
mode | Yes | Integer | 0 for fair, 1 for sta, 2 for p2p

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_set_multichannel_sched_mode_command(LSHandle *sh,
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

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(mode, integer)) REQUIRED_1(mode))),
	                             &parsedObj))
	{
		return true;
	}

	jvalue_ref modeObj = NULL;
	gint32 mode = 0;

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("mode"), &modeObj))
	{
		jnumber_get_i32(modeObj, &mode);

		if (mode != technology->multi_channel_mode &&
		        !connman_technology_set_multi_channel_mode(technology, mode))
		{
			LSMessageReplyCustomError(sh, message,
			                          "Error in changing multi channel sched mode",
			                          WCA_API_ERROR_MULTI_CHAN_SCHED_MODE);
			goto cleanup;
		}
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);
cleanup:
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getmultichannelschedmode getmultichannelschedmode

Get the multi channel scheduling mode for wifi technology

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
None

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
mode | Yes | Integer | 0 for fair, 1 for sta, 2 for p2p

@par Returns(Subscription)

Not applicable.

@}
*/
//->End of API documentation comment block

static bool handle_get_multichannel_sched_mode_command(LSHandle *sh,
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
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("mode"),
	            jnumber_create_i32(technology->multi_channel_mode));

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
@page com_webos_wifi com.webos.wifi
@{
@section com_webos_wifi_getwifidiagnostics getwifidiagnostics

Get the wifi diagnostic information from the driver.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
None

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True
version | Yes | String | Version info
ccode | Yes | String | Country code
ccodeRev | Yes | String | Country code revision
channel | Yes | String | Channel
MCS | Yes | String | MCS
MIMO | Yes | String | MIMO
rate | Yes | String | Rate
RSSI | Yes | String | RSSI
noise | Yes | String | Noise level
txpwr | Yes | String | Txpwr

@par Returns(Subscription)

As for a successful call

@}
*/
//->End of API documentation comment block

static bool handle_get_wifi_diagnostics_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
		return true;
	}

	jvalue_ref reply = jobject_create();
	bool subscribed = false;
	LSError lserror;
	LSErrorInit(&lserror);

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

	if (!wifi_technology_status_check_with_subscription(sh, message, subscribed))
	{
		goto cleanup;
	}

	if (!is_wifi_powered())
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message, "WiFi switched off",
		        WCA_API_ERROR_WIFI_SWITCHED_OFF, subscribed);
		goto cleanup;
	}

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);
	connman_technology_update_properties(technology);

	make_wifi_diagnostics_payload(technology, &reply);

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

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

static void handle_luna_subscription_cancel(LSHandle *sh, LSMessage *message, void *ctx)
{
	const char *category = LSMessageGetCategory(message);
	const char *method = LSMessageGetMethod(message);

	// check for findnetworks
	if (!g_strcmp0(category, LUNA_CATEGORY_ROOT) &&
	    !g_strcmp0(method, LUNA_METHOD_FINDNETWORKS))
	{
		wifi_scan_remove_interval(LSMessageGetUniqueToken(message));
	}
}

static void set_passthrough_params_cb(bool success, jvalue_ref params,
                                      void *user_data)
{
	luna_service_request_t *service_req = (luna_service_request_t *) user_data;
	LSHandle *sh = NULL;
	LSMessage *message = NULL;

	if (service_req)
	{
		sh = service_req->handle;
		message = service_req->message;
	}

	if (success)
	{
		if (params)
		{
			jvalue_ref reply = jobject_create();
			LSError lserror;
			LSErrorInit(&lserror);
			jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
			jobject_put(reply,  J_CSTR_TO_JVAL("params"), params);
			jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
			                              DOMOPT_NOOPT, NULL);

			if (response_schema)
			{
				if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema),
				                    &lserror))
				{
					LSErrorPrint(&lserror, stderr);
					LSErrorFree(&lserror);
				}

				jschema_release(&response_schema);
			}
			else
			{
				LSMessageReplyErrorUnknown(sh, message);
			}

			if (LSErrorIsSet(&lserror))
			{
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
			}

			j_release(&reply);
		}
		else
		{
			LSMessageReplySuccess(sh, message);
		}
	}
	else
		LSMessageReplyCustomError(sh, message,
		                          "Error in setting passthrough parameters",
		                          WCA_API_ERROR_SET_PASSTHROUGH_PARAMS_FAILED);

	if (service_req)
	{
		luna_service_request_free(service_req);
	}
}

static bool handle_set_passthrough_params_command(LSHandle *sh,
        LSMessage *message, void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(SCHEMA_ANY),
	                             &parsedObj))
	{
		return true;
	}

	jvalue_ref paramsObj = {0};

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("params"), &paramsObj))
	{
		luna_service_request_t *service_req = luna_service_request_new(sh, message);

		if (wca_support_wifi_set_passthrough_params(paramsObj,
		        set_passthrough_params_cb, service_req))
			LSMessageReplyCustomError(sh, message,
			                          "Error in setting passthrough parameters",
			                          WCA_API_ERROR_SET_PASSTHROUGH_PARAMS_FAILED);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
	}

	j_release(&parsedObj);
	return true;
}

static void agent_registered_callback(gpointer user_data)
{
	gchar *agent_path;

	agent_path = connman_agent_get_path(agent);

	if (!connman_manager_register_agent(manager, agent_path))
	{
		WCALOG_CRITICAL(MSGID_WIFI_AGENT_ERROR, 0,
		                "Could not register our agent instance with connman; functionality will be limited!");
	}
}

static void connman_service_stopped(GDBusConnection *conn, const gchar *name,
                                    const gchar *name_owner, gpointer user_data)
{
	WCALOG_DEBUG("connman service disappeared from the bus");

	/* if scan is still scheduled abort it */
	wifi_scan_stop();

	/* if signal_poll is still scheduled abort it */
	if (signal_polling_timeout_source > 0)
	{
		stop_signal_polling();
	}

	if (agent != NULL)
	{
		connman_agent_free(agent);
		agent = NULL;
	}

	if (manager != NULL)
	{
		connman_manager_free(manager);
		manager = NULL;
	}
}

static void connman_service_started(GDBusConnection *conn, const gchar *name,
                                    const gchar *name_owner, gpointer user_data)
{
	WCALOG_DEBUG("connman service appeared on the bus");

#ifndef ENABLE_SINGLE_PROFILE
	sync_network_configs_with_profiles();

	if (create_config_inotify_watch() == FALSE)
	{
		WCALOG_ERROR(MSGID_WIFI_CONFIG_INOTIFY_WATCH_ERR, 0,
		             "Failed to set inotify watch for wifi config files");
	}

#endif

	/* We just need one manager instance that stays throughout the lifetime
	 * of this daemon. Only its technologies and services lists are updated
	 * whenever the corresponding signals are received */
	manager = connman_manager_new();

	if (NULL == manager)
	{
		return;
	}

	agent = connman_agent_new();

	if (NULL == agent)
	{
		connman_manager_free(manager);
		manager = NULL;
		return;
	}

	connman_agent_set_registered_callback(agent, agent_registered_callback, NULL);

	/* Register for manager's "PropertyChanged" and "ServicesChanged" signals for sending 'getstatus' and 'findnetworks'
	   methods to their subscribers */
	connman_manager_register_property_changed_cb(manager,
	        manager_property_changed_callback);
	connman_manager_register_services_changed_cb(manager,
	        manager_services_changed_callback);
	connman_manager_register_technologies_changed_cb(manager,
	        manager_technologies_changed_callback);

	check_and_initialize_wifi_technology();
	check_and_initialize_ethernet_technology();
	check_and_initialize_cellular_technology();
	check_and_initialize_bluetooth_technology();

	connectionmanager_send_status_to_subscribers();
}

/**
 * @brief When the system UI locale has changed we need to adjust the displayed name of
 * all wifi service objects.
 */

void wifi_service_local_has_changed()
{
	GSList *ap;

	if (NULL == manager)
	{
		return;
	}

	for (ap = manager->wifi_services; NULL != ap ; ap = ap->next)
	{
		connman_service_t *service = (connman_service_t *)(ap->data);
		connman_service_update_display_name(service);
	}
}

/**
 * com.webos.service.wifi service Luna Method Table
 */

static LSMethod wifi_methods[] =
{
	{ LUNA_METHOD_GETPROFILELIST,   handle_get_profilelist_command },
	{ LUNA_METHOD_GETPROFILE,       handle_get_profile_command },
	{ LUNA_METHOD_SETSTATE,     handle_set_state_command },
	{ LUNA_METHOD_CONNECT,      handle_connect_command },
	{ LUNA_METHOD_CANCEL,       handle_cancel_command },
	{ LUNA_METHOD_FINDNETWORKS,     handle_findnetworks_command },
	{ LUNA_METHOD_SCAN,         handle_scan_command },
	{ LUNA_METHOD_GETNETWORKS,      handle_get_networks_command },
	{ LUNA_METHOD_CHANGENETWORK,    handle_change_network_command },
	{ LUNA_METHOD_DELETEPROFILE,    handle_delete_profile_command },
	{ LUNA_METHOD_GETSTATUS,        handle_get_status_command },
	{ LUNA_METHOD_CREATEWPSPIN,         handle_create_wpspin_command },
	{ LUNA_METHOD_STARTWPS,     handle_start_wps_command },
	{ LUNA_METHOD_CANCELWPS,        handle_cancel_wps_command },
	{ LUNA_METHOD_SET_MCHANNSCHED_MODE, handle_set_multichannel_sched_mode_command },
	{ LUNA_METHOD_GET_MCHANNSCHED_MODE, handle_get_multichannel_sched_mode_command },
	{ LUNA_METHOD_GET_WIFI_DIAGNOSTICS, handle_get_wifi_diagnostics_command },
	{ LUNA_METHOD_SET_PASSTHROUGH_PARAMS, handle_set_passthrough_params_command },
	{ },
};

/**
 *  @brief Initialize com.webos.service.wifi service and all of its methods
 *  Also initialize a manager instance
 */

int initialize_wifi_ls2_calls(GMainLoop *mainloop , LSHandle **wifi_handle)
{
	LSError lserror;
	LSErrorInit(&lserror);
	pLsHandle       = NULL;

	if (NULL == mainloop)
	{
		goto Exit;
	}

	if (LSRegister(WIFI_LUNA_SERVICE_NAME, &pLsHandle, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_WIFI_LUNA_BUS_ERROR, lserror.message);
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, LUNA_CATEGORY_ROOT, wifi_methods, NULL, NULL,
	                       &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_WIFI_METHODS_LUNA_ERROR, lserror.message);
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_WIFI_GLOOP_ATTACH_ERROR, lserror.message);
		goto Exit;
	}

	if (LSSubscriptionSetCancelFunction(pLsHandle, handle_luna_subscription_cancel, NULL, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_WIFI_SUBSCRIPTIONCANCEL_LUNA_ERROR, lserror.message);
		goto Exit;
	}

	g_type_init();

	g_bus_watch_name(G_BUS_TYPE_SYSTEM, "net.connman",
	                 G_BUS_NAME_WATCHER_FLAGS_NONE, connman_service_started, connman_service_stopped,
	                 NULL, NULL);

	retrieve_system_locale_info(pLsHandle);

	init_wifi_profile_list();

	*wifi_handle = pLsHandle;

	return 0;

Exit:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	if (pLsHandle)
	{
		LSErrorInit(&lserror);

		if (LSUnregister(pLsHandle, &lserror) == false)
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	return -1;
}
