// Copyright (c) 2014-2018 LG Electronics, Inc.
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
 * @file  pan_service.c
 *
 * @brief Implements all of com.webos.service.pan service methods using connman APIs
 * in the backend.
 */

#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <pbnjson.h>

#include "pan_service.h"
#include "connman_manager.h"
#include "lunaservice_utils.h"
#include "connman_common.h"
#include "connman_service.h"
#include "common.h"
#include "logging.h"
#include "utils.h"
#include "errors.h"
#include "connectionmanager_service.h"

//#define NAP_WITHOUT_COLON_ADDRESS_LENGTH 12
#define PAN_MAC_ADDRESS_LENGTH 17

static LSHandle *pLsHandle;

luna_service_request_t *current_connect_req;

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

	connman_technology_t *bluetooth_technology =
	    connman_manager_find_bluetooth_technology(manager);

	if (technology != bluetooth_technology)
	{
		return;
	}

	if (g_strcmp0(property, "Powered") == 0 ||
	        g_strcmp0(property, "Connected") == 0)
	{
		connectionmanager_send_status_to_subscribers();
		send_pan_connection_status_to_subscribers();
	}
	else if (g_strcmp0(property, "Tethering") == 0)
	{
		send_pan_connection_status_to_subscribers();
		connectionmanager_send_status_to_subscribers();
	}
}

/**
 *  @brief Callback function registered with connected bluetooth service whenever any of its properties change
 *
 *
 *  @param data
 *  @param property
 *  @param value
 */

static void service_changed_cb(gpointer user_data, const gchar *name,
                               GVariant *value)
{
	connectionmanager_send_status_to_subscribers();
}

/**
 *  @brief Add details about the connected service
 *
 *  @param reply
 *  @param connected_service
 *
 */

/**
 *  @brief Sets the bluetooth technologies tethering state
 *
 *  @param state
 */

static gboolean set_bluetooth_tethering(bool state)
{
	if (state == is_bluetooth_tethering())
	{
		return FALSE;
	}

	connman_technology_t *bluetooth_tech =
	    connman_manager_find_bluetooth_technology(manager);

	if (!bluetooth_tech)
	{
		return FALSE;
	}

	if (!is_bluetooth_powered() && state)
	{
		// we need to have Bluetooth powered otherwise we can't start tethering
		connman_technology_set_powered(bluetooth_tech, TRUE, NULL);

		// FIXME this should go away once we switch to asynchronous variant of
		// connman_technology_set_powered method
		g_usleep(2000000);
	}

	if (state)
	{
		connman_service_t *connected_service = connman_manager_get_connected_service(
		        manager->bluetooth_services);

		if (connected_service)
		{
			connman_service_disconnect(connected_service);
		}
	}

	return connman_technology_set_tethering(bluetooth_tech, state);
}

static void add_connected_network_status(jvalue_ref *reply,
        connman_service_t *connected_service)
{
	if (NULL == reply || NULL == connected_service)
	{
		return;
	}

	int connman_state = 0;
	jobject_put(*reply, J_CSTR_TO_JVAL("status"),
	            jstring_create("connectionStateChanged"));

	jvalue_ref network_info = jobject_create();

	/* Fill in details about the service NAP*/
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

	if (connected_service->address != NULL)
	{
		jobject_put(network_info, J_CSTR_TO_JVAL("address"),
		            jstring_create(connected_service->address));
	}

	if (connected_service->state != NULL)
	{
		connman_state = connman_service_get_state(connected_service->state);
	}

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

		jobject_put(network_info, J_CSTR_TO_JVAL("ipInfo"), ip_info);
	}

	jobject_put(*reply,  J_CSTR_TO_JVAL("networkInfo"), network_info);

}

/**
 * @brief Fill in information about the NAP
 *
 * @param status json status object to fill with the service status
 */

void append_nap_info(jvalue_ref *status)
{
	if (NULL == status)
	{
		return;
	}

	connman_service_t *connected_service = connman_manager_get_connected_service(
	        manager->bluetooth_services);

	if (NULL == connected_service)
	{
		return;
	}

	jvalue_ref nap_info = jobject_create();

	if (connected_service->address != NULL)
	{
		jobject_put(nap_info, J_CSTR_TO_JVAL("address"),
		            jstring_create(connected_service->address));
	}

	/* Fill in details about the service NAP*/
	if (connected_service->display_name != NULL)
	{
		jobject_put(nap_info, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(connected_service->display_name));
	}
	else
	{
		jobject_put(nap_info, J_CSTR_TO_JVAL("displayName"),
		            jstring_create(connected_service->name));
	}

	jobject_put(*status, J_CSTR_TO_JVAL("nap"), nap_info);
}

/**
 * @brief Fill in all status information to be sent with 'getStatus' method
 */

static void append_pan_status(jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("tetheringEnabled"),
	            jboolean_create(is_bluetooth_tethering()));

	gboolean powered = is_bluetooth_powered();

	jobject_put(*reply, J_CSTR_TO_JVAL("status"),
	            jstring_create(powered ? "serviceEnabled" : "serviceDisabled"));

	/* Get the service which is connecting or already in connected state */
	connman_service_t *connected_service = connman_manager_get_connected_service(
	        manager->bluetooth_services);

	if (connected_service != NULL)
	{
		add_connected_network_status(reply, connected_service);
	}
}

void send_pan_connection_status_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	append_pan_status(&reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		WCALOG_DEBUG("Sending payload : %s", payload);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_PAN_GETSTATUS, payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
}

static gboolean compare_address(char *first, char *second)
{
	gboolean ret;
	char *first_address, *second_address;

	first_address = g_ascii_strup(first, PAN_MAC_ADDRESS_LENGTH);
	second_address = g_ascii_strup(second, PAN_MAC_ADDRESS_LENGTH);

	if (!g_strcmp0(first_address, second_address))
	{
		ret = TRUE;
	}
	else
	{
		ret = FALSE;
	}

	g_free(first_address);
	g_free(second_address);

	return ret;
}

static void current_connect_req_free()
{
	luna_service_request_free(current_connect_req);
	current_connect_req = NULL;

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

	connman_service_t *service = current_connect_req->user_data;

	if (NULL == service || NULL == g_slist_find(manager->bluetooth_services, service))
	{
		goto reply;
	}

	if (NULL == service->path)
	{
		WCALOG_INFO(MSGID_PAN_SKIPPING_FETCH_PROPERTIES, 0,
		            "Skipping fetch properties");
		goto reply;
	}

	if (NULL == connman_manager_find_service_by_path(manager->bluetooth_services,
	        service->path))
	{
		WCALOG_INFO(MSGID_PAN_SERVICE_NOT_EXIST, 0, "Service %s doesn't exist",
		            service->name);
		goto reply;
	}

	GVariant *properties = connman_service_fetch_properties(service);

	if (NULL == properties)
	{
		goto reply;
	}

	connman_service_update_properties(service, properties);
	g_variant_unref(properties);

	if (g_strcmp0(service->error, "connect-failed") == 0)
	{
		error_message = "Could not establish a connection to NAP";
		error_code = WCA_API_ERROR_CONNECT_FAILED;
	}
	else if (g_strcmp0(service->error, "dhcp-failed") == 0)
	{
		error_message = "Could not retrieve a valid IP address by using DHCP";
		error_code = WCA_API_ERROR_DHCP_FAILED;
	}

reply:

	LSMessageReplyCustomError(current_connect_req->handle,
	                          current_connect_req->message,
	                          error_message, error_code);

	current_connect_req_free();
}

static void service_connect_callback(gboolean success, gpointer user_data)
{
	UNUSED(user_data);

	if (!current_connect_req)
	{
		// Something is wrong. It should have been there. There is no luna call to respond to. Log an error.
		WCALOG_ESCAPED_ERRMSG(MSGID_PAN_CONNECT_SERVICE_ERROR,
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

/**
 *  @brief Connect to a PAN server with the given target MAC adress
 *
 *  @param address the remote device address
 */

static void connect_pan_with_address(char *address,
                                     luna_service_request_t *service_req)
{
	GSList *nap;
	gboolean found_service = FALSE;
	connman_service_t *service = NULL;

	connman_technology_t *bluetooth_tech =
	    connman_manager_find_bluetooth_technology(manager);

	if (NULL == address || NULL == bluetooth_tech)
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

	for (nap = manager->bluetooth_services; NULL != nap ; nap = nap->next)
	{
		service = (connman_service_t *)(nap->data);

		/* Service's address or User input's address would be uppercase letters or lowercase letters.
		 * So, this converts these to uppercase letters to compare whether these are same or not. */
		if (compare_address(service->address, address))
		{
			found_service = TRUE;
			break;
		}
	}

	if (!found_service)
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Network not found", WCA_API_ERROR_NETWORK_NOT_FOUND);
		goto cleanup;
	}

	connman_service_t *connected_service = connman_manager_get_connected_service(
			manager->bluetooth_services);

	if (NULL != connected_service && (connected_service == service))
	{
		/* Already connected so connection was successful */
		LSMessageReplySuccess(service_req->handle, service_req->message);
		WCALOG_DEBUG("Already connected with network");
		goto cleanup;
	}

	service_req->user_data = service;
	current_connect_req = service_req;

	if (!connman_service_connect(service, service_connect_callback, service_req))
	{
		current_connect_req = NULL;
		LSMessageReplyErrorUnknown(service_req->handle, service_req->message);
		goto cleanup;
	}

	goto exit;

cleanup:
	luna_service_request_free(service_req);
exit:
	return;
}

//->Start of API documentation comment block
/**
@page com_webos_pan com.webos.pan
@{
@section com_webos_pan_connect

Connects to the remote Bluethooth device which is a NAP role.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
address | Yes | String | Address of discovered Bluetooth NAP device

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@}
*/
//->End of API documentation comment block
static bool handle_pan_connect_command(LSHandle *sh, LSMessage *message,
                                       void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!bluetooth_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_bluetooth_powered())
	{
		LSMessageReplyCustomError(sh, message, "Bluetooth switched off",
		                          WCA_API_ERROR_BLUETOOTH_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(address,
	                                     string)) REQUIRED_1(address))), &parsedObj))
	{
		return true;
	}

	jvalue_ref addressObj = {0};
	char *address;
	luna_service_request_t *service_req;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
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

	service_req = luna_service_request_new(sh, message);
	connect_pan_with_address(address, service_req);

	g_free(address);
cleanup:
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_pan com.webos.pan
@{
@section com_webos_pan_disconnect

Disconnects the remote Bluethooth device which is a NAP role.

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True

@}
*/
//->End of API documentation comment block
static bool handle_pan_disconnect_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!bluetooth_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_bluetooth_powered())
	{
		LSMessageReplyCustomError(sh, message, "Bluetooth switched off",
		                          WCA_API_ERROR_BLUETOOTH_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(address,
	                                     string)) REQUIRED_1(address))), &parsedObj))
	{
		return true;
	}

	jvalue_ref addressObj = {0};
	char *address;
	connman_service_t *connected_service;

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("address"), &addressObj))
	{
		raw_buffer address_buf = jstring_get(addressObj);
		address = g_strdup(address_buf.m_str);
		jstring_free_buffer(address_buf);
	}
	else
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto exit;
	}

	connected_service = connman_manager_get_connected_service(
	                        manager->bluetooth_services);

	if (!connected_service || !compare_address(connected_service->address, address))
	{
		LSMessageReplyCustomError(sh, message, "No service is connected",
		                          WCA_API_ERROR_NO_SERVICE_CONNECTED);
		goto cleanup;
	}

	if (!connman_service_disconnect(connected_service))
	{
		LSMessageReplyCustomError(sh, message,
		                          "Failed to disconnect the connected service",
		                          WCA_API_ERROR_DISCONNECT_FAILED);
		goto cleanup;
	}

	LSMessageReplySuccess(sh, message);

cleanup:
	g_free(address);
exit:
	j_release(&parsedObj);
	return true;
}

//->Start of API documentation comment block
/**
@page com_webos_pan com.webos.pan
@{
@section com_webos_pan_get_status

Gets the current status of pan connection on the system.

Callers can subscribe to this method to be notified of any changes
in the pan connection status.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
subscribe | No | Boolean | true to subscribe to this method

@par Returns(Call)

All optional fields are absent if PAN is not connected

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
networkInfo | No | Object | A single object describing the current connection
tetheringEnabled | Yes | Boolean | Indicates if PAN tethering is enabled or not

@par "networkInfo" Object

Name | Required | Type | Description
-----|--------|------|----------
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
static bool handle_pan_get_status_command(LSHandle *sh, LSMessage *message,
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

	if (!bluetooth_technology_status_check_with_subscription(sh, message,
	        subscribed))
	{
		goto cleanup;
	}

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	append_pan_status(&reply);

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

	if (!jis_null(parsedObj))
	{
		j_release(&parsedObj);
	}

	if (!jis_null(reply))
	{
		j_release(&reply);
	}

	return true;
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_service_pan com.webos.service.pan/setTethering
@{
@section com_webos_service_pan_setTethering setTethering

Set tethering state.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
enabled | Yes | boolean | enable / disable tethering

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
returnValue | Yes | Boolean | True, if call was successful. False otherwise.
errorText | No | String | Error text when call was not successful.
errorCode | No | Integer | Error code when call was not successful.

@par Returns(Subscription)
Not applicable.

@}
*/
/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////

static bool handle_pan_set_tethering_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(enabled,
	                                     boolean)) REQUIRED_1(enabled))), &parsedObj))
	{
		return true;
	}

	jvalue_ref enabledObj = {0};
	gboolean enable_tethering = FALSE;

	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!bluetooth_technology_status_check(sh, message))
	{
		return true;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("enabled"), &enabledObj))
	{
		jboolean_get(enabledObj, &enable_tethering);

		if (enable_tethering && is_bluetooth_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Already Enabled",
			                          WCA_API_ERROR_ALREADY_ENABLED);
			goto cleanup;
		}
		else if (!enable_tethering && !is_bluetooth_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Already Disabled",
			                          WCA_API_ERROR_ALREADY_DISABLED);
			goto cleanup;
		}
	}

	if (!set_bluetooth_tethering(enable_tethering))
	{
		if (enable_tethering)
		{
			LSMessageReplyCustomError(sh, message, "Failed to enable tethering mode",
			                          WCA_API_ERROR_TETHERING_ENABLE_FAILED);
		}
		else
		{
			LSMessageReplyCustomError(sh, message, "Failed to disable tethering mode",
			                          WCA_API_ERROR_TETHERING_DISABLE_FAILED);
		}

		goto cleanup;
	}
	else
	{
		LSMessageReplySuccess(sh, message);
	}


cleanup:
	j_release(&parsedObj);
	return true;
}

/**
 * com.webos.service.pan service Luna Method Table
 */

static LSMethod pan_methods[] =
{
	{ LUNA_METHOD_PAN_CONNECT,                 handle_pan_connect_command },
	{ LUNA_METHOD_PAN_DISCONNECT,              handle_pan_disconnect_command },
	{ LUNA_METHOD_PAN_GETSTATUS,               handle_pan_get_status_command },
	{ LUNA_METHOD_PAN_SETTETHERING,            handle_pan_set_tethering_command },
	{},
};

int initialize_pan_ls2_calls(GMainLoop *mainloop, LSHandle **pan_handle)
{
	LSError lserror;
	LSErrorInit(&lserror);
	pLsHandle = NULL;

	if (NULL == mainloop)
	{
		goto Exit;
	}

	if (LSRegister(PAN_LUNA_SERVICE_NAME, &pLsHandle, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_PAN_LUNA_BUS_ERROR, lserror.message);
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, LUNA_CATEGORY_ROOT, pan_methods, NULL, NULL,
	                       &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_PAN_METHODS_LUNA_ERROR, lserror.message);
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_PAN_GLOOP_ATTACH_ERROR, lserror.message);
		goto Exit;
	}

	*pan_handle = pLsHandle;

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

void check_and_initialize_bluetooth_technology(void)
{
	connman_technology_t *technology = connman_manager_find_bluetooth_technology(
	                                       manager);

	if (!technology)
	{
		return;
	}

	connman_technology_register_property_changed_cb(technology,
	        technology_property_changed_callback);

	/* Register property change callback for all connected bluetooth services */
	GSList *iter;

	for (iter = manager->bluetooth_services; iter != NULL; iter = iter->next)
	{
		connman_service_t *service = iter->data;

		if (!connman_service_is_connected(service))
		{
			continue;
		}

		connman_service_register_property_changed_cb(service, service_changed_cb);
	}
}
