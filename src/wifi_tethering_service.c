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
 * @file  wifi_tethering_service.c
 *
 * @brief Implements the com.webos.service.wifi/tethering service API with using connman in the backend.
 */

/**
 *  @brief Initialize com.webos.service.wifi/p2p service and all of its methods
 */

#include <glib.h>
#include <stdbool.h>
#include <string.h>

#include <wca-support.h>

#include "wifi_tethering_service.h"
#include "wifi_service.h"
#include "connman_manager.h"
#include "lunaservice_utils.h"
#include "connman_common.h"
#include "common.h"
#include "logging.h"
#include "errors.h"

#define WIFI_STATUS_TIMEOUT     1
#define WIFI_TETHERING_USED_RX_BYTES_TRESHOLD(x)        5000*x

LSHandle *tetheringpLSHandle = NULL;

static gboolean previous_wifi_legacy_powered = FALSE;

static guint wifi_tethering_timeout = 5;
static guint wifi_tethering_timeout_source = 0;
static guint wifi_tethering_client_count = 0;

void start_tethering_timeout(void);

static void support_tethering_disabled_cb(bool success, void *user_data)
{
	LSMessage *message = user_data;
	LSHandle *handle = 0;

	if (message)
	{
		handle = LSMessageGetConnection(message);
	}

	if (!success)
	{
		if (message)
			LSMessageReplyCustomError(handle, message,
			                          "Failed to disable tethering mode through support library",
			                          WCA_API_ERROR_TETHERING_SUPPORT_FAILED);

		return;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (!wifi_tech)
	{
		if (message)
			LSMessageReplyCustomError(handle, message, "WiFi technology unavailable",
			                          WCA_API_ERROR_WIFI_TECH_UNAVAILABLE);

		return;
	}

	if (!connman_technology_set_tethering(wifi_tech, FALSE))
	{
		if (message)
			LSMessageReplyCustomError(handle, message, "Failed to disable tethering mode",
			                          WCA_API_ERROR_TETHERING_DISABLE_FAILED);

		return;
	}


	if (!previous_wifi_legacy_powered &&
	        !connman_technology_set_powered(wifi_tech, FALSE, NULL))
	{
		if (message)
			LSMessageReplyCustomError(handle, message,
			                          "Failed to restore WiFi state after disbling tethering",
			                          WCA_API_ERROR_TETHERING_RESTORE_WIFI_STATE_FAILED);

		return;
	}

	LSMessageReplySuccess(handle, message);
}

static void support_tethering_disabled_after_failure_cb(bool success,
        void *user_data)
{
	(void) success;

	LSMessage *message = user_data;

	if (!message)
	{
		return;
	}

	LSHandle *handle = LSMessageGetConnection(message);

	LSMessageReplyCustomError(handle, message, "Failed to enable tethering mode",
	                          WCA_API_ERROR_TETHERING_ENABLE_FAILED);
}

static void support_tethering_enabled_cb(bool success, void *user_data)
{
	LSMessage *message = user_data;
	LSHandle *handle = 0;

	if (message)
	{
		handle = LSMessageGetConnection(message);
	}

	if (!success)
	{
		if (message)
			LSMessageReplyCustomError(handle, message,
			                          "Failed to enable tethering mode through support library",
			                          WCA_API_ERROR_TETHERING_SUPPORT_FAILED);

		return;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (!wifi_tech)
	{
		if (message)
			LSMessageReplyCustomError(handle, message, "WiFi technology unavailable",
			                          WCA_API_ERROR_WIFI_TECH_UNAVAILABLE);

		return;
	}

	if (!connman_technology_set_tethering(wifi_tech, TRUE))
	{
		/* disable tethering support again */
		wca_support_wifi_disable_tethering(support_tethering_disabled_after_failure_cb,
		                                   message);
		return;
	}

	wifi_tethering_client_count = 0;
	start_tethering_timeout();

	if (message)
	{
		LSMessageReplySuccess(handle, message);
	}
}

/**
 *  @brief Sets the wifi technologies tethering state
 *
 *  @param state
 */

gboolean set_wifi_tethering(bool state, LSMessage *message)
{
	if (state == is_wifi_tethering())
	{
		return false;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (!is_wifi_powered() && state)
	{
		previous_wifi_legacy_powered = FALSE;

		// we need to have WiFI powered otherwise we can't start tethering
		connman_technology_set_powered(wifi_tech, TRUE, NULL);

		// FIXME this should go away once we switch to asynchronous variant of
		// connman_technology_set_powered method
		g_usleep(2000000);
	}
	else if (is_wifi_powered() && state)
	{
		previous_wifi_legacy_powered = TRUE;
	}

	if (state)
	{
		connman_service_t *connected_service = connman_manager_get_connected_service(
		        manager->wifi_services);

		if (connected_service)
		{
			connman_service_disconnect(connected_service);
		}

		wca_support_wifi_enable_tethering(support_tethering_enabled_cb, message);
	}
	else
	{
		wca_support_wifi_disable_tethering(support_tethering_disabled_cb, message);
	}

	return TRUE;
}

static void send_tethering_state(jvalue_ref *reply)
{
	if (NULL == reply)
	{
		return;
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("enabled"),
	            jboolean_create(is_wifi_tethering()));

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (NULL != wifi_tech->tethering_identifier)
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("ssid"),
		            jstring_create(wifi_tech->tethering_identifier));
	}

	if (NULL != wifi_tech->tethering_identifier)
	{
		jobject_put(*reply, J_CSTR_TO_JVAL("securityType"),
		            jstring_create((NULL != wifi_tech->tethering_passphrase)
		                           && (strlen(wifi_tech->tethering_passphrase) != 0) ? "psk" : "open"));
	}

	jobject_put(*reply, J_CSTR_TO_JVAL("timeout"),
	            jnumber_create_i32(wifi_tethering_timeout));
}

void send_tethering_state_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));

	send_tethering_state(&reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		WCALOG_DEBUG("Sending payload : %s", payload);
		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(tetheringpLSHandle, "/tethering/getState",
		                        payload,
		                        &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);

}

static void send_sta_count(jvalue_ref *reply)
{
	if(NULL == reply)
		return;

	unsigned int sta_count = connman_manager_get_sta_count(manager);
	jobject_put(*reply, J_CSTR_TO_JVAL("stationCount"), jnumber_create_i32(sta_count));
}

void send_sta_count_to_subscribers(void)
{
	jvalue_ref reply = jobject_create();
	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));

	send_sta_count(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);
		WCALOG_DEBUG("Sending payload : %s",payload);
		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(tetheringpLSHandle, "/tethering/getStationCount", payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
}

static gboolean tethering_timeout_cb(gpointer user_data)
{
	WCALOG_DEBUG("WiFi tethering timeout occured. Disable tethering.");

	set_wifi_tethering(FALSE, 0);

	wifi_tethering_timeout_source = 0;

	return FALSE;
}

static void sta_authorized_cb(gpointer user_data)
{
	wifi_tethering_client_count++;

	// If timer is no longer active we don't have anything to do here
	if (wifi_tethering_timeout_source == 0)
	{
		return;
	}

	WCALOG_DEBUG("Got new WiFi tethering client");

	// Now that we have a client connected to our AP we can stop
	// the timeout.
	if (wifi_tethering_timeout_source != 0)
	{
		WCALOG_DEBUG("Abort running tethering timer");
		g_source_remove(wifi_tethering_timeout_source);
		wifi_tethering_timeout_source = 0;
	}
}

static void sta_deauthorized_cb(gpointer user_data)
{
	wifi_tethering_client_count--;

	WCALOG_DEBUG("WiFi tethering client disconnected");

	if (wifi_tethering_client_count > 0)
	{
		WCALOG_DEBUG("Not restarting timeout as we have %d clients left",
		             wifi_tethering_client_count);
		return;
	}

	start_tethering_timeout();
}

void start_tethering_timeout(void)
{
	if (wifi_tethering_timeout == 0 || wifi_tethering_timeout_source != 0)
	{
		return;
	}

	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	WCALOG_DEBUG("Setting WiFi tethering timeout to %d minutes",
	             wifi_tethering_timeout);

	// Make sure our handler gets registered with the WiFi technology
	// to get known when a new STA connects
	connman_technology_register_sta_authorized_cb(wifi_tech, sta_authorized_cb,
	        NULL);
	connman_technology_register_sta_deauthorized_cb(wifi_tech, sta_deauthorized_cb,
	        NULL);

	wifi_tethering_timeout_source = g_timeout_add_seconds(wifi_tethering_timeout *
	                                60,
	                                tethering_timeout_cb, NULL);
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_service_wifi com.webos.service.wifi/tethering/setState
@{
@section com_webos_service_wifi_tethering_setstate setState

Set tethering state.

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
enabled | No | boolean | enable / disable tethering
ssid | No | String | The tethering broadcasted identifier
passPhrase | No | String | The tethering connection passphrase

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

static bool handle_set_state_command(LSHandle *sh, LSMessage *message,
                                     void *context)
{
	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsedObj = {0};
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_5(PROP(enabled, boolean),
	                                     PROP(ssid, string), PROP(passPhrase, string), PROP(securityType, string),
	                                     PROP(timeout, integer)))), &parsedObj))
	{
		return true;
	}

	jvalue_ref enabledObj = {0}, ssidObj = {0}, passPhraseObj = {0}, securityTypeObj
	                                       = {0}, timeoutObj = {0};
	gboolean enable_tethering = FALSE, invalidArg = TRUE;
	gchar *ssid = NULL, *passphrase = NULL;
	int timeout = 0;
	gboolean is_open = FALSE;
	gboolean state_set = FALSE;

	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!wifi_technology_status_check(sh, message))
	{
		return true;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("ssid"), &ssidObj))
	{
		if (is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message,
			                          "Not allowed to change SSID while tethering is enabled",
			                          WCA_API_ERROR_TETHERING_SSID_FAILED);
			goto cleanup;
		}

		raw_buffer ssid_buf = jstring_get(ssidObj);
		ssid = g_strdup(ssid_buf.m_str);
		jstring_free_buffer(ssid_buf);

		if (NULL == ssid)
		{
			goto invalid_params;
		}

		invalidArg = FALSE;

		if (!connman_technology_set_tethering_identifier(
		            connman_manager_find_wifi_technology(manager), ssid))
		{
			LSMessageReplyCustomError(sh, message, "Error in setting tethering SSID",
			                          WCA_API_ERROR_TETHERING_SSID_FAILED);
			goto cleanup;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("securityType"),
	                       &securityTypeObj))
	{
		if (is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message,
			                          "Not allowed to change securityType while tethering is enabled",
			                          WCA_API_ERROR_TETHERING_NOT_ALLOWED_TO_CHANGE_SEC_TYPE);
			goto cleanup;
		}

		if (jstring_equal2(securityTypeObj, J_CSTR_TO_BUF("open")))
		{
			is_open = TRUE;
		}
		else if (jstring_equal2(securityTypeObj, J_CSTR_TO_BUF("psk")))
		{
			is_open = FALSE;
		}
		else
		{
			goto invalid_params;
		}

		if (is_open &&
		        !connman_technology_set_tethering_passphrase(
		            connman_manager_find_wifi_technology(manager), ""))
		{
			LSMessageReplyCustomError(sh, message, "Error in setting tethering passphrase",
			                          WCA_API_ERROR_TETHERING_PASSPHRASE_FAILED);
			goto cleanup;
		}

		invalidArg = FALSE;
	}

	if (!is_open &&
	        jobject_get_exists(parsedObj, J_CSTR_TO_BUF("passPhrase"), &passPhraseObj))
	{
		if (is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message,
			                          "Not allowed to change passphrase while tethering is enabled",
			                          WCA_API_ERROR_TETHERING_PASSPHRASE_FAILED);
			goto cleanup;
		}

		raw_buffer passphrase_buf = jstring_get(passPhraseObj);
		passphrase = g_strdup(passphrase_buf.m_str);
		jstring_free_buffer(passphrase_buf);

		if (NULL == passphrase)
		{
			goto invalid_params;
		}

		if (!is_open && (!passphrase || strlen(passphrase) == 0))
		{
			LSMessageReplyCustomError(sh, message,
			                          "No passphrase set but required for security type psk",
			                          WCA_API_ERROR_TETHERING_NO_PASSPHRASE);
			goto cleanup;
		}

		int passphrase_length = strlen(passphrase);

		if (!is_open && (passphrase_length < 8 || passphrase_length > 63))
		{
			LSMessageReplyCustomError(sh, message,
			                          "Passphrase doesn't match the requirements",
			                          WCA_API_ERROR_TETHERING_PASSPHRASE_INVALID);
			goto cleanup;
		}

		if (is_open && passphrase != NULL && strlen(passphrase) > 0)
		{
			LSMessageReplyCustomError(sh, message,
			                          "With security typen open specifying a passphrase is not possible",
			                          WCA_API_ERROR_TETHERING_PASSPHRASE_WITH_OPEN_FAILED);
			goto cleanup;
		}

		invalidArg = FALSE;

		if (!is_open &&
		        !connman_technology_set_tethering_passphrase(
		            connman_manager_find_wifi_technology(manager), passphrase))
		{
			LSMessageReplyCustomError(sh, message, "Error in setting tethering passphrase",
			                          WCA_API_ERROR_TETHERING_PASSPHRASE_FAILED);
			goto cleanup;
		}
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("timeout"), &timeoutObj))
	{
		if (is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message,
			                          "Not allowed to change timeout while tethering is enabled",
			                          WCA_API_ERROR_TETHERING_NOT_ALLOWED_TO_CHANGE_TIMEOUT);
			goto cleanup;
		}

		jnumber_get_i32(timeoutObj, &timeout);

		if (timeout < 0)
		{
			LSMessageReplyCustomError(sh, message,
			                          "Negative values are not allowed for the timeout",
			                          WCA_API_ERROR_TETHERING_TIMEOUT_NO_NEGATIVE_VALUES);
			goto cleanup;
		}

		wifi_tethering_timeout = timeout;

		invalidArg = FALSE;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("enabled"), &enabledObj))
	{
		jboolean_get(enabledObj, &enable_tethering);

		if (enable_tethering && is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Already Enabled",
			                          WCA_API_ERROR_ALREADY_ENABLED);
			goto cleanup;
		}
		else if (!enable_tethering && !is_wifi_tethering())
		{
			LSMessageReplyCustomError(sh, message, "Already Disabled",
			                          WCA_API_ERROR_ALREADY_DISABLED);
			goto cleanup;
		}

		state_set = TRUE;
		invalidArg = FALSE;
	}

	if (invalidArg == TRUE)
	{
		goto invalid_params;
	}

	if (state_set && !set_wifi_tethering(enable_tethering, message))
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

	goto cleanup;

invalid_params:
	LSMessageReplyErrorInvalidParams(sh, message);

cleanup:
	g_free(ssid);
	g_free(passphrase);
	j_release(&parsedObj);
	return true;
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_wifi com.webos.wifi/gettethering
@{
@page com_webos_service_wifi com.webos.service.wifi/tethering/getState
@{
@section com_webos_service_wifi_tethering_getstate getState

Get current tethering state.

@par Parameters
subscribe | No | boolean | Subscribe for updates

@par Returns(Call) for all forms

Name | Required | Type | Description
-----|--------|------|----------
state | No | boolean | enable / disable tethering
ssid | No | String | The tethering broadcasted identifier
passPhrase | No | String |  The tethering connection passphrase
securityType | No | String |  The tethering securityType
returnValue | Yes | Boolean | True, if call was successful. False otherwise.
errorText | No | String | Error text when call was not successful.
errorCode | No | Integer | Error code when call was not successful.

@par Returns(Subscription)
subscribed | No | Boolean | True when successfully subscribed. False when unsubscribed or subscription was not possible.

Not applicable.

@}
*/
/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////

static bool handle_get_state_command(LSHandle *sh, LSMessage *message,
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

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	send_tethering_state(&reply);

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

static bool handle_get_station_count_command(LSHandle *sh, LSMessage *message, void* context)
{
	jvalue_ref reply = jobject_create();
	LSError lserror;
	LSErrorInit(&lserror);
	bool subscribed = false;

	jvalue_ref parsedObj = {0};
	if(!LSMessageValidateSchema(sh, message, j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
		j_release(&reply);
		return true;
	}

	if (LSMessageIsSubscription(message))
	{
		if (!LSSubscriptionProcess(sh, message, &subscribed, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	if(!connman_status_check_with_subscription(manager, sh, message, subscribed))
		goto cleanup;

	if(!wifi_technology_status_check_with_subscription(sh, message, subscribed))
		goto cleanup;

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	send_sta_count(&reply);

	jschema_ref response_schema = jschema_parse (j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if(!response_schema)
	{
		LSMessageReplyErrorUnknown(sh,message);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply, response_schema), &lserror))
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

/**
 * com.webos.service.wifi/tethering service Luna Method Table
 */

static LSMethod wifi_tethering_methods[] =
{
	{ LUNA_METHOD_TETHERING_SETSTATE,              handle_set_state_command },
	{ LUNA_METHOD_TETHERING_GETSTATE,              handle_get_state_command },
	{ LUNA_METHOD_TETHERING_GETSTACOUNT,           handle_get_station_count_command },
	{},
};

int initialize_wifi_tethering_ls2_calls(GMainLoop *mainloop,
                                        LSHandle *pLsHandle)
{
	LSError lserror;
	LSErrorInit(&lserror);

	if (NULL == mainloop)
	{
		goto Exit;
	}

	tetheringpLSHandle = pLsHandle;

	if (LSRegisterCategory(pLsHandle, LUNA_CATEGORY_TETHERING,
	                       wifi_tethering_methods, NULL,
	                       NULL, &lserror) == false)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_TETHERING_METHODS_LUNA_ERROR, lserror.message);
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
