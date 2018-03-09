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
 * @file  common.c
 *
 * @brief Implements some of the common utility functions
 */

#include <glib.h>
#include <arpa/inet.h>

#include "common.h"
#include "logging.h"
#include "errors.h"
#include "wifi_service.h"
#include "lunaservice_utils.h"

static gchar *current_system_locale = NULL;

/**
 *  @brief Check if the connman manager is available and if network access is allowed and
 *  send an error message to the supplied luna message handle if one of both checks
 *  returns FALSE.
 *
 *  @param manager Connman manager object
 *  @param sh Luna service bus handle
 *  @param message Luna message handle
 *
 *  @return TRUE if the connman manager is not available or network access is not allowed.
 *  FALSE otherwise.
 */

gboolean connman_status_check(connman_manager_t *manager, LSHandle *sh,
                              LSMessage *message)
{
	if (!connman_manager_is_manager_available(manager))
	{
		LSMessageReplyCustomError(sh, message, "Connman service unavailable",
		                          WCA_API_ERROR_CONNMAN_UNAVAILABLE);
		return FALSE;
	}

	return TRUE;
}

gboolean connman_status_check_with_subscription(connman_manager_t *manager,
        LSHandle *sh, LSMessage *message, bool subscribed)
{
	if (!connman_manager_is_manager_available(manager))
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message,
		        "Connman service unavailable",
		        WCA_API_ERROR_CONNMAN_UNAVAILABLE, subscribed);
		return FALSE;
	}

	return TRUE;
}
/**
 *  @brief Check wether the wifi technology is powered (the "Powered" property has the
 *  value true).
 *
 *  @return Returns true if wifi technology is powered on
 */

gboolean is_wifi_powered(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);
	return (NULL != technology) && technology->powered;
}

/**
 *  @brief Check wether the wifi technology is currently tethering (the "Tethering"
 *         property has the value true)
 *
 * @return Returns true if wifi technology is currently tethering, false otherwise.
 */
gboolean is_wifi_tethering(void)
{
	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);
	return (NULL != technology) && technology->tethering;
}

/**
 *  @brief Check if the wifi technology is available. If the technology is not available
 *  an error message is send to the supplied luna message handle.
 *
 *  @param sh Luna śervice handle
 *  @param message Luna message handle
 *  @return TRUE if wifi technology is available, FALSE otherwise.
 */

gboolean wifi_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if (NULL == connman_manager_find_wifi_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "WiFi technology unavailable",
		                          WCA_API_ERROR_WIFI_TECH_UNAVAILABLE);
		return FALSE;
	}

	return TRUE;
}

gboolean wifi_technology_status_check_with_subscription(LSHandle *sh,
        LSMessage *message, bool subscribed)
{
	if (NULL == connman_manager_find_wifi_technology(manager))
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message,
		        "WiFi technology unavailable",
		        WCA_API_ERROR_WIFI_TECH_UNAVAILABLE, subscribed);
		return FALSE;
	}

	return TRUE;
}
/**
 * @brief Set the wifi power status according to wether network access is allowed or not
 */

gboolean set_wifi_powered_status(gboolean state)
{
	connman_technology_t *wifi_tech = connman_manager_find_wifi_technology(manager);

	if (wifi_tech)
	{
		if (connman_technology_set_powered(wifi_tech, state, NULL))
		{
			return TRUE;
		}
	}

	return FALSE;
}

void set_cellular_powered_status(gboolean state)
{
	connman_technology_t *cellular_tech = connman_manager_find_cellular_technology(
	        manager);

	if (!cellular_tech)
	{
		return;
	}

	connman_technology_set_powered(cellular_tech, state, NULL);
}

/**
*  @brief Returns true if wan technology is powered on
*
*/

gboolean is_cellular_powered(void)
{
	connman_technology_t *technology = connman_manager_find_cellular_technology(
	                                       manager);
	return (NULL != technology) && technology->powered;
}

/**
*  @brief Check if the wan technology is available
*   Send an error luna message if its not available
*
*  @param sh
*  @param message
*/

gboolean cellular_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if (NULL == connman_manager_find_cellular_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "Cellular technology unavailable",
		                          WCA_API_ERROR_CELLULAR_TECH_UNAVAILABLE);
		return FALSE;
	}

	return TRUE;
}

gboolean cellular_technology_status_check_with_subscription(LSHandle *sh,
        LSMessage *message, bool subscribed)
{
	if (NULL == connman_manager_find_cellular_technology(manager))
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message,
		        "Cellular technology unavailable",
		        WCA_API_ERROR_CELLULAR_TECH_UNAVAILABLE, subscribed);
		return FALSE;
	}

	return TRUE;
}

bool is_valid_ipv6address(char *ipAddress)
{
	unsigned char ipv6_addr[sizeof(struct in6_addr)];
	int result = 0;

	if (strstr(ipAddress, ":") != NULL)
	{
		result = inet_pton(AF_INET6, ipAddress, &ipv6_addr);
	}

	return result != 0;
}

bool is_valid_ipaddress(char *ipAddress)
{
	struct sockaddr_in sa;
	int result;

	if (is_valid_ipv6address(ipAddress))
	{
		result = TRUE;
	}
	else
	{
		result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
	}

	return result != 0;
}

/**
 * @brief Handle a response of a call to com.webos.settingsservice/getSystemSettings for
 * the current system UI locale.
 *
 * @param sh Luna service handle
 * @param message Luna message handle
 * @param ctx User context data
 *
 * @return TRUE if response handling was successfull. Otherwise FALSE.
 */

static bool locale_status_cb(LSHandle *sh, LSMessage *message, void *ctx)
{
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

	jvalue_ref settingsObj = {0}, localeInfoObj = {0}, localesObj = {0}, UIObj = {0};

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("settings"), &settingsObj))
	{
		if (jobject_get_exists(settingsObj, J_CSTR_TO_BUF("localeInfo"),
		                       &localeInfoObj))
		{
			if (jobject_get_exists(localeInfoObj, J_CSTR_TO_BUF("locales"), &localesObj))
			{
				if (jobject_get_exists(localesObj, J_CSTR_TO_BUF("UI"), &UIObj))
				{
					g_free(current_system_locale);
					raw_buffer address_buf = jstring_get(UIObj);
					current_system_locale = g_strdup(address_buf.m_str);
					jstring_free_buffer(address_buf);

					WCALOG_DEBUG("Received system locale '%s'", current_system_locale);

					wifi_service_local_has_changed();
				}
			}
		}
	}

	j_release(&parsedObj);

	return true;
}

/**
 * @brief Retrieve the currently configured system UI locale from the settings service
 */

void retrieve_system_locale_info(LSHandle *handle)
{
	if (!LSCall(handle, "palm://com.webos.settingsservice/getSystemSettings",
	       "{\"keys\":[\"localeInfo\"],\"subscribe\":true}", locale_status_cb, NULL, NULL,
	       NULL))
		WCALOG_DEBUG("Failed to get system locale information from com.webos.settingsservice");
}

const gchar *get_current_system_locale()
{
	return current_system_locale;
}

gboolean ethernet_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if (NULL == connman_manager_find_ethernet_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "Ethernet technology unavailable",
		                          WCA_API_ERROR_ETHERNET_TECHNOLOGY_UNAVAILABLE);
		return FALSE;
	}

	return TRUE;
}

gboolean is_ethernet_tethering(void)
{
	connman_technology_t *technology = connman_manager_find_ethernet_technology(
	                                       manager);
	return (NULL != technology) && technology->tethering;
}

/**
 *  @brief Check wether the bluetooth technology is powered (the "Powered" property has the
 *  value true).
 *
 *  @return Returns true if bluetooth technology is powered on
 */

gboolean is_bluetooth_powered(void)
{
	connman_technology_t *technology = connman_manager_find_bluetooth_technology(
	                                       manager);
	return (NULL != technology) && technology->powered;
}

/**
 *  @brief Check wether the bluetooth technology is currently tethering (the "Tethering"
 *         property has the value true)
 *
 * @return Returns true if bluetooth technology is currently tethering, false otherwise.
 */
gboolean is_bluetooth_tethering(void)
{
	connman_technology_t *technology = connman_manager_find_bluetooth_technology(
	                                       manager);
	return (NULL != technology) && technology->tethering;
}

/**
 *  @brief Check if the bluetooth technology is available. If the technology is not available
 *  an error message is send to the supplied luna message handle.
 *
 *  @param sh Luna śervice handle
 *  @param message Luna message handle
 *  @return TRUE if bluetooth technology is available, FALSE otherwise.
 */

gboolean bluetooth_technology_status_check(LSHandle *sh, LSMessage *message)
{
	if (NULL == connman_manager_find_bluetooth_technology(manager))
	{
		LSMessageReplyCustomError(sh, message, "Bluetooth technology unavailable",
		                          WCA_API_ERROR_BLUETOOTH_TECHNOLOGY_UNAVAILABLE);
		return FALSE;
	}

	return TRUE;
}

gboolean bluetooth_technology_status_check_with_subscription(LSHandle *sh,
        LSMessage *message, bool subscribed)
{
	if (NULL == connman_manager_find_bluetooth_technology(manager))
	{
		LSMessageReplyCustomErrorWithSubscription(sh, message,
		        "Bluetooth technology unavailable",
		        WCA_API_ERROR_BLUETOOTH_TECHNOLOGY_UNAVAILABLE, subscribed);
		return FALSE;
	}

	return TRUE;
}
