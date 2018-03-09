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

#include "wan_service.h"
#include "connman_manager.h"
#include "connman_agent.h"
#include "connman_service.h"
#include "lunaservice_utils.h"
#include "common.h"
#include "connectionmanager_service.h"
#include "logging.h"
#include "errors.h"

static LSHandle *pLsHandle;

extern connman_manager_t *manager;
extern connman_agent_t *agent;

static void service_changed_cb(gpointer user_data, const gchar *name,
                               GVariant *value)
{
	connectionmanager_send_status_to_subscribers();
}

static void retrieve_wan_context(jvalue_ref context_obj,
                                 connman_service_t *service)
{
	jvalue_ref ipv4_obj, ipv6_obj, dns_obj, hosts_obj;
	int i;

	jobject_put(context_obj, J_CSTR_TO_JVAL("name"), jstring_create(service->name));
	jobject_put(context_obj, J_CSTR_TO_JVAL("connected"),
	            jboolean_create(connman_service_is_connected(service)));
	jobject_put(context_obj, J_CSTR_TO_JVAL("onInternet"),
	            jboolean_create(connman_service_is_online(service)));

	if (service->ipinfo.iface)
	{
		jobject_put(context_obj, J_CSTR_TO_JVAL("interface"),
		            jstring_create(service->ipinfo.iface));
	}

	ipv4_obj = jobject_create();

	if (service->ipinfo.ipv4.address)
	{
		jobject_put(ipv4_obj, J_CSTR_TO_JVAL("address"),
		            jstring_create(service->ipinfo.ipv4.address));
	}

	if (service->ipinfo.ipv4.netmask)
	{
		jobject_put(ipv4_obj, J_CSTR_TO_JVAL("subnet"),
		            jstring_create(service->ipinfo.ipv4.netmask));
	}

	if (service->ipinfo.ipv4.gateway)
	{
		jobject_put(ipv4_obj, J_CSTR_TO_JVAL("gateway"),
		            jstring_create(service->ipinfo.ipv4.gateway));
	}

	if (jobject_size(ipv4_obj) > 0)
	{
		jobject_put(context_obj, J_CSTR_TO_JVAL("ipv4"), ipv4_obj);
	}
	else
	{
		j_release(&ipv4_obj);
	}

	ipv6_obj = jobject_create();

	if (service->ipinfo.ipv6.address)
	{
		jobject_put(ipv6_obj, J_CSTR_TO_JVAL("address"),
		            jstring_create(service->ipinfo.ipv6.address));
	}

	if (service->ipinfo.ipv6.prefix_length > 0)
	{
		jobject_put(ipv6_obj, J_CSTR_TO_JVAL("prefixLength"),
		            jnumber_create_i32(service->ipinfo.ipv6.prefix_length));
	}

	if (service->ipinfo.ipv6.gateway)
	{
		jobject_put(ipv6_obj, J_CSTR_TO_JVAL("gateway"),
		            jstring_create(service->ipinfo.ipv6.gateway));
	}

	if (jobject_size(ipv6_obj) > 0)
	{
		jobject_put(context_obj, J_CSTR_TO_JVAL("ipv6"), ipv6_obj);
	}
	else
	{
		j_release(&ipv6_obj);
	}

	dns_obj = jarray_create(NULL);

	if (service->ipinfo.dns)
	{
		for (i = 0; i < g_strv_length(service->ipinfo.dns); i++)
		{
			jarray_append(dns_obj, jstring_create(service->ipinfo.dns[i]));
		}
	}

	jobject_put(context_obj, J_CSTR_TO_JVAL("dns"), dns_obj);

	hosts_obj = jarray_create(NULL);

	for (i = 0; i < g_strv_length(service->hostroutes); i++)
	{
		jarray_append(hosts_obj, jstring_create(service->hostroutes[i]));
	}

	jobject_put(context_obj, J_CSTR_TO_JVAL("hosts"), hosts_obj);

}
static void append_context(jvalue_ref contexts_obj, connman_service_t *service)
{
	if (!jis_array(contexts_obj))
	{
		return;
	}

	jvalue_ref context_obj = jobject_create();

	retrieve_wan_context(context_obj, service);

	jarray_append(contexts_obj, context_obj);
}

void append_wan_status(jvalue_ref reply_obj)
{
	GSList *iter;
	connman_service_t *service = NULL;
	bool connected = false;
	bool online = false;
	jvalue_ref connected_contexts_obj;

	if (!reply_obj)
	{
		return;
	}

	connected_contexts_obj = jarray_create(NULL);

	for (iter = manager->cellular_services; NULL != iter; iter = iter->next)
	{
		service = (connman_service_t *)(iter->data);

		if (!connman_service_is_connected(service))
		{
			continue;
		}

		connected = TRUE;

		if (connman_service_is_online(service))
		{
			online = true;
		}

		connman_service_get_ipinfo(service);

		append_context(connected_contexts_obj, service);
	}

	jobject_put(reply_obj, J_CSTR_TO_JVAL("onInternet"), jboolean_create(online));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("connected"), jboolean_create(connected));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("connectedContexts"),
	            connected_contexts_obj);
}

void send_wan_connection_status_to_subscribers()
{
	jvalue_ref reply = jobject_create();

	jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));

	append_wan_status(reply);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply, response_schema);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_WAN_GETSTATUS, payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply);
}

static void append_contexts(jvalue_ref reply_obj)
{
	connman_service_t *service;
	GSList *iter;

	jvalue_ref contexts_obj = jarray_create(NULL);

	for (iter = manager->cellular_services; NULL != iter; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;

		connman_service_get_ipinfo(service);

		append_context(contexts_obj, service);
	}

	jobject_put(reply_obj, J_CSTR_TO_JVAL("contexts"), contexts_obj);
}

void send_wan_contexts_update_to_subscribers()
{
	jvalue_ref reply_obj = jobject_create();

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));

	append_contexts(reply_obj);

	jschema_ref response_schema = jschema_parse(j_cstr_to_buffer("{}"),
	                              DOMOPT_NOOPT, NULL);

	if (response_schema)
	{
		const char *payload = jvalue_tostring(reply_obj, response_schema);

		LSError lserror;
		LSErrorInit(&lserror);

		if (!LSSubscriptionReply(pLsHandle, LUNA_CATEGORY_ROOT LUNA_METHOD_WAN_GETCONTEXTS, payload, &lserror))
		{
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&response_schema);
	}

	j_release(&reply_obj);
}

static void service_connect_callback(gboolean success, gpointer user_data)
{
	luna_service_request_t *service_req = user_data;
	connman_service_t *service = service_req->user_data;

	if (!success)
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Failed to connect cellular service", WCA_API_ERROR_FAILED_TO_CONNECT);
		goto cleanup;
	}

	LSMessageReplySuccess(service_req->handle, service_req->message);

	connman_service_register_property_changed_cb(service, service_changed_cb);

cleanup:
	luna_service_request_free(service_req);
}


static void connect_wan_service(const char *name,
                                luna_service_request_t *service_req)
{
	GSList *iter;
	gboolean found_service = FALSE;
	connman_service_t *service = NULL;

	if (!name)
	{
		LSMessageReplyErrorInvalidParams(service_req->handle, service_req->message);
		goto cleanup;
	}

	for (iter = manager->cellular_services; NULL != iter ; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;

		if (g_strcmp0(service->name, name) == 0)
		{
			WCALOG_INFO(MSGID_WAN_CONNECT_INFO, 0, "Connecting to cellular service %s",
			            service->name);
			found_service = TRUE;
			break;
		}
	}

	if (!found_service)
	{
		LSMessageReplyCustomError(service_req->handle, service_req->message,
		                          "Cellular service not found", WCA_API_ERROR_NETWORK_NOT_FOUND);
		goto cleanup;
	}

	service_req->user_data = service;

	if (!connman_service_connect(service, service_connect_callback, service_req))
	{
		LSMessageReplyErrorUnknown(service_req->handle, service_req->message);
		goto cleanup;
	}

	return;

cleanup:
	luna_service_request_free(service_req);
}


static void disconnect_wan_service(const char *name, LSHandle *handle,
                                   LSMessage *message)
{
	GSList *iter;
	gboolean found_service = FALSE;
	connman_service_t *service = NULL;

	if (!name)
	{
		LSMessageReplyErrorInvalidParams(handle, message);
		return;
	}

	/* Look up for the service with the given type */
	for (iter = manager->cellular_services; NULL != iter ; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;

		if (g_strcmp0(service->name, name) == 0)
		{
			WCALOG_INFO(MSGID_WAN_DISCONNECT_INFO, 0,
			            "Disconnecting from cellular service %s", service->name);
			found_service = TRUE;
			break;
		}
	}

	if (!found_service)
	{
		LSMessageReplyCustomError(handle, message,
		                          "Cellular service not found", WCA_API_ERROR_NETWORK_NOT_FOUND);
		return;
	}

	if (!connman_service_disconnect(service))
	{
		LSMessageReplyErrorUnknown(handle, message);
		return;
	}

	LSMessageReplySuccess(handle, message);
}

static void technology_property_changed_callback(gpointer data,
        const gchar *property, GVariant *value)
{
	connman_technology_t *technology = (connman_technology_t *)data;

	if (NULL == technology)
	{
		return;
	}

	WCALOG_DEBUG("WAN technology: property [%s] changed", property);

	if ((technology == connman_manager_find_cellular_technology(manager)) &&
	        (g_strcmp0(property, "Powered") == 0 || g_strcmp0(property, "Connected") == 0))
	{
		send_wan_connection_status_to_subscribers();
		connectionmanager_send_status_to_subscribers();
	}
}

/**
 * @brief The connect method connects to a single context which is specified by its name.
 *
 * @param name Name of the context to connect to.
 */

static bool handle_wan_connect_command(LSHandle *sh, LSMessage *message,
                                       void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!cellular_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_cellular_powered())
	{
		LSMessageReplyCustomError(sh, message, "WAN switched off",
		                          WCA_API_ERROR_WAN_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(name, string))  REQUIRED_1(name))),
	                             &parsed_obj))
	{
		return true;
	}

	luna_service_request_t *service_req;
	jvalue_ref name_obj = 0;
	char *name = NULL;

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("name"), &name_obj))
	{
		raw_buffer name_buf = jstring_get(name_obj);
		name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);
	}

	if (name == NULL || strlen(name) == 0)
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	service_req = luna_service_request_new(sh, message);

	connect_wan_service(name, service_req);

cleanup:

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	g_free(name);

	return true;
}

/**
 * @brief The disconnect method disconnects a single context which is specified by its name.
 *
 * @param name Name of the context to disconnect
 */

static bool handle_wan_disconnect_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!cellular_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_cellular_powered())
	{
		LSMessageReplyCustomError(sh, message, "WAN switched off",
		                          WCA_API_ERROR_WAN_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(name, string))  REQUIRED_1(name))),
	                             &parsed_obj))
	{
		return true;
	}

	jvalue_ref name_obj = 0;
	char *name = NULL;

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("name"), &name_obj))
	{
		raw_buffer name_buf = jstring_get(name_obj);
		name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);
	}

	if (name == NULL || strlen(name) == 0)
	{
		LSMessageReplyErrorInvalidParams(sh, message);
		goto cleanup;
	}

	disconnect_wan_service(name, sh, message);

cleanup:

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	g_free(name);

	return true;
}

/**
 * @brief Reports the current WAN status to the caller.
 *
 * @param subscribe To be notified of any status changes, set subscribe to true
 */

static bool handle_wan_get_status_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	jvalue_ref parsedObj = {0};

	if (!LSMessageValidateSchema(sh, message,
                                     j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
                return true;
	}

	jvalue_ref reply_obj = 0;
	LSError lserror;
	LSErrorInit(&lserror);
	bool subscribed = false;

	reply_obj = jobject_create();

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

	if (!cellular_technology_status_check_with_subscription(sh, message,
		subscribed))
	{
		goto cleanup;
	}

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"),
	            jboolean_create(subscribed));

	append_wan_status(reply_obj);

	if (!LSMessageReply(sh, message, jvalue_tostring(reply_obj, jschema_all()),
	                    &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply_obj);
	j_release(&parsedObj);

	return true;
}

/**
 * @brief  Lists all available contexts
 *
 * @param subscribe To be notified of any status changes, set subscribe to true
 */

static bool handle_wan_get_contexts_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	jvalue_ref parsedObj = {0};

	if (!LSMessageValidateSchema(sh, message,
                                     j_cstr_to_buffer(SCHEMA_1(PROP(subscribe, boolean))), &parsedObj))
	{
                return true;
	}

	jvalue_ref reply_obj = 0;
	LSError lserror;
	LSErrorInit(&lserror);
	bool subscribed = false;

	reply_obj = jobject_create();

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

	if (!cellular_technology_status_check_with_subscription(sh, message,
	        subscribed))
	{
		goto cleanup;
	}


	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"),
	            jboolean_create(subscribed));

	append_contexts(reply_obj);

	if (!LSMessageReply(sh, message, jvalue_tostring(reply_obj, jschema_all()),
	                    &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

cleanup:

	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	j_release(&reply_obj);
	j_release(&parsedObj);

	return true;
}

/**
 * @brief  Get information of a given context
 *
 * @param name name of the context
 */

static bool handle_wan_get_context_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!cellular_technology_status_check(sh, message))
	{
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_1(PROP(name, string)) REQUIRED_1(name))),
	                             &parsed_obj))
	{
		return true;
	}

	jvalue_ref reply_obj = 0;
	jvalue_ref name_obj = 0;
	LSError lserror;
	LSErrorInit(&lserror);
	bool found_service = FALSE;
	GSList *iter;
	char *name = NULL;
	connman_service_t *service = NULL;

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("name"), &name_obj))
	{
		raw_buffer name_buf = jstring_get(name_obj);
		name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);
	}

	reply_obj = jobject_create();

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	for (iter = manager->cellular_services; NULL != iter; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;

		if (g_strcmp0(service->name, name) == 0)
		{
			connman_service_get_ipinfo(service);
			jvalue_ref wan_context_obj = jobject_create();
			retrieve_wan_context(wan_context_obj, service);
			jobject_put(reply_obj, J_CSTR_TO_JVAL("contextInfo"), wan_context_obj);
			found_service = TRUE;
			break;
		}
	}

	if (!found_service)
	{
		LSMessageReplyCustomError(sh, message, "Cellular service not found",
		                          WCA_API_ERROR_NETWORK_NOT_FOUND);
		goto cleanup;
	}

	if (!LSMessageReply(sh, message, jvalue_tostring(reply_obj, jschema_all()),
                            &lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

cleanup:

	if (!jis_null(reply_obj))
	{
		j_release(&reply_obj);
	}

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	g_free(name);

	return true;
}

/**
 * @brief  Set static host routing for a given context
 *
 * @param name  name of the context
 * @param hosts an array of host IP address to setup static route
 */

static bool handle_set_hostroutes_command(LSHandle *sh, LSMessage *message,
        void *context)
{
	if (!connman_status_check(manager, sh, message))
	{
		return true;
	}

	if (!cellular_technology_status_check(sh, message))
	{
		return true;
	}

	if (!is_cellular_powered())
	{
		LSMessageReplyCustomError(sh, message, "WAN switched off",
		                          WCA_API_ERROR_WAN_SWITCHED_OFF);
		return true;
	}

	// To prevent memory leaks, schema should be checked before the variables will be initialized.
	jvalue_ref parsed_obj = 0;
	if (!LSMessageValidateSchema(sh, message,
	                             j_cstr_to_buffer(STRICT_SCHEMA(PROPS_2(ARRAY(hosts, string), PROP(name, string))
	                                     REQUIRED_2(name, hosts))), &parsed_obj))
	{
		return true;
	}

	GStrv hosts = NULL;
	jvalue_ref name_obj = 0;
	jvalue_ref hosts_obj = 0;
	char *name = NULL;
	GSList *iter;
	gboolean found_service = false;
	connman_service_t *service = NULL;

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("name"), &name_obj))
	{
		raw_buffer name_buf = jstring_get(name_obj);
		name = g_strdup(name_buf.m_str);
		jstring_free_buffer(name_buf);
	}

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("hosts"), &hosts_obj))
	{
		int i, host_arrsize = jarray_size(hosts_obj);
		hosts = (GStrv) g_new0(GStrv, host_arrsize + 1);

		for (i = 0; i < host_arrsize; i++)
		{
			raw_buffer host_buf = jstring_get(jarray_get(hosts_obj, i));
			hosts[i] = g_strdup(host_buf.m_str);
			jstring_free_buffer(host_buf);

			if (!(is_valid_ipaddress(hosts[i]) || is_valid_ipv6address(hosts[i])))
			{
				LSMessageReplyErrorInvalidParams(sh, message);
				goto cleanup;
			}
		}
	}

	/* Look up for the service with the given type */
	for (iter = manager->cellular_services; NULL != iter ; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;

		if (g_strcmp0(service->name, name) == 0)
		{
			WCALOG_DEBUG("Setting host route for service %s", service->name);
			found_service = true;
			break;
		}
	}

	if (!found_service)
	{
		LSMessageReplyCustomError(sh, message,
		                          "Cellular service not found", WCA_API_ERROR_NETWORK_NOT_FOUND);
		goto cleanup;
	}

	if (connman_service_set_hostroutes(service, hosts))
	{
		LSMessageReplySuccess(sh, message);
	}
	else
	{
		LSMessageReplyCustomError(sh, message, "Hosts could not be set as static route",
		                          WCA_API_ERROR_HOST_ROUTE_NOT_SET);
	}

cleanup:

	if (!jis_null(parsed_obj))
	{
		j_release(&parsed_obj);
	}

	g_free(name);
	g_strfreev(hosts);

	return true;
}

static LSMethod wan_methods[] =
{
	{ LUNA_METHOD_WAN_CONNECT,       handle_wan_connect_command },
	{ LUNA_METHOD_WAN_DISCONNECT,    handle_wan_disconnect_command },
	{ LUNA_METHOD_WAN_GETSTATUS,     handle_wan_get_status_command },
	{ LUNA_METHOD_WAN_GETCONTEXTS,   handle_wan_get_contexts_command },
	{ LUNA_METHOD_WAN_GETCONTEXT,    handle_wan_get_context_command },
	{ LUNA_METHOD_WAN_SETHOSTROUTES, handle_set_hostroutes_command },
	{ },
};

int initialize_wan_ls2_calls(GMainLoop *mainloop, LSHandle **wan_handle)
{
	LSError lserror;
	LSErrorInit(&lserror);
	pLsHandle = NULL;

	if (NULL == mainloop)
	{
		goto Exit;
	}

	if (LSRegister(WAN_LUNA_SERVICE_NAME, &pLsHandle, &lserror) == false)
	{
		WCALOG_ERROR(MSGID_WAN_SRVC_REGISTER_FAIL, 0,
		             "LSRegister() returned error");
		goto Exit;
	}

	if (LSRegisterCategory(pLsHandle, LUNA_CATEGORY_ROOT, wan_methods, NULL, NULL,
	                       &lserror) == false)
	{
		WCALOG_ERROR(MSGID_WAN_SRVC_REGISTER_FAIL, 0,
		             "LSRegisterCategory() returned error");
		goto Exit;
	}

	if (LSGmainAttach(pLsHandle, mainloop, &lserror) == false)
	{
		WCALOG_ERROR(MSGID_WAN_SRVC_REGISTER_FAIL, 0,
		             "LSGmainAttach() returned error");
		goto Exit;
	}

	*wan_handle = pLsHandle;

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

void check_and_initialize_cellular_technology(void)
{
	connman_technology_t *technology = connman_manager_find_cellular_technology(
	                                       manager);

	if (!technology)
	{
		return;
	}

	connman_technology_register_property_changed_cb(technology,
	        technology_property_changed_callback);

	/* Register property change callback for all connected cellular services */
	GSList *iter;

	for (iter = manager->cellular_services; iter != NULL; iter = iter->next)
	{
		connman_service_t *service = iter->data;

		if (!connman_service_is_connected(service))
		{
			continue;
		}

		connman_service_register_property_changed_cb(service, service_changed_cb);
	}
}
