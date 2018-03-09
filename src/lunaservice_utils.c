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
 * @file lunaservice_utils.c
 *
 * @brief Convenience functions for sending luna error messages
 *
 */

#include "lunaservice_utils.h"
#include "logging.h"
#include "errors.h"

luna_service_request_t *luna_service_request_new(LSHandle *handle,
        LSMessage *message)
{
	luna_service_request_t *req = NULL;

	req = g_new0(luna_service_request_t, 1);
	req->handle = handle;
	req->message = message;

	LSMessageRef(message);

	return req;
}

void luna_service_request_free(luna_service_request_t *service_req)
{
	if (service_req->message)
	{
		LSMessageUnref(service_req->message);
	}

	g_free(service_req);
}

void
LSMessageReplyErrorUnknown(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *jsonMessage;
	jsonMessage =
	    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"Unknown error\",\"errorCode\":%d}",
	                    WCA_API_ERROR_UNKNOWN);

	bool retVal = LSMessageReply(sh, message, jsonMessage, &lserror);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(jsonMessage);
}

void
LSMessageReplyErrorInvalidParams(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *jsonMessage;
	jsonMessage =
	    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"Invalid parameters\",\"errorCode\":%d}",
	                    WCA_API_ERROR_INVALID_PARAMETERS);

	bool retVal = LSMessageReply(sh, message, jsonMessage, &lserror);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(jsonMessage);
}

void
LSMessageReplyErrorBadJSON(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *jsonMessage;
	jsonMessage =
	    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"Malformed json\",\"errorCode\":%d}",
	                    WCA_API_ERROR_MALFORMED_JSON);

	bool retVal = LSMessageReply(sh, message, jsonMessage, &lserror);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(jsonMessage);
}

void
LSMessageReplyCustomError(LSHandle *sh, LSMessage *message,
                          const char *errormsg, unsigned int error_code)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *errorString;

	errorString =
	    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"%s\",\"errorCode\":%d}",
	                    errormsg, error_code);

	bool retVal = LSMessageReply(sh, message, errorString, NULL);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(errorString);
}

void
LSMessageReplyCustomErrorWithSubscription(LSHandle *sh, LSMessage *message,
        const char *errormsg, unsigned int error_code, bool subscribed)
{
	LSError lserror;
	LSErrorInit(&lserror);
	char *errorString;

	if (subscribed)
	{
		errorString =
		    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"%s\",\"errorCode\":%d, \"subscribed\":true}",
		                    errormsg, error_code);
	}
	else
	{
		errorString =
		    g_strdup_printf("{\"returnValue\":false,\"errorText\":\"%s\",\"errorCode\":%d}",
		                    errormsg, error_code);
	}

	bool retVal = LSMessageReply(sh, message, errorString, NULL);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	g_free(errorString);
}

void
LSMessageReplySuccess(LSHandle *sh, LSMessage *message)
{
	LSError lserror;
	LSErrorInit(&lserror);

	bool retVal = LSMessageReply(sh, message, "{\"returnValue\":true}",
	                             NULL);

	if (!retVal)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

bool LSMessageValidateSchema(LSHandle *sh, LSMessage *message,
                             raw_buffer schema, jvalue_ref *parsedObj)
{
	bool ret = false;
	jschema_ref input_schema = jschema_parse(schema, DOMOPT_NOOPT, NULL);

	if (!input_schema)
	{
		return false;
	}

	JSchemaInfo schemaInfo;
	jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
	*parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)),
	                        DOMOPT_NOOPT, &schemaInfo);

	if (jis_null(*parsedObj))
	{
		input_schema = jschema_parse(j_cstr_to_buffer(SCHEMA_ANY), DOMOPT_NOOPT, NULL);
		jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
		*parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)),
		                        DOMOPT_NOOPT, &schemaInfo);

		if (jis_null(*parsedObj))
		{
			LSMessageReplyErrorBadJSON(sh, message);
		}
		else
		{
			LSMessageReplyCustomError(sh, message,
			                          "Could not validate json message against schema",
			                          WCA_API_ERROR_SCHEMA_VALIDATION);
			j_release(parsedObj);
		}
	}
	else
	{
		ret = true;
	}

	jschema_release(&input_schema);
	return ret;
}

static bool LSMessageParseToNative_valist(LSMessage *message, jvalue_ref *parsedObj, va_list args)
{
	char* error;
	JSchemaInfo schemaInfo;
	jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);
	*parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)),
	                        DOMOPT_NOOPT, &schemaInfo);

	if (jis_null(*parsedObj))
	{
		LSMessageReplyErrorBadJSON(LSMessageGetConnection(message), message);
		return false;
	}

	error = json_convert_to_native_valist(*parsedObj, &args);

	if (error)
	{
		char* error_msg = g_strdup_printf("Could not validate json message against schema: %s", error);

		LSMessageReplyCustomError(LSMessageGetConnection(message),
		                          message,
		                          error_msg,
		                          WCA_API_ERROR_SCHEMA_VALIDATION);
		j_release(parsedObj);
		g_free(error);
		g_free(error_msg);
		*parsedObj = NULL;
	}

	return error == NULL;
}

/**
 * Parse luna message to JSON and store fields to C variables.
 * Returns false and sends error message back to caller
 * if failed to parse or mandatory variables are missing or numeric fields
 * do not fit in specified data types (eg negative value for signed data).
 *
 * The parsed values are valid as long as the the parsed jvalue_ref is valid.
 *
 * Usage:
 * bool boolVar;
 * const char* stringVar;
 * jvalue_ref jvalue;
 *	LSMessageParseToNative(message, &jvalue,
 *		json_object_start,
 *		json_type_boolean, "boolParam", &boolVar, TRUE // Mandatory
 *		json_type_string, "stringParam", &const, FALSE, // Optional
 *		...
 *		json_object_start);
 *
 *   //Use the variables
 *
 *   j_release(jvalue);  // String variables are no longer valid after this.
 *
 * The json_object_start/json_object_end are delimiters,
 * used to validate parameters structure.
 *
 *
 */
bool LSMessageParseToNative(LSMessage *message,
                            jvalue_ref *parsedObj, ...)
{
	bool result;
	va_list args;

	va_start(args, parsedObj);
	result = LSMessageParseToNative_valist(message, parsedObj, args);
	va_end(args);

	return result;
}


/**
 * Call LSMessageParseToNative and then add to subscription list if subscribed.
 * This parses the message to json only once, compared to
 * regular LSMessageIsSubscription + LSSubscriptionProcess that would parse it 3
 * times.
 */
bool LSMessageParseToNativeWithSubscription(LSMessage *message,
                                            jvalue_ref *parsedObj, ...)
{
	bool result;
	va_list args;

	va_start(args, parsedObj);
	result = LSMessageParseToNative_valist(message, parsedObj, args);
	va_end(args);

	if (result)
	{
		jvalue_ref subscribeObj;
		bool subscribed = FALSE;

		if (jobject_get_exists(*parsedObj, J_CSTR_TO_BUF("subscribe"), &subscribeObj))
		{
			jboolean_get(subscribeObj, &subscribed);
		}

		if (subscribed)
		{
			LSError lserror;
			LSErrorInit(&lserror);

			const char *key = LSMessageGetKind(message);
			if (!LSSubscriptionAdd(LSMessageGetConnection(message), key, message, &lserror))
			{
				LSErrorPrint(&lserror, stderr);
				LSErrorFree(&lserror);
				LSMessageReplyErrorUnknown(LSMessageGetConnection(message), message);

				j_release(parsedObj);
				*parsedObj = NULL;
				result = false;
			}
		}
	}

	return result;
}

/*
 * Same as LSMessageParseToNative but works on already parsed jvalue.
 */
bool LSMessageParseFragmentToNative(LSMessage *message,
                                    jvalue_ref parsedObj, ...)
{
	char* error;
	va_list args;

	va_start(args, parsedObj);
	error = json_convert_to_native_valist(parsedObj, &args);
	va_end(args);

	if (error)
	{
		char* error_msg = g_strdup_printf("Could not validate json message against schema: %s", error);

		LSMessageReplyCustomError(LSMessageGetConnection(message),
		                          message,
		                          error_msg,
		                          WCA_API_ERROR_SCHEMA_VALIDATION);
		g_free(error);
		g_free(error_msg);
	}

	return error == NULL;
}

/**
 * Create reply message and send to caller.
 * Sends an error message to caller if failed to create requested message.
 *
 * Usage:
 *	LSMessageReplySuccessWithData(message,
 *		json_object_start,
 *		json_type_boolean, "boolParam", true,
 *		json_type_string, "stringParam", "stringValue", true,
 *		json_type_string, "int", intVariable, intVariable != NULL,
 *		...
 *		json_object_end);
 *
 * The json_object_start/json_object_end are delimiters,
 * used to validate parameters structure.
 *
 */

void LSMessageReplySuccessWithData(LSMessage *message, ...)
{
	LSError lserror;
	LSErrorInit(&lserror);
	jvalue_ref replyObj = 0;
	char* error;
	va_list args;


	va_start(args, message);
	error = json_generate_from_native_valist(&replyObj, &args);
	va_end(args);

	if (error)
	{
		WCALOG_ERROR(MSGID_LUNA_CREATE_JSON_FAILED, 0, "Failed to create JSON response: %s", error);
		LSMessageReplyErrorUnknown(LSMessageGetConnection(message), message);
		g_free(error);
		return;
	}

	/* Set returnValue=true if the caller has not already done so. */
	jobject_put(replyObj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	if (!LSMessageRespond(message,
	                    jvalue_tostring(replyObj, jschema_all()),
	                    &lserror))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_LUNA_SEND_FAILED, lserror.message);
		LSErrorFree(&lserror);
	}

	j_release(&replyObj);
}

/**
 * Same as LSMessageReplySuccessWithData, but compares response to previous reply
 * and does not send reply if contents equal.
 * And replaces previous reply with the new reply.
 */
void LSMessageReplySuccessWithDataNoDuplicates(LSMessage *message, char** previous_reply, ...)
{
	LSError lserror;
	LSErrorInit(&lserror);
	jvalue_ref replyObj = 0;
	char* error;
	va_list args;

	va_start(args, message);
	error = json_generate_from_native_valist(&replyObj, &args);
	va_end(args);

	if (error)
	{
		WCALOG_ERROR(MSGID_LUNA_CREATE_JSON_FAILED, 0, "Failed to create JSON response: %s", error);
		LSMessageReplyErrorUnknown(LSMessageGetConnection(message), message);
		g_free(error);
		return;
	}

	/* Set returnValue=true if the caller has not already done so. */
	jobject_put(replyObj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	const char* reply_string = jvalue_tostring(replyObj, jschema_all());

	if (previous_reply && *previous_reply && g_strcmp0(*previous_reply, reply_string) == 0)
	{
		// Duplicate response
		return;
	}

	if (!LSMessageRespond(message,
	                      reply_string,
	                      &lserror))
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_LUNA_SEND_FAILED, lserror.message);
		LSErrorFree(&lserror);
	}

	if (previous_reply)
	{
		g_free(*previous_reply);
		*previous_reply = g_strdup(reply_string);
	}

	j_release(&replyObj);
}
