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
 * @file lunaservice_utils.h
 *
 * @brief Header file defining convenience functions for sending luna error messages
 *
 */


#ifndef __LUNASERVICE_UTILS_H__
#define __LUNASERVICE_UTILS_H__

#include <luna-service2/lunaservice.h>
#include "json_utils.h"

typedef struct luna_service_request
{
	LSHandle *handle;
	LSMessage *message;
	void *user_data;
} luna_service_request_t;

extern luna_service_request_t *luna_service_request_new(LSHandle *handle,
        LSMessage *message);
extern void luna_service_request_free(luna_service_request_t *service_req);

extern void LSMessageReplyErrorUnknown(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyErrorInvalidParams(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyErrorBadJSON(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyCustomError(LSHandle *sh, LSMessage *message,
                                      const char *errormsg, unsigned int error_code);
extern void LSMessageReplySuccess(LSHandle *sh, LSMessage *message);
extern bool LSMessageValidateSchema(LSHandle *sh, LSMessage *message,
                                    raw_buffer schema, jvalue_ref *parsedObj);
extern void LSMessageReplyCustomErrorWithSubscription(LSHandle *sh,
                                                      LSMessage *message,
                                                      const char *errormsg,
                                                      unsigned int error_code,
                                                      bool subscribed);

extern bool LSMessageParseToNative(LSMessage *message,
                                   jvalue_ref *parsedObj, ...);

extern bool LSMessageParseFragmentToNative(LSMessage *message,
                                           jvalue_ref parsedObj, ...);
extern bool LSMessageParseToNativeWithSubscription(LSMessage *message,
                                            jvalue_ref *parsedObj, ...);

extern void LSMessageReplySuccessWithData(LSMessage *message, ...);
extern void LSMessageReplySuccessWithDataNoDuplicates(LSMessage *message, char** previous_reply, ...);

#endif //__LUNASERVICE_UTILS_H__
