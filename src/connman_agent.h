/* @@@LICENSE
*
*      Copyright (c) 2012 Simon Busch <morphis@gravedo.de>
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
 * @file  connman_agent.h
 *
 * @brief Header file defining functions and data structures for interacting with connman agent
 */

#ifndef CONNMAN_AGENT_H_
#define CONNMAN_AGENT_H_

#include "connman_common.h"

typedef struct connman_agent connman_agent_t;

typedef GVariant *(*connman_agent_request_input_cb)(GVariant *fields,
        gpointer user_data);
typedef void (*connman_agent_report_error_cb)(const char *error_message,
        gpointer user_data);
typedef void (*connman_agent_registered_cb)(gpointer user_data);

connman_agent_t *connman_agent_new(void);
void connman_agent_free(connman_agent_t *agent);
gchar *connman_agent_get_path(connman_agent_t *agent);
void connman_agent_set_registered_callback(connman_agent_t *agent,
        connman_agent_registered_cb cb, gpointer user_data);
void connman_agent_set_request_input_callback(connman_agent_t *agent,
        connman_agent_request_input_cb cb, gpointer user_data);
void connman_agent_set_report_error_cb(connman_agent_t *agent,
                                       connman_agent_report_error_cb cb, gpointer user_data);

#endif
