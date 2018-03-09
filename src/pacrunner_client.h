// Copyright (c) 2016-2018 LG Electronics, Inc.
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
 * @file  pacrunner_client.h
 *
 * @brief Header file defining functions and data structures for interacting with pacrunner client
 *
 */

#ifndef PACRUNNER_CLIENT_H_
#define PACRUNNER_CLIENT_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "pacrunner-interface.h"

/**
 * Local instance of a pacrunner client
 *
 * Stores all required information
 */

typedef struct pacrunner_client
{
	PacrunnerInterfaceClient *remote;
} pacrunner_client_t;

extern gchar *pacrunner_client_find_proxy_for_url(pacrunner_client_t *client,
		const gchar *url, const gchar *host);
/**
 * Initialize a new manager instance
 */
extern pacrunner_client_t *pacrunner_client_new(void);

/**
 * Free the client instance
 *
 * @param[IN]  client A client instance
 */
extern void pacrunner_client_free(pacrunner_client_t *client);

#endif /* PACRUNNER_CLIENT_H_ */
