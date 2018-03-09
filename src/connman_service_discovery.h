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

/**
 * @file  connman_service_discovery.h
 *
 * @brief Header file defining functions and data structures for interacting with connman service discovery object
 *
 */

#ifndef CONNMAN_SERVICE_DISCOVERY_H_
#define CONNMAN_SERVICE_DISCOVERY_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "connman_common.h"

typedef enum
{
	CONNMAN_SERVICE_TYPE_UPNP = 0,
	CONNMAN_SERVICE_TYPE_BONJOUR
} connman_service_type;

extern gboolean connman_service_discovery_request(const connman_service_type
        type, const gchar *address, const gint version, const gchar *description,
        const gchar *query);
extern gboolean connman_service_discovery_register(const connman_service_type
        type, const gchar *description, const gchar *query, const gchar *response);
extern gboolean connman_service_discovery_remove(const connman_service_type
        type, const gchar *description, const gchar *query);

#endif /* CONNMAN_SERVICE_DISCOVERY_H_ */

