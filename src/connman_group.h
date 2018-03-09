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
 * @file  connman_group.h
 *
 * @brief Header file defining functions and data structures for interacting with connman groups
 *
 */


#ifndef CONNMAN_GROUP_H_
#define CONNMAN_GROUP_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "connman_common.h"
#include "connman_service.h"

/**
 * Local instance of a connman group
 * Caches all required information for a group
 */
typedef struct connman_group
{
	ConnmanInterfaceGroup *remote;
	gchar *path;
	gchar *name;
	gchar *passphrase;
	gchar *group_owner;
	gchar *local_address;
	gboolean is_group_owner;
	gboolean is_persistent;
	gboolean tethering;
	gint freq;
	GSList *peer_list;
	gulong sighandler_id;
	connman_property_changed_cb     handle_property_change_fn;
} connman_group_t;

extern gboolean connman_group_set_tethering(connman_group_t *group,
        gboolean state);
extern gboolean connman_group_disconnect(connman_group_t *group);
extern gboolean connman_group_invite_peer(connman_group_t *group,
        connman_service_t *service);
extern gboolean connman_group_get_local_address(connman_group_t *group);

extern void connman_group_register_property_changed_cb(connman_group_t *group,
        connman_property_changed_cb func);
extern connman_group_t *connman_group_new(GVariant *variant);
extern void connman_group_free(gpointer data, gpointer user_data);

#endif /* CONNMAN_GROUP_H_ */

