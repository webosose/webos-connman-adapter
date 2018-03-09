// Copyright (c) 2015-2018 LG Electronics, Inc.
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
 * @file  connman_counter.h
 *
 * @brief Header file defining functions and data structures for interacting with connman counter
 */

#ifndef CONNMAN_COUNTER_H_
#define CONNMAN_COUNTER_H_

#include "connman_common.h"

typedef void (*connman_counter_usage_cb)(const gchar *path, GVariant *home,
        GVariant *roaming, gpointer user_data);
typedef void (*connman_counter_registered_cb)(gpointer user_data);

struct data_usage_timer_params
{
	int interval;
	unsigned int timeout;
};

typedef struct connman_counter
{
	ConnmanInterfaceCounter *interface;
	gchar *path;
	connman_counter_registered_cb registered_cb;
	gpointer registered_data;
	connman_counter_usage_cb usage_cb;
	gpointer usage_data;
	guint bus_id;
	struct data_usage_timer_params *timer;
} connman_counter_t;

typedef struct connman_counter_data
{
	guint rx_packet;
	guint tx_packet;
	guint rx_bytes;
	guint tx_bytes;
	guint rx_errors;
	guint tx_errors;
	guint tx_dropped;
	guint rx_dropped;
} connman_counter_data_t;

void connman_counter_parse_counter_data(GVariant *variant,
                                        connman_counter_data_t *data);
connman_counter_t *connman_counter_new(GSourceFunc counter_usage_send_func);
void connman_counter_free(connman_counter_t *counter);
gchar *connman_counter_get_path(connman_counter_t *counter);
void connman_counter_set_registered_callback(connman_counter_t *counter,
        connman_counter_registered_cb cb, gpointer user_data);
void connman_counter_set_usage_callback(connman_counter_t *counter,
                                        connman_counter_usage_cb cb, gpointer user_data);

#endif
