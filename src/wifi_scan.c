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
 * @file  wifi_scan.c
 *
 * @brief Functions for scanning wifi.
 *
 */

#include "wifi_scan.h"
#include "logging.h"
#include "utils.h"

#define MIN_SCAN_INTERVAL 1000

typedef struct scan_subscriber_data
{
	char* subscriber;
	/* Interval in ms*/
	guint interval;
	/* time for next result */
	gint64 next_result;
} scan_subscriber_data_t;


static connman_technology_t *wifi_tech = NULL;
static GArray* scan_subscribers = NULL;
static guint scan_timeout_source = 0;
static guint current_scan_interval = 0;
static gint64 scan_time = 0;
static gboolean scan_running = FALSE;
static gboolean scan_is_p2p = FALSE;

static gboolean regular_scan_pending = FALSE;
static gboolean p2p_scan_pending = FALSE;

wifi_scan_callback_t scan_done_callback_fn = NULL;
gpointer scan_done_callback_data = NULL;

static guint compute_scan_interval(void)
{
	guint min = 0;

	guint length = scan_subscribers->len;
	guint i;
	for (i = 0; i < length; i++)
	{
		scan_subscriber_data_t* data = &g_array_index(scan_subscribers,
		                                              scan_subscriber_data_t,
		                                              i);
		if (min == 0 || min > data->interval)
		{
			min = data->interval;
		}
	}

	return min;
}

void scan_done_callback(gpointer user_data)
{
	UNUSED(user_data);

	WCALOG_DEBUG("wifi_scan: Scan done callback");

	if (!scan_running)
	{
		WCALOG_INFO(MSGID_WIFI_SCAN_CALLBACK_NOT_RUNNING, 0,
		            "wifi_scan: Received scan done callback, but no scan running");
		return;
	}

	scan_running = FALSE;

	if (p2p_scan_pending)
	{
		wifi_scan_now_p2p();
	}
	else if (regular_scan_pending)
	{
		wifi_scan_now();
	}
	else if (scan_done_callback_fn)
	{
		//Clear before calling. To prevent clearing callback set in done func.
		wifi_scan_callback_t fn = scan_done_callback_fn;
		gpointer data = scan_done_callback_data;
		scan_done_callback_fn = NULL;
		scan_done_callback_data = NULL;

		fn(data);
	}
}

gboolean wifi_scan_now_p2p(void)
{
	gboolean result;

	if (scan_running && scan_is_p2p)
	{
		result = true;
	}
	else if (scan_running && !scan_is_p2p)
	{
		p2p_scan_pending = true;
		result = true;
	}
	else if (!wifi_tech)
	{
		return false;
	}
	else
	{
		WCALOG_DEBUG("wifi_scan: Scanning p2p");

		wifi_tech->handle_after_scan_fn = scan_done_callback;
		wifi_tech->after_scan_data = NULL;
		result = connman_technology_scan_network(wifi_tech, true);

		if (result)
		{
			scan_running = true;
			p2p_scan_pending = false;
		}

		scan_time = g_get_monotonic_time() / 1000;
	}

	return result;
}

gboolean wifi_scan_now(void)
{
	gboolean result;

	if (scan_running && !scan_is_p2p)
	{
		result = true;
	}
	else if (scan_running && scan_is_p2p)
	{
		regular_scan_pending = true;
		result = true;
	}
	else if (!wifi_tech)
	{
		return false;
	}
	else
	{
		WCALOG_DEBUG("wifi_scan: Scanning wifi");

		wifi_tech->handle_after_scan_fn = scan_done_callback;
		wifi_tech->after_scan_data = NULL;

		result = connman_technology_scan_network(wifi_tech, FALSE);

		if (result)
		{
			scan_running = TRUE;
			regular_scan_pending = FALSE;
		}

		scan_time = g_get_monotonic_time() / 1000;
	}

	return result;
}

gboolean wifi_scan_is_scanning()
{
	return scan_running;
}


void wifi_scan_execute_when_scan_done(wifi_scan_callback_t callback, gpointer user_data)
{
	if (scan_running)
	{
		scan_done_callback_fn = callback;
		scan_done_callback_data = user_data;
	}
	else
	{
		callback(user_data);
	}
}

static gboolean scan_timeout_cb(gpointer user_data)
{
	UNUSED(user_data);

	scan_timeout_source = 0;

	gboolean scan_started = wifi_scan_now();

	if (!scan_started)
	{
		WCALOG_DEBUG("wifi_scan: Failed to start scan");
	}

	// Schedule new scan.
	if (current_scan_interval != 0)
	{
		scan_timeout_source = g_timeout_add_full(G_PRIORITY_DEFAULT,
		                                         current_scan_interval,
		                                         scan_timeout_cb, NULL, NULL);
	}

	return FALSE;
}

gboolean wifi_scan_add_interval(const char* source, guint interval_ms)
{
	WCALOG_DEBUG("wifi_scan: Add scan interval, %s, %d", source, interval_ms);

	if (interval_ms <= 0 || source == NULL)
	{
		WCALOG_ERROR(MSGID_WIFI_SCAN_ADD_INTERVAL_INVALID_PARAMS, 0,
		             "wifi_scan: Add scan interval: invalid parameters");
		return false;
	}

	if (scan_subscribers == NULL)
	{
		scan_subscribers = g_array_new(false, false, sizeof(scan_subscriber_data_t));
	}

	gint64 cur_time = g_get_monotonic_time() / 1000;

	scan_subscriber_data_t data;
	data.interval = interval_ms;
	data.subscriber = g_strdup(source);
	data.next_result = cur_time;
	scan_subscribers = g_array_append_val(scan_subscribers, data);

	guint new_interval = compute_scan_interval();
	WCALOG_DEBUG("wifi_scan: Compute scan interval = %d", new_interval);

	if (new_interval == 0)
	{
		return FALSE;
	}

	// Reschedule timeout based on new interval.
	if (current_scan_interval == 0 || new_interval < current_scan_interval)
	{
		if (scan_timeout_source)
		{
			g_source_remove(scan_timeout_source);
		}

		current_scan_interval = new_interval;
		scan_timeout_source = g_timeout_add_full(G_PRIORITY_DEFAULT,
		                                         current_scan_interval,
		                                         scan_timeout_cb, NULL, NULL);
	}

	if (scan_time == 0 || cur_time > scan_time + MIN_SCAN_INTERVAL)
	{
		return wifi_scan_now();
	}
	else
	{
		return TRUE;
	}
}

gboolean wifi_scan_check_and_reset_interval(const char* source)
{
	gint64 curtime = g_get_monotonic_time() / 1000;

	// Using simple lookup here.
	// Should use hashmap if number of subscribers goes over 20.
	guint length = scan_subscribers->len;
	guint i;
	for (i = 0; i < length; i++)
	{
		scan_subscriber_data_t* data = &g_array_index(scan_subscribers,
		                                              scan_subscriber_data_t,
		                                              i);

		// Subsctract a bit to compensate for time intervals not being millisecond accurate.

		if (!g_strcmp0(data->subscriber, source) &&
				data->next_result < curtime + current_scan_interval - 100)
		{
			data->next_result = curtime + data->interval;
			WCALOG_INFO("DEBUG", 0, "wifi_scan: Interval OK %s", source);
			return true;
		}
	}

	WCALOG_INFO("DEBUG", 0, "wifi_scan: Interval skip %s", source);
	return false;
}

gboolean wifi_scan_remove_interval(const char* source)
{
	WCALOG_DEBUG("wifi_scan: Remove scan interval %s", source);
	gboolean found = FALSE;
	guint new_interval;
	guint length = scan_subscribers ? scan_subscribers->len : 0;
	guint i;
	for (i = 0; i < length; i++)
	{
		scan_subscriber_data_t* data = &g_array_index(scan_subscribers,
		                                              scan_subscriber_data_t,
		                                              i);

		if (!g_strcmp0(data->subscriber, source))
		{
			g_free(data->subscriber);
			data->subscriber = NULL;
			scan_subscribers = g_array_remove_index_fast(scan_subscribers, i);
			found = TRUE;
			i--;
			length--;
		}
	}

	if (!found)
	{
		WCALOG_INFO(MSGID_WIFI_SCAN_REMOVE_INVERVAL_NOT_FOUND, 0,
		            "wifi_scan: Remove inverval, interval not found, id: %s", source);
		return FALSE;
	}

	new_interval = compute_scan_interval();
	WCALOG_DEBUG("wifi_scan: Compute scan interval = %d", new_interval);

	if (scan_timeout_source == 0)
	{
		current_scan_interval = new_interval;
		return TRUE;
	}

	if (new_interval == 0)
	{
		g_source_remove(scan_timeout_source);
		scan_timeout_source = 0;
	}
	else if (new_interval > current_scan_interval)
	{
		// Extend already running timeout.
		gint64 curtime = g_get_monotonic_time() / 1000;
		guint transient_interval = (guint)MAX(1, scan_time + new_interval - curtime);

		g_source_remove(scan_timeout_source);
		scan_timeout_source = g_timeout_add_full(G_PRIORITY_DEFAULT,
		                                         transient_interval,
		                                         scan_timeout_cb, NULL, NULL);
	}

	current_scan_interval = new_interval;

	return TRUE;
}

void wifi_scan_stop(void)
{
	WCALOG_DEBUG("wifi_scan: stop");

	wifi_tech = NULL;

	if (scan_timeout_source != 0)
	{
		g_source_remove(scan_timeout_source);
		scan_timeout_source = 0;
	}

	scan_running = FALSE;

	scan_done_callback_fn = NULL;
	scan_done_callback_data = NULL;
}

void wifi_scan_start(connman_technology_t* _wifi_tech)
{
	WCALOG_DEBUG("wifi_scan: start");

	if (wifi_tech)
	{
		WCALOG_INFO(MSGID_WIFI_SCAN_START_ALREADY_STARTED, 0,
		             "wifi_scan: Scan start: already started");
	}

	wifi_tech = _wifi_tech;

	if (scan_subscribers == NULL)
	{
		scan_subscribers = g_array_new(false, false, sizeof(scan_subscriber_data_t));
	}

	if (current_scan_interval > 0 && scan_timeout_source == 0)
	{
		scan_timeout_cb(NULL);
	}
}
