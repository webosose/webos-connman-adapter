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
 * @file  wifi_scan.h
 *
 * @brief Functions for scanning wifi.
 * It manages various scan intervals set up subscriptions to findNetworks and
 * issues periodic scan requests.
 */

#include "lunaservice_utils.h"
#include "connman_manager.h"

typedef void (*wifi_scan_callback_t)(gpointer user_data);

/**
 * Is scan running.
 */
extern gboolean wifi_scan_is_scanning(void);

/**
 * Executes callback when scan done, or right away if no active scan running.
 */
extern void wifi_scan_execute_when_scan_done(wifi_scan_callback_t callback, gpointer user_data);

/**
 * Starts a fresh scan, or does nothing if scan already running.
 * Returns success/error.
 */
extern gboolean wifi_scan_now(void);

/**
 * Starts a fresh scan, or queues a new scan if regular scan is already running.
 * Returns success/error.
 */
extern gboolean wifi_scan_now_p2p(void);

/**
 * Adds scheduled peridic scan with specified interval.
 * The source variable can be used to cancel schaduled scan with remove_interval.
 */
extern gboolean wifi_scan_add_interval(const char* source, guint interval_ms);

/*
 * Removes scheduled scan.
 */
extern gboolean wifi_scan_remove_interval(const char* source);

/**
 * Returns true if interval has elapsed for the scan source.
 * If returns true, resets the interval counter.
 * TODO: not used right now.
 */
extern gboolean wifi_scan_check_and_reset_interval(const char* source);

/**
 * Starts all scan operations.
 */
void wifi_scan_start(connman_technology_t* _wifi_tech);

/**
 * Stops all scan operations. Consider started scan is failed.
 * Drop any pending callbacks.
 */
extern void wifi_scan_stop(void);

