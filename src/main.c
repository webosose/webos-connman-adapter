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
 * @file  main.c
 *
 */


#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>
#include <pthread.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <luna-service2/lunaservice.h>
#include <wca-support.h>
#include <nyx/common/nyx_core.h>

#include "connman_manager.h"
#include "logging.h"
#include "wifi_service.h"
#include "wifi_setting.h"
#include "wan_service.h"
#include "pan_service.h"
#include "connectionmanager_service.h"
#include "nyx.h"

static GMainLoop *mainloop = NULL;

int initialize_wifi_ls2_calls();

/**
 * Our PmLogLib logging context
 */
PmLogContext gLogContext;

static const char *const kLogContextName = "webos-connman-adapter";

void
term_handler(int signal)
{
	g_main_loop_quit(mainloop);
}

int
main(int argc, char **argv)
{
	LSHandle *wifi_handle, *wan_handle, *cm_handle, *pan_handle;
	signal(SIGTERM, term_handler);
	signal(SIGINT, term_handler);

	mainloop = g_main_loop_new(NULL, FALSE);

	(void) PmLogGetContext(kLogContextName, &gLogContext);

	WCALOG_DEBUG("Starting webos-connman-adapter");

	if (!init_nyx())
	{
		WCALOG_ERROR(MSGID_WIFI_SRVC_REGISTER_FAIL, 0,
		             "Error in initializing nyx");
		return -1;
	}

	if (initialize_wifi_ls2_calls(mainloop, &wifi_handle) < 0)
	{
		WCALOG_ERROR(MSGID_WIFI_SRVC_REGISTER_FAIL, 0,
		             "Error in initializing com.webos.service.wifi service");
		return -1;
	}

	if (initialize_wan_ls2_calls(mainloop, &wan_handle) < 0)
	{
		WCALOG_ERROR(MSGID_WAN_SRVC_REGISTER_FAIL, 0,
		             "Error in initializing com.webos.service.wan service");
		return -1;
	}

	if (initialize_pan_ls2_calls(mainloop, &pan_handle) < 0)
	{
		WCALOG_ERROR(MSGID_WAN_SRVC_REGISTER_FAIL, 0,
		             "Error in initializing com.webos.serivce.pan service");
		return -1;
	}

	if (initialize_connectionmanager_ls2_calls(mainloop, &cm_handle) < 0)
	{
		WCALOG_ERROR(MSGID_CM_SRVC_REGISTER_FAIL, 0,
		             "Error in initializing com.webos.service.connectionmanager service");
		return -1;
	}

	wca_support_connman_update_callbacks wca_support_library_cb = { 0 };

	if (wca_support_init(wifi_handle, cm_handle, wan_handle,
	                     &wca_support_library_cb, NULL, &gLogContext) < 0)
	{
		WCALOG_ERROR(MSGID_WCA_SUPPORT_FAIL, 0,
		             "Failed to initialize webOS connman adapter support library");
		return -1;
	}

	set_wca_support_connman_update_callbacks(&wca_support_library_cb);

	g_main_loop_run(mainloop);

	wca_support_release();

	remove_config_inotify_watch();

	g_main_loop_unref(mainloop);

	release_nyx();

	return 0;
}
