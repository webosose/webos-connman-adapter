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

#include <glib.h>
#include <string.h>
#include <nyx/nyx_module.h>
#include <nyx/client/nyx_device_info.h>

#include "nyx.h"
#include "logging.h"

static nyx_device_handle_t device_main = NULL;

bool init_nyx()
{
	if (nyx_init() != NYX_ERROR_NONE)
	{
		WCALOG_ERROR(MSGID_NYX_INIT_ERROR, 0, "Error in nyx_init");
		return false;
	}

	if (nyx_device_open(NYX_DEVICE_DEVICE_INFO, "Main", &device_main) != NYX_ERROR_NONE)
	{
		WCALOG_ERROR(MSGID_NYX_DEVICE_OPEN_ERROR, 0, "Error in nyx_device_open");
		return false;
	}

	return true;
}

void release_nyx()
{
	if (device_main)
	{
		if (nyx_device_close(device_main) != NYX_ERROR_NONE)
		{
			WCALOG_ERROR(MSGID_NYX_DEVICE_CLOSE_ERROR, 0, "Error while closing nyx device");
		}
		device_main = 0;
	}

	if (nyx_deinit() != NYX_ERROR_NONE)
	{
		WCALOG_ERROR(MSGID_NYX_DEINIT_ERROR, 0, "Error in nyx_deinit");
	}
}

static bool retrieve_nyx_data(nyx_device_info_type_t type, char* buffer, size_t buffer_size)
{
	nyx_error_t error;
	const char* nyx_buffer = NULL;

	error = nyx_device_info_query(device_main, type, &nyx_buffer);

	if (error != NYX_ERROR_NONE)
	{
		return false;
	}

	g_strlcpy(buffer, nyx_buffer, buffer_size);
	return true;
}

bool retrieve_wired_mac_address(char* buffer, size_t buffer_size)
{
	return retrieve_nyx_data(NYX_DEVICE_INFO_WIRED_ADDR, buffer, buffer_size);
}

bool retrieve_wifi_mac_address(char* buffer, size_t buffer_size)
{
	return retrieve_nyx_data(NYX_DEVICE_INFO_WIFI_ADDR, buffer, buffer_size);
}