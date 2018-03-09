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
 * @file  wifi_service.h
 *
 */


#ifndef _WIFI_SERVICE_H_
#define _WIFI_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define WIFI_LUNA_SERVICE_NAME "com.webos.service.wifi"

#define LUNA_CATEGORY_ROOT                  "/"

/**
 * @name Luna WiFi Method Names
 * @{
 */
#define LUNA_METHOD_CONNECT                 "connect"
#define LUNA_METHOD_CANCEL                  "cancel"
#define LUNA_METHOD_FINDNETWORKS            "findnetworks"
#define LUNA_METHOD_SCAN                    "scan"
#define LUNA_METHOD_GETNETWORKS             "getNetworks"
#define LUNA_METHOD_CHANGENETWORK           "changeNetwork"
#define LUNA_METHOD_DELETEPROFILE           "deleteprofile"
#define LUNA_METHOD_GETPROFILE              "getprofile"
#define LUNA_METHOD_GETPROFILELIST          "getprofilelist"
#define LUNA_METHOD_GETSTATUS               "getstatus"
#define LUNA_METHOD_SETSTATE                "setstate"
#define LUNA_METHOD_CREATEWPSPIN            "createwpspin"
#define LUNA_METHOD_STARTWPS                "startwps"
#define LUNA_METHOD_CANCELWPS               "cancelwps"
#define LUNA_METHOD_SET_MCHANNSCHED_MODE    "setmultichannelschedmode"
#define LUNA_METHOD_GET_MCHANNSCHED_MODE    "getmultichannelschedmode"
#define LUNA_METHOD_GET_WIFI_DIAGNOSTICS    "getwifidiagnostics"
#define LUNA_METHOD_SET_PASSTHROUGH_PARAMS  "setPassthroughParams"


#define WIFI_ENTERPRISE_SECURITY_TYPE       "ieee8021x"

typedef struct connection_settings
{
	char *passkey;
	char *ssid;
	bool wpsmode;
	char *wpspin;
	bool hidden;
	bool store;
	char *identity;
	char *eap_type;
	char *ca_cert_file;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_passphrase;
	char *phase2;
	char *passphrase;
} connection_settings_t;

extern int initialize_wifi_ls2_calls(GMainLoop *mainloop,
                                     LSHandle **wifi_handle);
extern connection_settings_t *connection_settings_new(void);
extern GVariant *agent_request_input_callback(GVariant *fields, gpointer data);
extern gint generate_new_wpspin(void);
extern void wifi_service_local_has_changed();
extern void send_getnetworks_status_to_subscribers();
extern void send_findnetworks_status_to_subscribers();

#endif /* _WIFI_SERVICE_H_ */
