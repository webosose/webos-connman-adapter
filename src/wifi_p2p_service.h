/* @@@LICENSE
*
* Copyright (c) 2024 LG Electronics, Inc.
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
 * @file  wifi_p2p_service.h
 *
 */


#ifndef _WIFI_P2P_SERVICE_H_
#define _WIFI_P2P_SERVICE_H_

#include <luna-service2/lunaservice.h>
#include "connman_service.h"

#define LUNA_CATEGORY_P2P                 "/p2p"

/**
 * @name Luna WiFi P2P Method Names
 * @{
 */
#define LUNA_METHOD_P2P_SETSTATE         "setstate"
#define LUNA_METHOD_P2P_GETSTATE         "getstate"
#define LUNA_METHOD_P2P_GETPEERS         "getpeers"
#define LUNA_METHOD_P2P_CONNECT          "connect"
#define LUNA_METHOD_P2P_DISCONNECT       "disconnect"
#define LUNA_METHOD_P2P_INVITE               "invite"
#define LUNA_METHOD_P2P_CREATEGROUP          "creategroup"
#define LUNA_METHOD_P2P_DISCONNECTGROUP      "disconnectgroup"
#define LUNA_METHOD_P2P_GETGROUPS            "getgroups"
#define LUNA_METHOD_P2P_SETTETHERING         "settethering"
#define LUNA_METHOD_P2P_GETGROUPPEERS        "getgrouppeers"
#define LUNA_METHOD_P2P_SETDEVICENAME        "setdevicename"
#define LUNA_METHOD_P2P_GETDEVICENAME        "getdevicename"
#define LUNA_METHOD_P2P_SETWIFIDISPLAYINFO   "setwifidisplayinfo"
#define LUNA_METHOD_P2P_GETWIFIDISPLAYINFO   "getwifidisplayinfo"
#define LUNA_METHOD_P2P_GETP2PREQUESTS       "getp2prequests"
#define LUNA_METHOD_P2P_FINDSERVICE          "findservice"
#define LUNA_METHOD_P2P_ADDSERVICE           "addservice"
#define LUNA_METHOD_P2P_DELETESERVICE        "deleteservice"
#define LUNA_METHOD_P2P_CANCEL               "cancel"
#define LUNA_METHOD_P2P_REJECTPEER           "rejectpeer"
#define LUNA_METHOD_P2P_DELETE_PROFILE       "deleteprofile"
#define LUNA_METHOD_P2P_SETLISTENPARAMS       "setlistenparams"
#define LUNA_METHOD_P2P_SETLISTENCHANNEL       "setlistenchannel"
#define LUNA_METHOD_P2P_SETGOINTENT           "setgointent"

extern int initialize_wifi_p2p_ls2_calls(GMainLoop *mainloop,
        LSHandle *pLsHandle);
extern void send_peer_information_to_subscribers(void);
extern void send_p2p_get_state_to_subscribers(void);
extern void update_p2p_device_name(void);
extern gboolean is_connected_peer(void);
extern void setPropertyUpdateCallback(connman_service_t *service);

#endif /* _WIFI_P2P_SERVICE_H_ */
