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

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <PmLogLib.h>

extern PmLogContext gLogContext;

/* Logging for webos-connman-adapter context ********
 * The parameters needed are
 * msgid - unique message id
 * kvcount - count for key-value pairs
 * ... - key-value pairs and free text. key-value pairs are formed using PMLOGKS or PMLOGKFV
 * e.g.)
 * WCALOG_CRITICAL(msgid, 2, PMLOGKS("key1", "value1"), PMLOGKFV("key2", "%d", value2), "free text message");
 **********************************************/
#define WCALOG_CRITICAL(msgid, kvcount, ...) \
        PmLogCritical(gLogContext, msgid, kvcount, ##__VA_ARGS__)

#define WCALOG_ERROR(msgid, kvcount, ...) \
        PmLogError(gLogContext, msgid, kvcount,##__VA_ARGS__)

#define WCALOG_WARNING(msgid, kvcount, ...) \
        PmLogWarning(gLogContext, msgid, kvcount, ##__VA_ARGS__)

#define WCALOG_INFO(msgid, kvcount, ...) \
        PmLogInfo(gLogContext, msgid, kvcount, ##__VA_ARGS__)

#define WCALOG_DEBUG(...) \
        PmLogDebug(gLogContext, ##__VA_ARGS__)

#define WCALOG_ESCAPED_ERRMSG(msgid, errmsg) \
    do { \
    gchar *escaped_errtext = g_strescape(errmsg, NULL); \
    WCALOG_ERROR(msgid, 1, PMLOGKS("Error", escaped_errtext), ""); \
    g_free(escaped_errtext); \
    } while(0)

#define WCALOG_ADDR_INFOMSG(msgid, name, addr) \
    do { \
    gchar straddr[16]; \
    snprintf(straddr, 16, "%p", addr); \
    WCALOG_INFO(msgid, 1, PMLOGKS(name, straddr), ""); \
    } while(0)

/** list of MSGID's */

/** common ones */
#define MSGID_WIFI_SRVC_REGISTER_FAIL                   "WIFI_SRVC_REGISTER_FAIL"
#define MSGID_CM_SRVC_REGISTER_FAIL                     "WIFI_CM_REGISTER_FAIL"
#define MSGID_WAN_SRVC_REGISTER_FAIL                    "WAN_SRVC_REGISTER_FAIL"
#define MSGID_PAN_SRVC_REGISTER_FAIL                    "PAN_SRVC_REGISTER_FAIL"

#define MSGID_WAN_SRVC_ALLOC_FAIL                       "WAN_SRVC_ALLOC_FAIL"
#define MSGID_INVALID_STATE                             "INVALID_STATE"

/** main.c */
#define MSGID_WCA_STARTING                              "WCA_STARTING"
#define MSGID_WCA_SUPPORT_FAIL                          "WCA_SUPPORT_FAIL"

/** connman_agent.c */
#define MSGID_AGENT_INIT_ERROR                          "AGENT_INIT_ERR"

/** connman_counter.c */
#define MSGID_COUNTER_INIT_ERROR                        "COUNTER_INIT_ERR"
#define MSGID_COUNTER_EXPORT_SUCCESS                    "COUNTER_EXPORT_SUCCESS"
#define MSGID_CM_DATA_ACTIVITY                          "CM_DATA_ACTIVITY"

/** connman_group.c */
#define MSGID_GROUP_SET_PROPERTY_ERROR                  "GRP_SET_PROPERTY_ERR"
#define MSGID_GROUP_DISCONNECT_ERROR                    "GRP_DISCONNECT_ERR"
#define MSGID_GROUP_INVITE_ERROR                        "GRP_INVITE_ERR"
#define MSGID_GROUP_GET_PROPERTIES_ERROR                "GRP_GET_PROPERTIES_ERR"
#define MSGID_GROUP_INIT_ERROR                          "GRP_INIT_ERR"

/** connman_manager.c */
#define MSGID_MANAGER_GET_PROPERTIES_ERROR              "MGR_GET_PROPERTIES_ERR"
#define MSGID_MANAGER_GET_SERVICES_ERROR                "MGR_GET_SERVICES_ERR"
#define MSGID_MANAGER_GET_SAVED_SERVICES_ERROR          "MGR_GET_SAVED_SERVICES_ERR"
#define MSGID_MANAGER_GET_TECHNOLOGIES_ERROR            "MGR_GET_TECHNOLOGIES_ERR"
#define MSGID_MANAGER_GET_PEERS_ERROR                   "MGR_GET_PEERS_ERR"
#define MSGID_MANAGER_GET_GROUPS_ERROR                  "MGR_GET_GROUPS_ERR"
#define MSGID_MANAGER_CREATE_GROUP_ERROR                "MGR_CREATE_GROUP_ERR"
#define MSGID_MANAGER_STATUS_CHECK                      "MGR_STATUS_CHECK"
#define MSGID_MANAGER_UNREGISTER_AGENT_ERROR            "MGR_UNREGISTER_AGENT_ERR"
#define MSGID_MANAGER_UNREGISTER_COUNTER_ERROR          "MGR_UNREGISTER_COUNTER_ERR"
#define MSGID_MANAGER_STATE_UPDATE_ERROR                "MGR_STATE_UPDATE_ERR"
#define MSGID_MANAGER_INIT_ERROR                        "MGR_INIT_ERR"
#define MSGID_MANAGER_NO_TECH_ERROR                     "MGR_NO_TECH_ERR"
#define MSGID_MANAGER_NO_WIRED_ERROR                    "MGR_NO_WIRED_ERR"
#define MSGID_MANAGER_SET_OFFLINEMODE_ERROR             "MGR_SET_OFFLINEMOE_ERR"
#define MSGID_MANAGER_REGISTER_COUNTER_ERROR            "MGR_REGISTER_COUNTER_ERROR"
#define MSGID_MANAGER_REGISTER_COUNTER_SUCCESS          "MGR_REGISTER_COUNTER_SUCCESS"
#define MSGID_MANAGER_CHANGE_SAVED_SERVICE_ERROR        "MGR_CHANGE_SAVED_SERVICE_ERROR"
#define MSGID_MANAGER_FIELDS_ERROR                      "MGR_FIELDS_ERROR"
#define MSGID_MANAGER_SET_WOL_WOWL_ERROR                "MGR_SET_WOL_WOWL_ERR"

/** connman_service.c */
#define MSGID_SERVICE_CONNECT_ERROR                     "SRVC_CONNECT_ERR"
#define MSGID_SERVICE_DISCONNECT_ERROR                  "SRVC_DISCONNECT_ERR"
#define MSGID_SERVICE_REMOVE_ERROR                      "SRVC_REMOVE_ERR"
#define MSGID_SERVICE_SET_IPV4_ERROR                    "SRVC_SET_IPV4_ERR"
#define MSGID_SERVICE_SET_IPV6_ERROR                    "SRVC_SET_IPV6_ERR"
#define MSGID_SERVICE_SET_NAMESERVER_ERROR              "SRVC_SET_NAMESERVER_ERR"
#define MSGID_SERVICE_AUTOCONNECT_ERROR                 "SRVC_AUTOCONNECT_ERR"
#define MSGID_SERVICE_GET_IPINFO_ERROR                  "SRVC_GET_IPINFO_ERR"
#define MSGID_SERVICE_FETCH_PROPERTIES_ERROR            "SRVC_FETCH_PROPERTIES_ERR"
#define MSGID_SERVICE_INIT_ERROR                        "SRVC_INIT_ERR"
#define MSGID_SERVICE_RUN_ONLINE_CHECK_ERROR            "SRVC_RUN_ONLINE_CHECK_ERROR"
#define MSGID_SERVICE_PASSPHRASE_ERROR          "SRVC_PASSPHRASE_ERR"
#define MSGID_SERVICE_REJECT_PEER_ERROR                 "SRVC_REJECT_PEER_ERR"
#define MSGID_SERVICE_SET_PROXY_ERROR                    "SRVC_SET_PROXY_ERR"

/** connman_service_discovery.c */
#define MSGID_SERVICE_DISCOVERY_REQUEST_ERROR           "SRVC_DISC_REQUEST_ERR"
#define MSGID_SERVICE_DISCOVERY_REGISTER_ERROR          "SRVC_DISC_REGISTER_ERR"
#define MSGID_SERVICE_DISCOVERY_REMOVE_ERROR            "SRVC_DISC_REMOVE_ERR"

/** connman_technology.c */
#define MSGID_TECHNOLOGY_SET_POWERED_ERROR              "TECH_SET_POWERED_ERR"
#define MSGID_TECHNOLOGY_SET_TETHERING_ERROR            "TECH_SET_TETHERING_ERR"
#define MSGID_TECHNOLOGY_SET_TETHERING_IDENTIFIER_ERROR "TECH_SET_TETHERING_IDENTI_ERR"
#define MSGID_TECHNOLOGY_SET_TETHERING_PASSPHRASE_ERROR "TECH_SET_TETHERING_PASSPH_ERR"
#define MSGID_TECHNOLOGY_CANCEL_P2P_ERROR               "TECH_CANCEL_P2P_ERR"
#define MSGID_TECHNOLOGY_CANCEL_WPS_ERROR               "TECH_CANCEL_WPS_ERR"
#define MSGID_TECHNOLOGY_START_WPS_ERROR                "TECH_START_WPS_ERR"
#define MSGID_TECHNOLOGY_SET_COUNTRY_CODE_ERROR         "TECH_SET_COUNTRY_CODE_ERR"
#define MSGID_TECHNOLOGY_DELETE_PROFILE_ERROR           "TECH_DELETE_PROFILE_ERR"
#define MSGID_TECHNOLOGY_SET_MULTI_CHANNEL_ERROR        "TECH_SET_MULTI_CHANNEL_ERR"
#define MSGID_TECHNOLOGY_SET_P2P_ERROR                  "TECH_SET_P2P_ERR"
#define MSGID_TECHNOLOGY_SET_P2P_IDENTIFIER_ERROR       "TECH_SET_IDENTIFIER_ERR"
#define MSGID_TECHNOLOGY_SET_WFD_ERROR                  "TECH_SET_WFD_ERR"
#define MSGID_TECHNOLOGY_SET_WFD_DEVTYPE_ERROR          "TECH_SET_WFD_DEVTYPE_ERR"
#define MSGID_TECHNOLOGY_SET_WFD_SESSION_ERROR          "TECH_SET_WFD_SESSION_ERR"
#define MSGID_TECHNOLOGY_SET_WFD_CPSUPPORT_ERROR        "TECH_SET_WFD_CPSUPPORT_ERR"
#define MSGID_TECHNOLOGY_SET_WFD_RTSPPORT_ERROR         "TECH_SET_WFD_RTSPSUPPORT_ERR"
#define MSGID_TECHNOLOGY_SET_P2P_LISTEN_ERROR           "TECH_SET_P2P_LISTEN_ERR"
#define MSGID_TECHNOLOGY_SET_P2P_PERSISTENT_ERROR       "TECH_SET_P2P_PERSISTENT_ERR"
#define MSGID_TECHNOLOGY_SET_LEGACY_SCAN_ERROR          "TECH_SET_LEGACY_SCAN_ERR"
#define MSGID_TECHNOLOGY_SCAN_ERROR                     "TECH_SCAN_ERR"
#define MSGID_TECHNOLOGY_INIT_ERROR                     "TECH_INIT_ERR"
#define MSGID_TECHNOLOGY_SAVED_SERVICES_ERROR           "TECH_SAVED_SERVICES_ERROR"
#define MSGID_TECHNOLOGY_SET_LISTEM_PARAMS_ERROR        "TECH_SET_LISTEM_PARAMS_ERROR"
#define MSGID_TECHNOLOGY_SET_LISTEM_CHANNEL_ERROR       "TECH_SET_LISTEM_CHANNEL_ERROR"
#define MSGID_TECHNOLOGY_GET_PROPERTIES_ERROR           "TECH_GET_PROPERTIES_ERR"
#define MSGID_TECHNOLOGY_GET_INTERFACE_PROPERTIES_ERROR "TECH_GET_INTERFACE_PROPERTIES_ERR"
#define MSGID_TECHNOLOGY_SET_GO_INTENT_ERROR            "TECH_SET_GO_INTENT_ERR"

/** connectionmanager_service.c */
#define MSGID_WIFI_MAC_ADDR_ERROR                       "WIFI_MAC_ADDR_ERR"
#define MSGID_WIRED_MAC_ADDR_ERROR                      "WIRED_MAC_ADDR_ERR"
#define MSGID_CM_LUNA_BUS_ERROR                         "CM_LUNA_BUS_ERR"
#define MSGID_CM_METHODS_LUNA_ERROR                     "CM_METADATA_LUNA_ERR"
#define MSGID_CM_GLOOP_ATTACH_ERROR                     "CM_GLOOP_ATTACH_ERR"
#define MSGID_CONNECTION_INFO                           "CONNECTION_INFO"
#define MSGID_CM_ONLINE_CHECK_INFO                      "CM_RUN_ONLINE_CHECK_INFO"
#define MSGID_CM_GET_MAC_INFO                           "CM_GET_MAC_INFO"

/** wifi_service.c */
#define MSGID_WIFI_CONNECT_HIDDEN_SERVICE               "WIFI_CONNECT_HIDDEN_SERVICE"
#define MSGID_WIFI_CONNECT_SERVICE                      "WIFI_CONNECT_SERVICE"
#define MSGID_WIFI_DISCONNECT_SERVICE                   "WIFI_DISCONNECT_SERVICE"
#define MSGID_WIFI_AGENT_ERROR                          "WIFI_AGENT_ERR"
#define MSGID_WIFI_COUNTER_ERROR                        "WIFI_COUNTER_ERR"
#define MSGID_WIFI_LUNA_BUS_ERROR                       "WIFI_LUNA_BUS_ERR"
#define MSGID_WIFI_METHODS_LUNA_ERROR                   "WIFI_METHODS_LUNA_ERR"
#define MSGID_WIFI_GLOOP_ATTACH_ERROR                   "WIFI_GLOOP_ATTACH_ERR"
#define MSGID_WIFI_FACTORY_MODE_ERROR                   "WIFI_FACTORY_MODE_ERR"
#define MSGID_WIFI_SKIPPING_FETCH_PROPERTIES            "WIFI_SKIPPING_FETCH_PROPERTIES"
#define MSGID_WIFI_SERVICE_NOT_EXIST                    "WIFI_SERVICE_NOT_EXIST"
#define MSGID_WIFI_CONFIG_INOTIFY_WATCH_ERR             "WIFI_CONFIG_INOTIFY_WATCH_ERR"
#define MSGID_WIFI_SUBSCRIPTIONCANCEL_LUNA_ERROR        "WIFI_SUBSCRIPTIONCANCEL_LUNA_ERROR"

/** Wifi Scan errors */
#define MSGID_WIFI_SCAN_CALLBACK_NOT_RUNNING            "WIFI_SCAN_CALLBACK_NOT_RUNNING"
#define MSGID_WIFI_SCAN_ADD_INTERVAL_STATE_MISMATCH     "WIFI_SCAN_ADD_INTERVAL_STATE_MISMATCH"
#define MSGID_WIFI_SCAN_ADD_INTERVAL_INVALID_PARAMS     "WIFI_SCAN_ADD_INTERVAL_INVALID_PARAMS"
#define MSGID_WIFI_SCAN_START_ALREADY_STARTED           "WIFI_SCAN_START_ALREADY_STARTED"
#define MSGID_WIFI_SCAN_STOP_ALREADY_STOPPED            "WIFI_SCAN_STOP_ALREADY_STOPPED"
#define MSGID_WIFI_SCAN_REMOVE_INVERVAL_NOT_FOUND       "WIFI_SCAN_REMOVE_INVERVAL_NOT_FOUND"

/** wifi_p2p_service.c */
#define MSGID_P2P_CONNECT_PEER                          "P2P_CONNECT_PEER"
#define MSGID_P2P_DISCONNECT_PEER                       "P2P_DISCONNECT_PEER"
#define MSGID_P2P_INVITE_PEER                           "P2P_INVITE_PEER"
#define MSGID_P2P_DISCONNECT_GROUP                      "P2P_DISCONNECT_GRP"
#define MSGID_P2P_SET_TETHERING                         "P2P_SET_TETHERING"
#define MSGID_P2P_DELETE_PROFILE                        "P2P_DELETE_PROFILE"
#define MSGID_P2P_METHODS_LUNA_ERROR                    "P2P_METHODS_LUNA_ERR"
#define MSGID_SETTINGS_SERVICE_REG_ERROR                "SETTINGS_SRVC_REG_ERR"

/* lunaservice_utils.c */
#define MSGID_LUNA_CREATE_JSON_FAILED                   "LUNA_CREATE_JSON_FAILED"
#define MSGID_LUNA_SEND_FAILED                          "LUNA_SEND_FAILED"

/** wifi_tethering_service. */
#define MSGID_TETHERING_METHODS_LUNA_ERROR              "TETHERING_METHODS_LUNA_ERR"

/** wifi_setting.c */
#define MSGID_SETTING_LPAPP_GET_ERROR                   "SETTING_LPAPP_GET_ERR"
#define MSGID_SETTING_LPAPP_COPY_ERROR                  "SETTING_LPAPP_COPY_ERR"
#define MSGID_SETTING_LPAPP_REMOVE_ERROR                "SETTING_LPAPP_REMOVE_ERR"
#define MSGID_SETTING_LPAPP_SET_ERROR                   "SETTING_LPAPP_SET_ERR"

/** pan_service.c */
#define MSGID_PAN_LUNA_BUS_ERROR                       "PAN_LUNA_BUS_ERR"
#define MSGID_PAN_METHODS_LUNA_ERROR                   "PAN_METHODS_LUNA_ERR"
#define MSGID_PAN_GLOOP_ATTACH_ERROR                   "PAN_GLOOP_ATTACH_ERR"
#define MSGID_PAN_CONNECT_SERVICE_ERROR                "PAN_CONNECT_SERVICE_ERROR"
#define MSGID_PAN_SKIPPING_FETCH_PROPERTIES            "PAN_SKIPPING_FETCH_PROPERTIES"
#define MSGID_PAN_SERVICE_NOT_EXIST                    "PAN_SERVICE_NOT_EXIST"

/** country_code.c */
#define MSGID_COUNTRY_CODE_INFO                         "COUNTRY_CODE_INFO"
#define MSGID_COUNTRY_CODE_FAILED                       "COUNTRY_CODE_FAILED"

/** nyx.c */
#define MSGID_NYX_INIT_ERROR                            "NYX_INIT_ERROR"
#define MSGID_NYX_DEVICE_OPEN_ERROR                     "NYX_DEVICE_OPEN_ERROR"
#define MSGID_NYX_DEVICE_CLOSE_ERROR                    "NYX_DEVICE_CLOSE_ERROR"
#define MSGID_NYX_DEINIT_ERROR                          "NYX_DEINIT_ERROR"

/** Wan info codes **/
#define MSGID_WAN_CONNECT_INFO                          "WAN_CONNECT_INFO"
#define MSGID_WAN_DISCONNECT_INFO                       "WAN_DISCONNECT_INFO"
#define MSGID_WAN_SET_HOSTROUTE_ERROR                   "WAN_SET_HOSTROUTE_ERR"

/** json_utils.c **/
#define MSGID_JSON_KEY_NULL                             "JSON_KEY_NULL"
#define MSGID_JSON_DEST_NULL                            "JSON_DEST_NULL"
#define MSGID_JSON_INVALID_TYPE                         "JSON_INVALID_TYPE"
#define MSGID_JSON_NOT_A_NUMEBR                         "JSON_NOT_A_NUMEBR"
#define MSGID_JSON_NOT_A_STRING                         "JSON_NOT_A_STRING"
#define MSGID_JSON_NOT_A_OBJECT                         "JSON_NOT_A_OBJECT"
#define MSGID_JSON_NOT_AN_ARRAY                         "JSON_NOT_AN_ARRAY"
#define MSGID_JSON_MANDATORY_FIELD_MISSING              "JSON_MANDATORY_FIELD_MISSING"
#define MSGID_JSON_NUMBER_OUT_OF_RANGE                  "JSON_NUMBER_OUT_OF_RANGE"

/** pacrunner_client.c **/
#define MSGID_PACRUNNER_CLIENT_INIT_ERROR					"MGR_PACRUNNER_CLIENT_INIT_ERR"
#define MSGID_PACRUNNER_CLIENT_FINDPROXYFORURL_ERROR    "MGR_PACRUNNER_CLIENT_FINDPROXYFORURL_ERR"

/** state_recovery.c **/
#define MSGID_STATE_RECOVERY_INFO                  "STATE_RECOVERY_INFO"

/** list of logkey ID's */

#define ERRTEXT         "Error"
#define FUNC            "Function"

#endif // __LOGGING_H__
