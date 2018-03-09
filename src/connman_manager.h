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
 * @file  connman_manager.h
 *
 * @brief Header file defining functions and data structures for interacting with connman manager
 *
 */

#ifndef CONNMAN_MANAGER_H_
#define CONNMAN_MANAGER_H_

#include <wca-support.h>

#include "connman_common.h"
#include "connman_service.h"
#include "connman_technology.h"
#include "connman_group.h"

#define ETHERNET_SERVICES_CHANGED   1
#define WIFI_SERVICES_CHANGED       2
#define P2P_SERVICES_CHANGED        4
#define CELLULAR_SERVICES_CHANGED   8
#define BLUETOOTH_SERVICES_CHANGED  16

/**
 * Callback function for handling any changes in connman services
 *
 * @param[IN] gpointer Any data to pass to this function
 * @param[OUT] unsigned char ORing of types of services changed
 *             (see above for types of services)
 */
typedef void (*connman_services_changed_cb)(gpointer, unsigned char);

typedef void (*connman_groups_changed_cb)(gpointer, gboolean);

typedef void (*connman_technologies_changed_cb)(gpointer);

extern wca_support_connman_update_callbacks *connman_update_callbacks;

/**
 * Local instance of a connman manager
 *
 * Stores all required information, including current services and technologies
 */

typedef struct connman_manager
{
	ConnmanInterfaceManager *remote;
	gchar   *state;
	GSList  *wifi_services;
	GSList  *wired_services;
	GSList  *p2p_services;
	GSList  *cellular_services;
	GSList  *bluetooth_services;
	GSList  *saved_services;
	GSList  *technologies;
	GSList  *groups;
	gboolean offline;
	gboolean wol_wowl;
	connman_property_changed_cb handle_property_change_fn;
	connman_services_changed_cb handle_services_change_fn;
	connman_groups_changed_cb   handle_groups_change_fn;
	connman_technologies_changed_cb handle_technologies_change_fn;
} connman_manager_t;

/**
 * Traverse through the given service list, comparing each service with the path provided
 * returning the service with the matching path
 *
 * @param[IN] service_list Manager's wired / wifi service list
 * @param[IN] path Service DBus object path to compare
 *
 * @return service with matching path, NULL if no matching service found
 */

extern connman_service_t *connman_manager_find_service_by_path(
    GSList *service_list, const gchar *path);

/**
 * Check if the manager is NOT in offline mode, i.e available to enable network
 * connections
 *
 * @param[IN]  manager A manager instance
 *
 * @return TRUE if manager's "offlineMode" property is FALSE
 */
extern gboolean connman_manager_is_manager_available(connman_manager_t
        *manager);

/**
 * Offlinemode on/off the given manager (see header for API details)
 *
 * @param[IN]  manager A manager instance
 * @param[IN]  state TRUE to enable offline mode, FALSE otherwise
 *
 * @return TRUE if the offline mode was set successfully
 */

gboolean connman_manager_set_offlinemode(connman_manager_t *manager,
        gboolean state);

/**
 * Enable/Disable the WOL/WOWL
 *
 * @param[IN]  technology A manager instance
 * @param[IN]  state TRUE for enable WOL/WOWL, FALSE for off
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_manager_set_wol_wowl_mode(connman_manager_t *manager, gboolean state);

/**
 * Check if the manager's state is "online"
 *
 * @param[IN]  manager A manager instance
 *
 * @return TRUE if manager's state is "online"
 */
extern gboolean connman_manager_is_manager_online(connman_manager_t *manager);

extern connman_technology_t *connman_manager_find_technology_by_name(
    connman_manager_t *manager, const char *name);

/**
 * Go through the manager's technologies list and get the technology with type "wifi"
 *
 * @param[IN]  manager A manager instance
 *
 * @return Technology with type "wifi"
 */
extern connman_technology_t *connman_manager_find_wifi_technology(
    connman_manager_t *manager);

/**
 * Go through the manager's technologies list and get the technology with type "wired"
 *
 * @param[IN]  manager A manager instance
 *
 * @return Technology with type "wired"
 */
extern connman_technology_t *connman_manager_find_ethernet_technology(
    connman_manager_t *manager);

/**
* Go through the manager's technologies list and get the technology with type "cellular"
*
* @param[IN]  manager A manager instance
*
* @return Technology with type "cellular"
*/
extern connman_technology_t *connman_manager_find_cellular_technology(
    connman_manager_t *manager);

/**
* Go through the manager's technologies list and get the technology with type "bluetooth"
*
* @param[IN]  manager A manager instance
*
* @return Technology with type "bluetooth"
*/
extern connman_technology_t *connman_manager_find_bluetooth_technology(
    connman_manager_t *manager);

/**
 * Go through the manager's given services list and get the one which is in "ready" or
 * "online" state , i.e  one of the connected states.
 *
 * @param[IN]  service_list Manager's service list (wired of wifi)
 *
 * @return Service which is in one of the connected states
 */
extern connman_service_t *connman_manager_get_connected_service(
    GSList *service_list);

/**
 * Go through the manager's given service list and find the currently connecting service
 * and return it.
 *
 * @param[IN]  service_list Manager's service list (wired of wifi)
 *
 * @return Service which is currently connecting.
 */
extern connman_service_t *connman_manager_get_connecting_service(
    GSList *service_list);

/**
 * Register for manager's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */
extern void connman_manager_register_property_changed_cb(
    connman_manager_t *manager, connman_property_changed_cb func);

/**
 * Register for manager's state changed case, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */
extern void connman_manager_register_services_changed_cb(
    connman_manager_t *manager, connman_services_changed_cb func);

/**
 * Register a agent instance on the specified dbus path with the manager
 *
 * @param[IN] DBus object path where the agents is available
 *
 * @return TRUE, if agent was successfully registered with the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_register_agent(connman_manager_t *manager,
        const gchar *path);

/**
 * Unegister a agent instance on the specified dbus path from the manager
 *
 * @param[IN] DBus object path where the agents is available
 *
 * @return TRUE, if agent was successfully unregistered from the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_unregister_agent(connman_manager_t *manager,
        const gchar *path);

/**
 * Register a counter instance on the specified dbus path with the manager
 *
 * @param[IN] DBus object path where the counter is available
 * @param[IN] accurancy which is is specified in kilo-bytes and defines a threshold for counter updates.
 * @param[IN] period value is in seconds
 *
 * @return TRUE, if counter was successfully registered with the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_register_counter(connman_manager_t *manager,
        const gchar *path, guint accuracy, guint period);

/**
 * Unegister a counter instance on the specified dbus path from the manager
 *
 * @param[IN] DBus object path where the agents is available
 *
 * @return TRUE, if counter was successfully unregistered from the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_unregister_counter(connman_manager_t *manager,
        const gchar *path);

/**
 * Create a new group
 *
 * @param [IN] manager A manager instance
 * @param [IN] ssid Name of the new group
 * @param [IN] passphrase Passphrase for the group
 *
 * @return TRUE, if the group creation was successful, FALSE otherwise.
 **/

extern connman_group_t *connman_manager_create_group(connman_manager_t *manager,
        const gchar *ssid, const gchar *passphrase);

/*
 * Get the number of connected station
 */
extern guint connman_manager_get_sta_count(connman_manager_t *manager);

/**
 * Populate the group's peer_list field with all of the group's peers
 *
 * @param [IN] manager A manager instance
 * @param [IN] group A group instance
 *
 * @return TRUE, if the group peers are correctly populated, FALSE otherwise.
 **/

extern gboolean connman_manager_populate_group_peers(connman_manager_t *manager,
        connman_group_t *group);

/**
 * Register for manager's "GroupAdded" and "GroupRemoved" siganls, calling the provided function whenever the callback function
 * for any of those signals is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */

extern void connman_manager_register_groups_changed_cb(connman_manager_t
        *manager, connman_groups_changed_cb func);

/**
 * Register for manager's "TechnologyAdded" and "TechnologyRemoved" siganls, calling the provided function whenever the callback function
 * for any of those signals is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */

extern void connman_manager_register_technologies_changed_cb(
    connman_manager_t *manager, connman_technologies_changed_cb func);

/**
 * Change passphrase of a network saved by connman i.e a network settings created by connman
 * but currently network is out of range
 *
 * @param[IN] manager A manager instance
 * @param[IN] service Saved service whose passphrase needs to be changed
 * @param[IN] passphrase The new passphrase to be saved
 *
 */

extern gboolean connman_manager_change_saved_passphrase(
    connman_manager_t *manager, connman_service_t *service,
    const gchar *passphrase);

/**
 * Initialize a new manager instance and update its services and technologies list
 */
extern connman_manager_t *connman_manager_new(void);

/**
 * Free the manager instance
 *
 * @param[IN]  manager A manager instance
 */
extern void connman_manager_free(connman_manager_t *manager);

/**
 * Set the wca library functionpointers
 *
 * @param[IN] manager A manager instance
 * @param[IN] service Saved service whose passphrase needs to be changed
 * @param[IN] passphrase The new passphrase to be saved
 *
 */
extern void set_wca_support_connman_update_callbacks(
    wca_support_connman_update_callbacks *callbacks);

#endif /* CONNMAN_MANAGER_H_ */

