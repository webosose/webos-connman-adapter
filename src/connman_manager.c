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
 * @file connman_manager.c
 *
 * @brief Connman manager interface
 *
 */

#include "connman_manager.h"
#include "logging.h"
#include "connectionmanager_service.h"
#include "utils.h"


wca_support_connman_update_callbacks *connman_update_callbacks = { { NULL } };

/**
 * Retrieve all the properties of the given manager instance
 *
 * @param[IN]  manager A manager instance
 *
 * @return A GVariant pointer containing manager properties, NULL if
 *         the call to get properties fails
 */

GVariant *connman_manager_get_properties(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GError *error = NULL;
	GVariant *ret;

	connman_interface_manager_call_get_properties_sync(manager->remote,
	        &ret, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_GET_PROPERTIES_ERROR, error->message);
		g_error_free(error);
		return NULL;
	}

	return ret;
}

/**
 * Get the service in the manager's list matching the path.
 *
 * @param[IN]  manager A connman manager instance
 * @param[IN]  path A path string to find.
 * @param[IN]  saved A gboolean indicating if this is a saved network
 *
 * @return A service with the path matching the one in path, NULL if
 *         no such service found
 */

static connman_service_t *find_service_from_path(connman_manager_t *manager,
                                          const gchar* path,
                                          gboolean saved)
{
	if (NULL == manager || NULL == path)
	{
		return NULL;
	}

	connman_service_t *service = NULL;

	if (saved == TRUE)
	{
		service = connman_manager_find_service_by_path(manager->saved_services, path);
	}
	else
	{
		service = connman_manager_find_service_by_path(manager->wifi_services, path);

		if (NULL != service)
		{
			return service;
		}

		service = connman_manager_find_service_by_path(manager->wired_services, path);

		if (NULL != service)
		{
			return service;
		}

		service = connman_manager_find_service_by_path(manager->p2p_services, path);

		if (NULL != service)
		{
			return service;
		}

		service = connman_manager_find_service_by_path(manager->bluetooth_services,
		                                               path);

		if (NULL != service)
		{
			return service;
		}

		service = connman_manager_find_service_by_path(manager->cellular_services,
		                                               path);
	}

	return service;
}

/*
 * Traverse through the manager's technologies list and return the technology
 * matching the path provided
 *
 * @param[IN] manager A connman manager instance
 * @param[IN] path Technology object path to compare
 *
 * @return Technology with matching path, NULL if matching technology not found
 */

static connman_technology_t *find_technology_by_path(connman_manager_t *manager,
        gchar *path)
{
	if (NULL == manager || NULL == path)
	{
		return NULL;
	}

	GSList *iter = NULL;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *technology = (connman_technology_t *)(iter->data);

		if (technology == NULL)
		{
			continue;
		}

		if (g_strcmp0(technology->path, path) == 0)
		{
			return technology;
		}
	}

	return NULL;
}

/**
 * Check if the given service's "Ethernet" properties matches system's wifi/wired interface
 *
 * @param[IN]  service_v GVariant listing service properties
 *
 * @return TRUE if the service is either on wifi/wired interface, FALSE otherwise
 */

static gboolean service_on_configured_iface(GVariant *service_v)
{
	if (NULL == service_v)
	{
		return FALSE;
	}

	GVariant *properties = g_variant_get_child_value(service_v, 1);
	gsize i;

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (!g_strcmp0(key, "Ethernet"))
		{
			GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_child_value(v, 0);
			gsize j;

			for (j = 0; j < g_variant_n_children(va); j++)
			{
				GVariant *ethernet = g_variant_get_child_value(va, j);
				GVariant *ekey_v = g_variant_get_child_value(ethernet, 0);
				const gchar *ekey = g_variant_get_string(ekey_v, NULL);

				if (!g_strcmp0(ekey, "Interface"))
				{
					GVariant *ifacev = g_variant_get_child_value(ethernet, 1);
					GVariant *ifaceva = g_variant_get_variant(ifacev);
					const gchar *iface = g_variant_get_string(ifaceva, NULL);

					g_variant_unref(properties);
					g_variant_unref(property);
					g_variant_unref(key_v);
					g_variant_unref(v);
					g_variant_unref(va);
					g_variant_unref(ethernet);
					g_variant_unref(ekey_v);
					g_variant_unref(ifacev);
					g_variant_unref(ifaceva);

					if (!g_strcmp0(iface, CONNMAN_WIFI_INTERFACE_NAME) ||
					        !g_strcmp0(iface, CONNMAN_WIRED_INTERFACE_NAME))
					{
						return TRUE;
					}
					else
					{
						return FALSE;
					}
				}

				g_variant_unref(ethernet);
				g_variant_unref(ekey_v);
			}

			g_variant_unref(v);
			g_variant_unref(va);
		}
		else if (!g_strcmp0(key, "Type"))
		{
			GVariant *v = g_variant_get_child_value(property, 1);
			GVariant *va = g_variant_get_child_value(v, 0);

			const gchar *type = g_variant_get_string(va, NULL);

			g_variant_unref(v);
			g_variant_unref(va);

			if (!g_strcmp0(type, "Peer"))
			{
				g_variant_unref(properties);
				g_variant_unref(property);
				g_variant_unref(key_v);

				return TRUE;
			}
			else if (!g_strcmp0(type, "cellular"))
			{
				g_variant_unref(properties);
				g_variant_unref(property);
				g_variant_unref(key_v);

				return TRUE;
			}
			else if (!g_strcmp0(type, "bluetooth"))
			{
				g_variant_unref(properties);
				g_variant_unref(property);
				g_variant_unref(key_v);

				return TRUE;
			}

		}

		g_variant_unref(property);
		g_variant_unref(key_v);
	}

	g_variant_unref(properties);

	return FALSE;
}

/**
 * Add the given service to manager's wifi/wired list based on the type of service
 *
 * @param[IN] manager A connman manager instance
 * @param[IN] service A service instance
 * @param[IN}  saved A gboolean indicating if this is a saved network
 */

static void add_service_to_list(connman_manager_t *manager,
                                connman_service_t *service, gboolean saved)
{
	if (saved == TRUE)
	{
		WCALOG_DEBUG("Adding saved service %s", service->path);
		manager->saved_services = g_slist_append(manager->saved_services, service);
	}
	else
	{
		WCALOG_DEBUG("Adding service %s, type %d", service->path, service->type);

		if (connman_service_type_wifi(service))
		{
			manager->wifi_services = g_slist_append(manager->wifi_services, service);
		}
		else if (connman_service_type_ethernet(service))
		{
			manager->wired_services = g_slist_append(manager->wired_services, service);
		}
		else if (connman_service_type_p2p(service))
		{
			manager->p2p_services = g_slist_append(manager->p2p_services, service);
		}
		else if (connman_service_type_wan(service))
		{
			manager->cellular_services = g_slist_append(manager->cellular_services,
			                             service);
		}
		else if (connman_service_type_bluetooth(service))
		{
			manager->bluetooth_services = g_slist_append(manager->bluetooth_services,
			                              service);
		}
	}
}

/**
 * Process new service data from connman.
 * Either update existing service or create new service.
 *
 * @param[IN] manager A connman manager instance
 * @param[IN] service_v A gvariant with service properties and values to update.
 * @param[IN] saved A gboolean indicating if this is a saved network
 *
 * @return A pointer to service if service was added or updated, NULL otherwise.
 */
static connman_service_t* update_or_add_service(connman_manager_t *manager,
                                      GVariant *service_v,
                                      gboolean saved)
{
	GVariant *path_v = g_variant_get_child_value(service_v, 0);
	GVariant *properties = g_variant_get_child_value(service_v, 1);
	const gchar *path = g_variant_get_string(path_v, NULL);
	connman_service_t *service = NULL;

	service = find_service_from_path(manager, path, saved);

	if (NULL != service)
	{
		connman_service_update_properties(service, properties);
	}
	else
	{
		/* Only in case that the service was added as new one it contains all
		 * properties and we can check wether it's on one of the supported
		 * network interfaces. If the service is a cellular one we ignore the
		 * interface check as the interface is just way to route data and not
		 * the primary control point. */
		if (saved || service_on_configured_iface(service_v) == TRUE)
		{
			service = connman_service_new(service_v);
			add_service_to_list(manager, service, saved);
		}
	}

	g_variant_unref(properties);
	g_variant_unref(path_v);

	return service;
}

/**
 * Go through the list of services in the "services" parameter and if the service
 * is already present in the manager's list , update its properties, and if not , add it
 * as a new service.
 *
 * @param[IN] manager A manager instance
 * @param[IN] services Properties of a new/existing service
 * @param[IN}  saved A gboolean indicating if this is a saved network
 * @param[OUT] service_type Flags ORing type of services updated
 *
 * @return TRUE only if any service is updated or added, return FALSE otherwise
 */

static gboolean connman_manager_update_services(connman_manager_t *manager,
        GVariant *services, unsigned char *service_type, gboolean saved)
{
	if (NULL == manager || NULL == services)
	{
		return FALSE;
	}

	gsize i;
	gboolean update_considered = FALSE;

	for (i = 0; i < g_variant_n_children(services); i++)
	{
		GVariant *service_v = g_variant_get_child_value(services, i);
		connman_service_t *service = update_or_add_service(manager, service_v, saved);
		g_variant_unref(service_v);

		if (!service)
		{
			continue;
		}

		update_considered = TRUE;

		/* determine service type only if the supplied argument for storing it is non-NULL
		 * (i.e not for saved networks) and when we're sure that something has changed
		 * otherwise it doesn't make sense
		 */
		if (service_type)
		{
			switch (service->type)
			{
				case CONNMAN_SERVICE_TYPE_ETHERNET:
					*service_type |= ETHERNET_SERVICES_CHANGED;
					break;

				case CONNMAN_SERVICE_TYPE_WIFI:
					*service_type |= WIFI_SERVICES_CHANGED;
					break;

				case CONNMAN_SERVICE_TYPE_P2P:
					*service_type |= P2P_SERVICES_CHANGED;
					break;

				case CONNMAN_SERVICE_TYPE_CELLULAR:
					*service_type |= CELLULAR_SERVICES_CHANGED;
					break;

				case CONNMAN_SERVICE_TYPE_BLUETOOTH:
					*service_type |= BLUETOOTH_SERVICES_CHANGED;
					break;

				default:
					break;
			}
		}
	}

	return update_considered;
}

/**
 * Remove services in the "services_removed" list from the given "service_list" list
 *
 * @param[IN] service_list Manager's wifi/wired list
 * @param[IN] services_removed List of services removed
 * @param[OUT] service_type Flags ORing type of services removed
 *
 * @return TRUE only if any service is removed from the list, FALSE otherwise
 */

static gboolean remove_services_from_list(GSList **service_list,
        gchar **services_removed)
{
	GSList *iter, *remove_list = NULL;
	gboolean ret = FALSE;
	gchar **services_removed_iter = services_removed;

	/* look for removed services */
	while (NULL != *services_removed_iter)
	{
		for (iter = *service_list; NULL != iter; iter = iter->next)
		{
			connman_service_t *service = (connman_service_t *)(iter->data);

			if (!g_strcmp0(service->path, *services_removed_iter))
			{
				WCALOG_DEBUG("Removing service : %s", service->name);
				remove_list = g_slist_append(remove_list, service);
				break;
			}
		}

		services_removed_iter = services_removed_iter + 1;
	}

	/*
	 * do the actual remove of services in an extra loop, so we don't
	 * alter the list we're walking
	 */
	for (iter = remove_list; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);
		*service_list = g_slist_delete_link(*service_list, g_slist_find(*service_list,
		                                    service));
		connman_service_free(service, NULL);
		ret = TRUE;
	}

	g_slist_free(remove_list);
	return ret;
}

/**
 * Remove all the wifi services in the "services_removed" string array from the manager's wifi service list
 * and thereafter removing wired services in "services_removed" from the manager's wired service list
 *
 * @param[IN] manager A manager instance
 * @param[IN] services_removed List of services removed
 *
 * @return TRUE only if atleast one service is removed, else return FALSE
 *
 */

static gboolean connman_manager_remove_old_services(connman_manager_t *manager,
        gchar **services_removed, unsigned char *service_type)
{
	if (NULL == manager || NULL == services_removed)
	{
		return FALSE;
	}

	gboolean wifi_services_removed = FALSE, wired_services_removed = FALSE,
	         p2p_services_removed = FALSE, cellular_services_removed = FALSE,
	         bluetooth_services_removed = FALSE;

	wifi_services_removed = remove_services_from_list(&manager->wifi_services,
	                        services_removed);
	wired_services_removed = remove_services_from_list(&manager->wired_services,
	                         services_removed);
	p2p_services_removed = remove_services_from_list(&manager->p2p_services,
	                       services_removed);
	cellular_services_removed = remove_services_from_list(
	                                &manager->cellular_services, services_removed);
	bluetooth_services_removed = remove_services_from_list(
	                                 &manager->bluetooth_services, services_removed);

	if (wired_services_removed)
	{
		*service_type |= ETHERNET_SERVICES_CHANGED;
	}

	if (wifi_services_removed)
	{
		*service_type |= WIFI_SERVICES_CHANGED;
	}

	if (p2p_services_removed)
	{
		*service_type |= P2P_SERVICES_CHANGED;
		// Refresh the peer list for all the groups as the removed service might be one of them
		GSList *iter;

		for (iter = manager->groups; NULL != iter; iter = iter->next)
		{
			connman_group_t *group = (connman_group_t *)(iter->data);
			connman_manager_populate_group_peers(manager, group);
		}
	}

	if (cellular_services_removed)
	{
		*service_type |= CELLULAR_SERVICES_CHANGED;
	}

	if (bluetooth_services_removed)
	{
		*service_type |= BLUETOOTH_SERVICES_CHANGED;
	}

	return (wifi_services_removed | wired_services_removed | p2p_services_removed |
	        cellular_services_removed | bluetooth_services_removed);
}

/**
 * Free the manager's services wifi and wired service list
 *
 * @param[IN]  manager A manager instance
 *
 */

static void connman_manager_free_services(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return;
	}

	g_slist_foreach(manager->wifi_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->wifi_services);
	manager->wifi_services = NULL;

	g_slist_foreach(manager->wired_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->wired_services);
	manager->wired_services = NULL;

	g_slist_foreach(manager->p2p_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->p2p_services);
	manager->p2p_services = NULL;

	g_slist_foreach(manager->cellular_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->cellular_services);
	manager->cellular_services = NULL;

	g_slist_foreach(manager->bluetooth_services, (GFunc) connman_service_free,
	                NULL);
	g_slist_free(manager->bluetooth_services);
	manager->bluetooth_services = NULL;

	g_slist_foreach(manager->saved_services, (GFunc) connman_service_free, NULL);
	g_slist_free(manager->saved_services);
	manager->saved_services = NULL;
}

/**
 * Free the manager's technologies list
 *
 * @param[IN]  manager A manager instance
 *
 */

static void connman_manager_free_technologies(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return;
	}

	g_slist_foreach(manager->technologies, (GFunc) connman_technology_free, NULL);
	g_slist_free(manager->technologies);
	manager->technologies = NULL;
}

/**
 * Free the manager's groups list
 *
 * @param[IN]  manager A manager instance
 *
 */

static void connman_manager_free_groups(connman_manager_t *manager)

{
	if (NULL == manager)
	{
		return;
	}

	g_slist_foreach(manager->groups, (GFunc) connman_group_free, NULL);
	g_slist_free(manager->groups);
	manager->groups = NULL;
}

/**
 * Retrieve all the services for the manager by making a "GetServices" remote call
 * and add them to its list
 *
 * @param[IN]  manager A manager instance
 *
 * @return FALSE if the remote call fails
 */

static gboolean connman_manager_add_services(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *services;
	gsize i;

	connman_interface_manager_call_get_services_sync(manager->remote,
	        &services, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_GET_SERVICES_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	if (connman_update_callbacks->services_changed)
	{
		connman_update_callbacks->services_changed(services, NULL);
	}


	for (i = 0; i < g_variant_n_children(services); i++)
	{
		GVariant *service_v = g_variant_get_child_value(services, i);
		(void)update_or_add_service(manager, service_v, FALSE);
		g_variant_unref(service_v);
	}

	g_variant_unref(services);

	return TRUE;
}

/**
 * Change passphrase of a network saved by connman i.e a network settings created by connman
 * but currently network is out of range
 *
 * @param[IN] manager A manager instance
 * @param[IN] service Saved service whose passphrase needs to be changed
 * @param[IN] passphrase The new passphrase to be saved
 *
 */

gboolean connman_manager_change_saved_passphrase(connman_manager_t *manager,
        connman_service_t *service, const gchar *passphrase)
{
	if (NULL == manager || NULL == service)
	{
		return FALSE;
	}

	GError *error = NULL;

	GVariantBuilder *key_b;
	GVariant *key_v;

	key_b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(key_b, "{sv}", "Passphrase",
	                      g_variant_new_string(passphrase));
	key_v = g_variant_builder_end(key_b);
	g_variant_builder_unref(key_b);


	connman_interface_manager_call_change_saved_service_sync(manager->remote,
	        service->identifier, key_v, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_CHANGE_SAVED_SERVICE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}



/**
 * Retrieve all the technologies for the manager by making a "GetTechnologies" remote call
 * and add them to its list
 *
 * @param[IN]  manager A manager instance
 *
 * @return FALSE if the remote call fails, TRUE otherwise
 */

static gboolean connman_manager_add_technologies(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *technologies;
	gsize i;

	connman_interface_manager_call_get_technologies_sync(manager->remote,
	        &technologies, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_GET_TECHNOLOGIES_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	for (i = 0; i < g_variant_n_children(technologies); i++)
	{
		GVariant *technology_v = g_variant_get_child_value(technologies, i);
		GVariant *path = g_variant_get_child_value(technology_v, 0);
		connman_technology_t *technology = connman_technology_new(g_variant_get_string(path, NULL));

		if (technology != NULL)
		{
			manager->technologies = g_slist_append(manager->technologies, technology);
		}

		g_variant_unref(path);
		g_variant_unref(technology_v);
	}

	g_variant_unref(technologies);

	return TRUE;
}

/*
 * Traverse through the manager's groups list and return the group
 * matching the path provided
 *
 * @param[IN] manager A connman manager instance
 * @param[IN] path Group object path to compare
 *
 * @return Group with matching path, NULL if matching group not found
 */

static connman_group_t *find_group_by_path(connman_manager_t *manager,
        const gchar *path)
{
	if (NULL == manager || NULL == path)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->groups; NULL != iter; iter = iter->next)
	{
		connman_group_t *group = (connman_group_t *)(iter->data);

		if (!g_strcmp0(group->path, path))
		{
			return group;
		}
	}

	return NULL;
}

/*
 * Populate the group's peers (see header for API details)
 */
gboolean connman_manager_populate_group_peers(connman_manager_t *manager,
        connman_group_t *group)
{
	if (NULL == group)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *peers = NULL;
	gsize i, j;

	connman_interface_group_call_get_peers_sync(group->remote, &peers, NULL,
	        &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_GET_PEERS_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	g_slist_free(group->peer_list);
	group->peer_list = NULL;

	for (i = 0; i < g_variant_n_children(peers); i++)
	{
		GVariant *peer_v = g_variant_get_child_value(peers, i);
		GVariant *o = g_variant_get_child_value(peer_v, 0);
		const gchar *path = g_variant_get_string(o, NULL);

		connman_service_t *peer = NULL;
		GSList *iter;
		gboolean peer_added = FALSE;

		for (iter = manager->p2p_services; NULL != iter; iter = iter->next)
		{
			peer = (connman_service_t *)(iter->data);

			if (!g_strcmp0(peer->path, path))
			{
				group->peer_list = g_slist_append(group->peer_list, peer);
				peer_added = TRUE;
				break;
			}
		}

		if (!peer_added)
		{
			g_variant_unref(peer_v);
			g_variant_unref(o);

			continue;
		}

		GVariant *properties = g_variant_get_child_value(peer_v, 1);

		for (j = 0; j < g_variant_n_children(properties); j++)
		{
			GVariant *property = g_variant_get_child_value(properties, j);
			GVariant *key_v = g_variant_get_child_value(property, 0);
			GVariant *val_v = g_variant_get_child_value(property, 1);
			GVariant *val = g_variant_get_variant(val_v);
			const gchar *key = g_variant_get_string(key_v, NULL);

			if (!g_strcmp0(key, "IPAddress"))
			{
				g_free(peer->ipinfo.ipv4.address);
				peer->ipinfo.ipv4.address = g_variant_dup_string(val, NULL);
			}

			g_variant_unref(property);
			g_variant_unref(key_v);
			g_variant_unref(val_v);
			g_variant_unref(val);
		}

		g_variant_unref(properties);
		g_variant_unref(peer_v);
		g_variant_unref(o);
	}

	g_variant_unref(peers);

	return TRUE;
}

/**
 * Retrieve all the groups for the manager by making a "GetGroups" remote call
 * and add them to its list
 *
 * @param[IN]  manager A manager instance
 *
 * @return FALSE if the remote call fails, TRUE otherwise
 */

static gboolean connman_manager_add_groups(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	GError *error = NULL;
	GVariant *groups;
	gsize i;

	connman_interface_manager_call_get_groups_sync(manager->remote,
	        &groups, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_GET_GROUPS_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	for (i = 0; i < g_variant_n_children(groups); i++)
	{
		GVariant *group_v = g_variant_get_child_value(groups, i);
		connman_group_t *group;

		GVariant *o = g_variant_get_child_value(group_v, 0);
		const gchar *path = g_variant_get_string(o, NULL);

		if (connman_update_callbacks->group_added)
		{
			connman_update_callbacks->group_added(path, group_v);
		}

		if (!find_group_by_path(manager, path))
		{
			group = connman_group_new(group_v);
			manager->groups = g_slist_append(manager->groups, group);
			connman_manager_populate_group_peers(manager, group);
		}

		g_variant_unref(group_v);
		g_variant_unref(o);

	}

	g_variant_unref(groups);

	return TRUE;
}

/*
 * Create a new group (see header for API details)
 */

connman_group_t *connman_manager_create_group(connman_manager_t *manager,
        const gchar *ssid, const gchar *passphrase)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	GError *error = NULL;
	gchar *group_path = NULL;

	connman_interface_manager_call_create_group_sync(manager->remote,
	        ssid, passphrase, &group_path, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_CREATE_GROUP_ERROR, error->message);
		g_error_free(error);
		return NULL;
	}

	WCALOG_DEBUG("New group (path : %s) added", group_path);

	connman_manager_add_groups(manager);
	connman_group_t *group = find_group_by_path(manager, group_path);

	if (group_path != NULL)
	{
		g_free(group_path);
	}

	return group;
}

/*
 * Get the number of connected station
 */
guint connman_manager_get_sta_count(connman_manager_t *manager)
{
	if (NULL == manager)
		return FALSE;

	GError *error = NULL;
	guint sta_count = 0;

	connman_interface_manager_call_get_sta_count_sync(manager->remote, &sta_count, NULL, &error);

	if (error)
	{
		g_error_free(error);
		return 0;
	}

	return sta_count;
}

/**
 * Traverse through the given service list, comparing each service with the path provided
 * returning the service with the matching path (See header for API details)
 */

connman_service_t *connman_manager_find_service_by_path(GSList *service_list,
        const gchar *path)
{
	GSList *iter;

	if (NULL == path)
	{
		/* Does not really help when accessing freed memory.*/
		WCALOG_ERROR(MSGID_INVALID_STATE, 0, "Path is NULL, something is wrong!");
		return NULL;
	}

	for (iter = service_list; NULL != iter; iter = iter->next)
	{
		connman_service_t *service = (connman_service_t *)(iter->data);

		if (!service->path)
		{
			continue;
		}

		if (!g_strcmp0(service->path, path))
		{
			return service;
		}
	}

	return NULL;
}

/**
 * Check if the manager is not in offline mode and available to
 * enable network connections (see header for API details)
 */

gboolean connman_manager_is_manager_available(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	return !manager->offline;
}


/**
 * Offlinemode on/off the given manager (see header for API details)
 */

gboolean connman_manager_set_offlinemode(connman_manager_t *manager,
        gboolean state)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	/* don't set offlinemode again if we're already in the right offline state */
	if (state == manager->offline)
	{
		return TRUE;
	}

	GError *error = NULL;

	connman_interface_manager_call_set_property_sync(manager->remote,
	        "OfflineMode",
	        g_variant_new_variant(g_variant_new_boolean(state)),
	        NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_SET_OFFLINEMODE_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	manager->offline = state;
	return TRUE;
}

/**
 * Enable/Disable wol/wowl the given manager (see header for API details)
 */

gboolean connman_manager_set_wol_wowl_mode(connman_manager_t *manager, gboolean state)
{
	if(NULL == manager)
		return FALSE;

	/* don't set again if we're already in the same state */
	if (state == manager->wol_wowl)
		return TRUE;

	GError *error = NULL;

	connman_interface_manager_call_set_property_sync(manager->remote,
			"WOLWOWLMode",
			g_variant_new_variant(g_variant_new_boolean(state)),
			NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_SET_WOL_WOWL_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	manager->wol_wowl = state;

	return TRUE;
}

static void enable_wol_status_for_quick_power_off_cb(bool success, void *user_data)
{
	WCALOG_INFO(MSGID_STATE_RECOVERY_INFO, 0, "Success in enabling wol status in quick power off case");
}

static void disable_wol_status_for_quick_power_off_cb(bool success, void *user_data)
{
	WCALOG_INFO(MSGID_STATE_RECOVERY_INFO, 0, "Success in disabling wol status in quick power off case");
}

/**
 * Update manager's state by making remote call for get_properties
 */

static void connman_manager_update_state(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return;
	}

	gsize i;
	GVariant *properties = connman_manager_get_properties(manager);

	if (NULL == properties)
	{
		WCALOG_CRITICAL(MSGID_MANAGER_STATE_UPDATE_ERROR, 0,
		                "Connman manager unavailable !!!");
		return;
	}

	for (i = 0; i < g_variant_n_children(properties); i++)
	{
		GVariant *property = g_variant_get_child_value(properties, i);
		GVariant *key_v = g_variant_get_child_value(property, 0);
		GVariant *v = g_variant_get_child_value(property, 1);
		GVariant *va = g_variant_get_variant(v);
		const gchar *key = g_variant_get_string(key_v, NULL);

		if (connman_update_callbacks->manager_property_changed)
		{
			connman_update_callbacks->manager_property_changed(key, va);
		}

		if (!g_strcmp0(key, "State"))
		{
			g_free(manager->state);
			manager->state = g_variant_dup_string(va, NULL);
		}
		else if (!g_strcmp0(key, "OfflineMode"))
		{
			manager->offline = g_variant_get_boolean(va);
		}
		else if (!g_strcmp0(key, "WOLWOWLMode"))
		{
			manager->wol_wowl = g_variant_get_boolean(va);

#ifdef ENABLE_QUICK_WOL
			if (manager->wol_wowl)
				wca_support_enable_wol_status(enable_wol_status_for_quick_power_off_cb, NULL);
			else
				wca_support_disable_wol_status(disable_wol_status_for_quick_power_off_cb, NULL);
#endif
		}

		g_variant_unref(v);
		g_variant_unref(va);
		g_variant_unref(property);
		g_variant_unref(key_v);
	}

	g_variant_unref(properties);
}

/**
 * Check if the manager in online ( its state is set to 'online')
 * (see header for API details)
 */

gboolean connman_manager_is_manager_online(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return FALSE;
	}

	connman_manager_update_state(manager);

	if (!g_strcmp0(manager->state, "online"))
	{
		return TRUE;
	}

	return FALSE;
}

connman_technology_t *connman_manager_find_technology_by_name(
    connman_manager_t *manager, const char *name)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (!tech)
		{
			continue;
		}

		if (g_strcmp0(name, tech->type) == 0)
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * Go through the manager's technologies list and get the wifi one
 * (see header for API details)
 */

connman_technology_t *connman_manager_find_wifi_technology(
    connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (!tech)
		{
			continue;
		}

		if (g_strcmp0("wifi", tech->type) == 0)
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * Go through the manager's technologies list and get the ethernet one
 * (see header for API details)
 */

connman_technology_t *connman_manager_find_ethernet_technology(
    connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (!tech)
		{
			continue;
		}

		if (g_strcmp0("ethernet", tech->type) == 0)
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * Go through the manager's technologies list and get the cellular one
 * (see header for API details)
 */

connman_technology_t *connman_manager_find_cellular_technology(
    connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (!tech)
		{
			continue;
		}

		if (g_strcmp0("cellular", tech->type) == 0)
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * Go through the manager's technologies list and get the bluetooth one
 * (see header for API details)
 */

connman_technology_t *connman_manager_find_bluetooth_technology(
    connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return NULL;
	}

	GSList *iter;

	for (iter = manager->technologies; NULL != iter; iter = iter->next)
	{
		connman_technology_t *tech = (struct connman_technology *)(iter->data);

		if (!tech)
		{
			continue;
		}

		if (g_strcmp0("bluetooth", tech->type) == 0)
		{
			return tech;
		}
	}

	return NULL;
}

/**
 * Go through the manager's given services list and get the one which is in
 * "ready" or "online" state (see header for API details)
 */

connman_service_t *connman_manager_get_connected_service(GSList *service_list)
{
	if (NULL == service_list)
	{
		return NULL;
	}

	GSList *iter;
	connman_service_t *service = NULL, *connected_service = NULL;

	for (iter = service_list; NULL != iter; iter = iter->next)
	{
		service = (struct connman_service *)(iter->data);
		int service_state = connman_service_get_state(service->state);

		if(service_state == CONNMAN_SERVICE_STATE_ONLINE
			|| service_state == CONNMAN_SERVICE_STATE_READY
			|| service_state == CONNMAN_SERVICE_STATE_CONFIGURATION)
		{
			connected_service = service;
			break;
		}
	}

	if (connected_service != NULL)
	{
		GVariant *properties = connman_service_fetch_properties(connected_service);

		if (NULL != properties)
		{
			connman_service_update_properties(connected_service, properties);
			g_variant_unref(properties);
			return connected_service;
		}
	}

	return NULL;
}

/**
 * Go through the manager's given service list and find the currently connecting service
 * and return it.
 */

connman_service_t *connman_manager_get_connecting_service(GSList *service_list)
{
	GSList *iter;
	connman_service_t *service = NULL;
	int state;

	if (!service_list)
	{
		return NULL;
	}

	for (iter = service_list; iter; iter = iter->next)
	{
		service = (connman_service_t *) iter->data;
		state = connman_service_get_state(service->state);

		if (state == CONNMAN_SERVICE_STATE_ASSOCIATION ||
		        state == CONNMAN_SERVICE_STATE_CONFIGURATION)
		{
			return service;
		}
	}

	return NULL;
}

/**
 * Callback for manager's "property_changed" signal (see header for API details)
 */

static void
property_changed_cb(ConnmanInterfaceManager *proxy, const gchar *property,
                    GVariant *v,
                    connman_manager_t      *manager)
{
	GVariant *va = g_variant_get_child_value(v, 0);
	WCALOG_DEBUG("Manager property %s changed : %s", property,
	             g_variant_get_string(va, NULL));

	if (connman_update_callbacks->manager_property_changed)
	{
		connman_update_callbacks->manager_property_changed(property, va);
	}

	if (!g_strcmp0(property, "State"))
	{
		g_free(manager->state);
		manager->state = g_variant_dup_string(va, NULL);
	}
	else if (!g_strcmp0(property, "OfflineMode"))
	{
		manager->offline = g_variant_get_boolean(va);
	}

	if (NULL != manager->handle_property_change_fn)
	{
		(manager->handle_property_change_fn)((gpointer)manager, property, v);
	}

	g_variant_unref(va);
}


/**
 * Callback for manager's "technology_added" signal
 */

static void
technology_added_cb(ConnmanInterfaceManager *proxy, gchar *path, GVariant *v,
                    connman_manager_t      *manager)
{
	WCALOG_DEBUG("Technology %s added", path);

	if (NULL == find_technology_by_path(manager, path))
	{
		connman_technology_t *technology = connman_technology_new(path);

		if (technology != NULL)
		{
			WCALOG_INFO("DEBUG", 0, "Updating manager's technology list");
			manager->technologies = g_slist_append(manager->technologies,
			                                       technology);

		}
	}

	if (connman_update_callbacks->technology_added)
	{
		connman_update_callbacks->technology_added(path, v);
	}

	if (NULL != manager->handle_technologies_change_fn)
	{
		(manager->handle_technologies_change_fn)(manager);
	}
}

/**
 * Callback for manager's "technology_removed" signal
 */

static void
technology_removed_cb(ConnmanInterfaceManager *proxy, gchar *path,
                      connman_manager_t      *manager)
{
	WCALOG_DEBUG("Technology removed");

	if (connman_update_callbacks->technology_removed)
	{
		connman_update_callbacks->technology_removed(path);
	}

	connman_technology_t *technology = find_technology_by_path(manager, path);

	if (NULL != technology)
	{
		manager->technologies = g_slist_remove_link(manager->technologies,
		                        g_slist_find(manager->technologies, technology));
		connman_technology_free(technology);
	}

	if (NULL != manager->handle_technologies_change_fn)
	{
		(manager->handle_technologies_change_fn)(manager);
	}
}

/**
 * Callback for manager's "group_added" signal
 */

static void
group_added_cb(ConnmanInterfaceManager *proxy, gchar *path, GVariant *v,
               connman_manager_t      *manager)
{
	WCALOG_DEBUG("Group %s added", path);

	if (connman_update_callbacks->group_added)
	{
		connman_update_callbacks->group_added(path, v);
	}

	if (NULL == find_group_by_path(manager, path))
	{
		GVariant *group_v = g_variant_new("(o@a{sv})", path, v);
		connman_group_t *group = connman_group_new(group_v);
		connman_manager_populate_group_peers(manager, group);
		WCALOG_DEBUG("Updating manager's group list");
		manager->groups = g_slist_append(manager->groups, group);
		connectionmanager_send_status_to_subscribers();
		g_variant_unref(group_v);
	}

	if (NULL != manager->handle_groups_change_fn)
	{
		(manager->handle_groups_change_fn)((gpointer)manager, TRUE);
	}
}

/**
 * Callback for manager's "group_removed" signal
 */

static void
group_removed_cb(ConnmanInterfaceManager *proxy, gchar *path,
                 connman_manager_t      *manager)
{
	WCALOG_DEBUG("group %s removed", path);

	if (connman_update_callbacks->group_removed)
	{
		connman_update_callbacks->group_removed(path);
	}

	connman_group_t *group = find_group_by_path(manager, path);

	if (NULL != group)
	{
		manager->groups = g_slist_remove_link(manager->groups,
		                                      g_slist_find(manager->groups, group));
		connman_group_free(group, NULL);
	}

	if (NULL != manager->handle_groups_change_fn)
	{
		(manager->handle_groups_change_fn)((gpointer)manager, FALSE);
	}
}

/**
 * Callback for manager's "services_changed" signal
 */

static void
services_changed_cb(ConnmanInterfaceManager *proxy, GVariant *services_added,
                    gchar **services_removed, connman_manager_t *manager)
{
	WCALOG_DEBUG("Services_changed ");

	if (connman_update_callbacks->services_changed)
	{
		connman_update_callbacks->services_changed(services_added, services_removed);
	}

	unsigned char service_type = 0;
	gboolean update_status = connman_manager_update_services(manager,
	                         services_added, &service_type, FALSE);
	gboolean remove_status = connman_manager_remove_old_services(manager,
	                         services_removed, &service_type);

	if (update_status == TRUE || remove_status == TRUE)
	{
		if (NULL != manager->handle_services_change_fn)
		{
			(manager->handle_services_change_fn)(manager, service_type);
		}
	}
}

/**
 * Callback for manager's "saved_services_changed" signal
 */

static void
saved_services_changed_cb(ConnmanInterfaceManager *proxy,
                          GVariant *saved_services_added,
                          gchar **saved_services_removed, connman_manager_t *manager)
{
	WCALOG_DEBUG("Saved_services_changed ");

	if (connman_update_callbacks->saved_services_changed)
	{
		connman_update_callbacks->saved_services_changed(saved_services_added,
		        saved_services_removed);
	}

	connman_manager_update_services(manager, saved_services_added, NULL, TRUE);
	remove_services_from_list(&manager->saved_services, saved_services_removed);
}

/**
 * Register for manager's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_manager_register_property_changed_cb(connman_manager_t *manager,
        connman_property_changed_cb func)
{
	if (NULL == func)
	{
		return;
	}

	manager->handle_property_change_fn = func;
}

/**
 * Register for manager's "services_changed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_manager_register_services_changed_cb(connman_manager_t *manager,
        connman_services_changed_cb func)
{
	if (NULL == func)
	{
		return;
	}

	manager->handle_services_change_fn = func;
}

/**
 * Register for manager's "group_added" and "group_removed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_manager_register_groups_changed_cb(connman_manager_t *manager,
        connman_groups_changed_cb func)
{
	if (NULL == func)
	{
		return;
	}

	manager->handle_groups_change_fn = func;
}

/**
 * Register for manager's "technology_added" and "technology_removed" signal, calling the provided function whenever the callback function
 * for the signal is called (see header for API details)
 */

void connman_manager_register_technologies_changed_cb(connman_manager_t
        *manager, connman_technologies_changed_cb func)
{
	if (NULL == func)
	{
		return;
	}

	manager->handle_technologies_change_fn = func;
}


/**
 * Register a agent instance on the specified dbus path with the manager
 * (see header for API details)
 **/

gboolean connman_manager_register_agent(connman_manager_t *manager,
                                        const gchar *path)
{
	GError *error = NULL;

	if (NULL == manager)
	{
		return FALSE;
	}

	connman_interface_manager_call_register_agent_sync(manager->remote,
	        path, NULL, &error);

	if (error)
	{
		WCALOG_DEBUG("%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	WCALOG_DEBUG("Registered agent successfully with connman");

	return TRUE;
}

/**
 * Unegister a agent instance on the specified dbus path from the manager
 * (see header for API details)
 **/

gboolean connman_manager_unregister_agent(connman_manager_t *manager,
        const gchar *path)
{
	GError *error;

	if (NULL == manager)
	{
		return FALSE;
	}

	connman_interface_manager_call_unregister_agent_sync(manager->remote,
	        path, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_UNREGISTER_AGENT_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}


/**
 * Register a counter instance on the specified dbus path with the manager
 * (see header for API details)
 **/

gboolean connman_manager_register_counter(connman_manager_t *manager,
        const gchar *path, guint accuracy, guint period)
{
	GError *error = NULL;

	if (NULL == manager)
	{
		return FALSE;
	}

	connman_interface_manager_call_register_counter_sync(manager->remote,
	        path, accuracy, period, NULL, &error);

	if (error)
	{
		WCALOG_INFO(MSGID_MANAGER_REGISTER_COUNTER_ERROR, 0, "%s", error->message);
		g_error_free(error);
		return FALSE;
	}

	WCALOG_INFO(MSGID_MANAGER_REGISTER_COUNTER_SUCCESS, 0,
	            "Registered counter successfully with connman");

	return TRUE;
}

gboolean connman_manager_unregister_counter(connman_manager_t *manager,
        const gchar *path)
{
	GError *error = NULL;

	if (NULL == manager || NULL == path)
	{
		return FALSE;
	}

	connman_interface_manager_call_unregister_counter_sync(manager->remote,
	        path, NULL, &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_UNREGISTER_COUNTER_ERROR, error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

/**
 * Initialize a new manager instance and update its services and technologies list
 * (see header for API details)
 */

connman_manager_t *connman_manager_new(void)
{
	GError *error = NULL;
	connman_manager_t *manager = g_new0(connman_manager_t, 1);

	if (manager == NULL)
	{
		return NULL;
	}

	manager->technologies = NULL;

	manager->remote = connman_interface_manager_proxy_new_for_bus_sync(
	                      G_BUS_TYPE_SYSTEM,
	                      G_DBUS_PROXY_FLAGS_NONE,
	                      "net.connman", "/",
	                      NULL,
	                      &error);

	if (error)
	{
		WCALOG_ESCAPED_ERRMSG(MSGID_MANAGER_INIT_ERROR, error->message);
		g_error_free(error);
		g_free(manager);
		return NULL;
	}

	g_signal_connect(G_OBJECT(manager->remote), "property-changed",
	                 G_CALLBACK(property_changed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "technology-added",
	                 G_CALLBACK(technology_added_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "technology-removed",
	                 G_CALLBACK(technology_removed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "services-changed",
	                 G_CALLBACK(services_changed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "saved-services-changed",
	                 G_CALLBACK(saved_services_changed_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "group-added",
	                 G_CALLBACK(group_added_cb), manager);

	g_signal_connect(G_OBJECT(manager->remote), "group-removed",
	                 G_CALLBACK(group_removed_cb), manager);

	connman_manager_update_state(manager);
	connman_manager_add_technologies(manager);
	connman_manager_add_services(manager);

	connman_technology_t *technology = connman_manager_find_wifi_technology(
	                                       manager);

	if ((NULL != technology) && technology->p2p)
	{
		connman_manager_add_groups(manager);
	}

	if (g_slist_length(manager->technologies) == 0)
	{
		WCALOG_ERROR(MSGID_MANAGER_NO_TECH_ERROR, 0 , "No technologies initialized");
	}

	if (g_slist_length(manager->wired_services) == 0)
	{
		WCALOG_ERROR(MSGID_MANAGER_NO_WIRED_ERROR, 0 , "No wired service found");
	}

	WCALOG_DEBUG("%d wifi services, %d technologies",
	             g_slist_length(manager->wifi_services),
	             g_slist_length(manager->technologies));

	WCALOG_DEBUG("%d cellular services, %d technologies",
	             g_slist_length(manager->cellular_services),
	             g_slist_length(manager->technologies));

	WCALOG_DEBUG("%d bluetooth services, %d technologies",
	             g_slist_length(manager->bluetooth_services),
	             g_slist_length(manager->technologies));

	return manager;
}

/**
 * Free the manager instance (see header for API details)
 */

void connman_manager_free(connman_manager_t *manager)
{
	if (NULL == manager)
	{
		return;
	}

	connman_manager_free_services(manager);
	connman_manager_free_technologies(manager);
	connman_manager_free_groups(manager);

	g_object_unref(manager->remote);

	g_free(manager->state);
	g_free(manager);
	manager = NULL;
}

void set_wca_support_connman_update_callbacks(
    wca_support_connman_update_callbacks *callbacks)
{
	if (callbacks)
	{
		connman_update_callbacks = callbacks;
	}
}
