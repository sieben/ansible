# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
    name: scaleway
    plugin_type: inventory
    authors:
      - Remy Leone <rleone@online.net>
    short_description: Scaleway inventory source
    description:
        - Get inventory hosts from Scaleway
'''

EXAMPLES = '''
# scaleway_inventory.yml file in YAML format
# Example command line: ansible-inventory --list -i scaleway_inventory.yml

plugin: scaleway
regions:
  - ams1
  - par1
tags:
  - foobar
'''

import json
import os

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.module_utils.scaleway import SCALEWAY_LOCATION
from ansible.module_utils.urls import open_url


def _fetch_information(token, url):
    try:
        response = open_url(url,
                            headers={'X-Auth-Token': token,
                                     'Content-type': 'application/json'})
    except Exception:
        raise AnsibleError("Error while fetching %s" % url)

    try:
        raw_json = json.loads(response.read())
    except ValueError:
        raise AnsibleError("Incorrect JSON payload")

    try:
        return raw_json["servers"]
    except KeyError:
        raise AnsibleError("Incorrect format from the Scaleway API response")


def _build_server_url(api_endpoint):
    return "/".join([api_endpoint, "servers"])


class InventoryModule(BaseInventoryPlugin):
    NAME = 'scaleway'

    def __init__(self):
        super(InventoryModule, self).__init__()

        self.token = os.environ["SCW_TOKEN"]
        self.config_data = None

    def verify_file(self, path):
        return "scaleway" in path

    def _fill_host_variables(self, server_id, server_info):
        targeted_attributes = (
            "arch",
            "commercial_type",
            "organization",
            "state",
            "hostname",
            "state"
        )
        for attribute in targeted_attributes:
            self.inventory.set_variable(server_id, attribute, server_info[attribute])

        self.inventory.set_variable(server_id, "tags", server_info["tags"])
        self.inventory.set_variable(server_id, "ipv4", server_info["public_ip"]["address"])

    @property
    def zones(self):
        config_zones = self.config_data.get("regions", SCALEWAY_LOCATION.keys())
        return set(SCALEWAY_LOCATION.keys()).intersection(config_zones)

    @property
    def tags(self):
        return self.config_data.get("tags", None)

    def match_groups(self, server_info):
        server_zone = server_info["location"]["zone_id"]
        server_tags = server_info["tags"]

        # If no filtering is defined, all tags are valid groups
        if self.tags is None:
            return set(server_tags).union((server_zone,))

        matching_tags = set(server_tags).intersection(self.tags)

        if not matching_tags:
            return set()
        else:
            return matching_tags.union((server_zone,))

    def do_zone_inventory(self, zone):
        self.inventory.add_group(zone)
        zone_info = SCALEWAY_LOCATION[zone]

        url = _build_server_url(zone_info["api_endpoint"])
        all_servers = _fetch_information(url=url, token=self.token)

        for server_info in all_servers:

            groups = self.match_groups(server_info)
            print(groups)
            server_id = server_info["id"]

            for group in groups:
                self.inventory.add_group(group=group)
                self.inventory.add_host(group=group, host=server_id)
                self._fill_host_variables(server_id=server_id, server_info=server_info)

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        self.config_data = self._read_config_data(path=path)

        for zone in self.zones:
            self.do_zone_inventory(zone=zone)
