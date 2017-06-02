#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
External inventory script for Scaleway
====================================

Shamelessly copied from an existing inventory script.

This script generates an inventory that Ansible can understand by making API requests to Scaleway API

Requires some python libraries, ensure to have them installed when using this script. (pip install requests https://pypi.python.org/pypi/requests)

Before using this script you may want to modify scaleway.ini config file.

This script generates an Ansible hosts file with these host groups:

<hostname>: Defines host itself with Scaleway's hostname as group name.
<tag>: Contains all hosts which has "<tag>" as tag.
<region>: Contains all hosts which are in the "<region>" region.
all: Contains all hosts defined in Scaleway.
'''

# (c) 2017, Paul B. <paul@bonaud.fr>
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import copy
import os
import requests
import six
from six.moves import configparser
import sys
import time
import traceback

try:
    import json
except ImportError:
    import simplejson as json

EMPTY_GROUP = {
    'children': [],
    'hosts': []
}


class ScalewayAPI:
    REGIONS = ['par1', 'ams1']

    def __init__(self, auth_token, region):
        self.session = requests.session()
        self.session.headers.update({
            'User-Agent': 'Ansible Python/%s' % (sys.version.split(' ')[0])
        })
        self.session.headers.update({
            'X-Auth-Token': auth_token.encode('latin1')
        })
        self.base_url = 'https://cp-%s.scaleway.com' % (region)

    def servers(self):
        raw = self.session.get('/'.join([self.base_url, 'servers']))

        try:
            response = raw.json()
            return self.get_resource('servers', response, raw)
        except ValueError:
            return []

    def get_resource(self, resource, response, raw):
        raw.raise_for_status()

        if resource in response:
            return response[resource]
        else:
            raise ValueError(
                "Resource %s not found in Scaleway API response" % (resource))


def env_or_param(env_key, param=None, fallback=None):
    env_value = os.environ.get(env_key)

    if (param, env_value) == (None, None):
        return fallback
    elif env_value is not None:
        return env_value
    else:
        return param


def save_cache(data, config):
    ''' saves item to cache '''
    dpath = config.get('cache', 'cache_dir')
    try:
        cache = open('/'.join([dpath, 'scaleway_ansible_inventory.json']), 'w')
        cache.write(json.dumps(data))
        cache.close()
    except IOError as e:
        pass  # not really sure what to do here


def get_cache(cache_item, config):
    ''' returns cached item  '''
    dpath = config.get('cache', 'cache_dir')
    inv = {}
    try:
        cache = open('/'.join([dpath, 'scaleway_ansible_inventory.json']), 'r')
        inv = cache.read()
        cache.close()
    except IOError as e:
        pass  # not really sure what to do here

    return inv


def cache_available(config):
    ''' checks if we have a 'fresh' cache available for item requested '''

    if config.has_option('cache', 'cache_dir'):
        dpath = config.get('cache', 'cache_dir')

        try:
            existing = os.stat(
                '/'.join([dpath, 'scaleway_ansible_inventory.json']))
        except OSError:
            return False

        if config.has_option('cache', 'cache_max_age'):
            maxage = config.get('cache', 'cache_max_age')
        else:
            maxage = 60
        if (int(time.time()) - int(existing.st_mtime)) <= int(maxage):
            return True

    return False


def generate_inv_from_api(config):
    try:
        inventory['all'] = copy.deepcopy(EMPTY_GROUP)

        if config.has_option('auth', 'api_token'):
            auth_token = config.get('auth', 'api_token')
        auth_token = env_or_param('SCALEWAY_TOKEN', param=auth_token)
        if auth_token is None:
            sys.stderr.write('ERROR: missing authentication token for Scaleway API')
            sys.exit(1)

        if config.has_option('compute', 'regions'):
            regions = config.get('compute', 'regions')
            if regions == 'all':
                regions = ScalewayAPI.REGIONS
            else:
                regions = map(str.strip, regions.split(','))
        else:
            regions = [
                env_or_param('SCALEWAY_REGION', fallback='par1')
            ]

        for region in regions:
            api = ScalewayAPI(auth_token, region)

            for server in api.servers():
                hostname = server['hostname']
                if config.has_option('defaults', 'public_ip_only') and config.getboolean('defaults', 'public_ip_only'):
                    ip = server['public_ip']['address']
                else:
                    ip = server['private_ip']
                for server_tag in server['tags']:
                    if server_tag not in inventory:
                        inventory[server_tag] = copy.deepcopy(EMPTY_GROUP)
                    inventory[server_tag]['children'].append(hostname)
                if region not in inventory:
                    inventory[region] = copy.deepcopy(EMPTY_GROUP)
                inventory[region]['children'].append(hostname)
                inventory['all']['children'].append(hostname)
                inventory[hostname] = []
                inventory[hostname].append(ip)

        return inventory
    except Exception:
        # Return empty hosts output
        traceback.print_exc()
        return {'all': {'hosts': []}, '_meta': {'hostvars': {}}}


def get_inventory(config):
    ''' Reads the inventory from cache or Scaleway api '''

    if cache_available(config):
        inv = get_cache('scaleway_ansible_inventory.json', config)
    else:
        inv = generate_inv_from_api(config)

    save_cache(inv, config)
    return json.dumps(inv)


if __name__ == '__main__':
    inventory = {}

    # Read config
    if six.PY3:
        config = configparser.ConfigParser()
    else:
        config = configparser.SafeConfigParser()
    for configfilename in [os.path.abspath(sys.argv[0]).rsplit('.py')[0] + '.ini', 'scaleway.ini']:
        if os.path.exists(configfilename):
            config.read(configfilename)
            break

    if cache_available(config):
        inventory = get_cache('scaleway_ansible_inventory.json', config)
    else:
        inventory = get_inventory(config)

    # return to ansible
    sys.stdout.write(str(inventory))
    sys.stdout.flush()
import argparse
import ConfigParser
import json
import logging
import os
import sys
import time

import requests


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)20s [%(levelname)s]: %(message)s',
)
logger = logging.getLogger()


REGIONS = ['ams1', 'par1']


class Cache(object):
    def __init__(self, cachedir, ttl):
        self.cachedir = cachedir
        self.ttl = ttl

    def get_region_data(self, region):
        path = os.path.join(self.cachedir, 'region-%s' % region)

        logger.info('Reading region information for %s from %s', region, path)

        try:
            stat = os.stat(path)
        except OSError:
            logger.debug('Cache file %s not found', path)
        else:
            delta = time.time() - stat.st_mtime
            if delta > 0 and delta < self.ttl:
                with open(path) as fp:
                    return json.load(fp)

    def write_region_cache(self, region, data):
        path = os.path.join(self.cachedir, 'region-%s' % region)

        logger.info('Writing region caache for %s to %s', region, path)

        if not os.path.exists(self.cachedir):
            logger.debug('Creating cache directory at %s', self.cachedir)
            os.makedirs(self.cachedir)

        with open(path, 'w') as fp:
            json.dump(data, fp)


def query_region_data(api_token, region):
    logger.info('Retrieving region data for %s', region)
    headers = {'X-Auth-Token': api_token}
    response = requests.get('https://cp-%s.scaleway.com/servers/' % region, headers=headers)
    response.raise_for_status()
    return response.json()


def get_host_vars(data, prefix='scw'):
    return dict(('%s_%s' % (prefix, key), value) for key, value in data.items())


def generate_region_data(cache, api_token):
    logger.info('Generating region data')

    for region in REGIONS:
        region_data = cache.get_region_data(region)
        if not region_data:
            logger.debug('No region data for %s cached, querying api.', region)
            region_data = query_region_data(api_token, region)
            cache.write_region_cache(region, region_data)
        yield region_data


def generate_server_data(cache, api_token):
    for region_data in generate_region_data(cache, api_token):
        for server in region_data['servers']:
            yield server


def get_hostname(data, hostname_field):
    if hostname_field == 'hostname':
        return data['hostname']
    elif hostname_field == 'private_dns':
        return '%s.priv.cloud.scaleway.com' % data['id']
    elif hostname_field == 'public_dns':
        return '%s.pub.cloud.scaleway.com' % data['id']


def generate_inventory(cache, api_token, hostname_field):
    logger.info('Generating Scaleway inventory')
    inventory = {'_meta': {}}
    hostvars = inventory['_meta'].setdefault('hostvars', {})

    for server in generate_server_data(cache, api_token):
        hostname = get_hostname(server, hostname_field)
        hostvars[hostname] = get_host_vars(server)
        inventory.setdefault('scaleway', []).append(hostname)

        for tag in server['tags']:
            try:
                prefix, value = tag.split(':')
            except ValueError:
                pass
            else:
                if prefix == 'ansible':
                    inventory.setdefault(value, []).append(hostname)

    return inventory


def get_host_meta(cache, api_token, hostname, hostname_field):
    logger.info('Retrieving meta information for %s', hostname)

    if hostname_field in ('public_dns', 'private_dns'):
        lookup_field = 'id'
        lookup_value, _, _ = hostname.partition('.')
    elif hostname_field == 'hostname':
        lookup_field = 'hostname'
        lookup_value = hostname

    for server in generate_server_data(cache, api_token):
        if server[lookup_field] == lookup_value:
            return get_host_vars(server)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-c', '--config',
        default='scaleway.ini',
        help='Specify a configuration file, default: ./scaleway.ini',
    )

    parser.add_argument(
        '--list',
        action='store_true',
        default=False,
        help='Output JSON inventory to stdout.'
    )

    parser.add_argument(
        '--host',
        nargs=1,
        help='Print an empty dictionary',
    )

    args = parser.parse_args()

    if (not args.host and not args.list) or (args.list and args.host):
        sys.stderr.write('Specify either --host or --list\n')
        return -1

    config = ConfigParser.RawConfigParser({
        'pretty': False,
        'cache_max_age': 300,
        'cache_dir': '.scaleway',
        'loglevel': 'INFO',
        'hostname': 'private_dns',
    })

    config.read(args.config)

    if config.get('scaleway', 'hostname') not in ('private_dns', 'public_dns', 'hostname'):
        sys.stderr.write('Invalid hostname configuration, set to private_dns, '
                         'public_dns or hostname\n')
        return -3

    logger.setLevel(config.get('scaleway', 'loglevel'))
    cache = Cache(config.get('scaleway', 'cache_dir'),
                  config.getint('scaleway', 'cache_max_age'))

    if args.list:
        data = generate_inventory(cache, config.get('scaleway', 'api_token'),
                                  config.get('scaleway', 'hostname'))
    elif args.host:
        data = get_host_meta(cache, config.get('scaleway', 'api_token'), args.host[0],
                             config.get('scaleway', 'hostname'))

    if config.getboolean('scaleway', 'pretty'):
        json.dump(data, sys.stdout, sort_keys=True, indent=4)
    else:
        json.dump(data, sys.stdout)

    return 0


if __name__ == '__main__':
    sys.exit(main())
