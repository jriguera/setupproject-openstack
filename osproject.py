#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Program to manage OpenStack projects by automating the creation of resourcers 
in order to start working on them: users, groups, roles, networks, security 
groups, routers, quotas and other features like:

* It is able to setup filters in aggregates metadata for specific projects
* It is able to allocate a range of floating IPs from a pool to a project
* It is idempotent, run as many times as you need (but it does not do rollback!)
* It reads all the configuration from a Yaml file

"""
# Python 2 and 3 compatibility
from __future__ import unicode_literals, print_function

__program__ = "osproject"
__version__ = "v0.1.0"
__author__ = "Jose Riguera"
__year__ = "2016"
__email__ = "jriguera@gmail.com"
__license__ = "MIT"
__purpose__ = "Made to learn OpenStack APIs"


import os 
import sys 
import logging 
import logging.config 
import argparse
from argparse import RawTextHelpFormatter

import ipcalc 
import yaml

from keystoneclient.auth.identity import v3 as ks_auth
from keystoneclient.auth import token_endpoint as ks_token
from keystoneclient import session as ks_session
from keystoneclient import exceptions as ks_exceptions
from keystoneclient.v3 import client as ks_client

from keystoneclient.service_catalog import ServiceCatalog
from keystoneclient.v3.domains import Domain, DomainManager
from keystoneclient.v3.roles import Role, RoleManager
from keystoneclient.v3.projects import Project, ProjectManager
from keystoneclient.v3.users import User, UserManager

from neutronclient.v2_0 import client as neutron_client
from neutronclient.common import exceptions as neutron_exceptions

from novaclient import client as nova_client
from novaclient import exceptions as nova_exceptions
from novaclient.v2 import aggregates as nova_aggregates
from novaclient.v2 import availability_zones as nova_az

from cinderclient.v2 import client as cinder_client
from cinderclient import exceptions as cinder_exceptions



class ProgramCli(object):
    PROG=__program__
    VERSION=__version__
    FILE="osproject.yml"
    DOMAIN="Default"
    LOGGING=os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "logging.conf")
    LOGLEVEL=logging.INFO
    LOGENVCONF="LOG_CFG"
    OUTPUT_FORMAT='%(name)s: %(message)s'

    class ProjectsAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
	        data = {
	        	'name': values[0],
                'domain': namespace.domain,
	        	'description': values[1],
            }
	        namespace.project.append(data)

    class GroupAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
            try:
                data = {
                    'name': values[0],
                    'description': values[1],
                    'domain': namespace.domain,
            	    'roles': [],
            	}
            except:
                parser.error('Missing group arguments!')
            namespace.groups.append(data)

    class GroupRolesAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
            try:
                data = { values[0]: values[1] }
                namespace.groups[-1]['roles'].append(data)
            except:
                parser.error('Missing group arguments!')

    class UserAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
            try:
                data = {
                    'name': values[0],
                    'email': values[1],
                    'password': values[2],
                    'domain': namespace.domain,
                    'groups': [],
            	}
            except:
                parser.error('Missing user arguments!')
            namespace.users.append(data)

    class UserGroupsAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
            try:
	            namespace.users[-1]['groups'] = values
            except:
                parser.error('Missing user!')

    class NeutronNetAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            try:
                data = {
                    'name': values[0],
                    'cidr': values[1],
                    'public': values[2]
            	}
                if not 'networks' in namespace.neutron:
                    namespace.neutron['networks'] = []
                namespace.neutron['networks'].append(data)
            except:
                parser.error('Missing network arguments!')

    class NeutronFipsAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
            try:
                data = { values[0] : values[1] }
            	if not 'floatingips' in namespace.neutron: 
                    namespace.neutron['floatingips'] = []
	    	    namespace.neutron['floatingips'].append(data)
            except:
                parser.error('Missing floating IPs arguments!')

    class NovaAggAction(argparse.Action):
    	def __call__(self, parser, namespace, values, option_string=None):
    	    if not 'aggregates' in namespace.nova:
    	        namespace.nova['aggregates'] = {}
            namespace.nova['aggregates']['aggregate'] = values


    def __init__(self):
        self.parser = None
        self.logpath = None
        self.logger = None
        self.setup_logging()
        self.setup_parser()


    def setup_logging(self):
        self.logpath = os.environ.get(self.LOGENVCONF, self.LOGGING)
    	try:
            #logging.config.fileConfig(self.logpath)
            with open(self.logpath) as logconfig:
                logdata = yaml.load(logconfig)
                logging.config.dictConfig(logdata)
    	except Exception as e:
    	    print("Error with '%s': %s" % (self.logpath, e))
            logging.basicConfig(level=self.LOGLEVEL, format=self.OUTPUT_FORMAT)
            lfile = False
    	else:
            lfile = True
    	self.logger = logging.getLogger(self.PROG)
    	if not lfile:
            self.logger.info("Using default logging settings")
    	else:
            self.logger.info("Using logging settings from '%s'" % self.logpath) 


    def setup_parser(self):
        epilog = __purpose__ + '\n'
        epilog += __version__ + ', ' + __year__ + ' '
        epilog += __author__ + ' ' + __email__
    	self.parser = argparse.ArgumentParser(
    	    formatter_class=RawTextHelpFormatter,
    	    description=__doc__, epilog=epilog)
    	g1 = self.parser.add_argument_group('Configuration options')
    	g1.add_argument(
    	    '-d', '--domain', type=str,
    	    dest='domain', default=self.DOMAIN, help="Keystone domain")
    	g1.add_argument(
    	    '-c', '--config', type=str,
    	    dest='config', default=self.FILE, help="Yaml configuration file")
    	g2 = self.parser.add_argument_group('Options to create new groups')
    	g2.add_argument(
    	    '--group', metavar=("NAME", "DESCRIPTION"), type=str, 
    	    dest='groups', default=[], action=self.GroupAction, nargs=2, 
    	    help="Project group name and description")
    	g2.add_argument(
    	    '--role', metavar=("NAME", "DESCRIPTION"), type=str,
    	    dest='groups', default=[], action=self.GroupRolesAction, nargs=2, 
    	    help="Roles name and description")
    	g3 = self.parser.add_argument_group('Arguments to define new users')
    	g3.add_argument(
    	    '--user', metavar=("USERID", "EMAIL", "PASSWORD"), type=str,
    	    dest='users', default=[], action=self.UserAction, nargs=3,
    	    help="Userid, email and password")
    	g3.add_argument(
    	    '--groups', metavar="GROUP", type=str,
    	    dest='users', default=[], action=self.UserGroupsAction, nargs='+', 
    	    help="List of user groups")
    	g4 = self.parser.add_argument_group('Options to create a new project')
    	g4.add_argument(
    	    '--project', metavar=("NAME", "DESCRIPTION"), type=str,
    	    dest='project', default=[], action=self.ProjectsAction, nargs=2, 
    	    help="Name of the project")
    	g4.add_argument(
    	    '--network', metavar=("NAME", "CIDR", "PUBLICNET"), type=str,
    	    dest='neutron', default={}, action=self.NeutronNetAction, 
    	    nargs=3, help="Internal project network name and CIDR")
    	g4.add_argument(
    	    '--floatingips', metavar=("PUBLICNET", "CIDR"), type=str,
    	    dest='neutron', default={}, action=self.NeutronFipsAction, 
    	    nargs=2, help="Reserve the floating IPs for the project")
    	g4.add_argument(
    	    '--aggregate', metavar=("AGGREGATE"), type=str,
    	    dest='nova', default={}, action=self.NovaAggAction, nargs=1, 
    	    help="Aggregate to attach the project")


    def parse_config(self, arguments=None):
    	args = self.parser.parse_args(arguments)
        try:
            with open(args.config) as ymlconfig:
                config = yaml.load(ymlconfig)
    	except Exception as e:
            msg = "Error reading Yaml configuration file '%s': %s"
            self.logger.error(msg % (args.config, e))
            raise ValueError(msg % (args.config, e))
        self.logger.info("Read configuration file '%s'" % args.config)
    	if args.users:
            users = config.get('users', []) 
            config['users'] = users + args.users
    	if args.groups:
            groups = config.get('groups', []) 
            config['groups'] = groups + args.groups
    	if args.project:
            arg_pr = args.__dict__['project'][0].copy()
            if args.neutron:
                arg_pr['neutron'] = args.neutron
            if args.nova:
                arg_pr['nova'] = args.nova
            new_prs = []
            projects = config.get('projects', [])
            for pr in projects:
                try:
            	    if pr['name'] == arg_pr['name']:
            	    	pr = dict_overwrite(arg_pr, pr)
                    new_prs.append(pr)
            	except:
                    msg = "Yaml configuration file not valid!"
            	    self.logger.error(msg)
            	    raise ValueError(msg)
            config['projects'] = new_prs
        auth = config.get('auth', {})
    	auth_vars = [
            'username', 
            'password', 
            'project_name', 
            'auth_url', 
            'region_name', 
            'user_domain_name',
            'project_domain_name',
            'cacert'
    	]
    	for var in auth_vars:
            try:
                auth[var] = os.environ['OS_' + var.upper()]
            except:
                pass
        if not auth['auth_url']:
            msg = 'No auth_url endpoint defined!'
            self.logger.error(msg)
            raise ValueError(msg)
        config['auth'] = auth
        return config



def dict_overwrite(base, default={}):
    """Creates a new dictionary overwriting the values from the 
       default dictionary completing with the base key/values.
    """ 
    # clone current level
    new = default.copy()
    for key,value in base.items():
    	if isinstance(value, list):
            new[key] = value[:]
        elif isinstance(value, dict):
            new[key] = dict_override(value, default.get(key, {}))
       	else:
	    new[key] = value
    return new



class OpenStackProject(object):

    def __init__(self, auth_url, auth={}, token=None, cert=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.auth_session = None
        self.ks = None
        self.nova = None
        self.cinder = None
        self.neutron = None
        self.auth_url = auth_url
        self._get_session(auth, token, cert)
        self._get_keystone_client()


    def _get_session(self, admauth=None, token=None, cert=None):
        try:
            if not self.auth_session:
                if token:
                    self.logger.debug("Getting auth session using token")
                    auth = ks_token.Token(endpoint=self.auth_url, token=token)
                elif admauth:
                    self.logger.debug("Getting session using admin credentials")
                    auth = ks_auth.Password(
                        auth_url=self.auth_url,
                        username=admauth['username'],
                        password=admauth['password'],
                        project_name=admauth['project_name'],
                        user_domain_name=admauth['user_domain_name'],
					    project_domain_name=admauth['project_domain_name'])
                else:
                    msg = "Token or auth settings not defined"
                    self.logger.error(msg)
                    raise ValueError(msg)
                verify = cert != None
                self.auth_session = ks_session.Session(
                    auth=auth, verify=verify, cert=cert)
                self.logger.debug(
                    "New session defined: '%s'" % (self.auth_session))
            return self.auth_session
        except ks_exceptions.ClientException as e:
            self.logger.error("Problem getting session: %s" % e)
            raise


    def _get_keystone_client(self):
        if not self.ks:
            self.logger.debug("Setting up Keystone client")
	    try:
                self.ks = ks_client.Client(session=self.auth_session)
            except ks_exceptions.ClientException as e:
            	self.logger.error("Problem setting up Keystone client: %s" % e)
            	raise
        return self.ks


    def _get_nova_client(self):
        if not self.nova:
            self.logger.debug("Setting up Nova client")
            try:
                self.nova = nova_client.Client('2', session=self.auth_session)
                self.nova.format='json'
            except nova_exceptions.ClientException as e:
            	self.logger.error("Problem setting up Nova client: %s" % e)
            	raise
        return self.nova


    def _get_cinder_client(self):
        if not self.cinder:
            self.logger.debug("Setting up Cinder client")
            try:
            	self.cinder = cinder_client.Client(session=self.auth_session)
            except cinder_exceptions.ClientException as e:
            	self.logger.error("Problem setting up Cinder client: %s" % e)
            	raise
        return self.cinder


    def _get_neutron_client(self):
        if not self.neutron:
            self.logger.debug("Setting up Neutron client")
            try:
            	self.neutron = neutron_client.Client(session=self.auth_session)
            	self.neutron.format = 'json'
            except neutron_exceptions.NeutronClientException as e:
            	self.logger.error("Problem setting up Neutron client: %s" % e)
            	raise
        return self.neutron


    def setup_domain(self, domain='default', desc=None):
        try:
            return self.ks.domains.find(name=domain)
        except ks_exceptions.NotFound:
            self.logger.debug("Domain '%s' not found! creating ..." % domain)
            d = self.ks.domains.create(domain, desc)
            self.logger.info("Created domain %s with id '%s'" % (domain, d.id))
            return d.id
        except ks_exceptions.NoUniqueMatch:
	        self.logger.error("Domain '%s' not unique!" % domain)
	        raise
        except ks_exceptions.ClientException as e:
            self.logger.error("Searching for domain '%s': %s" % (domain, e))
            raise


    def setup_user(self, name, password, email=None, desc=None, 
                   domain='default'):
        user_id = None
        try:
	        user_id = self.ks.users.find(domain=domain, name=name)
        except ks_exceptions.NotFound as e:
            self.logger.debug("User '%s' not found, creating ..." % name)
            user_id = self.ks.users.create(
                name=name, password=password, email=email, 
                description=desc, domain=domain)
            self.logger.info(
                "Created user %s with id '%s'" % (name, user_id.id))
        except ks_exceptions.NoUniqueMatch as e:
            self.logger.error("User '%s' not unique!" % name)
            raise
        return user_id


    def setup_group(self, name, desc=None, domain='default'):
        group_id = None
        try:
            group_id = self.ks.groups.find(domain=domain, name=name)
        except ks_exceptions.NotFound as e:
            self.logger.debug("Group '%s' not found, creating ..." % name)
            group_id = self.ks.groups.create(
                name=name, description=desc, domain=domain)
            self.logger.info(
                "Created group %s with id '%s'" % (name, group_id.id))
        except ks_exceptions.NoUniqueMatch as e:
            self.logger.error("Group '%s' not unique!" % name)
            raise
        return group_id


    def setup_role(self, role, desc, domain='default'):
        role_id = None
        try:
            role_id = self.ks.roles.find(domain=domain, name=role)
        except ks_exceptions.NotFound as e:
            self.logger.debug("Role '%s' not found, creating ..." % role)
            role_id = self.ks.roles.create(
                name=role, description=desc, domain=domain)
            self.logger.info(
                "Created role %s with id '%s'" % (role, role_id.id))
        except ks_exceptions.NoUniqueMatch as e:
            self.logger.error("Role '%s' not unique!" % role)
            raise
        return role_id


    def setup_user_project_roles(self, user, project_id, roles={}, 
                                 domain='default'):
        try:
            current_roles = { 
                r.name : r.id for r in self.ks.roles.list(
                    domain=domain, user_id=user.id)
            }
            assignments = [
                asg.role['id'] for asg in self.ks.role_assignments.list(
                    user=user.id, project=project_id)
            ]
        except ks_exceptions.NotFound as e:
            self.logger.error("Cannot find user '%s': %s" % (user.name, e))
            raise
        for role_name, role_desc in roles.items():
            if role_name in current_roles:
                msg = "User %s already granted the role '%s'"
                self.logger.debug(msg % (user.name, role_name))
                if current_roles[role_name] in assignments:
                    msg = "User %s already assigned to the project '%s'"
                    self.logger.debug(msg % (user.name, project_id))
                    continue
                msg = "User %s not assigned to the project '%s'"
                self.logger.debug(msg % (user.name, project_id))
            try:
                role = self.setup_role(role_name, role_desc, domain)
                self.ks.roles.grant(
                    role=role.id, user=user.id, project=project_id)
                msg = "Granted role '%s' to user '%s' for project '%s'"
                self.logger.info(msg % (role_name, user.name, project_id))
            except ks_exceptions.ClientException as e:
                msg = "Cannot grant user '%s' with role '%s': %s"
                self.logger.error(msg % (user.id, role_name, e))


    def setup_group_project_roles(self, group, project_id, roles={},
                                  domain='default'):
        try:
            current_roles = { 
                r.name : r.id for r in self.ks.roles.list(
                    domain=domain, group_id=group.id)
            }
            assignments = [
                asg.role['id'] for asg in self.ks.role_assignments.list(
                    group=group.id, project=project_id)
            ]
        except ks_exceptions.NotFound as e:
            self.logger.error("Cannot find group '%s': %s" % (group.name, e))
            raise
        for role_name, role_desc in roles.items():
            if role_name in current_roles:
                msg = "Group %s already granted the role '%s'"
                self.logger.debug(msg % (group.name, role_name))
                if current_roles[role_name] in assignments:
                    msg = "Group %s already assigned to the project '%s'"
                    self.logger.debug(msg % (group.name, project_id))
                    continue
                msg = "Group %s not assigned to the project '%s'"
                self.logger.debug(msg % (group.name, project_id))
            try:
                role = self.setup_role(role_name, role_desc, domain)
                self.ks.roles.grant(
                    role=role.id, group=group.id, project=project_id)
                msg = "Granted role '%s' to group '%s' for project '%s'"
                self.logger.info(msg % (role_name, group.name, project_id))
            except ks_exceptions.ClientException as e:
                msg = "Cannot grant group '%s' with role '%s': %s"
                self.logger.error(msg % (group.id, role_name, e))


    def setup_user_groups(self, user, group_ids=[], domain='default'):
        current_groups_id = [
            g.id for g in self.ks.groups.list(domain=domain, user=user.id)
        ]
        for group_id in group_ids:
            if group_id in current_groups_id:
                self.logger.debug(
                    "User %s already in group '%s'" % (user.name, group_id))
                continue
            try:
                self.ks.users.add_to_group(user.id, group_id)
                self.logger.info(
                    "User %s added to group '%s'" % (user.name, group_id))
            except ks_exceptions.ClientException as e:
                msg = "Cannot add user '%s' to group '%s': %s"
                self.logger.error(msg % (user.id, group_id, e))


    def setup_users(self, users=[], domain='default'):
        users_defined = []
        for user in users:
            name = user['name']
            mail = user.get('email', None)
            desc = user.get('description', None)
            password = user.get('password', None)
            udomain = user.get('domain', domain)
            groups = user.get('groups', [])
            user_id = self.setup_user(name, password, mail, desc, udomain)
            group_ids = []
            for group in groups:
                gr = self.setup_group(group, None, udomain)
                group_ids.append(gr.id)
            self.setup_user_groups(user_id, group_ids, udomain)
            users_defined.append(user_id)
        return users_defined


    def setup_groups(self, groups=[], domain='default'):
        groups_defined = []
        for gr in groups:
            name = gr['name']
            desc = gr.get('description', None)
            gdomain = gr.get('domain', domain)
            group_id = self.setup_group(name, desc, gdomain)
            groups_defined.append(group_id)
        return groups_defined


    def setup_project(self, name, desc, roles={}, domain='default'):
        try:
            project = self.ks.projects.find(domain=domain, name=name)
        except ks_exceptions.NotFound as e:
            self.logger.debug("Project '%s' not found, creating ..." % name)
            project = self.ks.projects.create(
                name=name, description=desc, domain=domain)
            self.logger.info(
                "Created project %s with id '%s'" % (name, project.id))
        except ks_exceptions.NoUniqueMatch as e:
            self.logger.error("Project '%s' not unique!" % name)
            raise
        except ks_exceptions.ClientException as e:
            self.logger.error("Cannot search for project '%s': %s" % (name, e))
            raise
        self.logger.debug("Project '%s' found: %s" % (name, project.id))
        project_id = project.id
        if 'groups' in roles:
            for group, groles in roles['groups'].items():
                try:
                    group_id = self.ks.groups.find(domain=domain, name=group)
                except ks_exceptions.NotFound as e:
                    self.logger.error("Group '%s' not found" % group)
                else:
                    self.setup_group_project_roles(
                        group_id, project_id, groles, domain)
        if 'users' in roles:
            for user, uroles in roles['users'].items():
                try:
            	    user_id = self.ks.users.find(domain=domain, name=user)
       	        except ks_exceptions.NotFound as e:
            	    self.logger.error("User '%s' not found" % user)
                else:
                    self.setup_user_project_roles(
                        user_id, project_id, uroles, domain)
        return project_id


    def setup_network(self, name, project_id, net_type=None, 
                      segmentation_id=None, physical_net=None):
        self._get_neutron_client()
        net_id = None
        search = {
            'tenant_id': project_id,
            'name': name
        }
        try:
            networks = self.neutron.list_networks(**search)
            if networks['networks']:
                net_id = networks['networks'][0]['id']
                self.logger.debug(
                    "Network '%s' found with id '%s'" % (name, net_id))
                return net_id
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot search for networks: %s" % e)
            raise
        try:
            net = {
                'name': name,
                'admin_state_up': True,
                'router:external': False,
                'shared': False,
                'tenant_id': project_id
            }
            if segmentation_id:
                net['provider:segmentation_id'] = segmentation_id
            if net_type:
                net['provider:network_type'] = net_type
            if physical_net:
                net['router:external'] = True
                net['provider:physical_network'] = physical_net
            network = self.neutron.create_network({'network': net})
            net_id = network['network']['id']
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot create network '%s': %s" % (name, e))
            raise
        self.logger.info("Network '%s' created with id '%s'" % (name, net_id))
        return net_id


    def setup_subnet(self, name, project_id, net_id, net_cidr, net_gw, 
                     net_nameservers=[], allocate_ips=(None, None), 
                     net_dhcp=True):
        self._get_neutron_client()
        subnet_id = None
        search = {
            'tenant_id': project_id,
            'name': name
        }
        try:
            subnets = self.neutron.list_subnets(**search)
            if subnets['subnets']:
                subnet_id = subnets['subnets'][0]['id']
                self.logger.debug(
                    "Subnet '%s' found with id '%s'" % (name, subnet_id))
                return subnet_id
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot search for subnets: %s" % e)
            raise
        try:
            subnet = {
                'name': name,
                'ip_version': 4,
                'tenant_id': project_id,
                'network_id': net_id,
                'cidr': net_cidr,
                'enable_dhcp': net_dhcp
            }
            subnet['allocation_pools'] = [{
                'start': allocate_ips[0],
                'end': allocate_ips[1]
            }]
            if net_gw:
                subnet['gateway_ip'] = net_gw
            if net_nameservers:
                subnet['dns_nameservers'] = net_nameservers
            sub = self.neutron.create_subnet({'subnet': subnet})
            subnet_id = sub['subnet']['id']
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot create subnet '%s': %s" % (name, e))
            raise
        self.logger.info("Subnet '%s' created with id '%s'" % (name, subnet_id))
        return subnet_id


    def setup_router(self, name, project_id, publicnet_id, subnet_id, ha=True):
        self._get_neutron_client()
        router_id = None
        search = {
            'tenant_id': project_id,
            'name': name
        }
        try:
            routers = self.neutron.list_routers(**search)
            if routers['routers']:
                router_id = routers['routers'][0]['id']
                self.logger.debug(
                    "Router '%s' found with id '%s'" % (name, router_id))
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot search for routers: %s" % e)
            raise
        if not router_id:
            self.logger.debug("Creating router '%s' ..." % (name))
            router = {
                'name': name,
                'tenant_id': project_id,
                'ha': ha,
            	'admin_state_up': True,
                'external_gateway_info': {
                    'enable_snat': True
                }
            }
            if publicnet_id:
                router['external_gateway_info']['network_id'] = publicnet_id
            try:
            	r = self.neutron.create_router({'router': router})
            	router_id = r['router']['id']
            except neutron_exceptions.NeutronClientException as e:
                self.logger.error("Cannot create router '%s': %s" % (name, e))
                raise
            self.logger.info(
                "Router '%s' created with id '%s'" % (name, subnet_id))
        # gw port
        subnetgw_id = None
        if subnet_id:
            search = {
                'tenant_id': project_id,
                'device_id': router_id
            }
            try:
                ports = self.neutron.list_ports(**search)
                if ports['ports']:
                    for port in  ports['ports']:
                        for subnet in port['fixed_ips']:
                            if subnet['subnet_id'] == subnet_id:
                                subnetgw_id = port['id']
                                msg = "Gw port for subnet '%s' found, id '%s'"
                                self.logger.debug(msg % (subnet_id,subnetgw_id))
                                break
            except neutron_exceptions.NeutronClientException as e:
                self.logger.error("Cannot search for network ports: %s" % e)
                raise
            if not subnetgw_id:
                msg = "Defining internal gw for '%s' on router '%s'"
                self.logger.debug(msg % (subnet_id, name))
                try:
                    port = self.neutron.add_interface_router(
                        router_id, {'subnet_id': subnet_id})
                    subnetgw_id = port['port_id']
                    self.logger.info(
                        "Defined GW for '%s' on router '%s'" % (subnet_id,name))
                except neutron_exceptions.NeutronClientException as e:
                    self.logger.error(
                        "Cannot add gw to router '%s': %s" % (name, e))
                    raise
        return (router_id, subnetgw_id)


    def setup_networking(self, name, project_id, net_nameservers=[], 
                         publicnet_name=None, net_dhcp=True, cidr='10.0.0.0/16', 
                         cidr_range=None, net_type=None, segmentation_id=None, 
                         physical_net=None, ha_router=True):
        self._get_neutron_client()
        net_name = "%s-net" % name
        subnet_name = "%s-subnet" % name
        router_name = None
        net_id = None
        subnet_id = None
        router_id = None
        publicnet_id = None
        try:
            net = ipcalc.Network(cidr)
            net_cidr = "%s/%s" % (net.network(), net.subnet())
            net_gw = str(net.host_first())
            if not cidr_range:
                # Reserve the first 9 ips
                net_ips = [ str(ip) for ip in net]
                net_allocation_ips = (net_ips[9], net_ips[-1])
            else:
                net_ips = [ str(ip) for ip in ipcalc.Network(cidr_range) ]
                # TODO do it better!
                if net_gw in net_ips:
                    net_allocation_ips = (net_ips[1], net_ips[-1])
                else:
                    net_allocation_ips = (net_ips[0], net_ips[-1])
        except Exception as e:
            self.logger.error("Cannot parse CIDR: %s" %  (e)) 
            raise
        if not physical_net and publicnet_name:
            router_name = "%s-%s" % (name, publicnet_name)
            try:
                # find public network
                search = {
                    'name': publicnet_name,
                    'router:external': True 
                }
                networks = self.neutron.list_networks(**search)
                publicnet_id = networks['networks'][0]['id']
            except neutron_exceptions.NeutronClientException as e:
                self.logger.error(
                    "Cannot search for network '%s': %s" % (publicnet_name,e))
                raise
            except Exception as e:
                self.logger.error(
                    "Public external network '%s' not found!" % publicnet_name)
                raise
            msg = "Public network '%s' found with id '%s'"
            self.logger.debug(msg % (publicnet_name, publicnet_id)) 
        net_id = self.setup_network(
            net_name, project_id, net_type, segmentation_id, physical_net)
        subnet_id = self.setup_subnet(
            subnet_name, project_id, net_id, net_cidr, net_gw, 
            net_nameservers, net_allocation_ips, net_dhcp)
        # If is a external network, these resources are not needed
        if not physical_net and publicnet_id:
            router = self.setup_router(
                router_name, project_id, publicnet_id, subnet_id, ha_router)
            router_id = router[0]    
        return (net_id, subnet_id, router_id)


    def add_project_volumetype(self, name, project_id, backend):
        self._get_cinder_client()
        pass


    def add_project_aggregate(self, project_id, name='', az=''):
        self._get_nova_client()
        try:
            aggregates = self.nova.aggregates.list()
        except nova_exceptions.ClientException as e:
            self.logger.error("Cannot search for aggregate: %s" % e)
            raise
        done = False
        for agg in aggregates:            
            if name and agg.name != name:
                continue
            if az and agg.metadata['availability_zone'] != az:
                continue
            metadata = agg.metadata
            try:
                project_list = metadata['filter_tenant_id'].split(',')
                projects = [ p.strip(' ') for p in project_list ]
            except:
                projects = []
            if project_id not in projects:
                projects.append(str(project_id))
                metadata['filter_tenant_id'] = ', '.join(projects)
                self.nova.aggregates.set_metadata(agg.id, metadata)
                msg = "Project id '%s' added to aggregate '%s'"
                self.logger.info(msg % (project_id, agg.name))
            else:
                msg = "Project id '%s' already in aggregate '%s'"
                self.logger.debug(msg % (project_id, agg.name))
            done = True
        if not done:
            msg = "Aggregate '%s' " % name if name else ''
            msg = msg + "AZ '%s' " % az if az else msg
            self.logger.info(msg + " not found!")
        return done 


    def setup_secgroup(self, name, desc, project_id, rules=[]):
        self._get_neutron_client()
        sg_id = None
        sg_def = {
            'name': name,
            'tenant_id': project_id
        }
        try:
            sec_groups = self.neutron.list_security_groups(**sg_def)
            if sec_groups['security_groups']:
                sg = sec_groups['security_groups'][0]
                sg_id = sg['id']
                self.logger.debug(
                    "Security group '%s' found with id '%s'" % (name, sg_id))
        except neutron_exceptions.NeutronClientException as e:
            self.logger.error("Cannot search for security groups: %s" % e)
            raise
        if not sg_id:
            msg = "Security group '%s' not found! ... creating"
            self.logger.debug(msg % (name))
            try:
                if desc:
                    sg_def['description'] = desc
                sec_groups = self.neutron.create_security_group(
                    {'security_group': sg_def})
                sg_id = sec_groups['security_group']['id']
                msg = "Security group '%s' created with id '%s'"
                self.logger.info(msg % (name, sg_id))
            except neutron_exceptions.NeutronClientException as e:
                self.logger.error("Cannot create security group: %s" % e)
                raise
        sgrules = []
        for sgrule in sg['security_group_rules']:
            rule = [
                sgrule['direction'],
                sgrule['protocol'] if sgrule['protocol'] else '',
                sgrule['remote_ip_prefix'] if sgrule['remote_ip_prefix'] else '',
                sgrule['port_range_max'] if sgrule['port_range_max'] else '',
            	sgrule['port_range_min'] if sgrule['port_range_min'] else ''
            ]
            sgrules.append(rule)
        addrules = []
        for rule in rules:
            try:
            	r1 = [
                    rule.get('direction', 'ingress'),
                    rule.get('protocol', 'tcp'),
                    rule.get('cidr', '0.0.0.0/0'),
                    rule.get('port_range_max', -1),
                    rule.get('port_range_min', rule.get('port_range_max', -1))
            	]
            	for r2 in sgrules:
                    diff = [i for i in range(5) if r1[i] != r2[i]]
                    if not diff: break
                else:
                    addrules.append(r1)
            except:
            	self.logger.error('Rule not correct: %s' % rule)
            	raise ValueError(msg)
        error = False
        for rule in addrules:
            self.logger.debug('Adding security group rule: %s' % rule)
            sg_rule_def = {
                'security_group_id': sg_id,
                'direction': rule[0],
                'protocol': rule[1],
                'remote_ip_prefix': rule[2],
                'port_range_max': rule[3],
                'port_range_min': rule[4],               
            }
            try:
                sec_group_rule = self.neutron.create_security_group_rule(
                    {'security_group_rule': sg_rule_def})
                sg_rule_id = sec_group_rule['security_group_rule']['id']
                msg = "Security group rule '%s' created with id '%s'"
                self.logger.info(msg % (rule, sg_rule_id))
            except neutron_exceptions.NeutronClientException as e:
                self.logger.error("Cannot create security group rule: %s" % e)
            	error = True
        if len(addrules) > 0:
            msg = "Added %d rules to security group %s in project id '%s'"
            self.logger.info(msg % (len(addrules), name, project_id))
        return error


    def add_project_floatingips(self, project_id, publicnet_name, cidr):
        self._get_neutron_client()
        try:
            search = {
            	'name': publicnet_name,
                'router:external': True
            }
            networks = self.neutron.list_networks(**search)
            publicnet_id = networks['networks'][0]['id']
        except neutron_exceptions.NeutronClientException as e:
            msg = "Cannot search for public network '%s': %s"
            self.logger.error(msg % (publicnet_name, e))
            raise
        except Exception:
            msg = "Public network '%s' not found!"
            self.logger.error(msg % publicnet_name)
            raise
        else:
            msg = "Public network %s found with id '%s'"
            self.logger.debug(msg % (publicnet_name, publicnet_id))
        try:
            net = ipcalc.Network(cidr)
            net_cidr = "%s/%s" % (net.network(), net.subnet())
            net_ips = [ str(ip) for ip in net ]
        except Exception as e:
            self.logger.error("Cannot parse network CIDR %s: %s" % (cidr, e)) 
            raise
        self.logger.debug(
            "Allocating CIDR %s in '%s'" % (net_cidr, publicnet_id))
        allocated = []
        errors = []
        search = { 'tenant_id': project_id }
        result = self.neutron.list_floatingips(**search)
        floatingips = [ 
            fip['floating_ip_address'] for fip in result['floatingips'] 
        ]
        for ip in net_ips:
            if ip not in floatingips:
            	fip = {
                    'tenant_id': project_id,
            	    'floating_network_id': publicnet_id,
            	    'floating_ip_address': str(ip)
    	        }
    	    	try:
                    result = self.neutron.create_floatingip({'floatingip': fip})
                    fip_id = result['floatingip']['id']
                    msg = "Floating IP %s successfully allocated with id '%s'"
                    self.logger.info(msg % (ip, fip_id))
                    allocated.append(ip)
                except Exception as e:
                    msg = "Cannot allocate floating IP %s: %s"
                    self.logger.warn(msg % (ip, e))
                    errors.append(ip)
            else:
                self.logger.debug("Floating IP %s already allocated" % ip)
        msg = "Floating IP(s) allocated for project id '%s': %s"
        self.logger.debug(msg % (project_id, len(allocated)))
        return allocated


    def setup_cinder_quotas(self, project_id, gigabytes=None, volumes=None, 
                            backups=None, snapshots=None, backup_gigabytes=None):
        self._get_cinder_client()
        # ToDo QoS
        updated = False
        msg = "Updating Cinder quotas %s for project id '%s' from %s to %s"
        quotas = self.cinder.quotas.get(project_id)
        qs = {
            'backup_gigabytes': quotas.backup_gigabytes,
            'backups': quotas.backups,
            'gigabytes': quotas.gigabytes,
            'snapshots': quotas.snapshots,
            'volumes': quotas.volumes
        }
        if backup_gigabytes is not None \
            and qs['backup_gigabytes'] != backup_gigabytes:
            self.logger.debug(msg % (
                'backup_gigabytes', 
                project_id, qs['backup_gigabytes'], 
                backup_gigabytes))
            qs['backup_gigabytes'] = backup_gigabytes
            updated = True
        if backups is not None and qs['backups'] != backups:
            self.logger.debug(msg % (
                'backups', project_id, qs['backups'], backups))
            qs['backups'] = backups
            updated = True
        if gigabytes is not None and qs['gigabytes'] != gigabytes:
            self.logger.debug(msg % (
                'gigabytes', project_id, qs['gigabytes'], gigabytes))
            qs['gigabytes'] = gigabytes
            updated = True
        if snapshots is not None and qs['snapshots'] != snapshots:
            self.logger.debug(msg % (
                'snapshots', project_id, qs['snapshots'], snapshots))
            qs['snapshots'] = snapshots
            updated = True
        if volumes is not None and qs['volumes'] != volumes:
            self.logger.debug(msg % (
                'volumes', project_id, qs['volumes'], volumes))
            qs['volumes'] = volumes
            updated = True
        if updated:
            try:
                self.cinder.quotas.update(
                    project_id, backup_gigabytes=qs['backup_gigabytes'], 
                    gigabytes=qs['gigabytes'], volumes=qs['volumes'], 
                    snapshots=qs['snapshots'], backups=qs['backups'])
            except nova_exceptions.ClientException as e:
                msg = "Unable to setup Cinder quotas for project id '%s': %s"
                self.logger.error(msg % (project_id, e))
                raise
            msg = "Cinder quotas updated successfully for project id '%s'"
            self.logger.info(msg % project_id)
        else:
            msg = "Cinder quotas update not needed for project id '%s'"
            self.logger.debug(msg % project_id)
        return updated


    def setup_nova_quotas(self, project_id, instances=None, cores=None, 
                          ram_mb=None, floating_ips=None):
        self._get_nova_client()
        updated = False
        msg = "Updating nova quota %s for project id '%s' from %s to %s"
        qs = self.nova.quotas.get(project_id).to_dict()
        if instances is not None and qs['instances'] != instances:
            self.logger.debug(msg % (
                'instances', project_id, qs['instances'], instances))
            qs['instances'] = instances
            updated = True
        if cores is not None and qs['cores'] != cores:
            self.logger.debug(msg % ('cores', project_id, qs['cores'], cores))
            qs['cores'] = cores
            updated = True
        if ram_mb is not None and qs['ram'] != ram_mb:
            self.logger.debug(msg % (
                'ram_mb', project_id, qs['ram'], ram_mb))
            qs['ram'] = ram_mb
            updated = True
        if floating_ips is not None and qs['floating_ips'] != floating_ips:
            self.logger.debug(msg % (
                'floating_ips', project_id,  qs['floating_ips'], floating_ips))
            qs['floating_ips'] = floating_ips
            updated = True
        if updated:
            try:
            	self.nova.quotas.update(
            	    project_id, instances=qs['instances'], 
                    cores=qs['cores'], ram=qs['ram'], 
                    floating_ips=qs['floating_ips'])
            except nova_exceptions.ClientException as e:
                msg = "Unable to setup new Nova quotas for project id '%s': %s"
                self.logger.error(msg % (project_id, e))
                raise
            msg = "Nova quotas updated successfully for project id '%s'"
            self.logger.info(msg % project_id)
        else:
            msg = "Nova quotas update not needed for project id '%s'"
            self.logger.debug(msg % project_id)
        return updated

 
    def setup_neutron_quotas(self, project_id, floating_ips=None, routers=None, 
                             subnets=None, networks=None, ports=None):
        self._get_neutron_client()
        updated = False
        msg = "Updating neutron quota %s for project id '%s' from %s to %s"
        neutron_qs = self.neutron.show_quota(project_id)
        qs = neutron_qs['quota']
        if floating_ips is not None and qs['floatingip'] != floating_ips:
            self.logger.debug(msg % (
                'floating_ips', project_id, qs['floatingip'], floating_ips))
            qs['floatingip'] = floating_ips
            updated = True
        if routers is not None and qs['router'] != routers:
            self.logger.debug(msg % (
                'routers', project_id, qs['router'], routers))
            qs['router'] = routers
            updated = True
        if subnets is not None and qs['subnet'] != subnets:
            self.logger.debug(msg % (
                'subnets', project_id, qs['subnet'], subnets))
            qs['subnet'] = subnets
            updated = True
        if networks is not None and qs['network'] != networks:
            self.logger.debug(msg % (
                'networks', project_id, qs['network'], networks))
            qs['network'] = networks
            updated = True
        if ports is not None and qs['port'] != ports:
            self.logger.debug(msg % ('ports', project_id, qs['port'], ports))
            qs['port'] = ports
            updated = True
        if updated:
            try:
            	self.neutron.update_quota(project_id, {'quota': qs})
            except neutron_exceptions.NeutronClientException as e:
                msg = "Unable to setup Neutron quotas for project id '%s': %s"
                self.logger.error(msg % (project_id, e))
                raise
            msg = "Neutron quotas updated successfully for project id '%s'"
            self.logger.info(msg % project_id)
        else:
            msg = "Neutron quotas update not needed for project id '%s'"
            self.logger.debug(msg % project_id)
        return updated



# Program functions for Yaml parsing

def project_nova(osproject, project_id, nova):
    if 'aggregates' in nova:
        nova_agg_az = nova['aggregates'].get('az', '')
        nova_agg_agg = nova['aggregates'].get('aggregate', '')
        osproject.add_project_aggregate(project_id, nova_agg_agg, nova_agg_az)
    if 'quotas' in nova:
        nova_q_instances = nova['quotas'].get('instances', None)
        nova_q_cores = nova['quotas'].get('cores', None)
        nova_q_ram = nova['quotas'].get('ram_mb', None)
        osproject.setup_nova_quotas(
            project_id, nova_q_instances, nova_q_cores, nova_q_ram)


def project_cinder(osproject, project_id, cinder):
    if 'quotas' in cinder:
    	cinder_q_gb = cinder['quotas'].get('gigabytes', None)
        cinder_q_volumes = cinder['quotas'].get('volumes', None)
        cinder_q_backups = cinder['quotas'].get('backups', None)
        cinder_q_snapshots = cinder['quotas'].get('snapshots', None)
        cinder_q_backup_gb = cinder['quotas'].get('backupgb', None)
        osproject.setup_cinder_quotas(
            project_id, cinder_q_gb, cinder_q_volumes, cinder_q_backups, 
            cinder_q_snapshots, cinder_q_backup_gb)


def project_neutron(osproject, project_id, neutron):
    for neutron_net in neutron.get('networks', []):
    	neutron_net_name = neutron_net['name']
        neutron_net_public = neutron_net.get('public', None)
        neutron_net_cidr = neutron_net.get('cidr', '10.0.0.0/24')
        neutron_net_range = neutron_net.get('dhcp_range', None)
        neutron_net_dns = neutron_net.get('dns', [])
        neutron_net_dhcp = bool(neutron_net.get('dhcp', True))
        neutron_net_type = neutron_net.get('type', None)
        neutron_net_segid = neutron_net.get('segmentation_id', None)
        neutron_net_physical = neutron_net.get('physical', None)
        neutron_net_harouter = bool(neutron_net.get('ha_router', True))
        osproject.setup_networking(
            neutron_net_name, project_id, neutron_net_dns, neutron_net_public, 
            neutron_net_dhcp, neutron_net_cidr, neutron_net_range,
            neutron_net_type, neutron_net_segid, neutron_net_physical,
            neutron_net_harouter)
    if 'floating_ips' in neutron:
        neutron_fips = neutron.get('floating_ips', {})
    	for neutron_fips_pool, neutron_fips_ips in neutron_fips.items():
            osproject.add_project_floatingips(
                project_id, neutron_fips_pool, neutron_fips_ips)
    if 'secgroups' in neutron:
        for neutron_seg in neutron['secgroups']:
            neutron_seg_name = neutron_seg['name']
            neutron_seg_des = neutron_seg.get('description', '')
            neutron_seg_rles = neutron_seg.get('rules', [])            
            osproject.setup_secgroup(
                neutron_seg_name, neutron_seg_des, project_id, neutron_seg_rles)
    if 'quotas' in neutron:
        neutron_q_net = neutron['quotas'].get('networks', None)
        neutron_q_port = neutron['quotas'].get('ports', None)
        neutron_q_subnet = neutron['quotas'].get('subnets', None)
        neutron_q_router = neutron['quotas'].get('routers', None)
        neutron_q_fpis = neutron['quotas'].get('floating_ips', None)
        osproject.setup_neutron_quotas(
            project_id, neutron_q_fpis, neutron_q_router, neutron_q_subnet, 
            neutron_q_net, neutron_q_port)


def project_project(osproject, pr, domain='default'):
    pr_name = pr['name']
    pr_domain = pr.get('domain', domain)
    pr_desc = pr.get('description', None)
    pr_roles = pr.get('roles', {})
    pr_id = osproject.setup_project(pr_name , pr_desc, pr_roles, pr_domain)
    if 'nova' in pr:
        project_nova(osproject, pr_id, pr['nova'])
    if 'cinder' in pr:
        project_cinder(osproject, pr_id, pr['cinder'])
    if 'neutron' in pr:
        project_neutron(osproject, pr_id, pr['neutron'])


def main():
    program = ProgramCli()
    try:
        config = program.parse_config()
    except:
        return 1
    logger = program.logger
    auth = config['auth']
    domain = auth['project_domain_name']
    logger.info("Talking with OpenStack API")
    try:
        os = OpenStackProject(auth['auth_url'], auth, logger=logger)
    except:
        return 2
    logger.info("Processing groups ...")
    try:
        os.setup_groups(config['groups'], domain)
    except:
        return 10
    logger.info("Processing users ...")
    try:
        os.setup_users(config['users'], domain)
    except:
        return 20
    pr_error = False
    for pr in config['projects']:
        logger.info("Processing project: %s ..." % pr['name'])
        try:
            project_project(os, pr, domain)
        except Exception as e:
            logger.error("Project %s: %s" % (pr['name'], e))
            pr_error = True
    rcode = 30 if pr_error else 0
    logger.info("Finished! (%d)" % rcode)
    return rcode

if __name__ == '__main__':
    sys.exit(main())

