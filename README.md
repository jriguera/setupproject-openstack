# osproject

Program to manage OpenStack projects by automating the creation of resourcers 
in order to start working on them: users, groups, roles, networks, security 
groups, routers, quotas and other features like:

* It is able to setup filters in aggregates metadata for specific projects
* It is able to allocate a range of floating IPs from a pool to a project
* It is idempotent, run as many times as you need (but id does not do rollback!)
* It reads all the configuration from a Yaml file

**This program does not delete resources**, everytime it runs, it tries to setup 
all resources defined by the Yaml configuration file. That means, those 
resources can have additional settings (other users, more rules on the security 
groups, other networks, ...) and those additional settings will not be changed,
except of course in cases like quotas.


# Using it

First, install all the python requirements, not many, only yaml, ipcalc and 
the python openstack libraries: `pip install -r requirements.txt`. It does not
use other kind of libraries.

**It was tested on OpenStack Liberty and it uses Keystone v3 API for sessions.** 

```
# python osproject.py --help
Error with 'logging.conf': [Errno 2] No such file or directory: u'logging.conf'
osproject: Using default logging settings
usage: osproject.py [-h] [-d DOMAIN] [-c CONFIG] [--group NAME DESCRIPTION]
                    [--role NAME DESCRIPTION] [--user USERID EMAIL PASSWORD]
                    [--groups GROUP [GROUP ...]] [--project NAME DESCRIPTION]
                    [--network NAME CIDR PUBLICNET]
                    [--floatingips PUBLICNET CIDR] [--aggregate AGGREGATE]

Program to manage OpenStack projects by automating the creation of resourcers 
in order to start working on them: users, groups, roles, networks, security 
groups, routers, quotas and other features like:

* It is able to setup filters in aggregates metadata for specific projects
* It is able to allocate a range of floating IPs from a pool to a project
* It is idempotent, run as many times as you need (but it does not do rollback!)
* It reads all the configuration from a Yaml file

optional arguments:
  -h, --help            show this help message and exit

Configuration options:
  -d DOMAIN, --domain DOMAIN
                        Keystone domain
  -c CONFIG, --config CONFIG
                        Yaml configuration file

Options to create new groups:
  --group NAME DESCRIPTION
                        Project group name and description
  --role NAME DESCRIPTION
                        Roles name and description

Arguments to define new users:
  --user USERID EMAIL PASSWORD
                        Userid, email and password
  --groups GROUP [GROUP ...]
                        List of user groups

Options to create a new project:
  --project NAME DESCRIPTION
                        Name of the project
  --network NAME CIDR PUBLICNET
                        Internal project network name and CIDR
  --floatingips PUBLICNET CIDR
                        Reserve the floating IPs for the project
  --aggregate AGGREGATE
                        Aggregate to attach the project

Made to learn OpenStack APIs
v0.1.0, 2016 Jose Riguera jriguera@gmail.com
```

At the top you will see a kind of "error", it is not important, it is only the 
configuration file for logging. with the default settings all the messages 
with level equal *INFO* will be shown. To avoid the "error", just copy the 
sample logging file: 
`cp logging.conf.sample logging.conf`

The program is able to read the **OS_** environment variables used for the 
OpenStack clients, there is an `openrc.sh.sample` example file you can use to 
edit the admin credentials and load within the env `. openrc.sh.sample`.

But, I think is better if we define a configuration file ...


# Configuration file

The program is idempotent, it checks the current settings of the resources 
before creating them. The idea is just add new projects to the configuration 
file and run it to converge with OpenStack.

The default configuration file is `osproject.yml` and there is an example 
called `osproject.yml.sample` which makes use of Yaml anchors to help having
a kind of defaults, but lets focus on the sections of the configuration file:

* `auth`: defines the admin credentials to setup a session with OpenStack.
Those variables can be loaded from the environment OS variables.

```yaml
auth:
  user_domain_name: Default
  project_domain_name: Default
  region_name: RegionOne
  username: admin
  password: admin
  project_name: admin
  auth_url: "http://1.1.1.1:5000/v3/"
```

* `groups`: defines a list of groups, only name and description.

```yaml
groups:
  - name: jose-test-managers
    description: "Administrators of jose-test"
  - name: jose-test-users
    description: "Users of jose-test"
```

* `users`: list of users with parameters to define each one of them. The 
password is used only at creation time, it will not be updated if the user 
decides to change it. Also you can define a list of groups to setup they 
membership.

```yaml
users:
  - name: jose1
    email: jose1@example.com
    password: hola1
    groups:
      - jose-test-admin
```

* and finally `project` a list of projects with all the parameters:

```yaml
projects:
  - name: jose-test
    description: "Jose test test"
    roles:
      groups:
        jose-test-users:
          _role_: "description of the role"
          _member_: "Horizon dashboard"
          Member: "Normal users"
        jose-test-managers:
          _member_: "Horizon dashboard"
          Member: "Normal users"
          Manager: "Manager of the project"
      users:
        jose1:
          admin: "admin"
    cinder:
      quotas:
        gigabytes: 1111
        volumes: 11
        backups: 22
        snapshots: 33
        backupgb: 2222
    nova:
      quotas:
        instances: 3
	cores: 1
	ram_mb: 1
      aggregates:
        az: Dordrecht
        aggregate: kvm.dogo
    neutron:
      secgroups:
        - name: default
          description: default
          rules:
            - protocol: tcp
              cidr: "0.0.0.0/0"
              port_range_max: 22
              port_range_min: 22
              direction: ingress
      quotas:
        networks: 90
	ports: 91
	subnets: 92
	routers: 93
	floating_ips: 94
      networks:
        - name: jose-test1
          public: online_dev
          cidr: "10.10.0.0/24"
          dns:
            - 8.8.8.8
          type: vlan
      floating_ips:
        online_dev: '10.230.18.14/31'
```

The `roles` section defines the assigments between users and/or groups and the
roles within the project context. 

In `nova`, the `aggregates` section has two optional parameters `az` and 
`aggregate`, they are used to setup the metadata fiter `tenant_id` for the 
nova scheduler in order to reserver specific compute hosts for the project 
(`aggregate` parameter should be enough in most of the cases, but you can
specify both).

In `neutron`, apart of the quotas, you can define additional rules in the 
security groups to allow connectivity to the VM. Also, it is possible to
pre-allocate a specific range of floating IPs for the project from a public
pool by the `floating_ip` parameter (`pool`: `ip-range`). Note, it is not 
enough setup the quotas according to that to limit the floating IPs per 
project, an user can release an IP and request another one, the proper way 
to do it is by defining roles (like manager) and editing the policy files. 
`networks` is a list of internal networks, if `public` is not provided, no
internal router will be created. 



# Output log

Ouput log file example `osproject.log` with `logging.conf.sample` configuration:

```
2016-02-24 18:41:38,326 osproject [INFO] Using logging settings from 'logging.conf'
2016-02-24 18:41:38,341 osproject [INFO] Read configuration file 'osproject.yml'
2016-02-24 18:41:38,341 osproject [INFO] Talking with OpenStack API
2016-02-24 18:41:38,341 osproject [DEBUG] Getting session using admin credentials
2016-02-24 18:41:38,342 osproject [DEBUG] New session defined: '<keystoneclient.session.Session object at 0x7fec3e305e50>'
2016-02-24 18:41:38,342 osproject [DEBUG] Setting up Keystone client
2016-02-24 18:41:38,342 osproject [INFO] Processing groups ...
2016-02-24 18:41:38,623 osproject [DEBUG] Group 'jose-test-1' not found, creating ...
2016-02-24 18:41:38,727 osproject [INFO] Created group jose-test-1 with id 'd6304af4d25249cebb1a56582dce7fc8'
2016-02-24 18:41:38,799 osproject [DEBUG] Group 'jose-test-2' not found, creating ...
2016-02-24 18:41:38,899 osproject [INFO] Created group jose-test-2 with id '2176c7243447415fa2d470a6389c9be5'
2016-02-24 18:41:38,900 osproject [INFO] Processing users ...
2016-02-24 18:41:39,008 osproject [DEBUG] User 'jose1' not found, creating ...
2016-02-24 18:41:39,117 osproject [INFO] Created user jose1 with id '6df446003503462d94e1ed12e9d31466'
2016-02-24 18:41:39,439 osproject [INFO] User jose1 added to group 'd6304af4d25249cebb1a56582dce7fc8'
2016-02-24 18:41:39,538 osproject [DEBUG] User 'jose2' not found, creating ...
2016-02-24 18:41:39,647 osproject [INFO] Created user jose2 with id 'e857db66ad32431ab402f82782ff742c'
2016-02-24 18:41:39,902 osproject [INFO] User jose2 added to group '2176c7243447415fa2d470a6389c9be5'
2016-02-24 18:41:39,903 osproject [INFO] Processing project: jose-test ...
2016-02-24 18:41:40,000 osproject [DEBUG] Project 'jose-test' not found, creating ...
2016-02-24 18:41:40,110 osproject [INFO] Created project jose-test with id '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:40,110 osproject [DEBUG] Project 'jose-test' found: 8e38fc5df8444f4a9fc6c9df746b6328
2016-02-24 18:41:40,413 osproject [DEBUG] Group jose-test-2 already granted the role 'Member'
2016-02-24 18:41:40,413 osproject [DEBUG] Group jose-test-2 not assigned to the project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:40,637 osproject [INFO] Granted role 'Member' to group 'jose-test-2' for project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:40,962 osproject [DEBUG] Group jose-test-1 already granted the role 'Member'
2016-02-24 18:41:40,962 osproject [DEBUG] Group jose-test-1 not assigned to the project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:41,176 osproject [INFO] Granted role 'Member' to group 'jose-test-1' for project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:41,177 osproject [DEBUG] Group jose-test-1 already granted the role '_member_'
2016-02-24 18:41:41,177 osproject [DEBUG] Group jose-test-1 not assigned to the project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:41,365 osproject [INFO] Granted role '_member_' to group 'jose-test-1' for project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:41,786 osproject [DEBUG] Role 'role_jose_1' not found, creating ...
2016-02-24 18:41:41,855 osproject [INFO] Created role role_jose_1 with id '5eb72016168d40c6969a8f4d6fbe7b56'
2016-02-24 18:41:41,941 osproject [INFO] Granted role 'role_jose_1' to user 'jose1' for project '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:41,941 osproject [DEBUG] Setting up Nova client
2016-02-24 18:41:42,253 osproject [INFO] Project id '8e38fc5df8444f4a9fc6c9df746b6328' added to aggregate 'kvm.dogo'
2016-02-24 18:41:42,274 osproject [DEBUG] Updating nova quota instances for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 20 to 3
2016-02-24 18:41:42,274 osproject [DEBUG] Updating nova quota cores for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 20 to 1
2016-02-24 18:41:42,274 osproject [DEBUG] Updating nova quota ram_mb for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 51200 to 1
2016-02-24 18:41:42,342 osproject [INFO] Nova quotas updated successfully for project id '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:42,342 osproject [DEBUG] Setting up Cinder client
2016-02-24 18:41:42,955 osproject [DEBUG] Updating Cinder quotas backup_gigabytes for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 1000 to 2222
2016-02-24 18:41:42,955 osproject [DEBUG] Updating Cinder quotas backups for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 10 to 22
2016-02-24 18:41:42,955 osproject [DEBUG] Updating Cinder quotas gigabytes for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 0 to 1111
2016-02-24 18:41:42,955 osproject [DEBUG] Updating Cinder quotas snapshots for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 0 to 33
2016-02-24 18:41:42,955 osproject [DEBUG] Updating Cinder quotas volumes for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 0 to 11
2016-02-24 18:41:43,488 osproject [INFO] Cinder quotas updated successfully for project id '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:43,489 osproject [DEBUG] Setting up Neutron client
2016-02-24 18:41:43,531 osproject [DEBUG] Public network 'online_dev' found with id '11b4a274-e8de-43c8-a268-456bc61fb4ea'
2016-02-24 18:41:43,659 osproject [INFO] Network 'jose-test1-net' created with id '19b6986a-bc92-408b-9f2c-b1658c01bd21'
2016-02-24 18:41:43,868 osproject [INFO] Subnet 'jose-test1-subnet' created with id '1b2699ad-7555-4e44-bcd8-81ad06a59b26'
2016-02-24 18:41:43,903 osproject [DEBUG] Creating router 'jose-test1-online_dev' ...
2016-02-24 18:41:44,617 osproject [INFO] Router 'jose-test1-online_dev' created with id '1b2699ad-7555-4e44-bcd8-81ad06a59b26'
2016-02-24 18:41:44,661 osproject [DEBUG] Defining internal gw for '1b2699ad-7555-4e44-bcd8-81ad06a59b26' on router 'jose-test1-online_dev'
2016-02-24 18:41:44,994 osproject [INFO] Defined GW for '1b2699ad-7555-4e44-bcd8-81ad06a59b26' on router 'jose-test1-online_dev'
2016-02-24 18:41:45,033 osproject [DEBUG] Public network online_dev found with id '11b4a274-e8de-43c8-a268-456bc61fb4ea'
2016-02-24 18:41:45,034 osproject [DEBUG] Allocating CIDR 10.230.18.14/31 in '11b4a274-e8de-43c8-a268-456bc61fb4ea'
2016-02-24 18:41:45,177 osproject [WARNING] Cannot allocate floating IP 10.230.18.14: Unable to complete operation for network 11b4a274-e8de-43c8-a268$
2016-02-24 18:41:45,296 osproject [WARNING] Cannot allocate floating IP 10.230.18.15: Unable to complete operation for network 11b4a274-e8de-43c8-a268$
2016-02-24 18:41:45,297 osproject [DEBUG] Floating IP(s) allocated for project id '8e38fc5df8444f4a9fc6c9df746b6328': 0
2016-02-24 18:41:45,325 osproject [DEBUG] Security group 'default' found with id '5533db31-ed89-4ad1-bf5c-3095fcf5f930'
2016-02-24 18:41:45,325 osproject [DEBUG] Adding security group rule: ['ingress', 'tcp', '0.0.0.0/0', 22, 22]
2016-02-24 18:41:45,392 osproject [INFO] Security group rule '['ingress', 'tcp', '0.0.0.0/0', 22, 22]' created with id 'd7bd3fb7-6e65-4530-b569-1e0211$
2016-02-24 18:41:45,392 osproject [INFO] Added 1 rules to security group default in project id '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:45,410 osproject [DEBUG] Updating neutron quota floating_ips for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 50 to 94
2016-02-24 18:41:45,410 osproject [DEBUG] Updating neutron quota routers for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 10 to 93
2016-02-24 18:41:45,410 osproject [DEBUG] Updating neutron quota subnets for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 10 to 92
2016-02-24 18:41:45,410 osproject [DEBUG] Updating neutron quota networks for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 10 to 90
2016-02-24 18:41:45,411 osproject [DEBUG] Updating neutron quota ports for project id '8e38fc5df8444f4a9fc6c9df746b6328' from 50 to 91
2016-02-24 18:41:45,473 osproject [INFO] Neutron quotas updated successfully for project id '8e38fc5df8444f4a9fc6c9df746b6328'
2016-02-24 18:41:45,474 osproject [INFO] Finished! (0)
```


## Author

José Riguera López <jriguera@gmail.com>

