# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import signal
import subprocess
import novaclient.exceptions as novaexception
import os
import shlex
import socket
import time

from heat.common import exception
from heat.openstack.common import log as logging
from heat.engine.resources.rackspace import rackspace_resource
from heat.engine import scheduler
from heat.engine.resources import nova_utils
from heat.engine.resources import instance

logger = logging.getLogger(__name__)


class Alarm(Exception):
    pass


def alarm_handler(signum, frame):
    raise Alarm


def run_command(cmd, lines=None, timeout=None):
    p = subprocess.Popen(shlex.split(cmd),
                         close_fds=True,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    signal.signal(signal.SIGALRM, alarm_handler)
    if timeout:
        signal.alarm(timeout)

    try:
        if lines:
            (stdout, stderr) = p.communicate(input=lines)

        status = p.wait()
        signal.alarm(0)
    except Alarm:
        logger.warning("Timeout running post-build process")
        status = 1
        stdout = ''
        p.kill()

    if lines:
        output = stdout

        # Remove this cruft from Windows build output
        output = output.replace('\x08', '')
        output = output.replace('\r', '')

    else:
        output = p.stdout.read().strip()

    return (status, output)

def wait_net_service(server, port, timeout=None):
    """ Wait for network service to appear
        @param timeout: in seconds, if None or 0 wait forever
        @return: True of False, if timeout is None may return only True or
                 throw unhandled network exception
    """

    s = socket.socket()
    if timeout:
        from time import time as now
        # time module is needed to calc timeout shared between two exceptions
        end = now() + timeout

    while True:
        try:
            if timeout:
                next_timeout = end - now()
                if next_timeout < 0:
                    return False
                else:
                    s.settimeout(next_timeout)

            s.connect((server, port))

        except:
            # Handle refused connections, etc.
            if timeout:
                next_timeout = end - now()
                if next_timeout < 0:
                    return False
                else:
                    s.settimeout(next_timeout)

            time.sleep(1)

        else:
            s.close()
            return True

def psexec_run_script(username, password, address, filename,
                      command, path="C:\\Windows"):
    psexec = "%s/psexec.py" % os.path.dirname(__file__)
    cmd_string = "nice python %s -path '%s' '%s':'%s'@'%s' " \
             "'c:\\windows\\sysnative\\cmd'"
    cmd = cmd_string % (psexec, path, username, password, address)

    lines = "put %s\n%s\nexit\n" % (filename, command)

    timeout = 300
    timeout_msg = "Port 445 never opened up after 5 minutes"

    if wait_net_service(address, 445, timeout=timeout):
        return run_command(cmd, lines=lines, timeout=1800)

    else:
        output = timeout_msg
        status = 1

        return (status, output)


class WindowsServer(instance.Instance):  

    properties_schema = {'flavor': {'Type': 'String', 'Required': True},
                         'image': {'Type': 'String', 'Required': True},
                         'user_data': {'Type': 'String'},
                         'key_name': {'Type': 'String'},
                         'Volumes': {'Type': 'List'},
                         'name': {'Type': 'String'}}

    attributes_schema = {'PrivateDnsName': ('Private DNS name of the specified'
                                            ' instance.'),
                         'PublicDnsName': ('Public DNS name of the specified '
                                           'instance.'),
                         'PrivateIp': ('Private IP address of the specified '
                                       'instance.'),
                         'PublicIp': ('Public IP address of the specified '
                                      'instance.')}

    def __init__(self, name, json_snippet, stack):
        super(WindowsServer, self).__init__(name, json_snippet, stack)
        self._server = None
        self._distro = None
        self._public_ip = None
        self._private_ip = None
        self.rs = rackspace_resource.RackspaceResource(name,
                                                       json_snippet,
                                                       stack)

    def physical_resource_name(self):
        name = self.properties.get('name')
        if name:
            return name

        return super(WindowsServer, self).physical_resource_name()

    def nova(self):
        return self.rs.nova()  # Override the Instance method

    def cinder(self):
        return self.rs.cinder()

    @property
    def server(self):
        """Get the Cloud Server object."""
        if not self._server:
            logger.debug("Calling nova().servers.get()")
            self._server = self.nova().servers.get(self.resource_id)
        return self._server

    @property
    def distro(self):
        """Get the distribution for this server."""
        if not self._distro:
            logger.debug("Calling nova().images.get()")
            image = self.nova().images.get(self.properties['image'])
            self._distro = image.metadata['os_distro']
        return self._distro

    @property
    def script(self):
        """Get the config script for the Cloud Server image."""
        return self.image_scripts[self.distro]

    @property
    def flavors(self):
        """Get the flavors from the API."""
        logger.debug("Calling nova().flavors.list()")
        return [flavor.id for flavor in self.nova().flavors.list()]


    def _get_ip(self, ip_type):
        """Return the IP of the Cloud Server."""
        if ip_type in self.server.addresses:
            for ip in self.server.addresses[ip_type]:
                if ip['version'] == 4:
                    return ip['addr']

        raise exception.Error("Could not determine the %s IP of %s." %
                              (ip_type, self.properties['image']))

    @property
    def public_ip(self):
        """Return the public IP of the Cloud Server."""
        if not self._public_ip:
            self._public_ip = self._get_ip('public')
        return self._public_ip

    @property
    def private_ip(self):
        """Return the private IP of the Cloud Server."""
        if not self._private_ip:
            self._private_ip = self._get_ip('private')
        return self._private_ip

    @property
    def has_userdata(self):
        if self.properties['user_data'] or self.metadata != {}:
            return True
        else:
            return False

    def validate(self):
        """Validate user parameters."""
        if self.properties['flavor'] not in self.flavors:
            return {'Error': "flavor not found."}

        # It's okay if there's no script, as long as user_data and
        # metadata are empty
        if not self.script and self.has_userdata:
            return {'Error': "user_data/metadata are not supported with %s." %
                    self.properties['image']}

    def handle_create(self):
        """Create a Rackspace Cloud Servers container.

        Rackspace Cloud Servers does not have the metadata service
        running, so we have to transfer the user-data file to the
        server and then trigger cloud-init.
        """
    
        windows_script = """\
netsh advfirewall firewall add rule name="Port 445" \
dir=in action=allow protocol=TCP localport=445
    """  
        
        # Retrieve server creation parameters from properties
        flavor = self.properties['flavor']
        image = self.properties['image']

        personality_files = {
            "C:\\cloud-automation\\bootstrap.cmd": windows_script}

        # Create server
        client = self.nova().servers
        logger.debug("Calling nova().servers.create()")
        server = client.create(self.physical_resource_name(),
                               image,
                               flavor,
                               files=personality_files)

        self.adminpass = server.adminPass

        # Save resource ID to db
        self.resource_id_set(server.id)

        return server, scheduler.TaskRunner(self._attach_volumes_task())

    
    def check_create_complete(self, cookie):
        """Check if server creation is complete and handle server configs."""
        if not self._check_active(cookie):
            return False

        if self.has_userdata:
            # Create heat-script and userdata files on server
            raw_userdata = self.properties['user_data'] or ''
            userdata = nova_utils.build_userdata(self, raw_userdata)

            run_script = '' # TODO: Define the bootstrap script
            

            (self.status, self.output) = psexec_run_script('Administrator',
                                                           self.adminpass,
                                                           self.connect_ip,
                                                           run_script,
                                                           run_command)

        return True

    def resource_mapping():
        if rackspace_resource.PYRAX_INSTALLED:
            return {
                'Rackspace::Cloud::WindowsServer': WindowsServer,
            }
        else:
            return {}
