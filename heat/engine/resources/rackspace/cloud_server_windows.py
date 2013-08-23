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

import impacket
import signal
import subprocess
import novaclient.exceptions as novaexception

from heat.common import exception
from heat.openstack.common import log as logging
from heat.engine.resources.rackspace import rackspace_resource
from heat.engine.resources.rackspace import cloud_server

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


class WindowsServer(CloudServer):

    windows_script = """\
netsh advfirewall firewall add rule name="Port 445" \
dir=in action=allow protocol=TCP localport=445
    """    

    image_scripts = {'windows': windows_script}


    def handle_create(self):
        """Create a Rackspace Cloud Servers container.

        Rackspace Cloud Servers does not have the metadata service
        running, so we have to transfer the user-data file to the
        server and then trigger cloud-init.
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

            (self.status, self.output) = psexec_run_script('Administrator',
                                                           self.adminpass,
                                                           self.connect_ip,
                                                           run_script,
                                                           run_command,
                                                           save_path)

        return True
