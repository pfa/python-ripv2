#!/usr/bin/env python

"""Interface to the OS."""

# ripserv.py 
# Copyright (C) 2012 Patrick F. Allen 
#  
# This program is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License 
# as published by the Free Software Foundation; either version 2 
# of the License, or (at your option) any later version. 
#  
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details. 
#  
# You should have received a copy of the GNU General Public License 
# along with this program; if not, write to the Free Software 
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import ipaddr
import subprocess
import re
import logging
import logging.config

class _RIPSystem(object):
    """Abstract class for OS-specific functions needed by RIP. These are all
    the OS-specific methods that need to be overridden by a subclass in order
    to make RIP functional on a different OS (e.g. Windows)."""

    def init_logging(self, log_config):
        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("System")
        self.phy_ifaces = []
        self.logical_ifaces = []

    def __init__(self, *args, **kwargs):
        """Args:
        log_config -- The logging configuration file."""
        kwargs.setdefault("log_config", "logging.conf")
        self.init_logging(kwargs["log_config"])
        self.update_interface_info()
        self.loopback = "127.0.0.1"

    def modify_route(self, rt):
        """Update the metric and nexthop address to a prefix."""
        self.uninstall_route(rt.network.ip.exploded, rt.network.prefixlen)
        self.install_route(rt.network.ip.exploded, rt.network.prefixlen,
                           rt.metric, rt.nexthop)

    def cleanup(self):
        """Clean up the system. Called when exiting.

        Override in subclass."""
        assert(False)

    def update_interface_info(self):
        """Updates self according to the current state of physical and logical
        IP interfaces on the device.

        Sets self.phy_ifaces and self.logical_ifaces to be lists of
        physical interfaces and logical interfaces, respectively. See
        PhysicalInterface and LogicalInterface classes for examples.

        Override in subclass."""
        assert(False)

    def uninstall_route(self, net, mask):
        """Uninstall a route from the system routing table.

        Override in subclass."""
        assert(False)

    def install_route(self, net, preflen, metric, nexthop):
        """Install a route in the system routing table.

        Override in subclass."""
        assert(False)

    def get_local_routes(self):
        """Retrieves routes from the system routing table.

        Return value is a list of RIPRouteEntry objects defining local routes.

        Override in subclass."""
        assert(False)

    def is_self(self, host):
        """Determines if an IP address belongs to the local machine.

        Returns True if so, otherwise returns False."""
        for iface in self.logical_ifaces:
            if host == iface.ip.ip.exploded:
                return True
        return False


class WindowsRIPSystem(_RIPSystem):
    """The Windows interface for RIP."""

    CMD_BASE = "route %(action)s"
    OPTS_BASE = " %(network)s mask %(mask)s"
    ROUTE_DEL = CMD_BASE % {"action": "delete"} + OPTS_BASE
    ROUTE_ADD = CMD_BASE % {"action": "add"} + OPTS_BASE + " %(nh)s metric %(metric)d"

    def __init__(self, *args, **kwargs):
        super(_RIPSystem, self).__thisclass__.__init__(self, *args, **kwargs)

    def cleanup(self):
        pass

    def update_interface_info(self):
        ipconfig_output = subprocess.check_output("ipconfig")

        self.phy_ifaces = []
        self.logical_ifaces = []

        # XXX Extract actual physical interfaces... though these aren't really
        # used now anyway except for debug messages.
        self.phy_ifaces.append(PhysicalInterface("GenericWindowsPhy", None))
        masks = re.findall("Subnet Mask.*: (.*)\r", ipconfig_output)
        ips = re.findall("IPv4 Address.*: (.*)\r", ipconfig_output)
        assert(len(ips) == len(masks))
        mapper = lambda ip, mask: ip + "/" + mask

        for net in map(mapper, ips, masks):
            self.logical_ifaces.append(LogicalInterface(self.phy_ifaces[0],
                                                        net))

    def uninstall_route(self, net, preflen):
        # Convert the prefix length into a dotted decimal mask
        mask = self.preflen_to_snmask(preflen)
        cmd = self.ROUTE_DEL % { "network": net,
                                 "mask": mask,
                               }
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if not "OK!" in output:
            raise ModifyRouteError("uninstall", output)

    def install_route(self, net, preflen, metric, nexthop):
        mask = self.preflen_to_snmask(preflen)
        cmd = self.ROUTE_ADD % { "network": net,
                                 "mask":    mask,
                                 "metric":  metric,
                                 "nh":      nexthop,
                               }

        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if not "OK!" in output:
            raise ModifyRouteError("uninstall", output)

    @staticmethod
    def preflen_to_snmask(preflen):
        return ipaddr.IPv4Network("0.0.0.0/%d" % preflen).netmask

    def get_local_routes(self):
        output = subprocess.check_output("route print",
                                         stderr=subprocess.STDOUT)
        routes = re.search("IPv4 Route Table.*?^ (.*?)=", output,
                           re.DOTALL | re.MULTILINE).group(1)

        local_routes = []
        for rtline in routes.splitlines():
            rtinfo = rtline.split()
            dst_network = rtinfo[0]
            mask = rtinfo[1]
            parsed_network = ipaddr.IPv4Network(dst_network + "/" + mask)

            rte = RIPRouteEntry(address=parsed_network.ip.exploded,
                                mask=parsed_network.netmask.exploded,
                                nexthop="0.0.0.0",
                                metric=1,
                                tag=0,
                                imported=True)
            local_routes.append(rte)
        return local_routes


class LinuxRIPSystem(_RIPSystem):
    """The Linux interface for RIP."""

    IP_CMD = "/sbin/ip"
    RT_DEL_ARGS = "route del %(net)s/%(mask)s"
    RT_ADD_ARGS = "route add %(net)s/%(mask)s via %(nh)s metric %(metric)d " \
                  "table %(table)d" 

    def __init__(self, table=52, priority=1000, *args, **kwargs):
        """Args:
        table -- the routing table to install routes to (if applicable on
            the platform RIP is running on).
        priority -- the desirability of routes learned by the RIP process
            relative to other routing daemons (if applicable on the platform
            RIP is running on)."""
        super(_RIPSystem, self).__thisclass__.__init__(self, *args, **kwargs)

        self.table = table
        self.priority = priority

        if self.table > 255 or self.table < 0:
            raise(ValueError)
        if self.priority > 32767 or self.priority < 0:
            raise(ValueError)
        self._install_rule()

    def _install_rule(self):
        cmd = [self.IP_CMD] + ("rule add priority %d table %d" % \
               (self.priority, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #(ModifyRouteError("rule_install"))

    def _uninstall_rule(self):
        cmd = [self.IP_CMD] + ("rule del priority %d table %d" % \
               (self.priority, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #(ModifyRouteError("rule_install"))

    def update_interface_info(self):
        """Updates self according to the current state of physical and logical
        IP interfaces on the device."""
        ip_output = subprocess.check_output("ip addr show".split())
        raw_ifaces = re.split("\n\d*: ", ip_output)

        # First interface does not start with a newline, so strip the interface
        # index.
        raw_ifaces[0] = raw_ifaces[0].lstrip("1: ")

        self.phy_ifaces = []
        self.logical_ifaces = []
        for iface in raw_ifaces:
            name = re.match("(.*):", iface).group(1)
            flags = re.search("<(\S*)> ", iface).group(1).split(",")
            addrs = []
            phy_iface = PhysicalInterface(name, flags)
            self.phy_ifaces.append(phy_iface)
            for addr in re.findall("\n\s*inet (\S*)", iface):
                logical_iface = LogicalInterface(phy_iface, addr)
                self.logical_ifaces.append(logical_iface)

    def uninstall_route(self, net, preflen):
        cmd = [self.IP_CMD] + ("route del %s/%s table %d" % \
               (net, preflen, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #ModifyRouteError("route_uninstall", output)

    def install_route(self, net, preflen, metric, nexthop):
        cmd = [self.IP_CMD] + ("route add %s/%s via %s metric %d table %d" % \
               (net, preflen, nexthop, metric, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #ModifyRouteError("route_install", output)

    def get_local_routes(self):
        cmd = [self.IP_CMD] + "route show".split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #ModifyRouteError("route_install", output)

        local_routes = []
        metric = 1
        tag = 0
        nexthop = "0.0.0.0"
        for route in output.splitlines():
            dst_network = route.split()[0]
            # Default route shows up as the word 'default'
            if dst_network == "default":
                dst_network = "0.0.0.0/0"
            parsed_network = ipaddr.IPv4Network(dst_network)

            rte = RIPRouteEntry(address=parsed_network.ip.exploded,
                                mask=parsed_network.netmask.exploded,
                                nexthop=nexthop,
                                metric=metric,
                                tag=tag,
                                imported=True)
            local_routes.append(rte)
        return local_routes

    def cleanup(self):
        """Perform any necessary system cleanup."""
        self._uninstall_rule()


class PhysicalInterface(object): 
    def __init__(self, name, flags): 
        self.name = name 
        self._flags = flags 
 
 
class LogicalInterface(object): 
    def __init__(self, phy_iface, ip, metric=1, activated=False): 
        self.phy_iface = phy_iface 
        self.ip = ipaddr.IPv4Network(ip) 
        self.activated = activated 
        self.metric = metric 
