#!/usr/bin/env python
#
# Python-RIPv2 -- A Python implementation of RIPv2.
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

import struct
import ipaddr
import sys
import subprocess
import re
import optparse
import binascii
import logging
import logging.config
from twisted.internet import protocol
from twisted.internet import reactor

class RIP(protocol.DatagramProtocol):
    """An implementation of RIPv2 using the twisted asynchronous networking
    framework."""

    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    def __init__(self, port=520, user_routes=None, importroutes=False,
                 requested_ifaces=None, log_config="logging.conf"):
        """
        port -- The UDP port to listen and send on (default 520).
        user_routes -- A list of routes to advertise.
        importroutes -- If True, look in the main kernel routing table for
            routes to import into RIP during startup.
        requested_ifaces -- A list of interface names to send updates out of.
            If None, use all interfaces.
        log_config -- The logging config file (default logging.conf)
        """
        self.init_logging(log_config)
        if sys.platform == "linux2":
            self._sys = LinuxRIPSystem(log_config=log_config)
        else:
            raise(NotImplemented("No support for current OS."))
        self.port = port
        self._routes = []
        if user_routes:
            metric = 0
            tag = 0

            # Nexthop of 0.0.0.0 tells receivers to use the source IP on the
            # packet for the nexthop address. See RFC 2453 section 4.4.
            nexthop = "0.0.0.0"

            for route in user_routes:
                parsed_rt = ipaddr.IPv4Network(route)
                rte = RIPRouteEntry(address=parsed_rt.ip.exploded,
                                    mask=parsed_rt.netmask.exploded,
                                    nexthop=nexthop,
                                    metric=metric,
                                    tag=tag)
                self.log.debug("Trying to add user route %s" % rte)
                self.try_add_route(rte, False)

        if importroutes:
            for rt in self._sys.get_local_routes():
                self.try_add_route(rt, False)

        self.activate_ifaces(requested_ifaces)

        # Use callWhenRunning so update jitter can be introduced for
        # send_update() later on.
        reactor.callWhenRunning(self.send_update)
        reactor.callWhenRunning(self.validate_routes)

    def init_logging(self, log_config):
        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("RIP")

    def activate_ifaces(self, requested_ifaces):
        """Enable RIP processing on the given IPs/interfaces.
        requested_ifaces -- A list of IP addresses to use"""
        if not requested_ifaces:
            raise(ValueError("Need one or more interface IPs to listen on."))

        usable_sys_ifaces = []
        for sys_iface in self._sys.logical_ifaces:
            if sys_iface.usable():
                self.log.debug("Iface %s is usable." % sys_iface.phy_iface.name)
                usable_sys_ifaces.append(sys_iface)

        for req_iface in requested_ifaces:
            activated_iface = False
            for sys_iface in usable_sys_ifaces:
                if req_iface == sys_iface.ip.ip.exploded:
                    sys_iface.activated = True
                    activated_iface = True
                    break
            if activated_iface == False:
                raise(ValueError("Requested IP %s is unusable. "
                      " (Is it assigned to this machine on an interface that "
                      "is 'up'?)" % req_iface))

    def startProtocol(self):
        for iface in self._sys.logical_ifaces:
            if iface.activated == True:
                self.transport.joinGroup("224.0.0.9", iface.ip.ip.exploded)

    def send_update(self):
        """
        Send an update message across the network.
        XXX -- Does not deal with >25 routes correctly.
        """
        self.log.debug("Sending an update.")
        msg = RIPHeader(cmd=self.TYPE_RESPONSE, ver=2).serialize()
        for rt in self._routes:
            msg += rt.serialize()

        for iface in self._sys.logical_ifaces:
            if iface.activated:
                self.transport.setOutgoingInterface(iface.ip.ip.exploded)
                self.transport.write(msg, ("224.0.0.9", self.port))

        reactor.callLater(5, self.send_update)

    def datagramReceived(self, data, (host, port)):
        if port != self.port:
            self.log.debug("Advertisement source port was not the RIP port. "
                           "Ignoring.")
            return

        if self._sys.is_local(host):
            self.log.debug("Ignoring message from local system.")
            return

        self.log.debug("Processing a datagram from host %s." % host)

        try:
            msg = RIPPacket(data=data, src_ip=host)
            self.log.debug(msg)
        except FormatException:
            self.log.warn("RIP packet with invalid format received.")
            self.log.debug("Hex dump:")
            self.log.debug(binascii.hexlify(data))
            return

        if msg.header.cmd == self.TYPE_REQUEST:
            self.process_request(msg)
        elif msg.header.cmd == self.TYPE_RESPONSE:
            self.process_response(msg)

    def validate_routes(self):
        pass

    def process_request(self, msg):
        pass

    def process_response(self, msg):
        for rte in msg.rtelist:
            rte.metric += 1
            self.try_add_route(rte)

    def try_add_route(self, rte, install=True):
        bestroute = self.get_route(rte.network.ip.exploded,
                                   rte.network.netmask.exploded)

        if (bestroute == None) or (rte.metric < bestroute.metric):
            self.uninstall_route(bestroute)
            self._routes.append(rte)
            if not install:
                return
            self._sys.install_route(rte.network.ip.exploded,
                                    rte.network.prefixlen, rte.metric,
                                    rte.nexthop)

    def uninstall_route(self, rt):
        if rt in self._routes:
            self._sys.uninstall_route(rt.network.exploded, rt.mask.exploded)
            self._routes.remove(rt)

    def get_route(self, net, mask):
        for rt in self._routes:
            if (net == rt.network.ip.exploded) and \
               (mask == rt.network.netmask.exploded):
                return rt
        return None

    def cleanup(self):
        """Clean up any system changes made while running (uninstall
        routes etc.)."""
        self.log.info("Cleaning up.")
        self._sys.uninstall_rule()
        for rt in self._routes:
            if rt.nexthop.exploded != "0.0.0.0":
                self._sys.uninstall_route(rt.network.exploded,
                                          rt.network.prefixlen)


class LinuxRIPSystem(object):
    """The Linux interface for RIP."""

    IP_CMD = "/sbin/ip"
    RT_DEL_ARGS = "route del %(net)s/%(mask)s"
    RT_ADD_ARGS = "route add %(net)s/%(mask)s via %(nh)s metric %(metric)d " \
                  "table %(table)d" 

    def __init__(self, table=52, priority=1000, log_config="logging.conf"):
        """
        table -- the routing table to install routes to (if applicable on
            the platform RIP is running on).
        priority -- the desirability of the RIP process relative to other
            routing daemons (if applicable on the platform RIP is running on).
        log_config -- The logging configuration file.
        """
        self.init_logging(log_config)
        if table > 255 or table < 0:
            raise(ValueError)
        if priority > 32767 or priority < 0:
            raise(ValueError)

        self.table = table
        self.priority = priority
        self.install_rule()
        self.update_interface_info()
        self.loopback = "127.0.0.1"

    def install_rule(self):
        cmd = [self.IP_CMD] + ("rule add priority %d table %d" % \
               (self.priority, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #(ModifyRouteError("rule_install"))

    def uninstall_rule(self):
        cmd = [self.IP_CMD] + ("rule del priority %d table %d" % \
               (self.priority, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #(ModifyRouteError("rule_install"))

    def init_logging(self, log_config):
        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("System")

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
            phy_iface = LinuxPhysicalInterface(name, flags)
            self.phy_ifaces.append(phy_iface)
            for addr in re.findall("\n\s*inet (\S*)", iface):
                logical_iface = LinuxLogicalInterface(phy_iface, addr)
                self.logical_ifaces.append(logical_iface)

    def uninstall_route(self, net, mask):
        cmd = [self.IP_CMD] + ("route del %s/%s table %d" % \
               (net, mask, self.table)).split()
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
        metric = 0
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
                                tag=tag)
            local_routes.append(rte)
        return local_routes

    def is_local(self, host):
        """Determines if an IP address belongs to the local machine."""
        for iface in self.logical_ifaces:
            if host == iface.ip.ip.exploded:
                return True
        return False


class LinuxPhysicalInterface(object):
    def __init__(self, name, flags):
        self.name = name
        self._flags = flags

    def multicast_enabled(self):
        return "MULTICAST" in self._flags

    def operational(self):
        return "UP" in self._flags and "LOWER_UP" in self._flags

    def usable(self):
        return self.multicast_enabled() and self.operational()


class LinuxLogicalInterface(object):
    def __init__(self, phy_iface, ip, metric=1, activated=False):
        self.phy_iface = phy_iface
        self.ip = ipaddr.IPv4Network(ip)
        self.activated = activated
        self.metric = metric

    def usable(self):
        return self.phy_iface.usable()


class ModifyRouteError(Exception):
    def __init__(self, operation, output=None):
        self.operation = operation
        self.output = output


class RIPPacket(object):
    def __init__(self, data=None, hdr=None, rtes=None, src_ip=None):
        """
        Create a RIP packet either from the binary data received from the
        network, or from a RIP header and RTE list.
        """
        if data and src_ip:
            self._init_from_net(data, src_ip)
        elif hdr and rtes:
            self._init_from_host(hdr, rtes)
        else:
            raise(ValueError)

    def __repr__(self):
        return "RIPPacket: Command %d, Version %d, number of RTEs %d." % \
                (self.header.cmd, self.header.ver, len(self.rtelist))

    def _init_from_net(self, data, src_ip):
        """Init from data received from the network."""
        # Quick check for malformed data
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise(FormatException)

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        if malformed_rtes != 0:
            raise(FormatException)

        numrtes = (datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE
        self.header = RIPHeader(data[0:RIPHeader.SIZE])

        # Route entries
        self.rtelist = []

        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE
        for i in range(numrtes):
            self.rtelist.append(RIPRouteEntry(rawdata=data[rte_start:rte_end],
                                              src_ip=src_ip))
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    def _init_from_host(self, hdr, rtes):
        """Init using a header and rte list provided by the application."""
        if hdr.ver != 2:
            raise(ValueError)
        self.hdr = hdr
        self.rtelist = rtes

    def serialize(self):
        """
        Return a bytestring representing this packet in a form that
        can be transmitted across the network.
        """
        if not self.packed:
            self.packed = self.hdr.serialize()
            for rte in self.rtelist:
                self.packed += rte.serialize()
        return self.packed


class RIPHeader(object):
    FORMAT = ">BBH"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, rawdata=None, cmd=None, ver=None):
        self.packed = None
        if cmd and ver:
            self._init_from_host(cmd, ver)
        elif rawdata:
            self._init_from_net(rawdata)
        else:
            raise(ValueError)

    def __repr__(self):
        return "RIPHeader(cmd=%d, ver=%d)" % (self.cmd, self.ver)

    def _init_from_net(self, rawdata):
        """Init from data received from the network."""
        header = struct.unpack(self.FORMAT, rawdata)

        self.cmd = header[0]
        self.ver = header[1]
        zero = header[2]
        if zero != 0:
            raise(FormatException)

    def _init_from_host(self, cmd, ver):
        """Init from data provided by the application."""
        if cmd != 1 and cmd != 2:
            raise(ValueError)
        else:
            self.cmd = cmd

        if ver != 1 and ver != 2:
            raise(ValueError)
        else:
            self.ver = ver

    def serialize(self):
        if not self.packed:
            self.packed = struct.pack(self.FORMAT, self.cmd, self.ver, 0)
        return self.packed


class RIPRouteEntry(object):
    FORMAT = ">HHIIII"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, rawdata=None, address=None, mask=None, nexthop=None,
                 metric=None, tag=0, src_ip=None):
        self.packed = None
        if rawdata and src_ip:
            self._init_from_net(rawdata, src_ip)
        elif address and \
             mask    and \
             nexthop and \
             metric != None and \
             tag    != None:
            self._init_from_host(address, mask, nexthop, metric, tag)
        else:
            raise(ValueError)

    def _init_from_host(self, address, mask, nexthop, metric, tag):
        """Init from data provided by the application."""
        # IPv4 only supported
        self.afi = 2
        self.network = ipaddr.IPv4Network(address + "/" + mask)
        self.nexthop = ipaddr.IPv4Address(nexthop)
        self.metric = metric
        self.tag = tag

    def _init_from_net(self, rawdata, src_ip):
        """Init from data received on the network."""
        self.packed = None
        rte = struct.unpack(self.FORMAT, rawdata)
        self.afi = rte[0]
        self.tag = rte[1]
        address = ipaddr.IPv4Address(rte[2])
        mask = ipaddr.IPv4Address(rte[3])
        self.nexthop = ipaddr.IPv4Address(rte[4])
        self.metric = rte[5]

        if self.nexthop.exploded == "0.0.0.0":
            self.nexthop = ipaddr.IPv4Address(src_ip)
        self.network = ipaddr.IPv4Network(address.exploded + "/" +
                                          mask.exploded)

    def __repr__(self):
        return "RIPRouteEntry(address=%s, mask=%s, nexthop=%s, metric=%d, " \
               "tag=%d)" % (self.network.ip.exploded, self.network.netmask.exploded, self.nexthop, self.metric, self.tag)

    def serialize(self):
        """
        Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453 section 4.
        """
        if not self.packed:
            self.packed = struct.pack(self.FORMAT, self.afi, self.tag,
                                      self.network.network._ip,
                                      self.network.netmask._ip,
                                      self.nexthop._ip, self.metric)
        return self.packed


class RIPException(Exception):
    pass


class FormatException(RIPException):
    pass


class RIPFactory(protocol.Protocol):
    def buildProtocol(self, addr):
        return RIP()

    def doStart(self):
        pass

    def doStop(self):
        pass


def parse_args(argv):
    op = optparse.OptionParser()
    op.add_option("-p", "--port", default=520, type="int",
                  help="The port number to use (520)")
    op.add_option("-i", "--interface", type="str", action="append",
                  help="An interface IP to use for RIP. "
                       "Can specify -i multiple times.")
    op.add_option("-I", "--import-routes", default=False, action="store_true",
                  help="Import local routes from the kernel upon startup.")
    op.add_option("-r", "--route", type="str", action="append",
                  help="A route to import, in CIDR notation. "
                        "Can specify -r multiple times.")
    op.add_option("-l", "--log-config", default="logging.conf",
                  help="The logging configuration file "
                        "(default logging.conf).")

    options, arguments = op.parse_args(argv)
    if not options.interface:
        op.error("At least one interface IP is required (-i).")

    if len(arguments) > 1:
        op.error("Unexpected non-option argument(s): '" + \
                 " ".join(arguments[1:]) + "'") 

    return options, arguments

def main(argv):
    options, arguments = parse_args(argv)

    # Must run as root to manipulate the routing table.
    userid = subprocess.check_output("id -u".split()).rstrip()
    if userid != "0":
        sys.stderr.write("Must run as root. Exiting.\n")
        sys.exit(1)

    ripserv = RIP(options.port, options.route, options.import_routes, options.interface, options.log_config)
    reactor.listenMulticast(options.port, ripserv)
    try:
        reactor.run()
    finally:
        ripserv.cleanup()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
