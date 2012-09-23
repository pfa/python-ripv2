#!/usr/bin/env python

import struct
import ipaddr
import sys
import subprocess
import re
import optparse
from twisted.internet import protocol
from twisted.internet import reactor
import logging

class RIP(protocol.DatagramProtocol):

    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    def __init__(self, user_routes=None, importroutes=False, requested_ifaces=None):
        """
        user_routes -- A list of routes to advertise.
        importroutes -- If True, look in the main kernel routing table for
            routes to import into RIP during startup.
        requested_ifaces -- A list of interface names to send updates out of.
            If None, use all interfaces.
        """
        self._sys = RIPSystem()

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
                self._routes.append(rte)

        if importroutes:
            for rt in self._sys.get_local_routes():
                if rt not in self._routes:
                    self._routes.append(rt)

        self.activate_ifaces(requested_ifaces)

        # Use callWhenRunning so update jitter can be introduced later on.
        reactor.callWhenRunning(self.send_update)
        reactor.callWhenRunning(self.validate_routes)

    def activate_ifaces(self, requested_ifaces):
        """Enable RIP processing on the given IPs/interfaces.
        requested_ifaces -- A list of IP addresses to use"""
        if not requested_ifaces:
            raise(ValueError("Need one or more interface IPs to listen on."))

        usable_sys_ifaces = []
        for sys_iface in self._sys.logical_ifaces:
            if sys_iface.usable():
                logging.warn("Iface %s is usable." % sys_iface.phy_iface.name)
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

    def use_iface(self, iface):
        """Determine if an interface can be used for RIP"""
        if self.active_ifaces != None:
            if iface in self.active_ifaces:
                return True
        return iface.usable()

    def startProtocol(self):
        for iface in self._sys.logical_ifaces:
            if iface.activated == True:
                self.transport.joinGroup("224.0.0.9", iface.ip.ip.exploded)

    def send_update(self):
        """
        Send an update message across the network.
        XXX -- Does not deal with >25 routes correctly.
        """
        logging.warn("Sending an update.")
        msg = RIPHeader(cmd=self.TYPE_RESPONSE, ver=2).serialize()
        for rt in self._routes:
            msg += rt.serialize()

        for iface in self._sys.logical_ifaces:
            if iface.activated:
                self.transport.setOutgoingInterface(iface.ip.ip.exploded)
                self.transport.write(msg, ("224.0.0.9", 520))

        reactor.callLater(5, self.send_update)

    def datagramReceived(self, data, (host, port)):
        if port != 520:
            print("Received datagram from host on a non-520 port. Ignoring.")
            return

        if self._sys.is_local(host):
            logging.warn("Ignoring message from local system.")
            return

        logging.warn("Processing a datagram from host %s." % host)

        try:
            msg = RIPPacket(data=data)
        except FormatException:
            # XXX invalid format -- log this instead
            logging.warn("Invalid format.")

        if msg.header.cmd == self.TYPE_REQUEST:
            self.process_request(msg)
        elif msg.header.cmd == self.TYPE_RESPONSE:
            self.process_response(msg)

    def validate_routes(self):
        pass

    def process_request(self, msg):
        pass

    def process_response(self, msg):
        for rte in msg.rtelist():
            rte.metric += 1
            bestroute = self.get_route(rte.network.exploded, rte.mask,exploded)

            if (bestroute == None) or (rte.metric < bestroute.metric):
                self.uninstall_route(bestroute)
                self.install_route(rte)

    def uninstall_route(rt):
        if rt in self._routes:
            RIPSystem.uninstall_route(rt.network.exploded, rt.mask.exploded)
            self._routes.remove(rt)

    def get_route(self, net, mask):
        for rt in self._routes:
            if (net == rt.network.exploded) and (mask == rt.netmask.exploded):
                return rt
        return None


class RIPSystem(object):
    """The interface to the system on which RIP is running."""

    DEFAULT_IP_CMD = "/sbin/ip"
    RT_DEL_ARGS = "route del %(net)s/%(mask)s"
    RT_ADD_ARGS = "route add %(net)s/%(mask)s via %(nh)s metric %(metric)d " \
                  "table %(table)d" 

    def __init__(self, table=52, priority=1000):
        """
        Table is the routing table to install routes to (if applicable on
        the platform RIP is running on).

        Priority is the desirability of the RIP process relative to other
        routing daemons (if applicable on the platform RIP is running on).
        """
        if table > 255 or table < 0:
            raise(ValueError)
        if priority > 32767 or priority < 0:
            raise(ValueError)

        self.table = table
        self.priority = priority

        cmd = [self.DEFAULT_IP_CMD] + ("rule add priority %d table %d" % \
               (priority, table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #(ModifyRouteError("rule_install"))

        self.update_interface_info()
        self.loopback = "127.0.0.1"

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
        cmd = [self.DEFAULT_IP_CMD] + ("route del %s/%s table %d" % \
               (net, mask, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #ModifyRouteError("route_uninstall", output)

    def install_route(self, net, mask, metric, nexthop):
        cmd = [self.DEFAULT_IP_CMD] + ("route add %s/%s via %s metric %d table %d" % \
               (net, mask, nexthop, metric, self.table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise #ModifyRouteError("route_install", output)

    def get_local_routes(self):
        return None

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
    def __init__(self, data=None, hdr=None, rtes=None):
        """
        Create a RIP packet either from the binary data received from the
        network, or from a RIP header and RTE list.
        """
        if data != None:
            self._init_from_net(data)
        elif hdr != None and rtes != None:
            self._init_from_host(hdr, rtes)
        else:
            raise(ValueError)

    def _init_from_net(self, data):
        """Init from data received from the network."""
        # Quick check for malformed data
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise(ValueError)

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        if malformed_rtes != 0:
            raise(ValueError)

        numrtes = (datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE
        if numrtes == 0:
            return

        self.header = RIPHeader(data[0:RIPHeader.SIZE])

        # Route entries
        self.rtelist = []

        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE
        for i in range(numrtes):
            self.rtelist.append(RIPRouteEntry(data[rte_start:rte_end]))
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
        if self.packed != None:
            return self.packed
        self.packed = self.hdr.serialize()
        for rte in self.rtelist:
            self.packed += rte.serialize()
        return self.packed


class RIPHeader(object):
    FORMAT = ">BBH"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, rawdata=None, cmd=None, ver=None):
        if cmd != None and ver != None:
            self._init_from_host(cmd, ver)
        elif rawdata != None:
            self._init_from_net(rawdata)
        else:
            raise(ValueError)

    def _init_from_net(self, rawdata):
        """Init from data received from the network."""
        raise(NotImplemented)

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
        return struct.pack(self.FORMAT, self.cmd, self.ver, 0)


class RIPRouteEntry(object):
    FORMAT = ">HhIIII"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, rawdata=None, address=None, mask=None, nexthop=None,
                 metric=None, tag=0):
        if rawdata != None:
            self._init_from_net(rawdata)
            return
        elif address == None or \
             mask    == None or \
             nexthop == None or \
             metric  == None:
            raise(TypeError)

        # IPv4 only supported
        self.packed = None
        self.afi = 2
        self.network = ipaddr.IPv4Network(address + "/" + mask)
        self.mask = mask
        self.nexthop = ipaddr.IPv4Address(nexthop)
        self.metric = metric
        self.tag = tag

    def serialize(self):
        """
        Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453 section 4.
        """
        if not self.packed:
            self.packed = struct.pack(self.FORMAT, self.afi, self.tag, self.network.network._ip, self.network.netmask._ip, self.nexthop._ip, self.metric)
        return self.packed

    def _init_from_net(self, rawdata):
        """Init from data received on the network."""
        self.packed = None
        rte = struct.unpack(self.FORMAT, rawdata)
        self.afi = rte[0]
        zero = rte[1]
        self.tag = rte[2]
        self.mask = rte[3]
        self.nexthop = rte[4]
        self.metric = rte[5]


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

    options, arguments = op.parse_args(argv)
    if not options.interface:
        op.error("At least one interface IP is required (-i).")
    return options, arguments

def main(argv):
    # Must run as root to manipulate the routing table.
    userid = subprocess.check_output("id -u".split()).rstrip()
    if userid != "0":
        print("Must run as root. Exiting.")
        sys.exit(1)

    options, arguments = parse_args(argv)

    ripserv = RIP(options.route, options.import_routes, options.interface)
    reactor.listenMulticast(520, ripserv)
    reactor.run()

if __name__ == "__main__":
    main(sys.argv)
