#!/usr/bin/env python

import struct
import ipaddr
import sys
import subprocess
import re
from twisted.internet import protocol
from twisted.internet import reactor
import logging

class RIP(protocol.DatagramProtocol):

    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    def __init__(self, routelist=None, importroutes=False):
        """
        routelist -- A list of routes to advertise
        importroutes -- Look in the main kernel routing table for routes to
        import into RIP during startup.
        """
        if routelist:
            self._routes = routelist
        else:
            self._routes = []

        if importroutes:
            for rt in self._sys.get_local_routes():
                if rt not in self._routes:
                    self._routes.append(rt)

        self._sys = RIPSystem()

        # Use callWhenRunning so update jitter can be introduced later on.
        reactor.callWhenRunning(self.send_update)
        reactor.callWhenRunning(self.validate_routes)
        for interface in self._sys.get_interface_info():
            reactor.listenMulticast(520, self, interface=interface,
                                    listenMultiple=True)
        reactor.run()

    def startProtocol(self):
        self.transport.joinGroup("224.0.0.9")

    def send_update(self):
        """
        Send an update message across the network.
        XXX -- Does not deal with >25 routes correctly.
        """
        msg = RIPHeader(cmd=self.TYPE_RESPONSE, ver=2).serialize()
        for rt in self._routes:
            # XXX Update to get the local IP to use as the next hop.
            # 0.0.0.0 means the receiving router should use the source addr of
            # the packet as the next hop. See RFC 2453 section 4.4.
            msg += RIPRouteEntry(rawdata=None, address=rt.network.exploded, mask=rt.netmask.exploded, nexthop="0.0.0.0", metric=0).serialize()
        self.transport.write(msg, ("224.0.0.9", 520))
        reactor.callLater(10, self.send_update)

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

        # XXX -- This only gets the first IP address from the first interface
        # reported by ifconfig. Good enough for now.
        self.ifaces = self.get_interface_info()
        #self.local_addrs = [subprocess.check_output("ifconfig").split("\n")[1].split()[1][5:]]

    def get_interface_info(self):
        """Returns a list of local network interface names and IPs. Each
        item in the list is a (name, [IP, IP...]) tuple. Multiple IPs may
        be assigned to the interface."""
        ip_output = subprocess.check_output("ip addr show".split())
        raw_iface_list = re.split("\nd*:", ip_addr_output)

        # First interface does not start with a newline, so strip the interface
        # index.
        raw_ifaces[0] = raw_iface_list[0].lstrip("1: ")

        parsed_ifaces = []
        for iface in raw_iface_list:
            name = 
            addresses = 

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
        return host in self.local_addrs

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
        """ Init from bytes received on the wire."""
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
        """
        Init using a header and rte list read off of the network.
        This is a terrible name.
        """
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
        """Init from data received on the network."""
        raise(Exception)

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
        self.afi = 2
        self.network = ipaddr.IPv4Network(address + "/" + mask)
        self.mask = mask
        self.nexthop = ipaddr.IPv4Address(nexthop)
        self.metric = metric
        self.tag = tag
        self.packed = None

    def serialize(self):
        """
        Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453 section 4.
        """

        if self.packed != None:
            return self.packed

        return struct.pack(self.FORMAT, self.afi, self.tag, self.network.network._ip, self.network.netmask._ip, self.nexthop._ip, self.metric)
#        self.packed = str()
#        self.packed += struct.pack(">I", self.afi)
#        self.packed += struct.pack(">I", self.tag)
#        self.packed += self.network.network.packed
#        self.packed += self.network.netmask.packed
#        self.packed += self.nexthop.packed
#        self.packed += struct.pack(">I", self.metric)

        return self.packed

    def _init_from_net(self, rawdata):
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


if __name__ == "__main__":
    # Must run as root to manipulate the routing table.
    userid = subprocess.check_output("id -u".split()).rstrip()
    if userid != "0":
        print("Must run as root. Exiting.")
        sys.exit(1)
    srv = RIP()
