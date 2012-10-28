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
import random
import datetime
import traceback
from twisted.internet import protocol
from twisted.internet import reactor

import ripadmin

class RIP(protocol.DatagramProtocol):
    """An implementation of RIPv2 using the twisted asynchronous networking
    framework."""

    MAX_ROUTES_PER_UPDATE = 25
    UPDATE_TIMER = 30
    JITTER_VALUE = 2
    TIMEOUT_TIMER = UPDATE_TIMER * 6
    GARBAGE_TIMER = UPDATE_TIMER * 4

    def __init__(self, port=520, user_routes=None, importroutes=False,
                 requested_ifaces=None, log_config="logging.conf"):
        """port -- The UDP port to listen and send on (default 520).
        user_routes -- A list of routes to advertise.
        importroutes -- If True, look in the main kernel routing table for
            routes to import into RIP during startup.
        requested_ifaces -- A list of interface names to send updates out of.
            If None, use all interfaces.
        log_config -- The logging config file (default logging.conf)"""
        self.init_logging(log_config)
        self._route_change = False
        self._gc_started = False
        if sys.platform == "linux2":
            self._sys = LinuxRIPSystem(log_config=log_config)
        else:
            raise(NotImplemented("No support for current OS."))
        self.port = port
        self._routes = []
        self._garbage_routes = []
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
                                    tag=tag,
                                    imported=True)
                self.log.debug("Trying to add user route %s" % rte)
                self.try_add_route(rte, False)

        if importroutes:
            for rt in self._sys.get_local_routes():
                self.try_add_route(rt, False)

        self.activate_ifaces(requested_ifaces)
        self._last_trigger_time = datetime.datetime.now()

        # Setup admin interface
        ripadmin.start(self)

        reactor.callWhenRunning(self.generate_update)
        reactor.callWhenRunning(self._check_route_timeouts)

    def _start_garbage_collection(self, rt):
        self.log.debug("Starting garbage collection for route %s" % rt)
        rt.changed = True
        rt.garbage = True
        rt.init_timeout()
        rt.metric = RIPRouteEntry.MAX_METRIC
        self._sys.modify_route(rt)
        self.handle_route_change()
        self._init_garbage_collection_timer()

    def _check_route_timeouts(self):
        self.log.debug("Checking route timeouts...")
        now = datetime.datetime.now()
        begin_invalid_time = now - datetime.timedelta(seconds=self.TIMEOUT_TIMER)
        timeout_val = datetime.timedelta(seconds=self.TIMEOUT_TIMER)
        lowest_timer = timeout_val

        for rt in self._routes:
            if not rt.garbage:
                if rt.timeout == None:
                    continue
                if rt.timeout < begin_invalid_time:
                    self.log.debug("Adding route to GC: %s" % rt)
                    self._start_garbage_collection(rt)
                else:
                    current_timer = (rt.timeout + timeout_val) - now
                    lowest_timer = min(lowest_timer,
                                        current_timer)

        next_call_time = lowest_timer.total_seconds() + 1
        self.log.debug("Checking timeouts again in %d second(s)" %
                       next_call_time)
        reactor.callLater(next_call_time, self._check_route_timeouts)

    def _init_garbage_collection_timer(self):
        if self._gc_started:
            return
        reactor.callLater(self.GARBAGE_TIMER, self._collect_garbage_routes)

    def _collect_garbage_routes(self):
        self.log.debug("Collecting garbage routes...")
        now = datetime.datetime.now()
        flush_before = now - datetime.timedelta(seconds=self.GARBAGE_TIMER)
        max_wait_time = self.GARBAGE_TIMER + 1
        lowest_route_timer = max_wait_time

        for rt in self._routes:
            if rt.garbage:
                if rt.timeout == None:
                    continue
                if rt.timeout < flush_before:
                    self.log.debug("Deleting route: %s" % rt)
                    self._sys.uninstall_route(rt.network.ip.exploded,
                                              rt.network.prefixlen)
                    self._routes.remove(rt)
                else:
                    lowest_route_timer = min(rt.timeout, lowest_route_timer)

        if lowest_route_timer == max_wait_time:
            self.log.debug("No more routes on GC.")
            self._gc_started = False
        else:
            next_call_time = (now - lowest_route_timer).total_seconds() + 1
            self.log.debug("Collecting garbage routes again in %d seconds" %
                           next_call_time)
            reactor.callLater(next_call_time, self._collect_garbage_routes)

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

    def generate_update(self, triggered=False):
        """Send an update message across the network."""
        self.log.debug("Sending an update. Triggered = %d." % triggered)
        header = RIPHeader(cmd=RIPHeader.TYPE_RESPONSE, ver=2).serialize()
        msg = header

        for iface in self.get_active_ifaces():
            self.log.debug("Preparing update for interface %s" %
                           iface.phy_iface.name)
            route_count = 0
            for rt in self._routes:
                self.log.debug("Trying to add route to update: %s." % rt)
                if rt.nexthop in iface.ip:
                    self.log.debug("Split horizon prevents sending route.")
                    continue
                if triggered and not rt.changed:
                    self.log.debug("Route not changed. Skipping.")
                    continue
                msg += rt.serialize()
                self.log.debug("Adding route to update.")
                route_count += 1
                if route_count == self.MAX_ROUTES_PER_UPDATE:
                    self.log.debug("Max routes per update reached."
                                   " Sending an update...")
                    self.send_update_multicast(msg, iface.ip.ip.exploded)
                    msg = header
                    route_count = 0

            if len(msg) > RIPHeader.SIZE:
                self.send_update_multicast(msg, iface.ip.ip.exploded)

        if triggered:
            for rt in self._routes:
                rt.changed = False
        else:
            reactor.callLater(self.get_update_interval(), self.generate_update)

    def get_update_interval(self):
        """Get the amount of time until the next update. This is equal to
        the default update timer +/- a number of a seconds to create update
        jitter."""
        return self.UPDATE_TIMER + random.randrange(-self.JITTER_VALUE,
                                                     self.JITTER_VALUE)

    def get_active_ifaces(self):
        """Return active logical interfaces."""
        for iface in self._sys.logical_ifaces:
            if iface.activated:
                yield iface

    def send_update_multicast(self, msg, ip):
        self.transport.setOutgoingInterface(ip)
        self.transport.write(msg, ("224.0.0.9", self.port))

    def datagramReceived(self, data, (host, port)):
        if port != self.port:
            self.log.debug("Advertisement source port was not the RIP port. "
                           "Ignoring.")
            return

        self.log.debug("Processing a datagram from host %s." % host)

        link_local = False
        host = ipaddr.IPv4Address(host)
        for local_iface in self._sys.logical_ifaces:
            if local_iface.ip.ip.exploded == host.exploded:
                self.log.debug("Ignoring message from local system.")
                return
            elif host in local_iface.ip:
                link_local = True
                break
        if not link_local:
            self.log.warn("Received advertisement from non link-local "
                          "host. Ignoring.")
            return

        try:
            msg = RIPPacket(data=data, src_ip=host.exploded)
            self.log.debug(msg)
        except FormatException:
            self.log.warn("RIP packet with invalid format received.")
            self.log.debug("Hex dump:")
            self.log.debug(binascii.hexlify(data))
            self.log.debug("Traceback:")
            self.log.debug(traceback.format_exc())
            return

        if msg.header.cmd == RIPHeader.TYPE_REQUEST:
            self.process_request(msg)
        elif msg.header.cmd == RIPHeader.TYPE_RESPONSE:
            self.process_response(msg)

    def process_request(self, msg):
        pass

    def process_response(self, msg):
        for rte in msg.rtelist:
            # XXX Should update to use the metric of the incoming interface
            rte.metric = min(rte.metric + 1, RIPRouteEntry.MAX_METRIC)
            self.try_add_route(rte)

    def handle_route_change(self):
        if self._route_change:
            return

        self._route_change = True
        current_time = datetime.datetime.now()
        trigger_suppression_timeout = \
                            datetime.timedelta(seconds=random.randrange(1, 5))

        if self._last_trigger_time + trigger_suppression_timeout > \
           current_time:
            self._send_triggered_update()
        else:
            reactor.callLater(trigger_suppression_timeout.total_seconds(),
                              self._send_triggered_update)

    def _send_triggered_update(self):
        self.log.debug("Sending triggered update.")
        self._route_change = False
        self.generate_update(triggered=True)

    def try_add_route(self, rte, install=True):
        self.log.debug("try_add_route: Received %s" % rte)
        bestroute = self.get_route(rte.network.ip.exploded,
                                   rte.network.netmask.exploded)

        if not bestroute:
            rte.changed = True
            self._routes.append(rte)

            if not install:
                return
            self.handle_route_change()
            self._sys.install_route(rte.network.ip.exploded,
                                    rte.network.prefixlen, rte.metric,
                                    rte.nexthop)
        else:
            if rte.nexthop == bestroute.nexthop:
                if bestroute.metric != rte.metric:
                    if bestroute.metric != RIPRouteEntry.MAX_METRIC and \
                       rte.metric >= RIPRouteEntry.MAX_METRIC:
                        self._start_garbage_collection(rte)
                    elif rte.metric != bestroute.metric:
                        self.update_route(bestroute, rte)
            elif rte.metric < bestroute.metric:
                self.log.debug("Found better route to %s via %s in %d", \
                               (rte.network.exploded, rte.nexthop, rte.metric))
                self.update_route(bestroute, rte)

    def update_route(self, oldrt, newrt):
        oldrt.init_timeout()
        oldrt.garbage = False
        oldrt.changed = True
        oldrt.metric = newrt.metric
        oldrt.nexthop = newrt.nexthop
        self._sys.modify_route(oldrt)
        self.handle_route_change()

    def get_route(self, net, mask):
        for rt in self._routes:
            if (net == rt.network.ip.exploded) and \
               (mask == rt.network.netmask.exploded):
                return rt
        return None

    def cleanup(self):
        """Clean up any system changes made while running (uninstall
        routes etc.)."""
        # XXX This should probably all be part of _sys.
        self.log.info("Cleaning up.")
        self._sys.cleanup()
        for rt in self._routes:
            if rt.nexthop.exploded != "0.0.0.0":
                self._sys.uninstall_route(rt.network.ip.exploded,
                                          rt.network.prefixlen)


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

    def modify_route(self, rt):
        """Update the system routing table to use a new metric and nexthop
        for the given prefix.

        Since only one path to a prefix should be in the system routing table,
        a minimum implementation of this function would consist of a call to
        self.uninstall_route(rt) followed by a call to self.install_route(rt).
        If the OS support modifying routes (both Windows and Linux do) without
        using a delete followed by an add, that could also be used.

        Override in subclass."""
        raise(NotImplemented)

    def cleanup(self):
        """Clean up the system. Called when exiting.

        Override in subclass."""
        raise(NotImplemented)

    def update_interface_info(self):
        """Updates self according to the current state of physical and logical
        IP interfaces on the device.

        Sets self.phy_ifaces and self.logical_ifaces to be lists of
        physical interfaces and logical interfaces, respectively. See
        LinuxPhysicalInterface and LinuxLogicalInterface classes for examples.

        Override in subclass."""
        raise(NotImplemented)

    def uninstall_route(self, net, mask):
        """Uninstall a route from the system routing table.

        Override in subclass."""
        raise(NotImplemented)

    def install_route(self, net, preflen, metric, nexthop):
        """Install a route in the system routing table.

        Override in subclass."""
        raise(NotImplemented)

    def get_local_routes(self):
        """Retrieves routes from the system routing table.

        Return value is a list of RIPRouteEntry objects defining local routes.

        Override in subclass."""
        raise(NotImplemented)

    def is_self(self, host):
        """Determines if an IP address belongs to the local machine.

        Returns True if so, otherwise returns False.

        Override in subclass."""

        raise(NotImplemented)

class LinuxRIPSystem(_RIPSystem):
    """The Linux interface for RIP."""

    IP_CMD = "/sbin/ip"
    RT_DEL_ARGS = "route del %(net)s/%(mask)s"
    RT_ADD_ARGS = "route add %(net)s/%(mask)s via %(nh)s metric %(metric)d " \
                  "table %(table)d" 

    def __init__(self, *args, **kwargs):
        """Args:
        table -- the routing table to install routes to (if applicable on
            the platform RIP is running on).
        priority -- the desirability of routes learned by the RIP process
            relative to other routing daemons (if applicable on the platform
            RIP is running on)."""
        super(_RIPSystem, self).__thisclass__.__init__(self, *args, **kwargs)
        kwargs.setdefault("table", 52)
        kwargs.setdefault("priority", 1000)

        self.table = kwargs["table"]
        self.priority = kwargs["priority"]

        if self.table > 255 or self.table < 0:
            raise(ValueError)
        if self.priority > 32767 or self.priority < 0:
            raise(ValueError)

        self._install_rule()
        self.update_interface_info()
        self.loopback = "127.0.0.1"
        self._route_change = False

    def modify_route(self, rt):
        """Update the metric and nexthop address to a prefix."""
        self.uninstall_route(rt.network.ip.exploded, rt.network.prefixlen)
        self.install_route(rt.network.ip.exploded, rt.network.prefixlen,
                           rt.metric, rt.nexthop)

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
                                tag=tag,
                                imported=True)
            local_routes.append(rte)
        return local_routes

    def cleanup(self):
        """Perform any necessary system cleanup."""
        self._uninstall_rule()

    def is_self(self, host):
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
        """Create a RIP packet either from the binary data received from the
        network, or from a RIP header and RTE list."""
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
        """Return a bytestring representing this packet in a form that
        can be transmitted across the network."""
        if not self.packed:
            self.packed = self.hdr.serialize()
            for rte in self.rtelist:
                self.packed += rte.serialize()
        return self.packed


class RIPHeader(object):
    FORMAT = ">BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

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
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, rawdata=None, address=None, mask=None, nexthop=None,
                 metric=None, tag=0, src_ip=None, imported=False):
        self.packed = None
        self.changed = False
        self.imported = imported
        self.init_timeout()
        self.garbage = False
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

    def init_timeout(self):
        """Sets a timer to the current time. The timer is used as either the
        "timeout" timer, or the garbage collection timer depending on whether
        or not self.garbage is set."""
        if self.imported:
            self.timeout = None
        else:
            self.timeout = datetime.datetime.now()

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

        # Validation
        if not (self.MIN_METRIC <= self.metric <= self.MAX_METRIC):
            raise(FormatException)

    def __repr__(self):
        return "RIPRouteEntry(address=%s, mask=%s, nexthop=%s, metric=%d, " \
               "tag=%d)" % (self.network.ip.exploded, self.network.netmask.exploded, self.nexthop, self.metric, self.tag)

    def __eq__(self, other):
        if self.afi     == other.afi      and \
           self.network == other.network  and \
           self.nexthop == other.nexthop  and \
           self.metric  == other.metric   and \
           self.tag     == other.tag:
            return True
        else:
            return False

    def serialize(self):
        """Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453
        section 4."""
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
