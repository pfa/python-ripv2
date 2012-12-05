#!/usr/bin/env python

"""A Python implementation of RIPv2."""

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
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log
import twisted.python.failure
import traceback

import ripadmin

class RIP(protocol.DatagramProtocol):
    """An implementation of RIPv2 using the twisted asynchronous networking
    framework."""

    MAX_ROUTES_PER_UPDATE = 25
    JITTER_VALUE = 2
    DEFAULT_UPDATE_TIMER = 30

    def __init__(self, port=520, user_routes=None, importroutes=False,
                 requested_ifaces=None, log_config="logging.conf",
                 base_timer=None):
        """port -- The UDP port to listen and send on.
        user_routes -- A list of routes to advertise.
        importroutes -- If True, look in the main kernel routing table for
            routes to import into RIP during startup.
        requested_ifaces -- A list of interface names to send updates out of.
            If None, use all interfaces.
        log_config -- The logging config file.
        base_timer -- Influences update/garbage/timeout timers"""
        self.init_logging(log_config)
        self.log.info("RIP is starting up...")

        log.addObserver(self._suppress_reactor_not_running)

        if not base_timer:
            base_timer = self.DEFAULT_UPDATE_TIMER

        self.update_timer = base_timer
        self.garbage_timer = base_timer * 4
        self.timeout_timer = base_timer * 6
        self.log.debug1("Using timers: Update: %d, gc: %d, timeout: %d" % \
                       (self.update_timer, self.garbage_timer,
                        self.timeout_timer))

        self._route_change = False
        self._gc_started = False
        if sys.platform == "linux2":
            self._sys = LinuxRIPSystem(log_config=log_config)
        elif sys.platform.startswith("win"):
            self._sys = WindowsRIPSystem(log_config=log_config)
        else:
            raise(NotSupported("No support for current OS."))
        self.port = port
        self._routes = []
        self._garbage_routes = []

        # Nexthop of 0.0.0.0 tells receivers to use the source IP on the
        # packet for the nexthop address. See RFC 2453 section 4.4.
        nexthop = "0.0.0.0"

        if user_routes:
            metric = 0
            tag = 0

            for route in user_routes:
                parsed_rt = ipaddr.IPv4Network(route)
                rte = RIPRouteEntry(address=parsed_rt.ip.exploded,
                                    mask=parsed_rt.netmask.exploded,
                                    nexthop=nexthop,
                                    metric=metric,
                                    tag=tag,
                                    imported=True)
                self.log.debug5("Trying to add user route %s" % rte)
                self.try_add_route(rte, nexthop, False)

        if importroutes:
            for rt in self._sys.get_local_routes():
                # Windows includes all local routes, including /32 routes
                # for local interfaces, in its main routing table. Filter
                # most of those out.
                if rt.network.ip.is_loopback   or \
                   rt.network.ip.is_link_local or \
                   rt.network.ip.is_multicast  or \
                   rt.network.ip.exploded == "255.255.255.255":
                    continue
                self.try_add_route(rt, nexthop, False)

        self.activate_ifaces(requested_ifaces)
        self._last_trigger_time = datetime.datetime.now()

        # Setup admin interface
        ripadmin.start(self)

        reactor.callWhenRunning(self.generate_periodic_update)
        reactor.callWhenRunning(self._check_route_timeouts)

    def _suppress_reactor_not_running(self, msg):
        # reactor apparently calls reactor.stop() more than once when shutting
        # down under certain circumstances, like when a signal goes uncaught
        # (e.g. CTRL+C). It only does this sometimes. It prints a stacktrace
        # to the console. I see several old (now-fixed) bug reports relating
        # to this and some stackexchange threads discussing how to suppress
        # these kinds of messages, but nothing that tells me how to get this
        # to stop happening "the right way". Since I never call reactor.stop
        # it seems like this is twisted's problem. This is kludgey but it
        # works, and it shouldn't block any useful messages from being printed.
        if msg['isError'] and msg["failure"].type == \
           twisted.internet.error.ReactorNotRunning:
            self.log.info("FIXME: Suppressing ReactorNotRunning error.")
            for k in msg:
                msg[k] = None

    def stopProtocol(self):
        self.log.info("RIP is shutting down.")
        self.cleanup()

    def _act_on_routes_before_time(self, action, cond, timer):
        """Take an action on a route if its timeout is less than a given time.
        Doesn't count routes that don't meet the given condition (cond) or
        if their timeout is set to None.

        timer is a number of seconds that will determine when the next call
        time should be.

        Returns the next time this function should be called based on the
        rt.timeout values, or returns None if no values were greater than
        before_time."""
        now = datetime.datetime.now()
        timeout_delta = datetime.timedelta(seconds=timer)
        before_time = now - timeout_delta
        lowest_timer = before_time

        for rt in self._routes:
            if not cond(rt):
                continue
            if rt.timeout == None:
                continue

            if rt.timeout < before_time:
                action(rt)
            else:
                lowest_timer = max(lowest_timer, rt.timeout)

        if lowest_timer == before_time:
            return None
        else:
            return (lowest_timer + timeout_delta - now).total_seconds() + 1

    def _start_garbage_collection(self, rt):
        if rt.garbage:
            self.log.debug2("Route was already on GC: %s" % rt)
            return

        self.log.debug2("Starting garbage collection for route %s" % rt)
        rt.changed = True
        rt.garbage = True
        rt.init_timeout()
        rt.metric = RIPRouteEntry.MAX_METRIC
        self._sys.modify_route(rt)
        self.handle_route_change()
        self._init_garbage_collection_timer()

    def _check_route_timeouts(self):
        self.log.debug2("Checking route timeouts...")
        action = self._start_garbage_collection
        cond = lambda x: not x.garbage
        now = datetime.datetime.now()

        next_call_time = self._act_on_routes_before_time(action, cond,
                                              self.timeout_timer)

        if not next_call_time:
            next_call_time = self.timeout_timer

        self.log.debug2("Checking timeouts again in %d second(s)" %
                       next_call_time)
        reactor.callLater(next_call_time, self._check_route_timeouts)

    def _init_garbage_collection_timer(self):
        if self._gc_started:
            return
        self._gc_started = True
        reactor.callLater(self.garbage_timer, self._collect_garbage_routes)

    def _collect_garbage_routes(self):
        self.log.debug2("Collecting garbage routes...")
        action = lambda x: setattr(x, "marked_for_deletion", True)
        cond = lambda x: x.garbage
        now = datetime.datetime.now()

        next_call_time = self._act_on_routes_before_time(action, cond,
                                               self.garbage_timer)
        if not next_call_time:
            self.log.debug2("No more routes on GC.")
            self._gc_started = False
        else:
            self.log.debug2("GC running again in %d second(s)" %
                            next_call_time)
            reactor.callLater(next_call_time, self._collect_garbage_routes)

        # Check for deletion flag and *safely* delete those routes
        for rt in self._routes[:]:
            if rt.marked_for_deletion:
                self._uninstall_route(rt)

    def _uninstall_route(self, rt):
        self.log.debug2("Deleting route: %s" % rt)
        self._sys.uninstall_route(rt.network.ip.exploded, rt.network.prefixlen)
        self._routes.remove(rt)

    def init_logging(self, log_config):
        # debug1 is less verbose, debug5 is more verbose.
        for (level, name) in [ (10, "DEBUG1"),
                               (9, "DEBUG2"),
                               (8, "DEBUG3"),
                               (7, "DEBUG4"),
                               (6, "DEBUG5"),
                             ]:
            self._create_new_log_level(level, name)

        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("RIP")

    def activate_ifaces(self, requested_ifaces):
        """Enable RIP processing on the given IPs/interfaces.
        requested_ifaces -- A list of IP addresses to use"""
        if not requested_ifaces:
            raise(ValueError("Need one or more interface IPs to listen on."))

        for req_iface in requested_ifaces:
            activated_iface = False
            for sys_iface in self._sys.logical_ifaces:
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

    def generate_update(self, triggered=False, ifaces=None, routes=None,
                        dst_ip="224.0.0.9", dst_port=None, split_horizon=True):
        """Send an update message across the network."""
        if not dst_port:
            dst_port = self.port

        self.log.debug2("Sending an update. Triggered = %d." % triggered)
        hdr = RIPHeader(cmd=RIPHeader.TYPE_RESPONSE, ver=2).serialize()

        if not ifaces:
            ifaces_to_use = self.get_active_ifaces()
        else:
            ifaces_to_use = ifaces

        if not routes:
            routes_to_use = self._routes
        else:
            routes_to_use = routes

        for iface in ifaces_to_use:
            msg = hdr
            self.log.debug4("Preparing update for interface %s" %
                           iface.phy_iface.name)
            route_count = 0
            for rt in routes_to_use:
                self.log.debug5("Trying to add route to update: %s." % rt)
                if split_horizon and rt.nexthop in iface.ip:
                    self.log.debug5("Split horizon prevents sending route.")
                    continue
                if triggered and not rt.changed:
                    self.log.debug5("Route not changed. Skipping.")
                    continue
                msg += rt.serialize()
                self.log.debug5("Adding route to update.")
                route_count += 1
                if route_count == self.MAX_ROUTES_PER_UPDATE:
                    self.log.debug5("Max routes per update reached."
                                   " Sending an update...")
                    self.send_update(msg, iface.ip.ip.exploded,
                                     dst_ip, dst_port)
                    msg = hdr
                    route_count = 0

            if len(msg) > RIPHeader.SIZE:
                self.send_update(msg, iface.ip.ip.exploded, dst_ip, dst_port)

        if triggered:
            for rt in self._routes:
                rt.changed = False

    def generate_periodic_update(self):
        self.generate_update()
        reactor.callLater(self.get_update_interval(),
                          self.generate_periodic_update)

    def get_update_interval(self):
        """Get the amount of time until the next update. This is equal to
        the default update timer +/- a number of a seconds to create update
        jitter."""
        return self.update_timer + random.randrange(-self.JITTER_VALUE,
                                                     self.JITTER_VALUE)

    def get_active_ifaces(self):
        """Return active logical interfaces."""
        for iface in self._sys.logical_ifaces:
            if iface.activated:
                yield iface

    def send_update(self, msg, src_iface_ip, dst_ip="224.0.0.9",
                    dst_port=None):
        if not dst_port:
            dst_port = self.port

        self.transport.setOutgoingInterface(src_iface_ip)
        self.transport.write(msg, (dst_ip, dst_port))

    def datagramReceived(self, data, (host, port)):
        self.log.debug2("Processing a datagram from host %s." % host)

        link_local = False
        host_local = False
        host = ipaddr.IPv4Address(host)
        for local_iface in self._sys.logical_ifaces:
            if host in local_iface.ip:
                link_local = True
            if local_iface.ip.ip.exploded == host.exploded:
                host_local = True
            if host_local or link_local:
                break

        if not link_local:
            self.log.warn("Received advertisement from non link-local "
                          "host. Ignoring.")
            return

        try:
            msg = RIPPacket(data=data, src_ip=host.exploded)
            self.log.debug5(msg)
        except FormatException:
            self.log.warn("RIP packet with invalid format received.")
            self.log.debug5("Hex dump:")
            self.log.debug1(binascii.hexlify(data))
            self.log.debug1("Traceback:")
            self.log.debug1(traceback.format_exc())
            return

        if msg.hdr.cmd == RIPHeader.TYPE_REQUEST:
            self.process_request(msg, host, port, local_iface)
        elif msg.hdr.cmd == RIPHeader.TYPE_RESPONSE:
            if host_local:
                self.log.debug5("Ignoring message from local system.")
                return
            if port != self.port:
                self.log.debug5("Advertisement source port was not the RIP "
                               "port.  Ignoring.")
                return

            self.process_response(msg, host)
        else:
            self.log.warn("Received a packet with a command field that was "
                          "not REQUEST or RESPONSE from %s:%d. Command = %d" % \
                           (host, port, msg.hdr.cmd))
            return

    def process_request(self, msg, host, port, local_iface):
        # See RFC 2453 section 3.9.1
        if not msg.rtes:
            return
        elif len(msg.rtes) == 1   and \
             msg.rtes[0].afi == 0 and \
             msg.rtes[0].metric == RIPRouteEntry.MAX_METRIC:
            self._send_whole_response(host, port, local_iface)
        else:
            self._send_partial_response(host, port, msg)

    def _send_whole_response(self, host, port, local_iface):
        """Provide the metric and nexthop address for known routes. Split
        horizon processing is performed. This is the "whole-table" case from
        RFC 2453 section 3.9.1."""
        self.generate_update(ifaces=[local_iface], dst_ip=host.exploded,
                             dst_port=port)

    def _send_partial_response(self, host, port, msg):
        """Provide the metric and nexthop address for every RTE in msg. No
        split horizon is performed. This is the "specific" case from RFC 2453
        section 3.9.1."""
        for rt in msg.rtes:
            matching_rt = self.get_route(rt.network.ip.exploded,
                                         rt.network.netmask.exploded)
            if not matching_rt:
                rt.metric = RIPRouteEntry.MAX_METRIC
            else:
                rt.metric = matching_rt.metric

        msg.hdr.cmd = RIPHeader.TYPE_RESPONSE
        self.transport.write(msg.serialize(), (host.exploded, port))

    def process_response(self, msg, host):
        for rte in msg.rtes:
            # XXX Should update to use the metric of the incoming interface
            rte.metric = min(rte.metric + 1, RIPRouteEntry.MAX_METRIC)
            self.try_add_route(rte, host)

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
        self.log.debug2("Sending triggered update.")
        self._route_change = False
        self.generate_update(triggered=True)

    def try_add_route(self, rte, host, install=True):
        self.log.debug5("try_add_route: Received %s" % rte)
        bestroute = self.get_route(rte.network.ip.exploded,
                                   rte.network.netmask.exploded)

        rte.set_nexthop(host)
        if not bestroute:
            if rte.metric == RIPRouteEntry.MAX_METRIC:
                return

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
                        self._start_garbage_collection(bestroute)
                    else:
                        self.update_route(bestroute, rte)
                elif not bestroute.garbage:
                    bestroute.init_timeout()
            elif rte.metric < bestroute.metric:
                self.log.debug3("Found better route to %s via %s in %d" % \
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

    @staticmethod
    def _create_new_log_level(level, name):
        def newlog(self, msg, level=level, *args, **kwargs):
            if self.isEnabledFor(level):
                self._log(level, msg, args, **kwargs)
        logging.addLevelName(level, name)
        setattr(logging.Logger, name.lower(), newlog)


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
        self._route_change = False

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
        for ip in re.findall("IPv4 Address.*: (.*)\r", ipconfig_output):
            self.logical_ifaces.append(LogicalInterface(self.phy_ifaces[0],
                                       ip))

    def uninstall_route(self, net, mask):
        pass

    def install_route(self, net, preflen, metric, nexthop):
        pass

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
                                metric=0,
                                tag=0)
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
                (self.hdr.cmd, self.hdr.ver, len(self.rtes))

    def _init_from_net(self, data, src_ip):
        """Init from data received from the network."""
        # Quick check for malformed data
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise(FormatException)

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        if malformed_rtes:
            raise(FormatException)

        numrtes = (datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE
        self.hdr = RIPHeader(data[0:RIPHeader.SIZE])

        self.rtes = []
        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE
        for i in range(numrtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end],
                                              src_ip=src_ip))
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    def _init_from_host(self, hdr, rtes):
        """Init using a header and rte list provided by the application."""
        if hdr.ver != 2:
            raise(ValueError("Only version 2 is supported."))
        self.hdr = hdr
        self.rtes = rtes

    def serialize(self):
        """Return a bytestring representing this packet in a form that
        can be transmitted across the network."""

        # Always re-pack in case the header or rtes have changed.
        packed = self.hdr.serialize()
        for rte in self.rtes:
            packed += rte.serialize()
        return packed


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
        # Always re-pack
        return struct.pack(self.FORMAT, self.cmd, self.ver, 0)


class RIPRouteEntry(object):
    FORMAT = ">HHIIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, rawdata=None, address=None, mask=None, nexthop=None,
                 metric=None, tag=0, src_ip=None, imported=False, afi=2):
        self.packed = None
        self.changed = False
        self.imported = imported
        self.init_timeout()
        self.garbage = False
        self.marked_for_deletion = False

        if rawdata and src_ip:
            self._init_from_net(rawdata, src_ip)
        elif address and \
             nexthop and \
             mask   != None and \
             metric != None and \
             tag    != None:
            self._init_from_host(address, mask, nexthop, metric, tag, afi)
        else:
            raise(ValueError)

    def _init_from_host(self, address, mask, nexthop, metric, tag, afi):
        """Init from data provided by the application."""
        self.afi = afi
        self.set_network(address, mask)
        self.set_nexthop(nexthop)
        self.metric = metric
        self.tag = tag

    def set_network(self, address, mask):
        self.network = ipaddr.IPv4Network(address + "/" + str(mask))

    def set_nexthop(self, nexthop):
        self.nexthop = ipaddr.IPv4Address(nexthop)

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

        self.set_nexthop(rte[4])
        self.metric = rte[5]

        if self.nexthop.exploded == "0.0.0.0":
            self.set_nexthop(src_ip)
        self.set_network(address.exploded, mask.exploded)

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

        # Always re-pack
        return struct.pack(self.FORMAT, self.afi, self.tag,
                                      self.network.network._ip,
                                      self.network.netmask._ip,
                                      self.nexthop._ip, self.metric)

class _RIPException(Exception):
    def __init__(self, message=""):
        self.message = message


class FormatException(_RIPException):
    pass


class NotSupported(_RIPException):
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
    op.add_option("-t", "--base-timer", type="int",
                  help="Use non-default update/gc/timeout timers. The update "
                  "timer is set to this value and gc/timeout timers are based "
                  "on it")

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
    if sys.platform.startswith("linux"):
        userid = subprocess.check_output("id -u".split()).rstrip()
        if userid != "0":
            sys.stderr.write("Must run as root. Exiting.\n")
            sys.exit(1)

    ripserv = RIP(options.port, options.route, options.import_routes, options.interface, options.log_config, options.base_timer)
    reactor.listenMulticast(options.port, ripserv)
    reactor.run()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
