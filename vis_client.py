#!/usr/bin/env python

"""Visualization client compatible with the Better Approach to Mobile Ad hoc
Networks (B.A.T.M.A.N.) visualization server. This is for version 23 of
the vis protocol."""

# Python-RIPv2 (http://python-ripv2.googlecode.com)
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
import socket
import time
import ipaddr

# Note that the Python-RIPv2 project doesn't do anything with this, just
# figured I'd post the code since I played around with it one night.
# See also: http://code.google.com/p/python-ripv2/wiki/VisualizationServerSetup

class VisClient23(object):
    """Client compatible with the Better Approach to Mobile Ad hoc Networks
    (B.A.T.M.A.N.) visualization server. (Version 23.)"""

    def __init__(self, server_ip, server_port, sender_ip, gw_class,
                 tq_max):
        self.sock = socket.socket(type=socket.SOCK_DGRAM)
        self.sock.connect((server_ip, server_port))
        self.pkt = VisPacket23(sender_ip, gw_class, tq_max).serialize()

    def send_pkt(self, data):
        self.sock.send(self.pkt + data)


class VisPacket23(object):
    """Packet format version 23 for the Better Approach to Mobile Ad hoc
    Networks (B.A.T.M.A.N.) visualization server."""

    FORMAT = ">IBBB"

    def __init__(self, sender_ip, gw_class, tq_max):
        self.sender_ip = int(ipaddr.IPv4Address(sender_ip))
        self.version = 23
        self.gw_class = gw_class
        self.tq_max = tq_max

    def serialize(self):
        return struct.pack(self.FORMAT, self.sender_ip, self.version,
                           self.gw_class, self.tq_max)


class VisData23(object):
    """Data format version 23 for the Better Approach to Mobile Ad hoc
    Networks (B.A.T.M.A.N.) visualization server."""

    FORMAT = ">BBI"

    DATA_TYPE_NEIGH = 1
    DATA_TYPE_SEC_IF = 2
    DATA_TYPE_HNA = 3

    def __init__(self, data_type, data, ip):
        # The 'ip' here is a neighbor IP, and 'data' is a transmission quality
        # measurement. The terminology used here is for consistency with
        # vis-types.h from the vis server source.
        self.data_type = data_type
        self.data = data
        self.ip = int(ipaddr.IPv4Address(ip))

    def serialize(self):
        return struct.pack(self.FORMAT, self.data_type, self.data, self.ip)


if __name__ == "__main__":
    print("See code for a usage example that is commented out.")
    #client2 = VisClient23("192.168.2.2", 4307, "2.2.2.2", 0, 1)
    #visdata = VisData23(VisData23.DATA_TYPE_NEIGH, 1, "3.3.3.3").serialize()
    #client2.send_pkt(visdata)
