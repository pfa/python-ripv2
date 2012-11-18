#!/usr/bin/env python

"""Send a RIP request. Used to test RIP request processing and responses."""

import sys
sys.path.append("..")

import optparse
import ipaddr
import socket

import ripserv

def main(argv):
    options, arguments = parse_args(argv)
    hdr = ripserv.RIPHeader(cmd=ripserv.RIPHeader.TYPE_REQUEST, ver=2)
    rtes = []
    for requested_rt in options.route:
        ip = ipaddr.IPv4Network(requested_rt)
        rtes.append(ripserv.RIPRouteEntry(address=ip.ip.exploded,
                    mask=ip.prefixlen, nexthop="0.0.0.0", metric=0, tag=0))
    request = ripserv.RIPPacket(hdr=hdr, rtes=rtes)

    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.connect((options.dst, 520))
    sock.send(request.serialize())
    sock.settimeout(5)

    # XXX Doesn't currently deal with >25 routes.
    buf = sock.recv(1024)
    response = ripserv.RIPPacket(data=buf, src_ip="0.0.0.0")

    validate_response(request, response)

def validate_response(request, response):
    pass_validation = True

    if response.hdr.cmd != ripserv.RIPHeader.TYPE_RESPONSE:
        print("Response had an unexpected cmd field: %d" % response.hdr.cmd)
        pass_validation = False
    if response.hdr.ver != 2:
        print("Response had an unexpected ver field: %d" % response.hdr.ver)
        pass_validation = False
    if len(response.rtes) != len(request.rtes):
        print("Different number of request vs response RTEs, %d vs %d." % \
              (len(response.rtes), len(request.rtes)))
        pass_validation = False

    # Other than the metrics and nexthops (nexthops are changed locally),
    # everything should be identical in the rte lists.
    for request_rte in request.rtes:
        rte_found = False
        for response_rte in response.rtes:
            if request_rte.afi == response_rte.afi         and \
               request_rte.network == response_rte.network and \
               request_rte.tag == response_rte.tag:
                rte_found = True
                break
        if not rte_found:
            if rte not in response.rtes:
                print("Missing RTE in response: %s" % rte)
                pass_validation = False

    if pass_validation:
        print("Response passed validation.")
    else:
        print("Warning: Response FAILED to pass validation.")

    return pass_validation

def parse_args(argv):
    op = optparse.OptionParser()
    op.add_option("-r", "--route", help="A route to request.", type="string",
                  action="append")
    op.add_option("-d", "--dst", help="The router to request from.",
                  type="string")
    options, arguments = op.parse_args()
    if arguments:
        op.error("No non-option arguments are expected.")
    if not options.route:
        op.error("At least one route to request is required (-r).")
    if len(options.route) > 25:
        op.error("Only <25 routes supported currently.")
    if not options.dst:
        op.error("The destination router must be specified (-d).")

    return options, arguments

if __name__ == "__main__":
    main(sys.argv)
