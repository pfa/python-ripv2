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

    # Create request
    hdr = ripserv.RIPHeader(cmd=ripserv.RIPHeader.TYPE_REQUEST, ver=2)
    if options.specific_routes:
        rtes = create_specific_rtes(options.route)
    elif options.whole_table:
        rtes = create_whole_rtes()
    request = ripserv.RIPPacket(hdr=hdr, rtes=rtes)

    # Send request
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.connect((options.dst, 520))
    sock.send(request.serialize())
    wait_time = 5
    sock.settimeout(wait_time)

    if not options.quiet:
        print("Sent request. Waiting %d second(s) for response." % wait_time)

    # Read response
    # Assumes the full response comes in a single datagram and that the size
    # doesn't exceed what we attempt to receive.
    # Note: a receive size of >1500 bytes does make sense since you may connect
    # to a local rip daemon.
    buf = ""
    try:
        buf = sock.recv(65535)
    except socket.timeout:
        print("Did not receive a response from remote router.")
        return -1
    except socket.error:
        print("Error sending to the remote router. (Is a RIP "
              "service listening at the destination?)")
        return -1

    response = ripserv.RIPPacket(data=buf, src_ip="0.0.0.0")

    if not options.quiet:
        print("Response contained:")
        for rte in response.rtes:
            print(rte)

    # Validate response
    return validate_response(request, response, options)

def create_specific_rtes(routes):
    rtes = []
    for requested_rt in routes:
        ip = ipaddr.IPv4Network(requested_rt)
        rtes.append(ripserv.RIPRouteEntry(address=ip.ip.exploded,
                    mask=ip.prefixlen, nexthop="0.0.0.0", metric=0, tag=0))
    return rtes

def create_whole_rtes():
    return [ripserv.RIPRouteEntry(afi=0, address="0.0.0.0", mask=0, tag=0,
                                  metric=ripserv.RIPRouteEntry.MAX_METRIC,
                                  nexthop="0.0.0.0")]

def validate_response(request, response, options):
    pass_validation = True

    if response.hdr.cmd != ripserv.RIPHeader.TYPE_RESPONSE:
        print("Response had an unexpected cmd field: %d" % response.hdr.cmd)
        pass_validation = False
    if response.hdr.ver != 2:
        print("Response had an unexpected ver field: %d" % response.hdr.ver)
        pass_validation = False

    if options.specific_routes:
        if not validate_specific_routes(request, response):
            pass_validation = False
    elif options.whole_table:
        if not validate_whole_table(response):
            pass_validation = False

    if pass_validation:
        print("Response passed validation.")
    else:
        print("Warning: Response FAILED to pass validation.")

    return pass_validation

def validate_whole_table(response):
    # Just check for sane ranges... whether or not the routes are expected
    # depends on the rest of the network and the router's configuration.
    pass_validation = True

    for rte in response.rtes:
        if rte.metric > ripserv.RIPRouteEntry.MAX_METRIC:
            print("Reported metric is above the maximum.")
            pass_validation = False
        if rte.tag:
            print("Tag not set to 0.")
            pass_validation = False

    return pass_validation

def validate_specific_routes(request, response):
    # Other than the metrics and nexthops (nexthops are changed locally),
    # everything should be identical in the rte lists.
    pass_validation = True

    for request_rte in request.rtes:
        rte_found = False
        for response_rte in response.rtes:
            if request_rte.afi == response_rte.afi         and \
               request_rte.network == response_rte.network and \
               request_rte.tag == response_rte.tag:
                rte_found = True
                break
        if not rte_found:
            if response_rte not in response.rtes:
                print("Missing RTE in response: %s" % rte)
                pass_validation = False

    if len(response.rtes) != len(request.rtes):
        print("Different number of request vs response RTEs, %d vs %d." % \
              (len(response.rtes), len(request.rtes)))
        pass_validation = False

    return pass_validation

def parse_args(argv):
    op = optparse.OptionParser()
    op.add_option("-r", "--route", help="A route to request.", type="string",
                  action="append")
    op.add_option("-d", "--dst", help="The router to request from.",
                  type="string")
    op.add_option("-w", "--whole-table", default=False,
                  action="store_true",
                  help="Request the whole routing table.")
    op.add_option("-s", "--specific-routes", default=False,
                  action="store_true",
                  help="Request specific routes (use -r).")
    op.add_option("-q", "--quiet", default=False,
                  action="store_true",
                  help="Only print validation messages.")
    options, arguments = op.parse_args()

    if arguments:
        op.error("No non-option arguments are expected.")

    if options.specific_routes and options.whole_table:
        op.error("Options -w and -s are mutually exclusive.")
    elif not options.specific_routes and not options.whole_table:
        op.error("Exactly one of -w or -s is required.")
    if options.specific_routes:
        if not options.route:
            op.error("At least one route to request is required (-r).")
#        if len(options.route) > 25:
#            op.error("Only <25 routes supported currently.")
    if options.whole_table:
        if options.route:
            op.error("No -r arguments are needed if -w is specified.")
    if not options.dst:
        op.error("The destination router must be specified (-d).")

    return options, arguments

if __name__ == "__main__":
    main(sys.argv)
