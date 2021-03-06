#!/usr/bin/env python
#
# Administrative interface for the RIP server.
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

from cmd import Cmd
from twisted.internet import protocol, reactor
from twisted.protocols.basic import LineReceiver
import pprint
import inspect
import logging
import traceback

class RIPAdminProtocol(LineReceiver):
    """Network accessible administrative interface for the RIPAdminCLI."""

    def __init__(self, ripinstance, prompt, *args, **kwargs):
        # Parent doesn't inherit from object and doesn't implement
        # __init__. No parent init to call.
        self.ripinstance = ripinstance
        self.prompt = prompt

    def connectionMade(self):
        self.cli = RIPAdminCLI(self.ripinstance, self.prompt,
                               stdin=self.transport, stdout=self.transport)

        # Using raw_input seems to cause some screwiness.
        self.cli.use_rawinput = False
        self.transport.write("Connected to the RIP administrative interface.\n"
                             "  Type ? for a list of commands.\n"
                             "  Type help <COMMAND> for command info.\n"
                             "  Type 'exit' to exit.\n")
        self.transport.write(self.cli.prompt)

    def lineReceived(self, line):
        try:
            self.transport.write(self.cli.onecmd(line))
            self.transport.write(self.cli.prompt)
        except RIPAdminExit:
            self.transport.loseConnection()


class RIPAdminCLI(Cmd):
    """Administrative interface for RIP."""

    def __init__(self, ripinstance, prompt, *args, **kwargs):
        Cmd.__init__(self, *args, **kwargs)
        self.ripinstance = ripinstance
        self.prompt = prompt
        self.my_handlers = {}

    def do_EOF(self, line):
        """Exit the CLI."""
        self.sendline("Disconnecting by operator command.\n")
        raise RIPAdminExit

    def do_show_routes(self, line):
        """Show routes known by RIP."""
        self.sendline("%d routes:" % len(self.ripinstance._routes))
        self.sendline(pprint.pformat(self.ripinstance._routes))

    def do_debug(self, line):
        """Subscribe to log messages from a subsystem.
        Usage: terminal_monitor <SUBSYSTEM> <level>
        SUBSYSTEM can be: RIP, SYSTEM
        LEVEL can be any valid logging level (debug1, error, etc.) or OFF."""
        args = line.split()
        if len(args) != 2:
            self.usage()
            return
        subsystem = args[0].upper()
        level = args[1].upper()

        if level not in logging._levelNames and not level == "OFF":
            self.stdout.write("Bad logging level.\n")
            self.usage()
            return

        if subsystem not in [ "RIP", "SYSTEM" ]:
            self.stdout.write("Bad subsystem name.\n")
            self.usage()
            return

        handler_name = subsystem
        self.stdout.write("Setting %s to level %s.\n" % (subsystem, level))

        if level == "OFF":
            self.delete_handler(handler_name)
            return

        # If the handler already exists, set the new requested level. Other-
        # wise create a new handler.
        try:
            self.my_handlers[handler_name].setLevel(level)
        except KeyError:
            new_handler = logging.StreamHandler(self.stdout)
            new_handler.setLevel(level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            new_handler.setFormatter(formatter)
            self.my_handlers[handler_name] = new_handler
            logging.getLogger(subsystem).addHandler(new_handler)

    def delete_handler(self, subsystem):
        log = logging.getLogger(subsystem)
        log.removeHandler(self.my_handlers[subsystem])
        del self.my_handlers[subsystem]

    def do_show_handlers(self, line):
        """Show debug handlers."""
        self.stdout.write(pprint.pformat(self.my_handlers) + "\n")

#    def do_python(self, line):
#        """Executes any arguments as Python code from within the RIPAdminCLI
#        object and prints the result to the vty.
#
#        Since the RIP process runs as root, telnet is made available
#        remotely without authentication, and this can execute system commands
#        (e.g. rm...), this is an eminently bad idea unless you're on a
#        machine in a trusted environment.  That's why this is commented
#        out by default. However, it can be extremely useful as an ad hoc
#        debugging tool."""
#        try:
#            self.stdout.write(pprint.pformat(eval(line)) + "\n")
#        except:
#            self.stdout.write(traceback.format_exc() + "\n")

    def usage(self):
        self.stdout.write("Error parsing command. Usage:\n")
        try:
            # Prints the docstring of the caller, which (for 'do_' functions)
            # is a usage string used by the Cmd class for the 'help' command.
            # So ugly... and yet so useful! Perhaps more 'snakelike' than
            # 'pythonic'.
            self.stdout.write(inspect.getdoc(getattr(self,
                              (inspect.stack()[1][3]))) + "\n")
        except AttributeError:
            self.stdout.write("No usage available.\n")

    def sendline(self, line):
        self.stdout.write(str(line) + "\n")

    def emptyline(self):
        pass

    # Command aliases
    do_quit = do_EOF
    do_exit = do_EOF


class RIPAdminExit(Exception):
    """Notification that the CLI should exit."""
    pass


class RIPAdminProtocolFactory(protocol.ServerFactory):
    def __init__(self, ripinstance, prompt):
        # ServerFactory doesn't inherit from object and doesn't implement
        # __init__. Calling parent init would give an error.
        self.ripinstance = ripinstance
        self.prompt = prompt

    def buildProtocol(self, addr):
        return RIPAdminProtocol(self.ripinstance, self.prompt)


def start(ripinstance=None, prompt="ripadmin> ", port=5120):
    reactor.listenTCP(port, RIPAdminProtocolFactory(ripinstance, prompt))
