#!/usr/bin/env python

import logging
import os
import ctypes
from twisted.internet import error

def create_new_log_level(level, name):
    """Add a custom log level. See my comment here:
    http://stackoverflow.com/questions/2183233/how-to-add-a-custom-loglevel-to-pythons-logging-facility
    """
    def newlog(self, msg, level=level, *args, **kwargs):
        if self.isEnabledFor(level):
            self._log(level, msg, args, **kwargs)
    logging.addLevelName(level, name)
    setattr(logging.Logger, name.lower(), newlog)

def is_admin():
    """Cross-platform method of checking for root/admin privs. Works on Linux
    and Windows, haven't tried mac. See:
    http://stackoverflow.com/questions/1026431/crossplatform-way-to-check-admin-rights-in-python-script
    """
    is_admin = False
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            sys.stderr.write("Unable to check if you are running as a \n"
                             "privileged user. You may be using an \n"
                             "unsupported OS.")
            return False
    return is_admin

def suppress_reactor_not_running(msg, logfunc=None):
    # reactor apparently calls reactor.stop() more than once when shutting
    # down under certain circumstances, like when a signal goes uncaught
    # (e.g. CTRL+C). It only does this sometimes. It prints a stacktrace
    # to the console. I see several old (now-fixed) bug reports relating
    # to this and some stackexchange threads discussing how to suppress
    # these kinds of messages, but nothing that tells me how to get this
    # to stop happening "the right way". Since I never call reactor.stop
    # it seems like this is twisted's problem. This is kludgey but it
    # works, and it shouldn't block any useful messages from being printed.
    if not msg.has_key("isError") or \
       not msg.has_key("failure"):
        return
    if msg["isError"] and \
       msg["failure"].type == error.ReactorNotRunning:
        if logfunc:
            logfunc("Suppressing ReactorNotRunning error.")
        for k in msg:
            msg[k] = None
