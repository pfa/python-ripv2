#!/usr/bin/env python

import logging
import os
import ctypes

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
