#!/usr/bin/env python

import logging

# See my comment here:
# http://stackoverflow.com/questions/2183233/how-to-add-a-custom-loglevel-to-pythons-logging-facility
def create_new_log_level(level, name):
    def newlog(self, msg, level=level, *args, **kwargs):
        if self.isEnabledFor(level):
            self._log(level, msg, args, **kwargs)
    logging.addLevelName(level, name)
    setattr(logging.Logger, name.lower(), newlog)
