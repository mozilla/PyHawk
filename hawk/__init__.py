# -*- coding: utf-8 -*-

# GO HAWKS!

"""
Python library for HAWK
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2013 by Mozilla.
:license: see LICENSE for more details.

"""

__title__ = 'pyhawk'
__version__ = '0.0.0'
__build__ = 0x010200
__copyright__ = 'Copyright 2013 Mozilla'


from .client import Client
from .server import Server, BadRequest, BadMac, MissingCredentials

# Set default logging handler to avoid "No handler found" warnings.
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())
