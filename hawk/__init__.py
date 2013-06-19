# -*- coding: utf-8 -*-

"""
Python library for HAWK
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2013 by Mozilla.
:license: see LICENSE for more details.

"""

import pkg_resources

__title__ = 'pyhawk'
__version__ = pkg_resources.get_distribution(__title__).version
__build__ = 0x010200
__copyright__ = 'Copyright 2013 Mozilla'


from .client import Client  # NOQA
from .server import Server  # NOQA
from .hcrypto import InvalidBewit  # NOQA
from .util import HawkException  # NOQA


# Set default logging handler to avoid "No handler found" warnings.
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        """ Install a null handler. """

        def emit(self, record):
            """ No-op. """
            pass

logging.getLogger(__name__).addHandler(NullHandler())
