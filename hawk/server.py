# -*- coding: utf-8 -*-

"""
Python library for HAWK
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2013 by Mozilla.
:license: see LICENSE for more details.

"""

import copy
import math
import time
from urlparse import urlparse, parse_qs

import hawk.hcrypto as hcrypto
import hawk.util as util


class BadMac(Exception):
    """Exception raised for mac mismatch."""
    pass


class BadRequest(Exception):
    """Exception raised for bad inputs on request."""
    pass


class MissingCredentials(Exception):
    """Exception raised for bad security configuration."""
    pass

class BewitExpired(Exception):
    """Exception raised when Bewit url has expired."""
    pass


class Server(object):
    """Object with authenticate and header methods."""

    def __init__(self, req):
        """Initialize a Server object."""
        self.req = req

    def authenticate(self, req, credentials, options):
        """

        options can have the following
        * checkNonceFn - A callback to validate if a given nonce is valid
        * timestampSkewSec - Allows for clock skew in seconds. Defaults to 60.
        * localtimeOffsetMsec - Offset for client time. Defaults to 0.
        * options.payload - Required

        """
        now = math.floor(time.time())

        self._check_options(options)

        attributes = util.parse_authorization_header(
            req['headers']['authorization'])

        artifacts = self._prepare_artifacts(req, attributes)

        mac = self._calculate_mac(credentials, artifacts)

        # TODO prevent timing attach
        if not mac == attributes['mac']:
            print "Ours [" + mac + "] Theirs [" + attributes['mac'] + "]"
            raise BadMac

        if 'payload' in options:
            if 'hash' not in attributes:
                print "Missing required payload hash"
                raise BadRequest
            p_hash = hcrypto.calculate_payload_hash(options['payload'],
                                                    credentials['algorithm'],
                                                    req['contentType'])
            if not p_hash == attributes['hash']:
                print "Bad payload hash"
                raise BadRequest

        if 'check_nonce_fn' in options:
            if not options['check_nonce_fn'](attributes['nonce'],
                                             attributes['ts']):
                raise BadRequest

        skew = int(options['timestampSkewSec'])
        if math.fabs(int(attributes['ts']) - now) > skew:
            print "Expired request"
            raise BadRequest

        return artifacts

    def _calculate_mac(self, credentials, artifacts):
        """Checks inputs and calculates MAC."""
        if 'key' not in credentials or 'algorithm' not in credentials:
            raise MissingCredentials
        
        mac = hcrypto.calculate_mac('header', credentials, artifacts)

        return mac

    def _prepare_artifacts(self, req, attributes):
        """Converts the request and attributes into an artifacts dict."""
        artifacts = {
            'method': req['method'],
            'host': req['host'],
            'port': req['port'],
            'resource': req['url']
        }
        artifact_keys = ['ts', 'nonce', 'hash', 'ext',
                         'app', 'dlg', 'mac', 'id']

        attrs = attributes.keys()
        for key in artifact_keys:
            if key in attrs:
                artifacts[key] = attributes[key]
            else:
                # I think we want empty strings in normalized header mac
                artifacts[key] = ''
        return artifacts

    def header(self, credentials, artifacts, options=None):
        """Generate a Server-Authorization header for a given response.

    credentials: {},                                        // Object received from authenticate()
    artifacts: {}                                           // Object received from authenticate(); 'mac', 'hash', and 'ext' - ignored
    options: {
        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
        contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
        hash: 'U4MKKSmiVxk37JCCrAVIjV='                     // Pre-calculated payload hash
    }
        """
        if options is None:
            options = {}

        if not artifacts or False == isinstance(artifacts, dict) or \
                False == isinstance(options, dict):
            return ''

        h_artifacts = copy.copy(artifacts)
        del h_artifacts['mac']

        if 'hash' in options:
            h_artifacts['hash'] = options['hash']

        if 'ext' in options:
            h_artifacts['ext'] = options['ext']

        if not credentials or 'key' not in credentials or \
                'algorithm' not in credentials:
            return ''

        if 'hash' not in h_artifacts or h_artifacts['hash'] is None or \
                len(h_artifacts['hash']) == 0:
            if 'payload' in options:
                h_artifacts['hash'] = hcrypto.calculate_payload_hash(
                    options['payload'], credentials['algorithm'],
                    options['contentType'])

        mac = hcrypto.calculate_mac('response', credentials, h_artifacts)

        header = 'Hawk mac="' + mac + '"'
        if 'hash' in h_artifacts:
            header += ', hash="' + h_artifacts['hash'] + '"'

        if 'ext' in h_artifacts and h_artifacts['ext'] is not None and \
                len(h_artifacts['ext']) > 0:

            h_ext = util.check_header_attribute(
                h_artifacts['ext']).replace('\\', '\\\\').replace('\n', '\\n')

            header += ', ext="' + h_ext + '"'

        return header

    def _check_options(self, options):
        """Provides defaults for options."""
        if 'timestampSkewSec' not in options:
            options['timestampSkewSec'] = 60

        if 'localtimeOffsetMsec' not in options:
            options['localtimeOffsetMsec'] = 0

    def authenticate_bewit(self, req, credentials, options):
        """Authenticate bewit one time requests.

        Compatibility Note: HAWK exposes this as hawk.uri.authenticate

        req is a dict with the keys:
        url
        method


        Optional options: 'hostHeaderName', 'localtimeOffsetMsec'
        
        """
        if not valid_bewit_args(req, options):            
            return False
        now = time.time() + int(options['localtime_offset_msec'])

        url = urlparse(req['url'])
        qs = parse_qs(url.query)

        if not 'bewit' in qs or len(qs['bewit']) != 1 or \
                len(qs['bewit'][0]) == 0:
            print "No bewit query string parameter"
            return False

        bewit = hcrypto.explode_bewit(qs['bewit'][0])

        original_url = normalize_url_without_bewit(req['url'], qs['bewit'][0])

        if bewit['exp'] < now:
            raise BewitExpired

        options['ts'] = bewit['exp']

        artifacts = {
            'ts': bewit['exp'],
            'nonce': '',
            'method': 'GET',
            'resource': original_url,
            'host': req['host'],
            'port': req['port'],
            'ext': bewit['ext']
        }

        mac = hcrypto.calculate_mac('bewit', credentials, artifacts, True)

        # TODO mitigate timing attack
        if mac != bewit['mac']:
            print "bewit " + mac + " didn't match " + bewit['mac']
            raise BadRequest

        return True
        

def valid_bewit_args(req, options):
    """Validates inputs and sets defaults for options."""

    if 'url' not in req or 'method' not in req:
        print "missing url or method in request"
        raise BadRequest

    if 'GET' != req['method'] and 'HEAD' != req['method']:
        print "Bad Method"
        raise BadRequest

    if 'headers' in req and 'authorization' in req['headers'] and \
            len(req['headers']['authorization']) > 0:
        print "ERROR: Attempt to use auth header and bewit"
        raise BadRequest

    if 'localtime_offset_msec' not in options or \
            options['localtime_offset_msec'] is None:
        options['localtime_offset_msec'] = 0

    return True

def normalize_url_without_bewit(url, bewit):
    """Normalizes url by removing bewit parameter."""
    bewit_pos = url.find('bewit=')
    # Chop off the last character before 'bewit=' which is either a ? or a &
    bewit_pos -= 1
    bewit_end = bewit_pos + len("bewit=" + bewit) + 1
    o_url = ''.join([url[0:bewit_pos], url[bewit_end:]])
    return o_url
