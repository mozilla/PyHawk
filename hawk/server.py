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

import hawk.hcrypto as hcrypto
import hawk.util as util


class BadMac(Exception):
    """ Exception raised for mac mismatch. """
    pass


class BadRequest(Exception):
    """ Exception raised for bad inputs on request. """
    pass


class MissingCredentials(Exception):
    """ Exception raised for bad security configuration. """
    pass


class Server(object):
    """ Object with authenticate and header methods. """

    def __init__(self, req):
        """ Initialize a Server object. """
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

        self.check_options(options)

        attributes = util.parse_authorization_header(req['headers']['authorization'])

        artifacts = self.prepare_artifacts(req, attributes)

        mac = self.calculate_mac(credentials, artifacts)

        # TODO prevent timing attach
        if not mac == attributes['mac']:
            print "Calculated [" + mac + "] Attributes included [" + attributes['mac'] + "]"
            raise BadMac

        if 'payload' in options:
            if 'hash' not in attributes:
                print "Missing required payload hash"
                raise BadRequest
            p_hash = hcrypto.calculate_payload_hash(options['payload'], credentials['algorithm'], req['contentType'])
            if not p_hash == attributes['hash']:
                print "Bad payload hash"
                raise BadRequest

        if 'check_nonce_fn' in options:
            if not options['check_nonce_fn'](attributes['nonce'], attributes['ts']):
                raise BadRequest

        if math.fabs(int(attributes['ts']) - now) > int(options['timestampSkewSec']):
            print "Expired request"
            raise BadRequest

        return artifacts

    def calculate_mac(self, credentials, artifacts):
        """ Checks inputs and calculates MAC. """
        if 'key' not in credentials or 'algorithm' not in credentials:
            raise MissingCredentials
        
        mac = hcrypto.calculate_mac('header', credentials, artifacts)

        return mac

    def prepare_artifacts(self, req, attributes):
        """ Converts the request and attributes into an artifacts dict. """
        artifacts = {
            'method': req['method'],
            'host': req['host'],
            'port': req['port'],
            'resource': req['url']
        }
        artifact_keys = ['ts', 'nonce', 'hash', 'ext', 'app', 'dlg', 'mac', 'id']
        attrs = attributes.keys()
        for key in artifact_keys:
            if key in attrs:
                artifacts[key] = attributes[key]
            else:
                # I think we want empty strings in normalized header mac
                artifacts[key] = ''
        return artifacts

    def header(self, credentials, artifacts, options=None):
        """ Generate a Server-Authorization header for a given response.

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

        if not artifacts or not isinstance(artifacts, dict) or not isinstance(options, dict):
            return ''

        h_artifacts = copy.copy(artifacts)
        del h_artifacts['mac']

        if 'hash' in options:
            h_artifacts['hash'] = options['hash']

        if 'ext' in options:
            h_artifacts['ext'] = options['ext']

        if not credentials or 'key' not in credentials or 'algorithm' not in credentials:
            return ''

        if 'hash' not in h_artifacts or h_artifacts['hash'] is None or len(h_artifacts['hash']) == 0:
            if 'payload' in options:
                h_artifacts['hash'] = hcrypto.calculate_payload_hash(options['payload'], credentials['algorithm'], options['contentType'])

        mac = hcrypto.calculate_mac('response', credentials, h_artifacts)

        header = 'Hawk mac="' + mac + '"'
        if 'hash' in h_artifacts:
            header += ', hash="' + h_artifacts['hash'] + '"'

        if 'ext' in h_artifacts and h_artifacts['ext'] is not None and len(h_artifacts['ext']) > 0:
            h_ext = util.check_header_attribute(h_artifacts['ext']).replace('\\', '\\\\').replace('\n', '\\n')
            header += ', ext="' + h_ext + '"'

        return header

    def check_options(self, options):
        """ Provides defaults for options. """
        if 'timestampSkewSec' not in options:
            options['timestampSkewSec'] = 60

        if 'localtimeOffsetMsec' not in options:
            options['localtimeOffsetMsec'] = 0
