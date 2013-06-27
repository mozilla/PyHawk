# -*- coding: utf-8 -*-

"""
Server APIs for HAWK Authentication.
"""

import math
import time
from urlparse import urlparse

import hawk.hcrypto as hcrypto
import hawk.util as util
from hawk.server import BadRequest


def header(url, method, options=None):
    """
    :param uri: 'http://example.com/resource?a=b'
    :param method: HTTP verb ('GET', 'POST', etc)
    :param options:

    Required Options:
    credentials (id, key, algorithm)

    Optional:
    ext:
    Application specific data (string)
    timestamp:
    A pre-calculated timestamp
    nonce:
    '2334f34f':  A pre-generated nonce
    localtimeOffsetMsec:
    Time offset to sync with server time (ignored if timestamp
    provided) (Example 400)
    payload:
    UTF-8 encoded string for body hash generation (ignored if hash
    provided) (Example '{"some":"payload"}')
    contentType:
    Payload content-type (ignored if hash provided) (Example
    'application/json')
    hash:
    Pre-calculated payload hash (Example 'U4MKKSmiVxk37JCCrAVIjV=')
    app:
    Oz application id ('24s23423f34dx')
    dlg:
    Oz delegated-by application id - '234sz34tww3sd'
    """
    result = {'field': '', 'artifacts': {}}

    if url is None or len(url) == 0:
        print "Bad URL skipping"
        return result

    if method is None or len(method) == 0:
        print "Bad method skipping"
        return result

    if not isinstance(options, dict):
        print "Bad options skipping"
        return result

    if 'credentials' not in options:
        print "Bad credentials skipping"
        return result

    cred = options['credentials']
    if 'id' not in cred or 'key' not in cred or 'algorithm' not in cred:
        print "Bad credentail elements skipping"
        return result

    timestamp = math.floor(time.time())
    if 'timestamp' in options:
        offset = 0
        if 'localtimeOffsetMsec' in options:
            offset = int(options['localtimeOffsetMsec'])
        timestamp = math.floor(options['timestamp'] + offset)

    if 'nonce' not in options:
        options['nonce'] = hcrypto.random_string(6)

    url_parts = parse_normalized_url(url)

    # TODO use None or '' for these optional artifacts?
    if 'hash' not in options:
        options['hash'] = None
    if 'ext' not in options:
        options['ext'] = None
    if 'app' not in options:
        options['app'] = None
    if 'dlg' not in options:
        options['dlg'] = None

    resource = url_parts['path']
    if len(url_parts['query']) > 0:
        resource += '?' + url_parts['query']

    artifacts = {
        'ts': int(timestamp),
        'nonce': options['nonce'],
        'method': method,
        'resource': resource,
        'host': url_parts['hostname'],
        'port': url_parts['port'],
        'hash': options['hash'],
        'ext': options['ext'],
        'app': options['app'],
        'dlg': options['dlg']
    }

    result['artifacts'] = artifacts

    if artifacts['hash'] is None and 'payload' in options:
        if 'contentType' not in options:
            options['contentType'] = 'text/plain'
        artifacts['hash'] = hcrypto.calculate_payload_hash(
               options['payload'], cred['algorithm'], options['contentType'])

    mac = hcrypto.calculate_mac('header', cred, artifacts)

    _header = ''.join([
        'Hawk id="', cred['id'], '"',
        ', ts="', str(artifacts['ts']), '"',
        ', nonce="', artifacts['nonce'], '"',
    ])

    if len(artifacts['hash']) > 0:
        _header += ', hash="' + artifacts['hash'] + '"'

    if artifacts['ext'] is not None and len(artifacts['ext']) > 0:
        util.check_header_attribute(artifacts['ext'])
        h_ext = artifacts['ext'].replace('\\', '\\\\').replace('\n', '\\n')
        _header += ', ext="' + h_ext + '"'

    _header += ', mac="' + mac + '"'

    if artifacts['app'] is not None:
        _header += ', app="' + artifacts['app'] + '"'
        if artifacts['dlg'] is not None:
            _header += ', dlg="' + artifacts['dlg'] + '"'

    result['field'] = _header

    return result

def authenticate(response, credentials, artifacts, options=None):
    """Validate server response.

    :param response: dictionary with server response
    :param artifacts:  object recieved from header().artifacts
    :param options: {
    payload:    optional payload received
    required:   specifies if a Server-Authorization header is required.
    Defaults to 'false'
    }
    """
    if not isinstance(response, dict) or 'headers' not in response:
        return False

    if 'content-type' not in response['headers']:
        print "WARNING response lacked content-type"
        response['headers']['content-type'] = 'text/plain'

    if options is None:
        options = {}

    if 'required' not in options:
        options['required'] = False

    if 'www-authenticate' in response['headers']:
        www_auth_attrs = util.parse_authorization_header(
            response['headers']['www-authenticate'],
            ['ts', 'tsm', 'error'])

        if 'ts' in www_auth_attrs:
            ts_mac = hcrypto.calculate_ts_mac(www_auth_attrs['ts'],
                                                  credentials)
            if not ts_mac == www_auth_attrs['ts']:
                print ts_mac + " didn't match " + www_auth_attrs['ts']
                return False

    if 'server-authorization' not in response['headers'] and \
            False == options['required']:
        return True

    if 'server-authorization' not in response['headers']:
        print "Unable to verify, no server-authorization header"
        return False

    s_auth_attrs = util.parse_authorization_header(
        response['headers']['server-authorization'],
                ['mac', 'ext', 'hash'])
    if 'ext' in s_auth_attrs:
        artifacts['ext'] = s_auth_attrs['ext']
    else:
        artifacts['ext'] = ''

    artifacts['hash'] = s_auth_attrs['hash']

    mac = hcrypto.calculate_mac('response', credentials, artifacts)
    if not mac == s_auth_attrs['mac']:
        print "server mac mismatch " + mac + " != " + s_auth_attrs['mac']
        return False

    if 'payload' in options:
        return True

    if 'hash' not in s_auth_attrs:
        return False

    content_type = response['headers']['content-type']
    p_mac = hcrypto.calculate_payload_hash(options['payload'],
                                           credentials['algorithm'],
                                           content_type)
    if not p_mac == s_auth_attrs['hash']:
        print "p_mac " + p_mac + " != " + s_auth_attrs['hash']

    return p_mac == s_auth_attrs['hash']

def get_bewit(uri, options=None):
    # XXX Where is credentials here?
    """
    Generate a bewit value for a given URI

    Compatibility Note: HAWK exposes this as hawk.uri.getBewit

    credentials is an object with the following keys: 'id, 'key',
    'algorithm'.

    options is an object with the following optional keys: 'ext',
    'localtime_offset_msec'

    uri: 'http://example.com/resource?a=b' or object from Url.parse()
    options: {

    Required

    credentials: {
    id: 'dh37fgj492je',
    key: 'aoijedoaijsdlaksjdl',
    algorithm: 'sha256'              // 'sha1', 'sha256'
    },
    ttl_sec: 60 * 60,                    // TTL in seconds

    Optional

    ext: 'application-specific',         // Application specific data
    // sent via the ext attribute.
    localtime_offset_msec: 400           // Time offset to sync with
    // server time
    }
    """

    if not valid_bewit_args(uri, options):
        return ''

    now = time.time() + int(options['localtime_offset_msec'])

    creds = options['credentials']
    if 'id' not in creds or 'key' not in creds or 'algorithm' not in creds:
        raise BadRequest

    url_parts = parse_normalized_url(uri)

    exp = now + int(options['ttl_sec'])

    resource = url_parts['path']
    if len(url_parts['query']) > 0:
        resource += '?' + url_parts['query']

        artifacts = {
            'ts': int(exp),
            'nonce': '',
            'method': 'GET',
            'resource': resource,
            'host': url_parts['hostname'],
            'port': str(url_parts['port']),
            'ext': options['ext']
            }

        return hcrypto.calculate_bewit(creds, artifacts, exp)


def valid_bewit_args(uri, options):
    """Validates inputs and sets defaults for options."""
    if uri is None or options is None:
        raise BadRequest

    if not isinstance(uri, basestring) or not isinstance(options, dict):
        return False

    if not 'ttl_sec' in options:
        return False

    if 'ext' not in options or options['ext'] is None:
        options['ext'] = ''

    if 'localtime_offset_msec' not in options or \
            options['localtime_offset_msec'] is None:
        options['localtime_offset_msec'] = 0

    return True


def parse_normalized_url(url):
    """Parse url and set port."""
    url_parts = urlparse(url)
    url_dict = {
        'scheme': url_parts.scheme,
        'hostname': url_parts.hostname,
        'port': url_parts.port,
        'path': url_parts.path,
        'query': url_parts.query

    }
    if url_parts.port is None:
        if url_parts.scheme == 'http':
            url_dict['port'] = 80
        elif url_parts.scheme == 'https':
            url_dict['port'] = 443
    return url_dict
