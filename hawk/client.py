import time
from urlparse import urlparse

import hcrypto
import math
import util


class Client(object):

    def header(self, url, method, options=None):
        """
        uri: 'http://example.com/resource?a=b'
        method: HTTP verb ('GET', 'POST', etc)
        options:
        Required Options:
            credentials (id, key, algorithm)

        Optional:
            ext: Application specific data (string)
            timestamp: A pre-calculated timestamp
            nonce: '2334f34f':  A pre-generated nonce
            localtimeOffsetMsec: Time offset to sync with server time (ignored if timestamp provided) (Example 400)
            payload: UTF-8 encoded string for body hash generation (ignored if hash provided) (Example '{"some":"payload"}')
            contentType: Payload content-type (ignored if hash provided) (Example 'application/json')
            hash: Pre-calculated payload hash (Example 'U4MKKSmiVxk37JCCrAVIjV=')
            app: Oz application id ('24s23423f34dx')
            dlg: Oz delegated-by application id - '234sz34tww3sd'
        """
        result = { 'field': '', 'artifacts': {} }
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
            options['nonce'] = hcrypto.randomString(6)
            
        urlParts = urlparse(url)
        if urlParts.port is None:
            if urlParts.scheme == 'http':
                urlParts.port = 80
            elif urlParts.scheme == 'https':
                urlParts.port = 443

        # TODO use None or '' for these optional artifacts?
        if 'hash' not in options:
            options['hash'] = None
        if 'ext' not in options:
            options['ext'] = None
        if 'app' not in options:
            options['app'] = None
        if 'dlg' not in options:
            options['dlg'] = None

        resource = urlParts.path
        if len(urlParts.query) > 0:
            resource += '?' + urlParts.query

        artifacts = {
            'ts': int(timestamp),
            'nonce': options['nonce'],
            'method': method,
            'resource': resource,
            'host': urlParts.hostname,
            'port': urlParts.port,
            'hash': options['hash'],
            'ext': options['ext'],
            'app': options['app'],
            'dlg': options['dlg']
        }

        result['artifacts'] = artifacts

        if artifacts['hash'] is None and 'payload' in options:
            if 'contentType' not in options:
                options['contentType'] = 'text/plain'
            artifacts['hash'] = hcrypto.calculatePayloadHash(options['payload'], cred['algorithm'], options['contentType'])

        mac = hcrypto.calculateMac('header', cred, artifacts)

        header = ''.join([
            'Hawk id="', cred['id'], '"',
            ', ts="', str(artifacts['ts']), '"',
            ', nonce="', artifacts['nonce'], '"',
        ])

        if len(artifacts['hash']) > 0:
            header += ', hash="' + artifacts['hash'] + '"'

        if artifacts['ext'] is not None and len(artifacts['ext']) > 0:
            hExt = util.checkHeaderAttribute(artifacts['ext']).replace('\\', '\\\\').replace('\n', '\\n')
            header += ', ext="' + hExt + '"'

        header += ', mac="' + mac + '"'

        if artifacts['app'] is not None:
            header += ', app="' + artifacts['app'] + '"'
            if artifacts['dlg'] is not None:
                header += ', dlg="' + artifacts['dlg'] + '"'

        result['field'] = header

        return result

    def authenticate(self, response, credentials, artifacts, options=None):
        """ Validate server response.

        response: dictionary with server response
        artifacts:  object recieved from header().artifacts
        options: {
        payload:    optional payload received
        required:   specifies if a Server-Authorization header is required. Defaults to 'false'
        }
        """
        if not isinstance(response, dict) or 'headers' not in response:
            return false

        if 'content-type' not in response['headers']:
            print "WARNING response lacked content-type"
            response['headers']['content-type'] = 'text/plain'

        if options is None:
            options = {}

        if 'required' not in options:
            options['required'] = False        

        if 'www-authenticate' in response['headers']:
            www_auth_attrs = util.parseAuthorizationHeader(res['headers']['www-authenticate'], ['ts', 'tsm', 'error']);

            if 'ts' in www_auth_attrs:
                ts_mac = hcrypto.calculateTsMac(www_auth_attrs['ts'], credentials)
                if not ts_mac == www_auth_attrs['ts']:
                    print ts_mac + " didn't match " + www_auth_attrs['ts']
                    return False

        if 'server-authorization' not in response['headers'] and False == options['required']:
            return True

        if 'server-authorization' not in response['headers']:
            print "Unable to verify, no server-authorization header"
            return False

        s_auth_attrs = util.parseAuthorizationHeader(response['headers']['server-authorization'], ['mac', 'ext', 'hash']);
        if 'ext' in s_auth_attrs:
            artifacts['ext'] = s_auth_attrs['ext']
        else:
            artifacts['ext'] = ''

        artifacts['hash'] = s_auth_attrs['hash']

        mac = hcrypto.calculateMac('response', credentials, artifacts)
        if not mac == s_auth_attrs['mac']:
            print "server-auth mac mismatch " + mac + " != " + s_auth_attrs['mac']
            return False

        if 'payload' in options:
            return True

        if 'hash' not in s_auth_attrs:
            return False

        p_mac = hcrypto.calculatePayloadHash(options['payload'], credentials['algorithm'], response['headers']['content-type'])
        if not p_mac == s_auth_attrs['hash']:
            print "p_mac " + p_mac + " != " + s_auth_attrs['hash']
        return p_mac == s_auth_attrs['hash']
