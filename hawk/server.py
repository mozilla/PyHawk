import copy
import math
import time

import hcrypto
import util

class BadMac(Exception):
    pass

class BadRequest(Exception):
    pass

class MissingCredentials(Exception):
    pass

class Server(object):

    def __init__(self, req):
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

        self.checkOptions(options)

        attributes = util.parseAuthorizationHeader(req['headers']['authorization'])

        artifacts = self.prepareArtifacts(req, attributes)

        mac = self.calculateMac(credentials, artifacts)

        # TODO prevent timing attach
        if not mac == attributes['mac']:
            print "Calculated [" + mac + "] Attributes included [" + attributes['mac'] + "]"
            raise BadMac

        if 'payload' in options:
            if 'hash' not in attributes:
                print "Missing required payload hash"
                raise BadRequest
            pHash = hcrypto.calculatePayloadHash(options['payload'], credentials['algorithm'], req['contentType'])
            if not pHash == attributes['hash']:
                print "Bad payload hash"
                raise BadRequest

        if 'checkNonceFn' in options:
            if not options.checkNonceFn(attributes.nonce, attributes.ts):
                raise BadRequest

        if math.fabs(int(attributes['ts']) - now) > int(options['timestampSkewSec']):
            print "Expired request"
            raise BadRequest

        return artifacts

    def calculateMac(self, credentials, artifacts):
        if 'key' not in credentials or 'algorithm' not in credentials:
            raise MissingCredentials
        
        mac = hcrypto.calculateMac('header', credentials, artifacts)

        return mac

    def prepareArtifacts(self, req, attributes):
        artifacts = {
            'method': req['method'],
            'host': req['host'],
            'port': req['port'],
            'resource': req['url']
        }
        artifactKeys = ['ts', 'nonce', 'hash', 'ext', 'app', 'dlg', 'mac', 'id']
        attrs = attributes.keys()
        for key in artifactKeys:
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

        hArtifacts = copy.copy(artifacts)
        del hArtifacts['mac']

        if 'hash' in options:
            hArtifacts['hash'] = options['hash']

        if 'ext' in options:
            hArtifacts['ext'] = options['ext']

        if not credentials or 'key' not in credentials or 'algorithm' not in credentials:
            return ''

        if 'hash' not in hArtifacts or hArtifacts['hash'] is None or len(hArtifacts['hash']) == 0:
            if 'payload' in options:
                hArtifacts['hash'] = hcrypto.calculatePayloadHash(options['payload'], credentials['algorithm'], options['contentType'])

        mac = hcrypto.calculateMac('response', credentials, hArtifacts)

        header = 'Hawk mac="' + mac + '"'
        if 'hash' in hArtifacts:
            header += ', hash="' + hArtifacts['hash'] + '"'

        if 'ext' in hArtifacts and hArtifacts['ext'] is not None and len(hArtifacts['ext']) > 0:
            hExt = util.checkHeaderAttribute(hArtifacts['ext']).replace('\\', '\\\\').replace('\n', '\\n')
            header += ', ext="' + hExt + '"'

        return header

    def checkOptions(self, options):
        if 'timestampSkewSec' not in options:
            options['timestampSkewSec'] = 60

        if 'localtimeOffsetMsec' not in options:
            options['localtimeOffsetMsec'] = 0
