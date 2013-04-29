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

        attributes = self.parseAuthorizationHeader(req['headers']['authorization'])

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
            

    def parseAuthorizationHeader(self, authHeader):
        """
        Example Authorization header:
        'Hawk id="dh37fgj492je", ts="1367076201", nonce="NPHgnG", ext="and welcome!", mac="CeWHy4d9kbLGhDlkyw2Nh3PJ7SDOdZDa267KH4ZaNMY="'
        """
        if not authHeader:
            raise BadRequest
        attributes = {}
        parts = authHeader.split(',')
        authSchemeParts = parts[0].split(' ')
        if not 'hawk' == authSchemeParts[0].lower():
            print "Unknown scheme: " + authSchemeParts[0].lower()
            raise BadRequest

        # Replace 'Hawk key: value' with 'key: value' which matches the rest of parts
        parts[0] = authSchemeParts[1]

        allowableKeys = ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg']
        requiredKeys = ['id', 'ts', 'nonce', 'mac']

        for part in parts:
            attrParts = part.split('=')
            key = attrParts[0].strip()
            if key not in allowableKeys:
                print "Unknown Hawk key_" + attrParts[0] + "_"
                raise BadRequest

            # mac value includes '=' character... fixup
            if 'mac' == key and len(attrParts) == 3:
                attrParts[1] += '=' + attrParts[2]

            # Chop of quotation marks
            value = attrParts[1]

            if attrParts[1].find('"') == 0:
                value = attrParts[1][1:]

            if value.find('"') > 0:
                value = value[0:-1]
            
            util.checkHeaderAttribute(value)

            if key in attributes:
                raise BadRequest

            attributes[key] = value

        for rKey in requiredKeys:
            if rKey not in attributes.keys():
                raise BadRequest
        return attributes

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
