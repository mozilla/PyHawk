import time

import hcrypto

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
        * nonceFn - A callback to validate if a given nonce is valid
        * timestampSkewSec - Allows for clock skew in seconds. Defaults to 60.
        * localtimeOffsetMsec - Offset for client time. Defaults to 0.
        * options.payload - Required

        """
        now = time.time()
        attributes = self.parseAuthorizationHeader(req['headers']['authorization'])

        artifacts = self.prepareArtifacts(req, attributes)

        mac = self.calculateMac(credentials, artifacts)

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
        # Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
        allowableValues = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        for part in parts:
            attrParts = part.split('=')
            key = attrParts[0].strip()
            if key not in allowableKeys:
                print "Unknown Hawk key_" + attrParts[0] + "_"
                raise BadRequest

            # Chop of quotation marks
            value = attrParts[1][1:-1]
            for c in value:
                if c not in allowableValues:
                    raise BadRequest

            if key in attributes:
                raise BadRequest

            attributes[key] = value

        for rKey in requiredKeys:
            if rKey not in attributes.keys():
                raise BadRequest
        return attributes

    def header(self, credentials, artifacts, options):
      return 'foo'
