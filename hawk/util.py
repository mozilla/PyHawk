
class BadRequest(Exception):
    pass


class ParseError(Exception):
    pass

# Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
allowableValues = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def checkHeaderAttribute(value):
    for c in value:
        if c not in allowableValues:
            raise BadRequest
    return value

def parseAuthorizationHeader(authHeader, allowableKeys=None):
    """
    Example Authorization header:
    'Hawk id="dh37fgj492je", ts="1367076201", nonce="NPHgnG", ext="and welcome!", mac="CeWHy4d9kbLGhDlkyw2Nh3PJ7SDOdZDa267KH4ZaNMY="'
    """

    if authHeader is None:
        raise BadRequest

    if allowableKeys is None:
        allowableKeys = ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg']

    attributes = {}
    parts = authHeader.split(',')
    authSchemeParts = parts[0].split(' ')
    if not 'hawk' == authSchemeParts[0].lower():
        print "Unknown scheme: " + authSchemeParts[0].lower()
        raise BadRequest

    # Replace 'Hawk key: value' with 'key: value' which matches the rest of parts
    parts[0] = authSchemeParts[1]
        
    for part in parts:
        attrParts = part.split('=')
        key = attrParts[0].strip()
        if key not in allowableKeys:
            print "Unknown Hawk key_" + attrParts[0] + "_"
            raise BadRequest

        # TODO we don't do a good job of parsing, '=' should work for more =.
        # hash or mac value includes '=' character... fixup
        if len(attrParts) == 3:
            attrParts[1] += '=' + attrParts[2]

        # Chop of quotation marks
        value = attrParts[1]

        if attrParts[1].find('"') == 0:
            value = attrParts[1][1:]

        if value.find('"') > 0:
            value = value[0:-1]
            
        checkHeaderAttribute(value)

        if key in attributes:
            raise BadRequest

        attributes[key] = value

    return attributes
