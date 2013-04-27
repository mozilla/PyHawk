from base64 import b64encode
import hashlib
import hmac


HAWK_VER = 1


class UnknownAlgorithm(Exception):
    pass


def calculateMac(macType, credentials, options):
    normalized = normalizeString(macType, options)
    if 'sha256' == credentials['algorithm']:
        digestmod = hashlib.sha256
    else:
        raise UnknownAlgorithm
    result = hmac.new(credentials['key'], normalized, digestmod)
    mac = b64encode(result.digest())

    return mac

def normalizeString(macType, options):
    normalized = '\n'.join(
        ['hawk.' + str(HAWK_VER) + '.' + macType,
         options['ts'],
         options['nonce'],
         options['method'].upper(),
         options['resource'],
         options['host'].lower(),
         options['port'],
         options['hash']])

    if 'ext' in options:
        nExt = options['ext'].replace('\\', '\\\\').replace('\n', '\\n')
        normalized += nExt + '\n'
    if 'app' in options:
        normalized += options['app'] + '\n'
        if 'dlg' in options:
            normalized += options['dlg']
        normalized += '\n'
    return normalized
