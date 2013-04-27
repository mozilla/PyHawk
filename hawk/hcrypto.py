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
    print mac
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

    if 'ext' in options and len(options['ext']) > 0:
        print "doing ext"
        nExt = options['ext'].replace('\\', '\\\\').replace('\n', '\\n')
        normalized += '\n' + nExt
    if 'app' in options and len(options['app']) > 0:
        print "doing app"
        normalized += '\n' + options['app']
        if 'dlg' in options and len(options['dlg']) > 0:
            print "doing dlg"
            normalized += '\n' + options['dlg']

    normalized += '\n'

    print "_" + normalized + "_"
    return normalized
