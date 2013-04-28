from base64 import b64encode
import hashlib
import hmac


HAWK_VER = 1


class UnknownAlgorithm(Exception):
    pass


def calculateMac(macType, credentials, options):
    normalized = normalizeString(macType, options)
    digestmod = moduleForAlgorithm(credentials['algorithm'])
    result = hmac.new(credentials['key'], normalized, digestmod)
    mac = b64encode(result.digest())
    return mac

def moduleForAlgorithm(algorithm):
    if 'sha256' == algorithm:
        return hashlib.sha256
    else:
        raise UnknownAlgorithm

def normalizeString(macType, options):
    # TODO this smells
    if 'hash' not in options or options['hash'] is None:
        options['hash'] = ''

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
        nExt = options['ext'].replace('\\', '\\\\').replace('\n', '\\n')
        normalized += '\n' + nExt
    if 'app' in options and len(options['app']) > 0:
        normalized += '\n' + options['app']
        if 'dlg' in options and len(options['dlg']) > 0:
            normalized += '\n' + options['dlg']

    normalized += '\n'

    return normalized

def calculatePayloadHash(payload, algorithm, contentType):
    pHash = hashlib.new(algorithm)
    pHash.update('hawk.' + str(HAWK_VER) + '.payload\n');
    pHash.update(parseContentType(contentType) + '\n');
    if payload:
        pHash.update(payload)
    else:
        pHash.update('')
    pHash.update('\n')
    return b64encode(pHash.digest())

def parseContentType(contentType):
    if contentType:
        return contentType.split(';')[0].strip().lower()
    else:
        return '';
