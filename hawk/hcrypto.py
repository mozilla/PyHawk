# -*- coding: utf-8 -*-

"""
Crypto functions for HAWK authentication
"""

from base64 import b64encode
import hashlib
import hmac
import random
import string


HAWK_VER = 1


class UnknownAlgorithm(Exception):
    """ Exception raised for bad configuration of algorithm. """
    pass


def calculate_mac(mac_type, credentials, options):
    """ Calculates a message authentication code (MAC). """
    normalized = normalize_string(mac_type, options)
    digestmod = module_for_algorithm(credentials['algorithm'])
    result = hmac.new(credentials['key'], normalized, digestmod)
    mac = b64encode(result.digest())
    return mac

def module_for_algorithm(algorithm):
    """ Returns a hashlib algorithm based on given string. """
    if 'sha256' == algorithm:
        return hashlib.sha256
    else:
        raise UnknownAlgorithm

def normalize_string(mac_type, options):
    """ Serializes mac_type and options into a HAWK string. """
    # TODO this smells
    if 'hash' not in options or options['hash'] is None:
        options['hash'] = ''

    normalized = '\n'.join(
        ['hawk.' + str(HAWK_VER) + '.' + mac_type,
         str(options['ts']),
         options['nonce'],
         options['method'].upper(),
         options['resource'],
         options['host'].lower(),
         str(options['port']),
         options['hash']])

    normalized += '\n'

    if 'ext' in options and len(options['ext']) > 0:
        n_ext = options['ext'].replace('\\', '\\\\').replace('\n', '\\n')
        normalized += n_ext

    normalized += '\n'

    if 'app' in options and options['app'] is not None and len(options['app']) > 0:
        normalized += options['app'] + '\n'
        if 'dlg' in options and len(options['dlg']) > 0:
            normalized += options['dlg'] + '\n'

    return normalized

def calculate_payload_hash(payload, algorithm, content_type):
    """ Calculates a hash for a given payload. """
    p_hash = hashlib.new(algorithm)
    p_hash.update('hawk.' + str(HAWK_VER) + '.payload\n')
    p_hash.update(parse_content_type(content_type) + '\n')
    if payload:
        p_hash.update(payload)
    else:
        p_hash.update('')
    p_hash.update('\n')
    return b64encode(p_hash.digest())

def parse_content_type(content_type):
    """ Cleans up content_type. """
    if content_type:
        return content_type.split(';')[0].strip().lower()
    else:
        return ''

def calculate_ts_mac(ts, credentials):
    """ Calculates a timestamp message authentication code for HAWK. """
    data = 'hawk.' + str(HAWK_VER) + '.ts\n' + ts + '\n'
    digestmod = module_for_algorithm(credentials['algorithm'])
    result = hmac.new(credentials['key'], data, digestmod)
    return b64encode(result.digest())

def random_string(length):
    """ Generates a random string for a given length."""
    return ''.join(random.choice(string.lowercase) for i in range(length))
