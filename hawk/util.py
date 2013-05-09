# -*- coding: utf-8 -*-

"""
Various low level helper functions for HAWK authentication.
"""


class HawkException(Exception):
    """Base class for HAWK Exceptions."""
    pass


class BadRequest(HawkException):
    """ Exception raised for bad inputs on request. """
    pass


class ParseError(HawkException):
    """ Exception raised for bad values. """
    pass

# Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and
# space, a-z, A-Z, 0-9
ALLOWABLE_CHARS = ("!#$%&'()*+,-./:;<=>?@[]^_`{|}~ abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def check_header_attribute(value):
    """ Validates header values contain allowable characters. """
    for char in value:
        if char not in ALLOWABLE_CHARS:
            raise BadRequest
    return value


def parse_authorization_header(auth_header, allowable_keys=None):
    """
    Example Authorization header:

        'Hawk id="dh37fgj492je", ts="1367076201", nonce="NPHgnG", ext="and
        welcome!", mac="CeWHy4d9kbLGhDlkyw2Nh3PJ7SDOdZDa267KH4ZaNMY="'
    """

    if auth_header is None:
        raise BadRequest

    if allowable_keys is None:
        allowable_keys = ['id', 'ts', 'nonce', 'hash',
                          'ext', 'mac', 'app', 'dlg']

    attributes = {}
    parts = auth_header.split(',')
    auth_scheme_parts = parts[0].split(' ')
    if not 'hawk' == auth_scheme_parts[0].lower():
        print "Unknown scheme: " + auth_scheme_parts[0].lower()
        raise BadRequest

    # Replace 'Hawk key: value' with 'key: value'
    # which matches the rest of parts
    parts[0] = auth_scheme_parts[1]

    for part in parts:
        attr_parts = part.split('=')
        key = attr_parts[0].strip()
        if key not in allowable_keys:
            print "Unknown Hawk key_" + attr_parts[0] + "_"
            raise BadRequest

        # TODO we don't do a good job of parsing, '=' should work for more =.
        # hash or mac value includes '=' character... fixup
        if len(attr_parts) == 3:
            attr_parts[1] += '=' + attr_parts[2]

        # Chop of quotation marks
        value = attr_parts[1]

        if attr_parts[1].find('"') == 0:
            value = attr_parts[1][1:]

        if value.find('"') > 0:
            value = value[0:-1]

        check_header_attribute(value)

        if key in attributes:
            raise BadRequest

        attributes[key] = value

    return attributes
