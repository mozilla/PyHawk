
# Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
allowableValues = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def checkHeaderAttribute(value):
    for c in value:
        if c not in allowableValues:
            raise BadRequest
    return value
