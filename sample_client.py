# -*- coding: utf-8 -*-

"""
Example usage of PyHawk.
You can point this at HAWK's server.js example node server.

Or you can point it at sample_server.py
"""
import requests

import hawk

def main():
    """
    Run the sample_client.py from the CLI
    """
    credentials = {
        'id': 'dh37fgj492je',
        'key': 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        'algorithm': 'sha256'
    }

    url = 'http://127.0.0.1:8002/resource/1?b=1&a=2'
    params = {'b': 1, 'a': 2}

    client = hawk.Client()

    header = client.header(url, 'GET', { 'credentials': credentials,
                                         'ext': 'and welcome!' })

    headers = [('Authorization', header['field'])]
    res = requests.get(url, data=params, headers=headers)

    print str(res.status_code) + ' ' + res.text

    response = {
        'headers': res.headers
    }

    if client.authenticate(response, credentials, header['artifacts'],
                           { 'payload': res.text }):
        print "(valid)"
    else:
        print "(invalid)"

    print "Generating bewit url"
    print url + '&bewit=' + client.get_bewit(url, {'credentials': credentials,
                                                   'ttl_sec': 60 * 1000})

if __name__ == '__main__':
    main()
