# -*- coding: utf-8 -*-

"""
Example usage of PyHawk.
You can run this server and point HAWK's client.js at it.

Or you can point sample_client.py at it.
"""
from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server

import hawk
from hawk.util import HawkException


def main():
    """
    Run the sample_server.py from the CLI
    """

    def simple_app(environ, start_response):
        """
        Usage: python test_server.py

        Then in tests/server/ run
        node client.js

        This will make an unauthorized and then a HAWK authorized
        request. The authed one should say (valid).
        """
        setup_testing_defaults(environ)

        # TODO no querysting, don't append
        url = environ['PATH_INFO'] + '?' + environ['QUERY_STRING']

        http_auth_header = ''
        if 'HTTP_AUTHORIZATION' in environ:
            http_auth_header = environ['HTTP_AUTHORIZATION']

        # TODO do host and port better
        req = {
            'method': environ['REQUEST_METHOD'],
            'url': url,
            'host': environ['HTTP_HOST'].split(':')[0],
            'port': environ['HTTP_HOST'].split(':')[1],
            'headers': {
                'authorization': http_auth_header
            }
        }

        # Look up from DB or elsewhere
        credentials = { 
            'dh37fgj492je': {
                'id': 'dh37fgj492je',
                'algorithm': 'sha256',
                'key': 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
                }
        }
        
        server = hawk.Server(req, lambda cid: credentials[cid])

        if url.find('bewit=') == -1:
            print "HAWK based authentication"
            return hawk_authentication(start_response, server, req)
        else:
            print "Bewit based authentication"
            return hawk_bewit_authentication(start_response, server, req)

    httpd = make_server('', 8002, simple_app)
    print "Serving on port 8002..."
    httpd.serve_forever()

def hawk_authentication(start_response, server, req):
    """Authenticate the request using HAWK."""
    try:
        artifacts = server.authenticate(req, {})
        payload = 'Hello ' + artifacts['ext']
        status = '200 OK'
        auth = server.header(artifacts,
                             { 'payload': payload,
                               'contentType': 'text/plain' })

        headers = [('Content-Type', 'text/plain'),
                   ('Server-Authorization', auth)]

        start_response(status, headers)

        return payload
    except (HawkException):
        start_response('401 Unauthorized', [])
        return 'Please authenticate'

def hawk_bewit_authentication(start_response, server, req):
    """Authenticate the request using a Bewit from HAWK."""
    options = {}
    try:
        if server.authenticate_bewit(req, options):

            payload = 'Hello '
            status = '200 OK'

            headers = [('Content-Type', 'text/plain')]

            start_response(status, headers)
            return payload
        else:
            print "Bad Bewit, sending 401"
            start_response('401 Unauthorized', [])
            return 'Please authenticate'
    except (HawkException):
        print "Exception, sending 401"
        start_response('401 Unauthorized', [])
        return 'Please authenticate'

if __name__ == '__main__':
    main()
