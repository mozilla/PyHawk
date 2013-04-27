#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

import unittest
import SimpleHTTPServer
import SocketServer

import hawk

class HawkTestCase(unittest.TestCase):

    def setUp(self):
        """Create simple data set with headers."""
        pass

    def tearDown(self):
        """Teardown."""
        pass

    def test_entry_points(self):

        hawk.Client
        hawk.Server


if __name__ == '__main__':
#    unittest.main()

    from wsgiref.util import setup_testing_defaults
    from wsgiref.simple_server import make_server

    # A relatively simple WSGI application. It's going to print out the
    # environment dictionary after being updated by setup_testing_defaults
    def simple_app(environ, start_response):
        setup_testing_defaults(environ)
        
        # TODO no querysting, don't append
        url = environ['PATH_INFO'] + '?' + environ['QUERY_STRING']

        print environ['HTTP_AUTHORIZATION']
        
        # TODO do host and port better
        req = {
            'method': environ['REQUEST_METHOD'],
            'url': url,
            'host': environ['HTTP_HOST'].split(':')[0],
            'port': environ['HTTP_HOST'].split(':')[1],
            'headers': {
                'authorization': environ['HTTP_AUTHORIZATION']
            }
        }

        server = hawk.Server(req)

        # Look up from DB or elsewhere
        credentials = { 'id': 'dh37fgj492je',
                        'algorithm': 'sha256',
                        'key': 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn' }

        artifacts = server.authenticate(req, credentials, {})

        payload = 'Hello ' + credentials['id'] + ' ' + artifacts['ext']
        status = '200 OK'
        auth = server.header(credentials, artifacts, { 'payload': payload,
                                                            'contentType': 'text/plain'})
        headers = [('Content-type', 'text/plain'), ('Server-Authorization', auth)]

        start_response(status, headers)

        ret = ["%s: %s\n" % (key, value)
               for key, value in environ.iteritems()]
        return ret

    httpd = make_server('', 8002, simple_app)
    print "Serving on port 8002..."
    httpd.serve_forever()
