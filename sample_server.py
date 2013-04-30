from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server

import hawk

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

    httpAuthHeader = ''
    if 'HTTP_AUTHORIZATION' in environ:
        print environ['HTTP_AUTHORIZATION']
        httpAuthHeader = environ['HTTP_AUTHORIZATION']
        
    # TODO do host and port better
    req = {
        'method': environ['REQUEST_METHOD'],
        'url': url,
        'host': environ['HTTP_HOST'].split(':')[0],
        'port': environ['HTTP_HOST'].split(':')[1],
        'headers': {
            'authorization': httpAuthHeader
        }
    }

    server = hawk.Server(req)

    # Look up from DB or elsewhere
    credentials = { 'id': 'dh37fgj492je',
                    'algorithm': 'sha256',
                    'key': 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
    }

    try:
        artifacts = server.authenticate(req, credentials, {})
        payload = 'Hello ' + credentials['id'] + ' ' + artifacts['ext']
        status = '200 OK'
        auth = server.header(credentials, artifacts, { 'payload': payload,
                                                            'contentType': 'text/plain'})

        print "SERVER HEADER AUTH=" + auth

        headers = [('Content-Type', 'text/plain'), ('Server-Authorization', auth)]

        print headers

        start_response(status, headers)

        return payload
    except (hawk.BadRequest, hawk.BadMac, hawk.util.BadRequest):
        start_response('401 Unauthorized', [])
        return 'Please authenticate'

httpd = make_server('', 8002, simple_app)
print "Serving on port 8002..."
httpd.serve_forever()
