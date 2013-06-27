Python Libraries for HAWK
==========================

Hawk_ is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

.. _Hawk: https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices from Python.

Usage (Client Side)
-------------------
If you had code that consumed a HAWK authenticated webservice,
you could do something like the following:
```
import hawk
import requests

# Hawk is secured with a shared secret
credentials = db.lookup_secrets(some_id)

# Prepare your request headers
header = hawk.client.header(url, 'GET', {
    'credentials': credentials,
    'ext': 'Yo Yo'})

# Which goes into Authorization field of HTTP headers
headers = [('Authorization', header['field'])]
res = requests.get(url, data=params, headers=headers)

response = { 'headers': res.headers }

# We can verify we're talking to our trusted server
verified = hawk.client.authenticate(response, credentials,
                                    header['artifacts'],
                                    {'payload': res.text})
if verified:
    print res.text
else:
    print "Something fishy going on."
```

See `sample_client.py`_ for details.

.. _`sample_client.py`: https://github.com/mozilla/PyHawk/blob/master/sample_client.py

Usage (Server side)
-------------------
If you provide a webservice and want to do authentication via HAWK,
do something like the following:
```
import hawk

# req is a Request object from your webserver framework


# A callback function for looking up credentials
def lookup_hawk_credentials(id):
    # Some collection of secrets
    return db.lookup(id)

if 'Hawk ' in req.headers['Authorization']:
    return check_auth_via_hawk(req)
else:
    return failure(req, res)

def check_auth_via_hawk(req):
    server = hawk.Server(req, lookup_hawk_credentials)

    # This will raise a hawk.util.HawkException if it fails
    artifacts = server.authenticate()

    # Sign our response, so clients can trust us
    auth = server.header(artifacts,
                             { 'payload': payload,
                               'contentType': 'text/plain' })

    headers = [('Content-Type', 'text/plain'),
                   ('Server-Authorization', auth)]

    start_response(status, headers)

    return payload
```

See `sample_server.py`_ for details.

.. _`sample_server.py`: https://github.com/mozilla/PyHawk/blob/master/sample_client.py


Status
------

This is under development, ready for adventurous users.
There doesn't appear to be a Python library for HAWK.
Let me know if there is already a robust library.

Development
-----------

Optionally use `env` as a virtualenv

```
virtualenv env
source env/bin/activate
```

Locally install source:
```
python setup.py develop
```

Unit tests are in `hawk/tests`. Additionally, one can test compatibility:

The `compatibility/nodejs` directory has a server.js and a client.js (Node code) which are from HAWK's usage.js.

To test the server, do the following:

1) python sample_server.py
2) cd compatibility/nodejs/
3) node client.js

Output should be 

    Authenticated Request is 200 (OK)
    Response validates (OK)
    Unauthenticated request should 401 - (OK)

Note: the port numbers in test_pyhawk.py and client.js must match.

To test the client, do the following:

1) cd compatibility/nodejs/
2) node server.js
3) cd ../..
4) python sample_client.py

Output should be

    Response validates (OK)

Plan
----

Iterate on a python library until it can communicate with the test client/server.

1) ✓ Write Server API
2) ✓ Write client API
3) ✓ Switch to callback style
4) Improve code style
5) Make API elegant
6) Put a release together

A source for inspiration on 4 and 5 should be macauthlib_, from the Mozilla Services team, which is basically PyHawk, before Hawk existed. (Thanks rfk!)

.. _macauthlib: https://github.com/mozilla-services/macauthlib

Status
------

Client and Server APIs are working according to the Node.js implementation. W00t!

Please file issues for code style, bugs, etc.
