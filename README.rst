Python Libraries for HAWK
==========================

Hawk_ is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

.. _Hawk: https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices from Python.

Alternatives
------------

PyHawk's goal is to track as closely to the original NodeJS' hawk code,
because hawk is a primarily an authentication scheme documented by
the implementaiton (as opposed to a standard).

If you find this module un-pythonic, also consider:

* mohawk_ Pythonic Hawk library

* hawkauthlib_
 
.. _mohawk: https://github.com/kumar303/mohawk
.. _hawkauthlib: https://github.com/mozilla-services/hawkauthlib

Usage (Client Side)
-------------------

If you had code that consumed a HAWK authenticated webservice,
you could do something like the following

::

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

See `sample_client.py`_ for details.

.. _`sample_client.py`: https://github.com/mozilla/PyHawk/blob/master/sample_client.py

Usage (Server side)
-------------------
If you provide a webservice and want to do authentication via HAWK,
do something like the following:

::


    import hawk

    # A callback function for looking up credentials
    def lookup_hawk_credentials(id):
        # Some collection of secrets
        return db.lookup(id)

    # req is a Request object from your webserver framework
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

See `sample_server.py`_ for details.

.. _`sample_server.py`: https://github.com/mozilla/PyHawk/blob/master/sample_client.py

Logging
-------

PyHawk uses `python logging`_ to emit information about why authorization is
failing and so on. You can configure these logger channels with ``INFO``,
``DEBUG``, etc, to get some helpful output.

**hawk**
    All hawk logging, including everything below.

**hawk.client**
    All hawk client related messages, including header construction.

**hawk.server**
    All hawk server related messages, including authorization.

**hawk.hcrypto**
    All hawk crypto related messages, including bewit handling.

**hawk.util**
    All shared hawk code such as header normalization.


.. _`python logging`: http://docs.python.org/2/library/logging.html


Status
------

This is under development, ready for adventurous users.
There doesn't appear to be a Python library for HAWK.
Let me know if there is already a robust library.

Development
-----------

Optionally use `env` as a virtualenv

::

    virtualenv env
    source env/bin/activate


Locally install source:

::

    python setup.py develop

Unit tests are in `hawk/tests`.

::

    python hawk/tests/test_*.py


Additionally, one can test compatibility:

The `compatibility/nodejs` directory has a server.js and a client.js (Node code) which are from HAWK's usage.js.

To test the server, do the following:

1) python sample_server.py
2) cd compatibility/nodejs/
3) node client.js

Output should be

::

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

::

    Response validates (OK)

Publishing Versions
-------------------

Edit setup.py and bump the version number.

::

    python setup.py sdist upload

You should see your updates at https://pypi.python.org/pypi?%3Aaction=pkg_edit&name=PyHawk
