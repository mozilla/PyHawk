Python Libraries for HAWK
==========================

Hawk_ is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

.. _Hawk: https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices from Python.

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
