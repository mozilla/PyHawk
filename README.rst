Python Libraries for HAWK
==========================

Hawk_ is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

.. _Hawk: https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices form Python.

Status
------

This is under development, not ready for primetime.
There doesn't appear to be a Python library for HAWK.
Let me know if there is already a robust library.

Development
-----------

The `tests/server` directory has a server.js and a client.js (Node code) which are from HAWK's usage.js.

To test the server, do the following:

1) python test_pyhawk.py
2) cd tests/server
3) node client.js

Output should be 

    authenticated request was:
    200: Hello dh37fgj492je and welcome! (valid)
    Unauthenticated request was
    401: Please authenticate

Note: the port numbers in test_pyhawk.py and client.js must match.

Plan
----

Iterate on a python library until it can communicate with the test client/server.

1) Write Server API
2) Write client API
3) Improve code style
4) Make API elegant

Status
------

Server API is working according to the Node.js implementation. W00t!
