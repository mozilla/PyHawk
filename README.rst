Python Libraries for HAWK
==========================

Hawk_ is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

.. _Hawk: https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices from Python.

Status
------

This is under development, not ready for primetime.
There doesn't appear to be a Python library for HAWK.
Let me know if there is already a robust library.

Development
-----------

The `tests/server` directory has a server.js and a client.js (Node code) which are from HAWK's usage.js.

To test the server, do the following:

1) python sample_server.py
2) cd tests/server
3) node client.js

Output should be 

    authenticated request was:
    200: Hello dh37fgj492je and welcome! (valid)
    Unauthenticated request was
    401: Please authenticate

Note: the port numbers in test_pyhawk.py and client.js must match.

To test the client, do the following:

1) cd tests/server
2) node server.js
3) cd ../..
4) python sample_client.py

Output should be

    200 Hello Steve and welcome!

Plan
----

Iterate on a python library until it can communicate with the test client/server.

1) Write Server API
2) Write client API
3) Improve code style
4) Make API elegant

Status
------

Client and Server APIs are working according to the Node.js implementation. W00t!
