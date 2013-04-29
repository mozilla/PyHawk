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

    def test_client_server(self):
        """
        TODO: Take logic from sample_client.py and sample_server.py
        and put them into a test here.
        """
        pass        


if __name__ == '__main__':
    unittest.main()
