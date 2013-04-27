#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

import unittest

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
    unittest.main()

