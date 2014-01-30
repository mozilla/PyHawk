#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

import time
import unittest

import hawk

CREDS = {
    'foobar-1234': {
        'id': 'foobar-1234',
        'key': 'some long random string',
        'algorithm': 'sha256'
    }
}

url = 'http://example.com/bazz?buzz=fizz&mode=ala'
params = {'buzz': 'fizz', 'mode': 'ala'}

class HawkTestCase(unittest.TestCase):

    def setUp(self):
        """Create simple data set with headers."""
        pass

    def tearDown(self):
        """Teardown."""
        pass

    def test_entry_points(self):

        hawk.client.header
        hawk.client.authenticate
        hawk.Server

    def test_client_api(self):
        header = hawk.client.header(url, 'GET', { 'credentials': CREDS['foobar-1234'],
                                                  'ext': 'and welcome!',
                                                  'nonce': 'lwfuar',
                                                  'timestamp': 1367927332})

        assert header['field'] == 'Hawk id="foobar-1234", ts="1367927332", nonce="lwfuar", ext="and welcome!", mac="ZZI/y3M0gV7PWCRX1VddptkWhunWxrpQikXAsLYzblU="'
        assert header['artifacts'] == {
            'nonce': 'lwfuar', 'ext': 'and welcome!', 'host': 'example.com',
            'dlg': None, 'resource': '/bazz?buzz=fizz&mode=ala', 'hash': '',
            'app': None, 'port': 80, 'ts': 1367927332, 'method': 'GET'
        }

        resp = {
            'headers': {
                'date': 'Tue, 07 May 2013 11:54:57 GMT',
                'content-type': 'text/plain',
                'server-authorization':
'Hawk mac="okjCR+o26FMhInYoJ1QO30Fu9cl3wGIWmwqydQXND+w=", hash="y+iZjG+hr2is3SmZLFOe551/LGS3PQPMY9ZWjToaNjg=", ext="and welcome!"',
               'server': 'WSGIServer/0.1 Python/2.7.2+'
           }
        }

        assert hawk.client.authenticate(resp, CREDS['foobar-1234'], header['artifacts'], {
                'payload': 'Hello and welcome!'
                })

    def test_bad_content_auth(self):
        header = hawk.client.header(url, 'GET', { 'credentials': CREDS['foobar-1234'],
                                                  'ext': '',
                                                  'nonce': 'lwfuar',
                                                  'timestamp': 1367927332})
        req = {
            'method': 'GET',
            'url': url,
            'host': 'example.com',
            'port': 80,
            'headers': {
                'authorization': header['field']
                }
            }

        payload = 'this is some content'
        server = hawk.Server(req, lambda cid: CREDS[cid])
        request_body = ''
        artifacts = server.authenticate({'payload': request_body})
        header = server.header(artifacts,
                               { 'payload': payload,
                                 'contentType': 'text/plain' })
        resp = {
            'headers': {
                'date': 'Tue, 07 May 2013 11:54:57 GMT',
                'content-type': 'text/plain',
                'server-authorization': header,
           }
        }

        assert hawk.client.authenticate(resp, CREDS['foobar-1234'], header['artifacts'], {
                'payload': payload
                })
        assert not hawk.client.authenticate(resp, CREDS['foobar-1234'], header['artifacts'], {
                'payload': payload + 'TAMPERED_WITH'
                })

    def test_bewit(self):
        bewit = hawk.client.get_bewit(url, {'credentials': CREDS['foobar-1234'],
                                            'ttl_sec': 60 * 1000})
        req = {
            'method': 'GET',
            'url': '/bazz?buzz=fizz&mode=ala&bewit=' + bewit,
            'host': 'example.com',
            'port': 80,
            'headers': {}
            }

        server = hawk.Server(req, lambda cid: CREDS[cid])
        assert server.authenticate_bewit({})

    def test_server_api(self):
        url = '/bazz?buzz=fizz&mode=ala'

        req = {
            'method': 'GET',
            'url': url,
            'host': 'example.com',
            'port': 80,
            'headers': {
                'authorization': 'Hawk id="foobar-1234", ts="1367927332", nonce="lwfuar", ext="and welcome!", mac="ZZI/y3M0gV7PWCRX1VddptkWhunWxrpQikXAsLYzblU="'
                }
            }
        server = hawk.Server(req, lambda cid: CREDS[cid])
        artifacts = server.authenticate({'timestampSkewSec': self._skewed_now()})

        assert artifacts == {
            'nonce': 'lwfuar', 'ext': 'and welcome!', 'dlg': '',
            'resource': '/bazz?buzz=fizz&mode=ala', 'app': '',
            'ts': '1367927332', 'port': 80,
            'mac': 'ZZI/y3M0gV7PWCRX1VddptkWhunWxrpQikXAsLYzblU=',
            'host': 'example.com', 'id': 'foobar-1234', 'hash': '',
            'method': 'GET'
        }

        payload = 'Hello and welcome!'
        header = server.header(artifacts,
                               { 'payload': payload,
                                 'contentType': 'text/plain' })

        assert header == 'Hawk mac="okjCR+o26FMhInYoJ1QO30Fu9cl3wGIWmwqydQXND+w=", hash="y+iZjG+hr2is3SmZLFOe551/LGS3PQPMY9ZWjToaNjg=", ext="and welcome!"'

    def test_server_api_with_abs_url(self):
        url = 'http://someserver/bazz?buzz=fizz&mode=ala'

        req = {
            'method': 'GET',
            'url': url,
            'host': 'example.com',
            'port': 80,
            'headers': {
                'authorization': 'Hawk id="foobar-1234", ts="1367927332", nonce="lwfuar", ext="and welcome!", mac="ZZI/y3M0gV7PWCRX1VddptkWhunWxrpQikXAsLYzblU="'
                }
            }
        server = hawk.Server(req, lambda cid: CREDS[cid])
        artifacts = server.authenticate({'timestampSkewSec': self._skewed_now()})

        self.assertEqual(artifacts['resource'],
                         '/bazz?buzz=fizz&mode=ala')

        payload = 'Hello and welcome!'
        header = server.header(artifacts,
                               { 'payload': payload,
                                 'contentType': 'text/plain' })

        assert header == 'Hawk mac="okjCR+o26FMhInYoJ1QO30Fu9cl3wGIWmwqydQXND+w=", hash="y+iZjG+hr2is3SmZLFOe551/LGS3PQPMY9ZWjToaNjg=", ext="and welcome!"'

    def test_parsing_empty_attrs(self):
        url = '/bazz?buzz=fizz&mode=ala'

        req = {
            'method': 'GET',
            'url': url,
            'host': 'example.com',
            'port': 80,
            'headers': {
                'authorization': 'Hawk id="foobar-1234", app="", ts="1367927332", nonce="lwfuar", ext="and welcome!", mac="ZZI/y3M0gV7PWCRX1VddptkWhunWxrpQikXAsLYzblU="'
                }
            }
        server = hawk.Server(req, lambda cid: CREDS[cid])
        artifacts = server.authenticate({'timestampSkewSec': self._skewed_now()})

    def _skewed_now(self):
        # Add 100 plus the difference between now and our hardcoded timestamp
        return time.time() - 1367927332 + 100

if __name__ == '__main__':
    unittest.main()
