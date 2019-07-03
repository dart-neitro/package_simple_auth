"""
Test simple_auth.SimpleAuthServer

"""
import json

import unittest
from unittest import mock


from simple_auth.core.client import SimpleAuthClient


USER_DATA = {
            'timestamp': 1,
            'user': {
                'name': 'User name', 'level': 5, 'access': [1, 2, 3]}}

FAKE_RESPONSE_GET_TOKEN = {
    'error': False,
    'msg': '',
    'result': {
        'timestamp': 1,
        'token': {
            'access_token': 'mock_uud4_0',
            'expired_access_token': 130,
            'expired_update_token': 160,
            'update_token': 'mock_uud4_1'
        },
        'user': USER_DATA['user']
    }}


class MyTestCase(unittest.TestCase):

    def test_init(self):
        """
        SimpleAuthClient.__init__

        :return:
        """

        with self.assertRaises(TypeError):
            SimpleAuthClient()

        with self.assertRaises(TypeError):
            SimpleAuthClient(url_server_auth='http://localhost', fake_param=1)

        client = SimpleAuthClient(url_server_auth='http://localhost')

    @mock.patch('simple_auth.core.client.json')
    @mock.patch('simple_auth.core.client.requests')
    def test_get_identifier(self, mock_requests, mock_json):
        """
        SimpleAuthClient.get_identifier

        :return:
        """

        # init
        fake_response = {'result': {'identifier': 'mock_uud4'}, 'error': False,
                         'msg': ''}

        mock_json.loads = mock.MagicMock(return_value=fake_response)

        # action
        client = SimpleAuthClient(url_server_auth='http://localhost')
        identifier = client.get_identifier()

        # post-check
        self.assertEqual(identifier, fake_response)

    def test_get_auth_url(self):
        """
        SimpleAuthClient.

        :return:
        """
        client = SimpleAuthClient(url_server_auth='http://localhost')
        identifier = 'fake_identifier'
        current_url = 'http://fake.url'
        url = client.get_auth_url(identifier=identifier,
                                  current_url=current_url)
        self.assertEqual(
            url,
            'http://localhost?identifier=fake_identifier'
            '&redirect_uri=http%3A%2F%2Ffake.url')

    @mock.patch('simple_auth.core.client.requests')
    def test_get_token(self, fake_requests):
        """
        SimpleAuthClient.get_token

        :return:
        """

        # success
        fake_response = FAKE_RESPONSE_GET_TOKEN
        
        class FakeResponse:
            text = json.dumps(fake_response)

        fake_requests.post = mock.MagicMock(
            return_value=FakeResponse())

        client = SimpleAuthClient(url_server_auth='http://localhost')

        identifier = 'fake_identifier'

        response = client.get_token(identifier=identifier)

        # post-check
        self.assertEqual(response, fake_response)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

