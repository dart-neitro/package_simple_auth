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
            SimpleAuthClient(url_server_auth='http://localhost', mock_param=1)

        client = SimpleAuthClient(url_server_auth='http://localhost')

    @mock.patch('simple_auth.core.client.json')
    @mock.patch('simple_auth.core.client.requests')
    def test_get_identifier(self, mock_requests, mock_json):
        """
        SimpleAuthClient.get_identifier

        :return:
        """

        # init
        mock_response = {'result': {'identifier': 'mock_uud4'}, 'error': False,
                         'msg': ''}

        mock_json.loads = mock.MagicMock(return_value=mock_response)

        # action
        client = SimpleAuthClient(url_server_auth='http://localhost')
        identifier = client.get_identifier()

        # post-check
        self.assertEqual(identifier, mock_response)

    def test_get_auth_url(self):
        """
        SimpleAuthClient.

        :return:
        """
        client = SimpleAuthClient(url_server_auth='http://localhost')
        identifier = 'mock_identifier'
        current_url = 'http://fake.url'
        url = client.get_auth_url(identifier=identifier,
                                  current_url=current_url)
        self.assertEqual(
            url,
            'http://localhost?identifier=mock_identifier'
            '&redirect_uri=http%3A%2F%2Ffake.url')

    @mock.patch('simple_auth.core.client.requests')
    def test_get_token(self, mock_requests):
        """
        SimpleAuthClient.get_token

        :return:
        """

        # success
        mock_response = FAKE_RESPONSE_GET_TOKEN

        class FakeResponse:
            text = json.dumps(mock_response)

        mock_requests.post = mock.MagicMock(
            return_value=FakeResponse())

        client = SimpleAuthClient(url_server_auth='http://localhost')

        identifier = 'mock_identifier'

        response = client.get_token(identifier=identifier)

        # post-check
        self.assertEqual(response, mock_response)

    @mock.patch('simple_auth.core.client.time')
    def test_is_valid_token(self, mock_time):
        client = SimpleAuthClient(url_server_auth='http://localhost')

        token = {
            'access_token': 'mock_uud4_0',
            'expired_access_token': 130,
            'expired_update_token': 160,
            'update_token': 'mock_uud4_1'
        }

        mock_time.time = lambda: 100
        self.assertEqual(
            client.is_valid_token(token=token),
            True
        )

        mock_time.time = lambda: 130
        self.assertEqual(
            client.is_valid_token(token=token),
            False
        )

        mock_time.time = lambda: 131
        self.assertEqual(
            client.is_valid_token(token=token),
            False
        )

        self.assertEqual(
            client.is_valid_token(token=None),
            False
        )

        self.assertEqual(
            client.is_valid_token(token={}),
            False
        )

    @mock.patch('simple_auth.core.client.requests')
    def test_is_valid_identifier(self, mock_requests):
        """
        SimpleAuthClient.is_valid_identifier

        :return:
        """

        # mocks
        mock_response = {'error': False, 'msg': '',
                         'result': {'identifier': 'fake_identifier'}}

        class FakeResponse:
            def __init__(self, data):
                self.text = json.dumps(data)

        mock_requests.post = mock.MagicMock(
            return_value=FakeResponse(mock_response))

        # init
        client = SimpleAuthClient(url_server_auth='http://localhost')
        result = client.is_valid_identifier(identifier='fake_identifier')

        # post-check
        self.assertEqual(result, True)

        # Error

        # mocks
        mock_response = {'error': True, 'msg': '', 'result': None}
        mock_requests.post = mock.MagicMock(
            return_value=FakeResponse(mock_response))

        # init
        client = SimpleAuthClient(url_server_auth='http://localhost')
        result = client.is_valid_identifier(identifier='fake_identifier')

        # check
        self.assertEqual(result, False)









if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

