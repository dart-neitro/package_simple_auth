"""
Test simple_auth.SimpleAuthServer

"""
import json
import copy

import unittest
from unittest import mock


from simple_auth.core import flask_client
from simple_auth.core.client import SimpleAuthClient


EXAMPLE_USER = {'user_id': '123', 'level': [1, 2, 3]}
EXAMPLE_TOKEN = {
            'access_token': 'mock_uud4_0',
            'expired_access_token': 130,
            'expired_update_token': 160,
            'update_token': 'mock_uud4_1'
        }

class MyDefaultNone:
    @staticmethod
    def is_default_none():
        return True


class FakeG:
    """
    mock for flask.g
    """

    default_none = MyDefaultNone()

    def __init__(self, **kwargs):
        self.__store = copy.deepcopy(kwargs)
        for key in kwargs:
            setattr(self, key, kwargs[key])

    def __setattr__(self, key, value):
        if key != '_FakeG__store':
            self.__store[key] = value
        return super().__setattr__(key, value)

    def __delattr__(self, key):
        if key in self.__store:
            del self.__store[key]
        return super().__delattr__(key)

    def pop(self, key, default=default_none):
        if default is self.default_none:
            value = self.__store.pop(key)

            return value
        return self.__store.pop(key, default)

    def get(self, key, default=None):
        return self.__store.get(key, default)

    def get_store(self):
        return copy.deepcopy(self.__store)


class MyTestCase(unittest.TestCase):

    @mock.patch("simple_auth.core.flask_client.SimpleAuthClient")
    @mock.patch("simple_auth.core.flask_client.flask")
    def test_check_auth_identifier_1(self, mock_flask, mock_SimpleAuthClient):
        """
        Test function: flask_client.check_auth_identifier
        Only actual identifier

        :return:
        """
        mock_is_valid_identifier = mock.MagicMock(
            return_value=True)
        mock_get_auth_url = mock.MagicMock(
            return_value='mock_get_auth_url')
        mock_SimpleAuthClient.return_value = mock.MagicMock(
            is_valid_identifier=mock_is_valid_identifier,
            get_auth_url=mock_get_auth_url
        )

        mock_flask.g = FakeG()

        with self.assertRaises(KeyError):
            flask_client.check_auth_identifier()

        mock_flask.g.auth_identifier = 'fake_identifier'
        flask_client.check_auth_identifier()

        self.assertEqual(
            mock_flask.g.get_store(),
            {'auth_identifier': 'fake_identifier',
             'auth_redirect': 'mock_get_auth_url'}
        )

    @mock.patch("simple_auth.core.flask_client.SimpleAuthClient")
    @mock.patch("simple_auth.core.flask_client.flask")
    def test_check_auth_identifier_2(self, mock_flask, mock_SimpleAuthClient):
        """
        Test function: flask_client.check_auth_identifier
        Only non-actual identifier

        :return:
        """

        mock_is_valid_identifier = mock.MagicMock(
            return_value=False)
        mock_get_auth_url = mock.MagicMock(
            return_value='mock_get_auth_url')
        mock_SimpleAuthClient.return_value = mock.MagicMock(
            is_valid_identifier=mock_is_valid_identifier,
            get_auth_url=mock_get_auth_url
        )

        mock_flask.g = FakeG()

        with self.assertRaises(KeyError):
            flask_client.check_auth_identifier()

        mock_flask.g.auth_identifier = 'fake_identifier'
        flask_client.check_auth_identifier()

        self.assertEqual(
            mock_flask.g.get_store(),
            {}
        )

    @mock.patch("simple_auth.core.flask_client.SimpleAuthClient")
    @mock.patch("simple_auth.core.flask_client.flask")
    def test_check_auth_identifier_3(self, mock_flask, mock_SimpleAuthClient):
        """
        Test function: flask_client.check_auth_identifier
        actual identifier + user + token

        :return:
        """

        mock_is_valid_identifier = mock.MagicMock(
            return_value=True)
        mock_get_auth_url = mock.MagicMock(
            return_value='mock_get_auth_url')
        mock_SimpleAuthClient.return_value = mock.MagicMock(
            is_valid_identifier=mock_is_valid_identifier,
            get_auth_url=mock_get_auth_url
        )

        mock_flask.g = FakeG()

        with self.assertRaises(KeyError):
            flask_client.check_auth_identifier()

        mock_flask.g.auth_identifier = 'fake_identifier'
        mock_flask.g.user = {'user_id': '123', 'level': [1, 2, 3]}
        mock_flask.g.auth_token = {'token': '123'}

        flask_client.check_auth_identifier()

        self.assertEqual(
            mock_flask.g.get_store(),
            {'auth_identifier': 'fake_identifier',
             'auth_redirect': 'mock_get_auth_url'}
        )

    @mock.patch("simple_auth.core.flask_client.SimpleAuthClient")
    @mock.patch("simple_auth.core.flask_client.flask")
    def test_check_auth_identifier_4(self, mock_flask, mock_SimpleAuthClient):
        """
        Test function: flask_client.check_auth_identifier
        non-actual identifier + user + token


        :return:
        """

        mock_is_valid_identifier = mock.MagicMock(
            return_value=False)
        mock_get_auth_url = mock.MagicMock(
            return_value='mock_get_auth_url')
        mock_SimpleAuthClient.return_value = mock.MagicMock(
            is_valid_identifier=mock_is_valid_identifier,
            get_auth_url=mock_get_auth_url
        )

        mock_flask.g = FakeG()

        with self.assertRaises(KeyError):
            flask_client.check_auth_identifier()

        mock_flask.g.auth_identifier = 'fake_identifier'
        mock_flask.g.user = {'user_id': '123', 'level': [1, 2, 3]}
        mock_flask.g.auth_token = {'token': '123'}

        flask_client.check_auth_identifier()

        self.assertEqual(
            mock_flask.g.get_store(),
            {}
        )

    @mock.patch("simple_auth.core.client.time")
    @mock.patch("simple_auth.core.flask_client.SimpleAuthClient")
    @mock.patch("simple_auth.core.flask_client.flask")
    def test_check_auth_token_1(self, mock_flask, mock_SimpleAuthClient,
                                mock_time):
        """
        Test function: flask_client.check_auth_identifier
        actual identifier + user + token


        :return:
        """

        mock_SimpleAuthClient.return_value = mock.MagicMock(
            is_valid_token=SimpleAuthClient.is_valid_token)

        mock_flask.g = FakeG()

        with self.assertRaises(KeyError):
            flask_client.check_auth_token()

        mock_flask.g.user = {'user_id': '123', 'level': [1, 2, 3]}

        with self.assertRaises(KeyError):
            flask_client.check_auth_token()

        mock_flask.g.user = {'user_id': '123', 'level': [1, 2, 3]}
        mock_flask.g.auth_token = {'token': '123'}

        flask_client.check_auth_token()

        self.assertEqual(
            {},
            mock_flask.g.get_store()

        )

        # work with time - actual
        mock_time.time = lambda: 100
        mock_flask.g.auth_identifier = 'fake_identifier'
        mock_flask.g.user = EXAMPLE_USER
        mock_flask.g.auth_token = EXAMPLE_TOKEN

        flask_client.check_auth_token()

        self.assertEqual(
            {'auth_token': EXAMPLE_TOKEN, 'user': EXAMPLE_USER},
            mock_flask.g.get_store()

        )

        # work with time - expired access token
        mock_time.time = lambda: 130
        mock_flask.g.user = EXAMPLE_USER
        mock_flask.g.auth_token = EXAMPLE_TOKEN

        flask_client.check_auth_token()

        self.assertEqual(
            {},
            mock_flask.g.get_store()

        )


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

