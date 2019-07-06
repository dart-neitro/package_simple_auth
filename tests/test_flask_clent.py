"""
Test simple_auth.SimpleAuthServer

"""
import json
import copy

import unittest
from unittest import mock


from simple_auth.core import flask_client


class FakeG:
    """
    mock for flask.g
    """

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


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

