"""
Test simple_auth.SimpleAuthServer

"""

import unittest
from unittest import mock


from simple_auth.core.server import SimpleAuthServer


class FakeSimpleAuthUser:
    id: int = 10

    @property
    def is_simple_auth_user(self):
        return True

    def to_storage_dict(self):
        return dict(
            id=self.id,
            name='User name',
            level=5,
            access=[1, 2, 3]
        )

    @classmethod
    def get(cls, user_id):
        user = cls()
        user.id = user_id
        return user


class SimpleAuthServer(SimpleAuthServer):
    session_storage_type = dict

    expired_access_token_delta = 30
    expired_update_token_delta = 60

    user_model = FakeSimpleAuthUser


class MyTestCase(unittest.TestCase):

    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_get_identifier(self, mock_uuid, mock_time):
        """
        Test SimpleAuthServer.get_identifier

        :return:
        """

        mock_uuid.uuid4 = lambda: 'mock_uud4'
        mock_time.time = lambda: 100
        server = SimpleAuthServer()
        response = server.get_identifier()
        self.assertEqual(
            response,
            {'result': {'identifier': 'mock_uud4'}, 'error': False, 'msg': ''},
            'Cann\'t get identifier {}'.format(response))

        self.assertEqual(
            server.session_storage,
            {'mock_uud4': {'timestamp': 100}})

    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_render_token(self, mock_uuid, mock_time):
        """
        Test SimpleAuthServer.render_token

        :return:
        """

        server = SimpleAuthServer()

        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_0', 'mock_uud4_1'])
        mock_time.time = lambda: 100

        response = server.render_token()

        self.assertEqual(
            response,
            {'access_token': 'mock_uud4_0',
             'expired_access_token': 130,
             'expired_update_token': 160,
             'update_token': 'mock_uud4_1'}
        )

    def test_add_user(self):
        """
        Test SimpleAuthServer.add_user_data

        :return:
        """

        server = SimpleAuthServer()
        server.session_storage['fake_identifier'] = dict(
            timestamp=1)

        response = server.add_user_data(
            identifier='wrong_identifier',
            user_id=1)

        self.assertEqual(
            response,
            {'error': True, 'msg': 'The identifier is wrong', 'result': None}
        )

        response = server.add_user_data(
            identifier='fake_identifier',
            user_id=1)

        self.assertEqual(
            response,
            {'error': False, 'msg': '', 'result': None}
        )

    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_get_token(self, mock_uuid, mock_time):
        """
        Test SimpleAuthServer.get_token

        :return:
        """

        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_0', 'mock_uud4_1'])
        mock_time.time = lambda: 100

        server = SimpleAuthServer()

        user_data = {
            'timestamp': 1,
            'user': {
                'name': 'User name', 'level': 5, 'access': [1, 2, 3]}}

        server.session_storage['fake_identifier'] = user_data
        server.session_storage['fake_identifier_without_user'] = {
            'timestamp': 1}

        response = server.get_token(
            identifier='wrong_identifier')

        self.assertEqual(
            response,
            {'error': True, 'msg': 'The identifier is wrong', 'result': None}
        )

        response = server.get_token(
            identifier='fake_identifier_without_user')

        self.assertEqual(
            response,
            {
                'error': True,
                'msg': 'Have no information about user',
                'result': None
            }
        )

        response = server.get_token(
            identifier='fake_identifier')

        self.assertEqual(
            response,
            {'error': False,
             'msg': '',
             'result': {
                 'timestamp': 1,
                 'token': {'access_token': 'mock_uud4_0',
                           'expired_access_token': 130,
                           'expired_update_token': 160,
                           'update_token': 'mock_uud4_1'},
                 'user': user_data['user']
                 }}
        )

    def template(self):
        """
        Test SimpleAuthServer.

        :return:
        """


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

