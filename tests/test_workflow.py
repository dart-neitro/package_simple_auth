"""
Test workflow

"""

import json

import unittest
from unittest import mock

from simple_auth.core.client import SimpleAuthClient
from simple_auth.core.server import SimpleAuthServer


USER_DATA = {
            'timestamp': 100,
            'timestamp_expired': 145,

            'user': {
                'id': 1,
                'level': 5,
                'name': 'User name',
                'level': 5,
                'access': [1, 2, 3]}}

FAKE_RESPONSE_GET_TOKEN = {
    'error': False,
    'msg': '',
    'result': {
        'timestamp': 100,
        'timestamp_expired': 130,
        'token': {
            'access_token': 'mock_uud4_0',
            'expired_access_token': 130,
            'expired_update_token': 160,
            'update_token': 'mock_uud4_1'
        },
        'user': USER_DATA['user']
    }}

FAKE_RESPONSE_GET_TOKEN2 = {
    'error': False,
    'msg': '',
    'result': {
        'timestamp': 100,
        'timestamp_expired': 130,
        'token': {
            'access_token': 'mock_uud4_2',
            'expired_access_token': 130,
            'expired_update_token': 160,
            'update_token': 'mock_uud4_3'
        },
        'user': USER_DATA['user']
    }}


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
    expired_identifier_delta = 45
    time_delta = 1

    user_model = FakeSimpleAuthUser


def render_requests_redirect(server):
    def requests_redirect(*args, **kwargs):
        if args:
            url = args[0]
            del args[0]
        else:
            url = kwargs.pop('url', None)

        if not url:
            raise Exception('Have no url')

        params = kwargs.pop('json', {})
        command = params.pop('command')

        if not hasattr(server, command):
            raise Exception('Server don\'t have command <%s>' % command)
        method = getattr(server, command)

        return type('Response', (object,),
                    dict(text=json.dumps(method(**params))))()
    return requests_redirect


class MyTestCase(unittest.TestCase):

    @mock.patch('simple_auth.core.client.requests')
    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_workflow1(self, mock_uuid, mock_time, mock_requests):
        # init
        server = SimpleAuthServer()
        client = SimpleAuthClient(url_server_auth='http://localhost')

        # mocks
        requests_redirect = render_requests_redirect(server)
        mock_requests.post = requests_redirect
        mock_uuid.uuid4 = lambda: 'mock_uud4'
        mock_time.time = lambda: 100

        # get identifier
        response = client.get_identifier()

        self.assertEqual(
            response,
            {'result': {'identifier': 'mock_uud4'}, 'error': False,
             'msg': ''}
        )

        identifier = response['result']['identifier']

        # get token
        response = client.get_token(identifier=identifier)

        self.assertEqual(
            response,
            {'result': None, 'error': True,
             'msg': 'Have no information about user'}
        )

        # added user
        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_0', 'mock_uud4_1'])

        response = server.add_user_data(
            identifier=identifier,
            user_id=1)

        self.assertEqual(
            response,
            {'error': False, 'msg': '', 'result': None}
        )

        # get token
        response = client.get_token(identifier=identifier)

        self.assertEqual(response, FAKE_RESPONSE_GET_TOKEN)

        # check that identifier does not exist
        response = client.get_token(identifier=identifier)
        self.assertEqual(
            response,
            {'result': None, 'error': True, 'msg': 'The identifier is wrong'})

        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_0', 'mock_uud4_1'])
        response = client.get_token(identifier='mock_uud4_0')
        self.assertEqual(response, FAKE_RESPONSE_GET_TOKEN)
        token = response['result']['token']

        # update token
        self.assertEqual(
            server.session_storage[token['access_token']],
            FAKE_RESPONSE_GET_TOKEN['result'])

        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_2', 'mock_uud4_3'])
        response = client.update_token(token=token)
        self.assertEqual(response, FAKE_RESPONSE_GET_TOKEN2)

    @mock.patch('simple_auth.core.client.requests')
    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_expired_session(self, mock_uuid, mock_time, mock_requests):
        server = SimpleAuthServer()
        client = SimpleAuthClient(url_server_auth='http://localhost')

        requests_redirect = render_requests_redirect(server)

        mock_requests.post = requests_redirect
        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_0', 'mock_uud4_1'])
        mock_time.time = lambda: 100
        identifier = 'mock_uud4_1'

        server.session_storage.clear()
        server.session_storage[identifier] = FAKE_RESPONSE_GET_TOKEN['result']
        response = client.get_token(identifier=identifier)
        self.assertEqual(response, FAKE_RESPONSE_GET_TOKEN)

        token = response['result']['token']

        # we have enough time

        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_2', 'mock_uud4_3'])
        server.session_storage[identifier] = FAKE_RESPONSE_GET_TOKEN['result']

        response = client.update_token(token=token)
        self.assertEqual(response, FAKE_RESPONSE_GET_TOKEN2)

        # we have no time
        mock_time.time = lambda: 161

        server.session_storage.clear()
        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_2', 'mock_uud4_3'])
        server.session_storage[identifier] = FAKE_RESPONSE_GET_TOKEN['result']

        response = client.update_token(token=token)
        self.assertEqual(response,
                         {'error': True, 'msg': 'This identifier has expired',
                          'result': None})

    @mock.patch('simple_auth.core.client.requests')
    @mock.patch('simple_auth.core.server.time')
    @mock.patch('simple_auth.core.server.uuid')
    def test_multi_client(self, mock_uuid, mock_time, mock_requests):
        server = SimpleAuthServer()
        client1 = SimpleAuthClient(url_server_auth='http://localhost')
        client2 = SimpleAuthClient(url_server_auth='http://localhost')

        mock_requests.post = render_requests_redirect(server)
        mock_uuid.uuid4 = mock.MagicMock(
            side_effect=['mock_uud4_%s' % i for i in range(1000)])

        # mocks
        mock_time.time = lambda: 100

        # get identifiers from server
        identifier1 = client1.get_identifier()['result']['identifier']
        self.assertEqual('mock_uud4_0', identifier1, "Wrong identifier")

        identifier2 = client2.get_identifier()['result']['identifier']
        self.assertEqual('mock_uud4_2', identifier2, "Wrong identifier")

        expected_session_storage = {
            'mock_uud4_0': {
                'timestamp': 100,
                'timestamp_expired': 145,
                'main_token': 'mock_uud4_1',
                'action': 'identifier'},

            'mock_uud4_2': {
                'timestamp': 100,
                'timestamp_expired': 145,
                'main_token': 'mock_uud4_3',
                'action': 'identifier'}}

        self.assertEqual(
            expected_session_storage,
            server.session_storage,
            "Session storage has got wrong data"
        )

        # authenticate the user on the server
        # set up user to identifier1
        server.add_user_data(identifier1, 1)
        expected_session_storage[identifier1]['user'] = {
            'id': 1, 'name': 'User name', 'level': 5, 'access': [1, 2, 3]}

        self.assertEqual(
            expected_session_storage,
            server.session_storage,
            "Session storage has got wrong data"
        )

        response = server.get_token(identifier1)['result']

        expected_response = {'timestamp': 100, 'timestamp_expired': 130,
                             'user': {'id': 1, 'name': 'User name', 'level': 5,
                                      'access': [1, 2, 3]},
                             'token': {'access_token': 'mock_uud4_4',
                                       'update_token': 'mock_uud4_5',
                                       'expired_access_token': 130,
                                       'expired_update_token': 160}}

        self.assertEqual(
            expected_response,
            response,
            "The request server.get_token has returned a wrong response"
        )

        key1 = 'mock_uud4_1'
        # authenticate the user on the server
        # set up user to identifier1
        response = server.merge_main_tokens(
            key1=key1,
            key2=identifier2
        )

        self.assertEqual(
            {'error': False, 'msg': '', 'result': None},
            response,
            "The request server.get_token has returned a wrong response"
        )

        expected_session_storage = {
            'mock_uud4_2': {'timestamp': 100, 'timestamp_expired': 145,
                            'main_token': 'mock_uud4_1',
                            'action': 'identifier'},
            'mock_uud4_4': {'timestamp': 100, 'timestamp_expired': 130,
                            'main_token': 'mock_uud4_1',
                            'action': 'access',
                            'user': {'id': 1, 'name': 'User name',
                                     'level': 5, 'access': [1, 2, 3]},
                            'token': {'access_token': 'mock_uud4_4',
                                      'update_token': 'mock_uud4_5',
                                      'expired_access_token': 130,
                                      'expired_update_token': 160}},
            'mock_uud4_5': {'timestamp': 100, 'timestamp_expired': 160,
                            'main_token': 'mock_uud4_1',
                            'action': 'update',
                            'user': {'id': 1, 'name': 'User name',
                                     'level': 5, 'access': [1, 2, 3]},
                            'token': {'access_token': 'mock_uud4_4',
                                      'update_token': 'mock_uud4_5',
                                      'expired_access_token': 130,
                                      'expired_update_token': 160}},
            'mock_uud4_1': {'timestamp': 100,
                            'main_token': 'mock_uud4_1',
                            'timestamp_expired': 160, 'action': 'main'}}

        self.assertEqual(
            expected_session_storage,
            server.session_storage,
            "Session storage has got wrong data"
        )

        return



if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTestCase)
    runner = unittest.TextTestRunner(verbosity=2)
    result_test = runner.run(suite)

