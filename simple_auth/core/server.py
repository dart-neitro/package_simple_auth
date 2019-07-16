"""
classes for server side

Pay attention:
token is a dictionary not string (!)

"""

import time
import copy

import schema

from .base import BaseMixin
import uuid


schema_session_storage_entry = schema.Schema({
    'timestamp': int,
    'timestamp_expired': int,
    'main_token': str,
    'action': schema.And(str, lambda x: x in (
        'access', 'update', 'main', 'identifier')),
    schema.Optional('user'): dict,
    schema.Optional('token'): dict,
})


class DictSessionStorage(dict):

    def __setitem__(self, key, value):
        value = schema_session_storage_entry.validate(data=value)
        return super(DictSessionStorage, self).__setitem__(key, value)


class SimpleAuthUser:
    id: int

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


class SimpleAuthServer(BaseMixin):
    session_storage_type = DictSessionStorage
    # sec
    expired_access_token_delta = 30
    expired_update_token_delta = 60
    expired_identifier_delta = 45
    time_delta = 1

    user_model = SimpleAuthUser

    def __init__(self):
        self.session_storage = self.session_storage_type()

    def get_identifier(self):
        identifier = str(uuid.uuid4())
        timestamp = int(time.time())

        response = dict(
            identifier=identifier
        )
        self.session_storage[identifier] = dict(
            timestamp=timestamp,
            timestamp_expired=(timestamp + self.expired_identifier_delta),
            main_token=str(uuid.uuid4()),
            action='identifier'
        )

        return self.format(result=response)

    def add_user_data(self, identifier: str, user_id: (int, str)):
        user = self.user_model.get(user_id)
        user_detail = user.to_storage_dict()

        if identifier in self.session_storage:
            self.session_storage[identifier]['user'] = user_detail
            return self.format()
        return self.format(error=True, msg="The identifier is wrong")

    def render_token(self):
        timestamp = int(time.time())
        expired_access_token = timestamp + self.expired_access_token_delta
        expired_update_token = timestamp + self.expired_update_token_delta

        return dict(
            access_token=str(uuid.uuid4()),
            update_token=str(uuid.uuid4()),
            expired_access_token=expired_access_token,
            expired_update_token=expired_update_token
        )

    def get_token(self, identifier: str):
        """
        Get token and information about user

        :param identifier:

        :return:
        """

        response = self.check_identifier(identifier=identifier)
        if response.get('error', True):
            return response

        if 'user' not in self.session_storage[identifier]:
            return self.format(
                error=True, msg="Have no information about user")

        token = self.render_token()
        record = copy.deepcopy(self.session_storage[identifier])

        del self.session_storage[identifier]
        record['token'] = token

        access_token = token['access_token']
        update_token = token['update_token']

        record['timestamp_expired'] = token['expired_access_token']
        record['action'] = 'access'
        self.session_storage[access_token] = copy.deepcopy(record)

        record['timestamp_expired'] = token['expired_update_token']
        record['action'] = 'update'
        self.session_storage[update_token] = copy.deepcopy(record)

        main_token = record['main_token']
        if main_token in self.session_storage:
            # update main token
            data_token = self.session_storage[main_token]
            data_token['timestamp_expired'] = token['expired_update_token']
            self.session_storage[main_token] = data_token
        else:
            # create new token
            data_token = dict(
                timestamp=int(time.time()),
                main_token=main_token,
                timestamp_expired=token['expired_update_token'],
                action='main'
            )
            self.session_storage[main_token] = data_token

        # remove the main token
        data_access_token = copy.deepcopy(
            self.session_storage[access_token])

        del data_access_token['main_token']
        del data_access_token['action']

        return self.format(result=data_access_token)

    def check_user(self, user_id: dict):
        # TODO add method
        return self.format()

    def check_identifier(self, identifier: str):
        """
        Check identifier

        :param identifier: string

        :return:
        """

        if identifier not in self.session_storage:
            return self.format(error=True, msg="The identifier is wrong")

        current_time = int(time.time())
        timestamp_default = current_time - 1
        timestamp_expired = self.session_storage[identifier].get(
            'timestamp_expired', timestamp_default)
        if timestamp_expired - current_time < self.time_delta:
            return self.format(
                error=True, msg="This identifier has expired")

        return self.format(result=dict(identifier=identifier))

    def check_token(self, token: dict):
        # TODO add method
        key = token.get('access_token')
        if key in self.session_storage:
            if 'user' in self.session_storage[key]:
                return self.format()
        return self.format(error=True, msg='Access token have n\'t found')

    def update_token(self, token: dict):
        # How can we check user_data:
        response = self.get_token(token.get('update_token'))

        return response







