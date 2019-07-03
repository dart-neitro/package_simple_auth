"""
classes for server side

Pay attention:
token is a dictionary not string (!)
"""

import time
import copy

from .base import BaseMixin
import uuid


class SessionStorage(dict):
    pass


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
    session_storage_type = SessionStorage
    # sec
    expired_access_token_delta = 30
    expired_update_token_delta = 60

    user_model = SimpleAuthUser

    def __init__(self):
        self.session_storage = self.session_storage_type()

    def get_identifier(self):
        identifier = str(uuid.uuid4())

        response = dict(
            identifier=identifier
        )
        self.session_storage[identifier] = dict(timestamp=time.time())

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

        if identifier in self.session_storage:
            if 'user' in self.session_storage[identifier]:
                token = self.render_token()
                record = copy.deepcopy(self.session_storage[identifier])

                del self.session_storage[identifier]
                record['token'] = token

                access_token = token['access_token']
                update_token = token['update_token']

                self.session_storage[access_token] = record
                self.session_storage[update_token] = record

                return self.format(result=record)
            else:
                return self.format(
                    error=True, msg="Have no information about user")
        else:
            return self.format(error=True, msg="The identifier is wrong")

        return self.format(error=True, msg="Unknown error")

    def check_user(self, user_id: dict):
        # TODO add method
        return self.format()

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







