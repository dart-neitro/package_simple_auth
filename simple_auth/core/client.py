"""
Client side

resource=
client_id=
redirect_uri=
response_type=
state=
"""
import requests
import json
import urllib

from .base import BaseMixin


class SimpleAuthClient(BaseMixin):
    """
    Class for auth
    """

    def __init__(self, url_server_auth: str, token=None):
        self.url_server_auth = url_server_auth
        self.url_server_auth_api = url_server_auth + '/api'
        self.token = token

    def request(self, **kwargs):
        """
        Data transfer method

        :param kwargs: data transfer

        :return:
        """
        try:
            response = requests.post(url=self.url_server_auth_api, json=kwargs)
            data = json.loads(response.text)
            return data
        except Exception as e:
            pass

        return self.format(error=True, msg='Transfer data error')

    def get_identifier(self):

        response = self.request(
            command='get_identifier'
        )

        return response

    def get_auth_url(self, identifier: str, current_url: str):

        query = urllib.parse.urlencode(
            dict(
                identifier=identifier,
                redirect_uri=current_url
            )
        )

        return "{}?{}".format(self.url_server_auth, query)

    def get_token(self, identifier: str):

        response = self.request(
            command='get_token',
            identifier=identifier
        )

        return response

    def update_token(self, token):
        response = self.request(
            command='update_token',
            token=token
        )
        return response



