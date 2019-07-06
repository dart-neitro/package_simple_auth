from functools import wraps
import time

import flask

from .client import SimpleAuthClient


def check_auth_identifier():
    url_server_auth = 'http://localhost'

    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    if not hasattr(flask.g, 'auth_identifier'):
        raise KeyError('Object flask.g have not got <auth_identifier>')

    if hasattr(flask.g, 'user'):
        del flask.g.user
    if hasattr(flask.g, 'auth_token'):
        del flask.g.auth_token

    if client.is_valid_identifier(identifier=flask.g.auth_identifier):

        flask.g.auth_redirect = client.get_auth_url(
            identifier=flask.g.auth_identifier,
            current_url=flask.request.url)

        return
    else:
        del flask.g.auth_identifier
    return

