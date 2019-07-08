from functools import wraps
import time

import flask

from .client import SimpleAuthClient


def check_auth_identifier():
    url_server_auth = flask.current_app.config.get('URL_AUTH_SERVER')

    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    if not hasattr(flask.g, 'auth_identifier'):
        raise KeyError('Object flask.g have not got <auth_identifier>')

    flask.g.pop('user', None)
    flask.g.pop('auth_token', None)

    if client.is_valid_identifier(identifier=flask.g.auth_identifier):
        response = client.get_token(identifier=flask.g.auth_identifier)
        if response.get('error', True):
            flask.g.auth_redirect = client.get_auth_url(
                identifier=flask.g.auth_identifier,
                current_url=flask.request.url)
            return

        new_token = response.get('result', {}).get('token')
        new_user = response.get('result', {}).get('user')
        if new_token and new_user:
            flask.g.user = new_user
            flask.g.auth_token = new_token
            return

    else:
        del flask.g.auth_identifier
    return


def check_auth_token():
    """
    Check auth token

    :return:
    """
    url_server_auth = flask.current_app.config.get('URL_AUTH_SERVER')

    if not hasattr(flask.g, 'auth_token'):
        raise KeyError('Object flask.g have not got <auth_token>')

    if not hasattr(flask.g, 'user'):
        raise KeyError('Object flask.g have not got <user>')

    flask.g.pop('auth_identifier', None)
    if hasattr(flask.g, 'auth_identifier'):
        del flask.g.auth_identifier

    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    if client.is_valid_token(token=flask.g.auth_token):
        if flask.g.get('user'):
            return
    elif client.is_valid_token_for_update(token=flask.g.auth_token):
        response = client.update_token(token=flask.g.auth_token)
        if not response.get('error', True):
            new_token = response.get('result', {}).get('token')
            new_user = response.get('result', {}).get('user')
            if new_token and new_user:
                flask.g.user = new_user
                flask.g.auth_token = new_token
                return

    flask.g.pop('user', None)
    flask.g.pop('auth_token', None)
    return


def check_get_identifier():
    # clear data
    url_server_auth = flask.current_app.config.get('URL_AUTH_SERVER')
    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    flask.g.user = None
    flask.g.auth_token = None

    # we have got no identifier
    response = client.get_identifier()

    if not response.get('error', True):
        flask.g.auth_identifier = response.get('result', {}).get('identifier')


# @bp.before_app_request
def load_logged_in_user():
    url_server_auth = 'http://localhost'

    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    flask.g.user = flask.session.get("user") or None
    flask.g.auth_identifier = flask.session.get("auth_identifier") or None
    flask.g.auth_token = flask.session.get("auth_token") or None

    # we have got identifier
    if flask.g.auth_identifier:
        check_auth_identifier()
        if flask.g.get('auth_redirect'):
            return

    # we've got token
    if flask.g.auth_token:
        check_auth_token()
        if flask.g.get('auth_redirect'):
            return


    return


def get_data_from_cookies():
    pass


def only_auth_user(f):
    """
    This decorator provides ability to get view for only auth user

    :param f:
    :return:
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if flask.g.user:
            return f(*args, **kwargs)

        return flask.url_for('http://localhost:9999')

    return wrapper


def init_app(app):
    # TODO It
    pass