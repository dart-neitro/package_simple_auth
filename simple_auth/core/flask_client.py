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


def get_auth_identifier():
    """
    Get auth identifier

    :return:
    """

    url_server_auth = flask.current_app.config.get('URL_AUTH_SERVER')
    url_if_auth_server_unvailable = flask.current_app.config.get(
        'URL_IF_AUTH_SERVER_UNAVAILABLE')

    # unavailable
    client = SimpleAuthClient(
        url_server_auth=url_server_auth)

    flask.g.pop('user', None)
    flask.g.pop('auth_token', None)
    flask.g.pop('auth_identifier', None)

    response = client.get_identifier()

    if not response.get('error', True):
        flask.g.auth_identifier = response.get('result', {}).get('identifier')
        flask.g.auth_redirect = client.get_auth_url(
            identifier=flask.g.auth_identifier,
            current_url=flask.request.url
        )
        return

    flask.g.auth_redirect = url_if_auth_server_unvailable
    return


def load_before_view():
    flask.g.user = flask.session.get("user") or None
    flask.g.auth_identifier = flask.session.get("auth_identifier") or None
    flask.g.auth_token = flask.session.get("auth_token") or None

    # we have got identifier
    if flask.g.get('auth_identifier'):
        check_auth_identifier()
        if flask.g.get('auth_redirect'):
            return

    # we've got token
    if flask.g.get('auth_token'):
        check_auth_token()
        if flask.g.get('auth_redirect'):
            return
        elif flask.g.get('auth_token') and flask.g.get('user'):
            return

    return get_auth_identifier()


def load_after_view():
    flask.session.pop('auth_identifier', None)
    flask.session.pop('user', None)
    flask.session.pop('auth_token', None)
    flask.session.pop('auth_redirect', None)

    identifier = flask.g.pop('auth_identifier', None)
    if identifier:
        flask.session['auth_identifier'] = identifier
        return

    user = flask.g.pop('user', None)
    if user:
        flask.session['user'] = user

    token = flask.g.pop('auth_token', None)
    if user:
        flask.session['auth_token'] = token

    flask.g.pop('auth_identifier', None)
    flask.g.pop('user', None)
    flask.g.pop('auth_token', None)
    flask.g.pop('auth_redirect', None)

    return


def available_for_anonymous_user(f):
    """
    This decorator provides ability to get view for any user

    :param f:
    :return:
    """

    @wraps(f)
    def wrapper(*args, **kwargs):

        return f(*args, **kwargs)
    return wrapper


def control_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        is_only_for_auth_users = getattr(f, 'is_only_for_auth_users', False)

        load_before_view()

        if is_only_for_auth_users:
            url_redirect = flask.g.get('auth_redirect')

            if url_redirect:
                load_after_view()
                return flask.redirect(url_redirect)

        result = f(*args, **kwargs)
        load_after_view()

        return result
    return wrapper


def init_app(app):
    for view in app.view_functions.keys():
        app.view_functions[view] = control_auth(app.view_functions[view])
    return app


def only_auth_user(f):
    """
    This decorator provides ability to get view for only auth user

    :param f:
    :return:
    """

    setattr(f, 'is_only_for_auth_users', True)

    return f
