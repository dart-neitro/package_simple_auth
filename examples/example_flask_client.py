import flask

from simple_auth.core.flask_client import init_app, only_auth_user

app = flask.Flask(__name__)

app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['URL_AUTH_SERVER'] = 'http://localhost:5011'
app.config['URL_IF_AUTH_SERVER_UNAVAILABLE'] = 'http://localhost:5003/'


@app.route('/')
def index():
    return 'Hello, World. <a href="{}">User</a>'.format(
        flask.url_for('auth_user'))


@app.route('/user')
@only_auth_user
def auth_user():

    return f'<p> User: {flask.g.user}</p><p> Token: {flask.g.auth_token}</p>'


@app.route('/error')
def error():
    return 'Hello, You\'ve got error'


app = init_app(app)

if __name__ == "__main__":
    app.run(port=5003)
