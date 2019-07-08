import flask

from simple_auth.core.server import SimpleAuthServer

app = flask.Flask(__name__)

app.config['SECRET_KEY'] = 'SECRET_KEY'


class FakeSimpleAuthUser:
    id: int = 11

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
    user_model = FakeSimpleAuthUser


SERVER = SimpleAuthServer()


@app.route('/')
def index():
    server = SERVER
    parameters = flask.request.args.to_dict()
    identifier = parameters['identifier']
    response = server.add_user_data(
        identifier=identifier,
        user_id=11
    )
    print('index |', response)
    redirect_url = parameters['redirect_url']
    return flask.redirect(redirect_url)



    # return 'It,s server auth'


@app.route('/api', methods=['GET', 'POST'])
def auth_user():
    server = SERVER
    parameters = flask.request.json
    print('parameters :', parameters)
    command = parameters.pop('command')
    result = getattr(server, command)(**parameters)
    print('result :', result)
    return flask.jsonify(result)


if __name__ == "__main__":
    app.run(port=5011)
