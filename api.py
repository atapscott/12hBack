#!/usr/bin/env python

"""
12hBack
==================
Api that builds upon Miguel Grinberg's Flask-HTTPAuth example
https://github.com/miguelgrinberg/REST-auth

"""

import os
import json
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists, and_
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from uuid import uuid4

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the$god%machine&knows/all(but)gives=out?nothing¿'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

SETTINGS_FILE = 'settings.json'


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

class Key(db.Model):
    __tablename__ = 'keys'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), index=True)

class UserKeyValue(db.Model):
    __tablename__ = 'user_key_value'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('keys.id'), primary_key=True)
    value = db.Column(db.String(50))

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def create_user(username, password):
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)

    db.session.add(user)
    db.session.commit()

    initial_key_values = get_initial_key_values()

    for initial_key_value in initial_key_values:
        [k, v] = initial_key_value
        key_object = Key.query.filter_by(name=k).first()
        user_key_value = UserKeyValue(user_id=user.id, key_id=key_object.id, value=v)
        db.session.add(user_key_value)


    db.session.commit()
    return user


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    user = create_user(username, password)
    response = app.response_class(
        response=json.dumps({'username': user.username, 'id': user.id}),
        status=201,
        mimetype='application/json'
    )
    return response


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/values', methods=['GET'])
@auth.login_required
def get_values():
    username = request.authorization.get('username')
    user = User.query.filter_by(username=username).first()
    user_key_values = UserKeyValue.query.filter_by(user_id=user.id).all()
    key_values = []
    for ukv in user_key_values:
        key = Key.query.filter_by(id=ukv.key_id).first()
        key_values.append([key.name, ukv.value])

    return jsonify({'data': key_values})


def get_key_object(key_name):
    key_object = Key.query.filter_by(name=key_name).first()
    return key_object


def get_key_value_object(key_name, username):

    user = User.query.filter_by(username=username).first()
    key_object = get_key_object(key_name)

    if not key_object:
        key_object = Key(name=key_name)
        db.session.add(key_object)
        db.session.commit()

    user_key_value_object = UserKeyValue.query.filter_by(key_id=key_object.id, user_id=user.id).first()

    if not user_key_value_object:
        user_key_value_object = UserKeyValue(user_id=user.id, key_id=key_object.id)
        db.session.add(user_key_value_object)
        db.session.commit()

    return user_key_value_object


@app.route('/api/keyvalue/<key_name>', methods=['PUT'])
@auth.login_required
def set_key_value(key_name):
    username = request.authorization.get('username')
    new_value = request.json.get('value')

    user_key_value_object = get_key_value_object(key_name, username)

    user_key_value_object.value = new_value
    db.session.commit()

    response = app.response_class(
        response=json.dumps({key_name: user_key_value_object.value, 'username': username}),
        status=201,
        mimetype='application/json'
    )
    return response


@app.route('/api/keyvalue/<key_name>', methods=['GET'])
@auth.login_required
def get_key_value(key_name):
    username = request.authorization.get('username')

    user_key_value_object = get_key_value_object(key_name, username)

    response = app.response_class(
        response=json.dumps({key_name: user_key_value_object.value, 'username': username}),
        status=201,
        mimetype='application/json'
    )
    return response


@app.route('/api/keyvalues', methods=['GET'])
@auth.login_required
def get_key_values():
    username = request.authorization.get('username')
    user = User.query.filter_by(username=username).first()

    key_objects = Key.query.all()

    user_key_values = {}

    for key_object in key_objects:
        user_key_value_objects = UserKeyValue.query.filter_by(key_id=key_object.id, user_id=user.id).all()
        for ukvo in user_key_value_objects:
            user_key_values[key_object.name] = ukvo.value

    response = app.response_class(
        response=json.dumps({'key_values': user_key_values, 'username': username}),
        status=201,
        mimetype='application/json'
    )
    return response


def get_initial_key_values():
    settings_data = get_settings_data()
    initial_key_values = settings_data.get('initial_key_values')
    return initial_key_values


def get_settings_data():
    with open(SETTINGS_FILE, encoding='utf-8') as f:
        settings_data = json.load(f)
        return settings_data


def is_admin(username):
    setting_data = get_settings_data()
    admins = setting_data['admins']
    if username in [a[0] for a in admins]:
        return True
    return False


@app.route('/main', methods=['GET'])
@auth.login_required
def main():
    if not is_admin(request.authorization.get('username')):
        abort(403)

    return_string = ""

    return_string += '<h1>SystemKeys</h1><br></br>'
    for k in Key.query.all():
        return_string += '{}-{}<br></br>'.format(k.id, k.name)

    return_string += "<h1>Users</h1>"
    for u in User.query.all():
        return_string += '<h2>{}-{}</h2>'.format(u.id, u.username)

        return_string += 'key:values<br></br>'
        for ukv in UserKeyValue.query.filter_by(user_id=u.id):
            key_object = Key.query.filter_by(id=ukv.key_id).first()
            return_string += ' {}:{}<br></br>'.format(key_object.name, ukv.value)
    return_string += '<br></br>'

    return return_string


def initialize():
    db.create_all()
    settings_data = get_settings_data()

    for system_key in settings_data.get('system_keys'):
        new_key = Key(name=system_key)
        db.session.add(new_key)

    for admin_data in settings_data.get('admins'):
        create_user(admin_data[0], admin_data[1])

    db.session.commit()


@app.route('/api/purge', methods=['POST'])
@auth.login_required
def purge_data():
    username = request.authorization.get('username')
    user = User.query.filter_by(username=username).first()
    if is_admin(user.username):
        UserKeyValue.query.delete()
        Key.query.delete()
        User.query.delete()
        initialize()

        return app.response_class(status=200)
    return abort(403)


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        initialize()
    # app.run(debug=True)
    app.run(debug=True, use_debugger=False, use_reloader=False, passthrough_errors=True)
