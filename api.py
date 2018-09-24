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
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the god machine knows all but gives out nothing'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


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


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/values', methods=['GET'])
@auth.login_required
def get_values():
    user_key_values = UserKeyValue.query.filter_by(user_id=g.user.id).all()
    key_values = []
    for ukv in user_key_values:
        key = Key.query.filter_by(id=ukv.key_id).first()
        key_values.append([key.name, ukv.value])

    return jsonify({'data': key_values})

@app.route('/api/values', methods=['PUT'])
@auth.login_required
def update_values():
    username = request.json.get('username')
    user = User.query.filter_by(username=username).first()
    key_values = request.json.get('key_values')
    for key_name, value in key_values.items():
        key = Key.query.filter_by(name=key_name).first()
        user_key_value = UserKeyValue(user_id=user.id, key_id=key.id, value=value)
        db.session.add(user_key_value)
        db.session.commit()

    return jsonify({'data': str(g.user.__dict__)})


@app.route('/main', methods=['GET'])
@auth.login_required
def main():
    return_string = "Users<br></br>"
    for u in [(u.id, u.username) for u in User.query.all()]:
        return_string += '{}<br></br>'.format(str(u))
    return_string += 'Keys<br></br>'
    for k in Key.query.all():
        return_string += 'Id:{} Name:{}<br></br>'.format(k.id, k.name)
    return_string += 'UserKeyValues<br></br>'
    for ukv in UserKeyValue.query.all():
        return_string += 'User:{} Key:{} Value:{}<br></br>'.format(ukv.user_id, ukv.key_id, ukv.value)
    return return_string


def initialize():
    db.create_all()
    with open('settings.json', encoding='utf-8') as f:
        setting_data = json.load(f)
        for key_name in setting_data['keys']:
            key = Key(name=key_name)
            db.session.add(key)
            db.session.commit()


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        initialize()
    # app.run(debug=True)
    app.run(debug=True, use_debugger=False, use_reloader=False, passthrough_errors=True)
