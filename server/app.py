from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
import bcrypt
from pymongo import MongoClient, ReturnDocument
from db import db

parser = reqparse.RequestParser()

app = Flask(__name__)
Users = db["Users"]
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)
api = Api(app)


def verifyPassword(username, password):
    hashed_pwd = Users.find_one({
        "username": username
    })["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pwd) == hashed_pwd:
        return True
    else:
        return False

def userExists(username):
    user = Users.find_one({
        "username": username
    })
    if user is not None:
        return True
    else:
        return False

class Register(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data["username"]
            password = data["password"]
            if userExists(username):
                return jsonify({
                    'message': 'User with username "{}" already exist!'.format(username)
                })

            hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

            Users.insert_one({
                "username": username,
                "password": hashed_pw
            })
            access_token = create_access_token(identity = data['username'])

            retJson = {
                "message": "User registered successfully",
                'access_token': access_token,
                "status": 201
            }
            return jsonify(retJson)
        except Exception as err:
            retJson = {
                "status": 500,
                "message": "err"
            }
            return jsonify(retJson)

class Login(Resource):
    def post(self):
        data = parser.parse_args()

        if not userExists(data['username']):
            return jsonify({'message': 'User {} doesn\'t exist'.format(data['username'])})
        correct_pswd = verifyPassword(data['username'], data['password'])
        if correct_pswd:
            access_token = create_access_token(identity = data['username'])
            retJson = {
                "message": "Successfully logged in!",
                "access_token": access_token
            }
            return jsonify(retJson)
        else:
            return jsonify({'message': 'Wrong credentials'})

class SecretResource(Resource):
    @jwt_required
    def get(self):
        return jsonify({
            'username': get_jwt_identity(),
            'answer': 42
        })

api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(SecretResource, "/secret")

app.run(port=5000)