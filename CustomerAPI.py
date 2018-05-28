import datetime
from flask import Flask, json, session, jsonify
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required, get_jwt_identity)
from flask_jwt_extended.config import config
from flask_jwt_extended.tokens import decode_jwt
from flask_restful import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_swagger import swagger
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.sqlite3'
db = SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = ',312./\[]sdpsdedh239312ehcfwehdfwo'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
jwt = JWTManager(app)
class Customer(db.Model):
    username = db.Column(db.String(100), primary_key=True)
    password = db.Column(db.String(50))
    address = db.Column(db.String(10))

    def __init__(self, username, pwd, addr):
        self.username = username
        self.password = pwd
        self.address = addr
api = Api(app)
blacklist = set()
@app.route("/spec")
def spec():
    return jsonify(swagger(app))
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist
class SignIn(Resource):
    def post(self):
        if 'username' in session:
            if session:
                pass
            else:
                return
            msg = {"logged_in": False, "msg": "User " + session['username'] + " already logged In!", "status": 403}
        else:
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, required=True,  help='Username needed for Login')
            parser.add_argument('password', type=str, required=True,  help='Password needed for Login')
            args = parser.parse_args()
            if Customer.query.filter_by(username=args['username'], password=args['password']).first():
                session['username'] = args['username']
                token_data = {'username': args['username'], 'password': args['password']}
                access_token = create_access_token(identity=token_data, expires_delta=datetime.timedelta(days=365*3))
                decoded = decode_jwt(encoded_token=access_token, secret=config.decode_key, algorithm=config.algorithm, identity_claim_key=config.identity_claim_key,user_claims_key=config.user_claims_key)

                msg = {'logged_in': True, 'msg': "User " + str(args['username']) + " logged in successfully!",
                       "status": 200, "access_token": access_token, "token_identity": decoded['identity']}
            else:
                msg = {'logged_in': False, 'msg': "User " + str(args['username']) +
                                                  " does not exists against these credentials.", "status": 403}
        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )


class SignUp(Resource):
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, required=True, help='Username needed for SignUp')
            parser.add_argument('password', type=str, required=True, help='Password needed for SignUp')
            parser.add_argument('address', type=str, required=True, help='Address needed for SignUp')
            args = parser.parse_args()
            customer = Customer(args['username'], args['password'], args['address'])
            db.session.add(customer)
            db.session.commit()
            msg = {'created': True, 'msg': "Successful Registered Customer " + str(args['username']), "status": 200}
        except Exception as e:
            msg = {'created': False, 'msg': "Some error occured while registering Customer " + str(args['username']),'exception': str(e), "status": 403}
        finally:
            return app.response_class(
                response=json.dumps(msg),
                status=msg['status'],
                mimetype='application/json'
            )


class UpdateInfo(Resource):
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username needed for Updating Information')
        parser.add_argument('address', type=str, required=True, help='Address needed for Updating Information')
        args = parser.parse_args()
        customer = Customer.query.filter_by(username=args['username']).first()
        if customer:
            customer.address = args['address']
            db.session.commit()
            msg = {'updated': True, 'msg': "Updated Info against User " + str(args['username']), 'status': 200}
        else:
            msg = {'updated': False, 'msg': "User " + str(args['username']) + " does not exists.", 'status': 403}

        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )
class UpdatePassword(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username needed for Updating Password')
        parser.add_argument('password', type=str, required=True, help='Password needed for Updating Password')
        args = parser.parse_args()
        customer = Customer.query.filter_by(username=args['username']).first()
        if customer:
            customer.address = args['password']
            db.session.commit()
            msg = {'updated': True, 'msg': "Updated Password against User " + str(args['username']), 'status': 200}
        else:
            msg = {'updated': False, 'msg': "User " + str(args['username']) + " does not exists.", "status": 403}

        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )
class DeleteCustomer(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username needed for Deleting Customer')
        args = parser.parse_args()
        customer = Customer.query.filter_by(username=args['username']).first()
        if customer:
            db.session.delete(customer)
            db.session.commit()
            msg = {'deleted': True, 'msg': "Deleted User " + str(args['username']), 'status': 200}
        else:
            msg = {'deleted': False, 'msg': "User " + str(args['username']) + " does not exists.", 'status': 403}

        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )


class SignOut(Resource):
    #@jwt_required
    def post(self):
        #jti = get_raw_jwt()
        #blacklist.add(jti['jti'])
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username needed for Deleting Customer')
        args = parser.parse_args()
        if 'username' in session and session['username'] == args['username']:
            session.pop('username')
            msg = {"logged_out": True, "msg": "Logged Out " + args['username'] + " successfully!",
                   'status': 200}
        else:
            msg = {"logged_out": False, "msg": "User not logged In! Unable to Log Out.", 'status': 403}

        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )
api.add_resource(SignIn, '/customer_api/login/')
api.add_resource(SignOut, '/customer_api/logout/')
api.add_resource(SignUp, '/customer_api/signup/')
api.add_resource(UpdateInfo, '/customer_api/update_info/')
api.add_resource(UpdatePassword, '/customer_api/update_password/')
api.add_resource(DeleteCustomer, '/customer_api/delete_customer/')
if __name__ == "__main__":
    app.secret_key = 'd4dh2,/.,32ifsda'
    app.run(debug=True, port=8000)

