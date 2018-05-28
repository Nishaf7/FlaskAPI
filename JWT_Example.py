from flask import Flask, Blueprint, request, json, session
from flask_restful import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (JWTManager,create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.sqlite3'
db = SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = 'cvewcwevwevvwehdfwo'
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

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


class SignIn(Resource):
    def post(self):
        if 'username' in session:
            msg = {"logged_in": False, "msg": "User " + session['username'] + " already logged In!", "status": 403}
        else:
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, required=True,  help='Username needed for Login')
            parser.add_argument('password', type=str, required=True,  help='Password needed for Login')
            args = parser.parse_args()
            if Customer.query.filter_by(username=args['username'], password=args['password']).first():
                session['username'] = args['username']
                access_token = create_access_token(identity=(args['username'], args['password']))
                msg = {'logged_in': True, 'msg': "User " + str(args['username']) + " logged in successfully!",
                       "status": 200, "access_token": access_token}
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
            msg = {'created': False, 'msg': "Some error occured while registering Customer " + str(args['username']),
                   'exception': str(e), "status": 403}
        finally:
            return app.response_class(
                response=json.dumps(msg),
                status=msg['status'],
                mimetype='application/json'
            )


class TokenRefresh(Resource):
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class UpdateInfo(Resource):
    @jwt_required
    def post(self):
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
            if session['username'] == args['username']:
                session.pop('username')
            msg = {'deleted': True, 'msg': "Deleted User " + str(args['username']), 'status': 200}
        else:
            msg = {'deleted': False, 'msg': "User " + str(args['username']) + " does not exists.", 'status': 403}

        return app.response_class(
            response=json.dumps(msg),
            status=msg['status'],
            mimetype='application/json'
        )


class SignOut(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        blacklist.add(jti)
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
api.add_resource(TokenRefresh, '/customer_api/refresh_token/')


if __name__ == "__main__":
    app.secret_key = 'd4dh2,/.,32ifsda'
    app.run(debug=True, port=8000)





'''
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MjY4OTkwOTYsIm5iZiI6MTUyNjg5OTA5NiwianRpIjoiNjI1OGUyOTYtMDRiNi00OTZhLTg0Y2MtY2NmOGViMmQyNDc1IiwiZXhwIjoxNTI2ODk5OTk2LCJpZGVudGl0eSI6Im5pc2hhZjciLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.r5n8Q_C0HfmGanULGx69bXvRgpgwTzB5wLptJ1A1kbI",
    "logged_in": true,
    "msg": "User nishaf7 logged in successfully!",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MjY4OTkwOTYsIm5iZiI6MTUyNjg5OTA5NiwianRpIjoiMWZlNzBjOGMtNTE5YS00OGRiLThmN2YtYWE4MmQyMzIyOGU0IiwiZXhwIjoxNTI5NDkxMDk2LCJpZGVudGl0eSI6Im5pc2hhZjciLCJ0eXBlIjoicmVmcmVzaCJ9.tzF2ECrHAyi8XE5KKsT0xiBWDcTcHAmwehWB8ZZNWMc",
    "status": 200
}

{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MjY4OTkxODIsIm5iZiI6MTUyNjg5OTE4MiwianRpIjoiYzEyYTNiZWEtYWNlMy00N2NjLThjY2YtOGFiMzlhMGI3NDkzIiwiZXhwIjoxNTI2OTAwMDgyLCJpZGVudGl0eSI6Im5pc2hhZiIsImZyZXNoIjpmYWxzZSwidHlwZSI6ImFjY2VzcyJ9.DOL7Dx1scC4APaK4PL_dEcS9U-6pRFREQlOVSJAo0nI",
    "logged_in": true,
    "msg": "User nishaf logged in successfully!",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MjY4OTkxODIsIm5iZiI6MTUyNjg5OTE4MiwianRpIjoiNzFjODM4Y2ItYzZlZC00MTRiLWFkZTQtNmI0NTdmZDMwNDNlIiwiZXhwIjoxNTI5NDkxMTgyLCJpZGVudGl0eSI6Im5pc2hhZiIsInR5cGUiOiJyZWZyZXNoIn0.bb2waPpdo_DvpD-XfhaP6mrxz3XbXDBaC_dmhY6I9HA",
    "status": 200
}
'''