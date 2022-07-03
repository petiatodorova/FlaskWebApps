import enum
from datetime import datetime, timedelta
from flask_httpauth import HTTPTokenAuth
import jwt
from jwt import InvalidSignatureError, ExpiredSignatureError
from marshmallow_enum import EnumField
from marshmallow import Schema, fields, ValidationError, validates

from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.exceptions import BadRequest, Forbidden
from werkzeug.security import generate_password_hash

app = Flask(__name__)

db_user = config("DB_USER")
db_password = config("DB_PASSWORD")
db_port = config("DB_PORT")
db_name = config("DB_NAME")

app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"postgresql://{db_user}:{db_password}@localhost:{db_port}/{db_name}"

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


auth = HTTPTokenAuth(scheme='Bearer')

@auth.verify_token
def verify_token(token):
    try:
        data = jwt.decode(token, config("SECRET_KEY"), algorithms=['HS256'])
        user_id = data["sub"]
        user = User.query.filter_by(id=user_id).first()
        if not user:
            pass
        return user
    except InvalidSignatureError:
        raise BadRequest("Invalid token!")
    except ExpiredSignatureError:
        raise BadRequest("Token expired!")
    except Exception as ex:
        raise ex


def permission_required(role):
    def decorator(func):
        def decorated_function(*args, **kwargs):
            current_user = auth.current_user()
            if current_user.role == role:
                return func(*args, **kwargs)
            raise Forbidden("You don't have permissions to access this resource!")
        return decorated_function
    return decorator


def permission_admin_required(role):
    def decorator(func):
        def decorated_function(*args, **kwargs):
            current_user = auth.current_user()
            if current_user.role in [UserRole.admin, UserRole.super_admin]:
                return func(*args, **kwargs)
            raise Forbidden("You don't have permissions to access this resource!")
        return decorated_function
    return decorator


def validate_schema(schema_name):
    def decorator(func):
        def decorated_function(*args, **kwargs):
            data = request.get_json()
            schema = schema_name()
            errors = schema.validate(data)
            if errors:
                raise BadRequest(errors)
            return func(*args, **kwargs)
        return decorated_function
    return decorator


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


class ColorEnum(enum.Enum):
    pink = "pink aa"
    black = "black"
    white = "white"
    yellow = "yellow"


class UserRole(enum.Enum):
    user = "User"
    admin = "Admin"
    super_admin = "Super Admin"


class SingleClothSchema(Schema):
    id = fields.Integer()
    name = fields.String()
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)
    create_on = fields.DateTime()
    updated_on = fields.DateTime()


class UserOutShema(Schema):
    id = fields.Integer()
    full_name = fields.String()
    clothes = fields.List(fields.Nested(SingleClothSchema), many=True)


class UserSignInSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.String()
    password = fields.String(required=True)

    @validates("full_name")
    def validate_name(self, value):
        try:
            first_name, last_name = value.split()
        except ValueError:
            raise ValidationError(
                "Full name should consists of first and last name at least"
            )
        if len(first_name) < 3 or len(last_name) < 3:
            raise ValueError("Name should be at least 3 characters")


users_clothes = db.Table(
    "users_clothes",
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.Text)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())
    clothes = db.relationship("Clothes", secondary=users_clothes)
    role = db.Column(db.Enum(UserRole), server_default=UserRole.user.name, nullable=False)

    def encode_token(self):
        payload = {"exp": datetime.utcnow() + timedelta(days=2), "sub": self.id}
        try:
            return jwt.encode(payload, config("SECRET_KEY"), algorithm="HS256")
        except Exception as ex:
            raise ex


class Clothes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(db.Enum(ColorEnum), default=ColorEnum.white, nullable=False)
    size = db.Column(db.Enum(SizeEnum), default=SizeEnum.s, nullable=False)
    photo = db.Column(db.String(255), nullable=False)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


class SignUp(Resource):
    @validate_schema(UserSignInSchema)
    def post(self):
        data = request.get_json()
        data["password"] = generate_password_hash(data['password'], method='sha256')
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        token = user.encode_token()
        return {"token": token}, 201


class UserResource(Resource):
    def get(self, pk):
        user = User.query.filter_by(id=pk).first()
        return UserOutShema().dump(user)


class ClothesRouter(Resource):
    @auth.login_required
    @permission_required(UserRole.user)
    def get(self):
        return UserOutShema().dump(auth.current_user())


api.add_resource(SignUp, "/register/")
api.add_resource(ClothesRouter, "/clothes/")
api.add_resource(UserResource, "/users/<int:pk>/")

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
