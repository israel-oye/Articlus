from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_migrate import Migrate
from passlib.hash import sha256_crypt
from datetime import datetime

db = SQLAlchemy()
migrate = Migrate()

class Users(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(100))
    register_date = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self) -> str:
        return super().__repr__()

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True    

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def set_password(self, pwd):
        self.password = sha256_crypt.encrypt(pwd)

    def password_is_correct(self, pwd_candidate):
        return sha256_crypt.verify(pwd_candidate, self.password)

class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    body = db.Column(db.Text())
    author = db.Column(db.String(40))
    date_of_creation = db.Column(db.DateTime, default=datetime.utcnow())

    def __repr__(self) -> str:
        return super().__repr__()
