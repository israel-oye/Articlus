from server import db
from datetime import datetime

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(40), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(100))
    register_date = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self) -> str:
        return super().__repr__()

class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    body = db.Column(db.String(1000))
    author = db.Column(db.String(40))
    date_of_creation = db.Column(db.DateTime, default=datetime.utcnow())

    def __repr__(self) -> str:
        return super().__repr__()
