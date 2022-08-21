from flask_wtf import FlaskForm as Form
from wtforms import validators, StringField, EmailField, PasswordField, SubmitField, TextAreaField, ValidationError
from models import Users

class RegistrationForm(Form):

    username = StringField('Username', [validators.DataRequired() ,validators.Length(min=3, max=25)], render_kw={'autofocus': True})
    email = EmailField('Email', [validators.InputRequired(), validators.Length(min=6, max=50)])
    password = PasswordField('Password',
               [validators.DataRequired(),
               validators.EqualTo('confirm', message='Passwords do not match')               
               ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Username already exists, please try again.")

    def validate_email(self, email):
        user = Users.query.filter_by(email=email).first()
        if user:
            raise ValidationError("Email is taken!")

class ArticleForm(Form):
    title = StringField('Title', [validators.InputRequired()])
    body = TextAreaField('Body', [validators.Length(min=1)], render_kw={'id': 'mytextarea', 'placeholder': "Unleash the Krakken!"})