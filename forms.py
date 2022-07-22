from flask_wtf import FlaskForm as Form
from wtforms import validators, StringField, EmailField, PasswordField, SubmitField, TextAreaField

class RegistrationForm(Form):
    name = StringField('Name', [validators.DataRequired(), validators.Length(min=2, max=50)], render_kw={'autofocus': True})
    username = StringField('Username', [validators.DataRequired() ,validators.Length(min=3, max=25)])
    email = EmailField('Email', [validators.InputRequired(), validators.Length(min=6, max=50)])
    password = PasswordField('Password',
               [validators.DataRequired(),
               validators.EqualTo('confirm', message='Passwords do not match')               
               ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')

class ArticleForm(Form):
    title = StringField('Title', [validators.InputRequired()])
    body = TextAreaField('Body', [validators.Length(min=1)], render_kw={'id': 'mytextarea', 'placeholder': "Unleash the Krakken!"})