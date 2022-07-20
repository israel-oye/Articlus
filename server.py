import os
import html
from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask, abort, render_template, url_for, flash, redirect, request, session, logging
# from data import get_articles
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm as Form
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField, validators
from passlib.hash import sha256_crypt

# all_articles = get_articles()
all_articles = None

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['MYSQL_HOST'] = os.getenv('DB_HOST')
app.config['MYSQL_USER'] = os.getenv('DB_USER')
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = os.getenv('DB_NAME')
app.config['MYSQL_CURSORCLASS'] = os.getenv('DB_CURSOR_CLASS')
app.config['WTF_CSRF_ENABLED'] = False
app.permanent_session_lifetime = timedelta(hours=3)


csrf = CSRFProtect(app=app)

mysql = MySQL(app=app)

@app.route('/')
def home():

    return render_template("home.html")

@app.route('/articles')
def article():
    cursor = mysql.connection.cursor()
    result = cursor.execute("SELECT * FROM articles WHERE author = %s", (session['username'],))
    
    articles = cursor.fetchall()
    cursor.close()

    return render_template("article.html", allArticles=articles)
    

@app.route('/about')
def about():
    
    return render_template("about.html")

@app.route('/articles/<int:id>')
def article_page(id):
    requested_article = None

    cursor = mysql.connection.cursor()
    result = cursor.execute("SELECT * FROM articles WHERE author = %s", (session['username'],))
    
    articles = cursor.fetchall()
    cursor.close()

    for article in articles:
        if article['id'] == id:
            requested_article = article
            return render_template("article_page.html", article=requested_article)

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    input_form = RegistrationForm(request.form)

    if request.method == 'POST' and input_form.validate_on_submit():
        name = input_form.name.data
        username = input_form.username.data
        email = input_form.email.data
        pwd = sha256_crypt.encrypt(str(input_form.password.data)) 

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, username, email, password) VALUES (%s, %s, %s, %s)", (name, username, email, pwd))
        mysql.connection.commit()
        cursor.close()

        flash("You are now registered and can login", 'success')

        return redirect(url_for('login'))

    return render_template("register.html", form=input_form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username, ))
        result = cursor.fetchone()
        

        if result['COUNT(*)'] > 0:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username, ))
            data = cursor.fetchone()
            cursor.close()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                app.logger.info("Password matched")
                session['logged_in'] = True
                session['username'] = username

                flash("You are now logged in", 'success')
                session.permanent = True

                return redirect(url_for('dashboard'))
            else:
                error = "Incorrect password"
                return render_template("login.html", error=error)
            
        else:
            error = "User not found"
            return render_template("login.html", error=error)

    return render_template("login.html")

def is_logged_in(f):
    @wraps(f)
    def wrapped_func(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, please login", 'danger')
            return redirect(url_for("login"))
    return wrapped_func

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("Successfully signed out", 'success')
    return redirect(url_for("login"))

@app.route("/dashboard")
@is_logged_in
def dashboard():
    
    cursor = mysql.connection.cursor()
    result = cursor.execute("SELECT * FROM articles WHERE author = %s", (session['username'],))
    
    articles = cursor.fetchall()
    cursor.close()

    if result > 0:
        return render_template("dashboard.html", user_articles=articles)
    else:
        msg = f"Oops. User: {session['username']} does not have any article"
        return render_template("dashboard.html", msg=msg, is_empty = True)
    

class ArticleForm(Form):
    title = StringField('Title', [validators.InputRequired()], render_kw={'autofocus': True})
    body = TextAreaField('Body', [validators.Length(min=1)], render_kw={'id': 'mytextarea', 'placeholder': "Unleash the Krakken!"})

@app.route("/add_article", methods=['GET', 'POST'])
@is_logged_in
def add_article():
    edit_form = ArticleForm(request.form)

    if request.method == 'POST' and edit_form.validate_on_submit():
        title = edit_form.title.data
        post_body = edit_form.body.data

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO articles (title, body, author) VALUES (%s, %s, %s)", (title, post_body, session['username']))
        mysql.connection.commit()
        cursor.close()

        flash("Article created", 'success')
        return redirect(url_for("dashboard"))

    return render_template("new_article.html", form=edit_form)  

@app.route("/edit_article/<int:id>", methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    cursor = mysql.connection.cursor()
    result = cursor.execute("SELECT * FROM articles WHERE id = %s;", (id,))
    article = cursor.fetchone()

    edit_form = ArticleForm(request.form)
    edit_form.title.data = article['title']
    edit_form.body.data = article['body']

    if request.method == 'POST' and edit_form.validate_on_submit():
        title = request.form['title']
        post_body = request.form['body']

        cursor.execute("UPDATE articles SET title=%s, body=%s WHERE id = %s;", (title, post_body, id))
        

        flash("Article edited", 'success')
        return redirect(url_for("dashboard"))

    return render_template("edit_article.html", form=edit_form)

@app.route("/delete_article/<string:id>", methods=['POST'])
@is_logged_in
def delete_article(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM articles WHERE id = %s;", (id,))
    mysql.connection.commit()
    cursor.close()

    flash("Article deleted", "success")
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True)