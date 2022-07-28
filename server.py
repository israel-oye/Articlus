import os
import html
from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv
from forms import RegistrationForm, ArticleForm
from models import Articles, Users, db
from flask import Flask, abort, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt


load_dotenv()

app = Flask(__name__)
db.init_app(app)

csrf = CSRFProtect(app=app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['WTF_CSRF_ENABLED'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///articlus_db.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(hours=3)


def is_logged_in(f):
    @wraps(f)
    def wrapped_func(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, please login", 'danger')
            return redirect(url_for("login"))
    return wrapped_func

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    input_form = RegistrationForm(request.form)

    if request.method == 'POST' and input_form.validate_on_submit():
        nm = input_form.name.data
        uname = input_form.username.data
        mail = input_form.email.data
        pwd = sha256_crypt.encrypt(str(input_form.password.data)) 

        user = Users.query.filter_by(username=uname).first()
        
        if user is None:
            user = Users(name=nm, username=uname, email=mail, password=pwd)
            db.session.add(user)
            db.session.commit()

            flash("You are now registered and can login", 'success')
            return redirect(url_for('login'))
        else:
            flash("Username is taken!", "danger")
            return redirect(url_for('register'))

    return render_template("register.html", form=input_form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        user_data = Users.query.filter_by(username=username).first()

        if user_data:    
            password = user_data.password

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

@app.route("/dashboard")
@is_logged_in
def dashboard():
    
    articles = Articles.query.filter_by(author=session['username']).all()

    if len(articles) > 0:
        return render_template("dashboard.html", user_articles=articles)
    else:
        msg = f"Oops. User: {session['username']} does not have any article"
        return render_template("dashboard.html", msg=msg, is_empty = True)

@app.route('/articles')
@is_logged_in
def articles():

    articles = Articles.query.filter_by(author=session['username']).all()

    if len(articles) > 0:
        return render_template("article.html", allArticles=articles)
    else:
        msg = f"Oops. User: {session['username']} does not have any article"
        return redirect(url_for("dashboard", msg=msg, is_empty = True))

@app.route('/articles/<int:id>')
def article_page(id):
        
    requested_article = Articles.query.filter_by(id=id).first()
    return render_template("article_page.html", article=requested_article)
  
@app.route("/add_article", methods=['GET', 'POST'])
@is_logged_in
def add_article():
    new_form = ArticleForm(request.form)

    if request.method == 'POST' and new_form.validate_on_submit():
        title = new_form.title.data
        post_body = new_form.body.data

        new_article = Articles(title=title, body=post_body, author=session['username'])
        db.session.add(new_article)
        db.session.commit()

        flash("Article created", 'success')
        return redirect(url_for("dashboard"))

    return render_template("new_article.html", form=new_form)  

@app.route("/edit_article/<string:article_id>", methods=['GET', 'POST'])
@is_logged_in
def edit_article(article_id):
    
    article = Articles.query.get_or_404(article_id)

    if article.author == session['username']:

        edit_form = ArticleForm(request.form)
        edit_form.title.data = article.title
        edit_form.body.data = article.body

        if request.method == 'POST' and edit_form.validate_on_submit():
            title = request.form['title']
            post_body = request.form['body']

            article.title = title
            article.body = post_body
            article.author = session['username']

            db.session.add(article)
            db.session.commit()
                    
            flash("Article edited", 'success')
            return redirect(url_for("dashboard"))

        return render_template("edit_article.html", form=edit_form)

    else:
        flash("Unauthorized access", 'danger')
        return redirect(url_for("dashboard"))

@app.route("/delete_article/<int:id>", methods=['POST'])
@is_logged_in
def delete_article(id):

    article = Articles.query.get_or_404(id)

    if article.author == session['username']:

        db.session.delete(article)
        db.session.commit()

        flash("Article deleted", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Unauthorized access", 'danger')
        return redirect(url_for('dashboard'))

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("Successfully signed out", 'success')
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)