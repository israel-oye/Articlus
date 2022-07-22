import os
import html
from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv
from forms import RegistrationForm, ArticleForm
import data as db
from flask import Flask, abort, render_template, url_for, flash, redirect, request, session
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt


load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['WTF_CSRF_ENABLED'] = False
app.permanent_session_lifetime = timedelta(hours=3)


csrf = CSRFProtect(app=app)


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
        name = input_form.name.data
        username = input_form.username.data
        email = input_form.email.data
        pwd = sha256_crypt.encrypt(str(input_form.password.data)) 

        db.connect_database()
        db.register_user(name=name, username=username, email=email, password=pwd)

        flash("You are now registered and can login", 'success')

        return redirect(url_for('login'))

    return render_template("register.html", form=input_form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    db.connect_database()

    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        user_data = db.fetch_data(username)

        if user_data:    
            password = user_data['password']

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
    db.connect_database() 
    articles = db.get_articles(session['username'])

    if articles:
        return render_template("dashboard.html", user_articles=articles)
    else:
        msg = f"Oops. User: {session['username']} does not have any article"
        return render_template("dashboard.html", msg=msg, is_empty = True)

@app.route('/articles')
@is_logged_in
def articles():
    
    db.connect_database()
    articles = db.get_articles(author=session['username'])

    if articles:
        return render_template("article.html", allArticles=articles)
    else:
        msg = f"Oops. User: {session['username']} does not have any article"
        return redirect(url_for("dashboard.html", msg=msg, is_empty = True))

@app.route('/articles/<string:id>')
def article_page(id):
    requested_article = None

    db.connect_database()
    articles = db.get_articles(author=session['username'])
    
    for article in articles:
        if article['id'] == id:
            requested_article = article
            return render_template("article_page.html", article=requested_article)
  
@app.route("/add_article", methods=['GET', 'POST'])
@is_logged_in
def add_article():
    edit_form = ArticleForm(request.form)

    if request.method == 'POST' and edit_form.validate_on_submit():
        title = edit_form.title.data
        post_body = edit_form.body.data

        db.connect_database()
        db.create_article(title=title, body=post_body, author=session['username'])

        flash("Article created", 'success')
        return redirect(url_for("dashboard"))

    return render_template("new_article.html", form=edit_form)  

@app.route("/edit_article/<string:id>", methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    db.connect_database()
    article = db.get_article(id=id)

    edit_form = ArticleForm(request.form)
    edit_form.title.data = article['title']
    edit_form.body.data = article['body']

    if request.method == 'POST' and edit_form.validate_on_submit():
        title = request.form['title']
        post_body = request.form['body']

        db.connect_database()
        db.update_article(id=id, title=title, body=post_body)
                
        flash("Article edited", 'success')
        return redirect(url_for("dashboard"))

    return render_template("edit_article.html", form=edit_form)

@app.route("/delete_article/<int:id>", methods=['POST'])
@is_logged_in
def delete_article(id):
    
    db.connect_database()
    db.delete_article(article_id=id)

    flash("Article deleted", "success")
    return redirect(url_for('dashboard'))

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("Successfully signed out", 'success')
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)