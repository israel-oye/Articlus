import os, requests, json
from datetime import timedelta
from dotenv import load_dotenv
from forms import RegistrationForm, ArticleForm
from models import Article, User, db, migrate
from flask import Flask, abort, render_template, url_for, flash, redirect, request, session
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt
from oauthlib.oauth2 import WebApplicationClient

load_dotenv()

app = Flask(__name__)


csrf = CSRFProtect(app=app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['WTF_CSRF_ENABLED'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.getenv("CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = (u"Unauthorized, please login")
login_manager.login_message_category = "danger"
login_manager.needs_refresh_message = (u"Session timedout, please re-login")
login_manager.needs_refresh_message_category = "info"

db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)

with app.app_context():
    db.create_all()

client = WebApplicationClient(GOOGLE_CLIENT_ID)

c_username = None

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=24)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    input_form = RegistrationForm(request.form)

    if request.method == 'POST' and input_form.validate_on_submit():
        
        uname = input_form.username.data
        mail = input_form.email.data
        pwd = sha256_crypt.encrypt(str(input_form.password.data)) 

        user_exists = False
        
        if User.query.filter_by(email=mail).first() or User.query.filter_by(username=uname).first():
            user_exists = True
        
        if not user_exists:
            user = User(username=uname, email=mail, password=pwd)
            db.session.add(user)
            db.session.commit()
            login_user(user)

            flash("Registered successfully", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash("Email or username is taken!", "danger")
            return redirect(url_for('register'))

    return render_template("register.html", form=input_form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        user_data = User.query.filter_by(email=email).first()

        if user_data:    
            password = user_data.password

            if user_data.password_is_correct(password_candidate):

                app.logger.info("Password matched")
                login_user(user=user_data)

                session["username"] = current_user.username
                global c_username
                c_username = current_user.username

                flash("You are now logged in", 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Incorrect password"
                return render_template("login.html", error=error)
        else:
            error = "User not found"
            return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/auth", methods=['POST'])
def auth():

    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg['authorization_endpoint']

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"]
    )
    return redirect(request_uri)

@app.route("/auth/callback")
def callback():
    code = request.args.get('code')

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg['token_endpoint']
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code = code
    )

    token_response = requests.post(
        url=token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    user_info_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(user_info_endpoint)
    user_info_response = requests.get(url=uri, headers=headers, data=body)

    response = user_info_response.json()

    if response.get("email_verified"):
        u_name = response['given_name']
        u_mail = response['email']
        u_gid = response['sub']
    else:
        flash("Email not verified, please try again...", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=u_mail).first()

    if user is None:
        user = User(username=u_name, email=u_mail)
        user.set_password(u_gid)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session["username"] = current_user.username
    return redirect(url_for('dashboard'))


@app.route("/dashboard")
@login_required
def dashboard():
    
    articles = current_user.articles

    if len(articles) > 0:
        return render_template("dashboard.html", user_articles=articles)
    else:
        msg = f"Oops. User: {current_user.username} does not have any article"
        return render_template("dashboard.html", msg=msg, is_empty = True)

@app.route('/articles')
@login_required
def articles():

    articles = current_user.articles

    if len(articles) > 0:
        return render_template("article.html", allArticles=articles)
    else:
        msg = f"Oops. User: {current_user.username} does not have any article"
        return redirect(url_for("dashboard", msg=msg, is_empty = True))

@app.route('/articles/<int:id>')
@login_required
def article_page(id, username=c_username):
        
    requested_article = Article.query.filter_by(id=id).first()
    if requested_article.author_id != current_user.id:
        flash("Don't be an intruder O_O", category="dark")
        return redirect(url_for('dashboard'))
    return render_template("article_page.html", article=requested_article)
  
@app.route("/<string:username>/add_article", methods=['GET', 'POST'])
@login_required
def add_article(username=c_username):
    new_form = ArticleForm(request.form)

    if request.method == 'POST' and new_form.validate_on_submit():
        title = new_form.title.data
        post_body = new_form.body.data

        new_article = Article(title=title, body=post_body, author=current_user)
        db.session.add(new_article)
        db.session.commit()

        flash("Article created", 'success')
        return redirect(url_for("dashboard"))

    return render_template("new_article.html", form=new_form)  

@app.route("/edit_article/<string:article_id>", methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    try:
        article = Article.query.get_or_404(article_id)
    except:
        msg = "Sorry, that article does not exist."
        flash(msg, category="info")
        return redirect(url_for("dashboard"))
    
    if article.author == current_user:

        edit_form = ArticleForm(request.form)
        edit_form.title.data = article.title
        edit_form.body.data = article.body

        if request.method == 'POST' and edit_form.validate_on_submit():
            title = request.form['title']
            post_body = request.form['body']

            article.title = title
            article.body = post_body
            article.author = current_user

            db.session.add(article)
            db.session.commit()
                    
            flash("Article edited", 'success')
            return redirect(url_for("dashboard"))

        return render_template("edit_article.html", form=edit_form)
    else:
        flash("You are not permitted to do that...", 'danger')
        return redirect(url_for("dashboard"))

@app.route("/delete_article/<int:id>", methods=['POST'])
@login_required
def delete_article(article_id):
    try:
        article = Article.query.get_or_404(article_id)
    except:
        msg = "Sorry, that article does not exist."
        flash(msg, category="info")
        return redirect(url_for("dashboard"))
    if article.author == current_user:

        db.session.delete(article)
        db.session.commit()

        flash("Article deleted", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Unauthorized access", 'danger')
        return redirect(url_for('dashboard'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Successfully signed out", 'success')
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run()