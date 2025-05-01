# Import standard and third-party libraries
import os
from flask import Flask, redirect, url_for, session, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.consumer import oauth_error, oauth_authorized
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(24)  # Secret key for session encryption

# Set up MySQL credentials from environment variables or default values
mysql_user = os.getenv('MYSQL_USER', 'root')
mysql_pass = os.getenv('MYSQL_PASSWORD', '')
mysql_host = os.getenv('MYSQL_HOST', '127.0.0.1')
mysql_port = os.getenv('MYSQL_PORT', '3306')
mysql_db   = os.getenv('MYSQL_DB', 'oauth_db')

# Configure the database URI for SQLAlchemy (MySQL + PyMySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{mysql_user}:{mysql_pass}@{mysql_host}:{mysql_port}/{mysql_db}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking for performance

# Initialize extensions
db = SQLAlchemy(app)           # Database ORM
bcrypt = Bcrypt(app)           # Password hashing
login_manager = LoginManager(app)  # Session manager
login_manager.login_view = 'login' # Default login route for @login_required

# ================================
# Database Models
# ================================

# User model for storing user credentials and auth method
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))  # Only used for manual login
    github_id = db.Column(db.String(50), unique=True, nullable=True)  # GitHub user ID if signed in with GitHub
    auth_method = db.Column(db.String(20), nullable=False)  # 'manual' or 'github'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Account creation time

# LoginLog model to track login attempts (timestamp & IP)
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

# User loader for Flask-Login (used to keep user logged in)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Disable caching for all responses to enhance security (especially logout/login)
@app.after_request
def set_secure_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# ================================
# GitHub OAuth Configuration
# ================================

# Enable OAuth over HTTP (only for development)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Create GitHub OAuth blueprint with client credentials
github_bp = make_github_blueprint(
    client_id=os.getenv("Ov23li96ayqDNuQQpLlw"),
    client_secret=os.getenv("7be3cd53d01bf02fbeee916e4fc7ff17fbd2fd17"),
    scope="read:user",  # Permission scope
    redirect_url="/"    # Redirect after login
)
# Register the GitHub blueprint under /login/github
app.register_blueprint(github_bp, url_prefix="/login")

# Handle OAuth errors (e.g. user denies permission)
@oauth_error.connect_via(github_bp)
def github_oauth_error(blueprint, message, response):
    flash("GitHub login failed. Please try again.", 'danger')
    return redirect(url_for('login'))

# Handle successful GitHub login
@oauth_authorized.connect_via(github_bp)
def github_logged_in(blueprint, token):
    if not token:
        flash("GitHub token missing, authorization failed.", 'danger')
        return False

    # Get user info from GitHub API
    resp = blueprint.session.get("/user")
    if not resp.ok:
        flash("Failed fetching GitHub user info.", 'danger')
        return False
    info = resp.json()

    # Check if user already exists by GitHub ID
    user = User.query.filter_by(github_id=str(info.get('id'))).first()

    if not user:
        # Try finding by email (if available) to link accounts
        user = User.query.filter_by(email=info.get('email')).first()
        if user:
            user.github_id = str(info.get('id'))
            user.auth_method = 'github'
            db.session.commit()
        else:
            # Create new user from GitHub info
            user = User(
                username=info.get('login'),
                email=info.get('email') or f"{info.get('id')}@github",  # fallback email
                github_id=str(info.get('id')),
                auth_method='github'
            )
            db.session.add(user)
            db.session.commit()

    # Log the user in
    login_user(user)
    db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))  # Log login IP
    db.session.commit()

    return redirect(url_for('home'))

# ================================
# Manual Signup/Login Routes
# ================================

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username or email already exists
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('signup'))

        # TODO: Add password strength validation

        # Hash the password and create user
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=pw_hash, auth_method='manual')
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ident = request.form['email']  # Can be email or username
        password = request.form['password']
        remember = 'remember' in request.form

        # Look up user
        user = User.query.filter((User.email==ident)|(User.username==ident)).first()

        # Check password only if manual login is allowed
        if user and user.auth_method == 'manual' and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))
            db.session.commit()
            return redirect(url_for('home'))

        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

# ================================
# Protected Routes
# ================================

@app.route('/')
def home():
    # Redirect to login if not authenticated
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('home.html', username=current_user.username)

@app.route("/profile")
@login_required
def profile():
    # Check if GitHub is authorized (OAuth token present)
    if github.authorized:
        resp = github.get("/user")
        if not resp.ok:
            flash("Failed to fetch GitHub profile.", "danger")
            session.clear()
            return redirect(url_for("home"))
        user_info = resp.json()
        return render_template("profile.html", user=user_info, github_profile_url=user_info.get("html_url"))
    else:
        # Fallback for manual login users or GitHub unlinked
        return render_template(
            "profile.html",
            user=current_user,
            github_profile_url="https://github.com/" + current_user.username if current_user.auth_method == "github" else None
        )

@app.route('/logout')
def logout():
    # Clear session and log out the user
    logout_user()
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# ================================
# Application entry point
# ================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)  # Run app in debug mode (turn off in production)
