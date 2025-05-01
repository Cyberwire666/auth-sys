from flask import Blueprint, render_template, redirect, url_for, request, flash
from models import db, User, LoginActivity
from flask_login import login_user, logout_user, login_required
import bcrypt
import re
from flask_dance.contrib.github import github

auth_bp = Blueprint('auth', __name__)

# Route for login
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            login_user(user, remember=True)
            record_login(user.id, request.remote_addr)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

# Route for signup
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not validate_password(password):
            flash('Password must be at least 8 characters and contain upper, lower, number, and special char.', 'danger')
            return redirect(url_for('auth.signup'))

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Username or Email already exists.', 'danger')
            return redirect(url_for('auth.signup'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            auth_method='manual'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')

# Route for logout
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login'))

# Route for GitHub login
@auth_bp.route('/github')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))

    resp = github.get("/user")
    if not resp.ok:
        flash('Failed to fetch user info from GitHub.', 'danger')
        return redirect(url_for('auth.login'))

    github_info = resp.json()
    github_id = str(github_info['id'])
    github_username = github_info['login']
    github_email = github_info.get('email')

    # Sometimes GitHub hides email, so fallback
    if not github_email:
        emails_resp = github.get("/user/emails")
        if emails_resp.ok:
            github_email = emails_resp.json()[0]['email']

    # Check if user exists
    user = User.query.filter_by(github_id=github_id).first()

    if not user:
        user = User(
            username=github_username,
            email=github_email or f"{github_username}@github.com",
            password_hash=bcrypt.hashpw(b'github_dummy_password', bcrypt.gensalt()),
            github_id=github_id,
            auth_method='github'
        )
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    record_login(user.id, request.remote_addr)
    flash(f'Logged in as {github_username} via GitHub!', 'success')
    return redirect(url_for('home'))

# Route for GitHub OAuth callback
@auth_bp.route('/github/authorized')
def github_authorized():
    if not github.authorized:
        flash("GitHub login failed.", 'danger')
        return redirect(url_for('auth.login'))

    resp = github.get('/user')
    if not resp.ok:
        flash("Failed to fetch user info from GitHub.", 'danger')
        return redirect(url_for('auth.login'))

    github_info = resp.json()
    github_id = str(github_info['id'])
    github_username = github_info['login']
    github_email = github_info.get('email')

    # Handle the case where email is not public on GitHub
    if not github_email:
        emails_resp = github.get("/user/emails")
        if emails_resp.ok:
            github_email = emails_resp.json()[0]['email']

    # Check if user exists in the database
    user = User.query.filter_by(github_id=github_id).first()

    if not user:
        user = User(
            username=github_username,
            email=github_email or f"{github_username}@github.com",
            password_hash=bcrypt.hashpw(b'github_dummy_password', bcrypt.gensalt()),
            github_id=github_id,
            auth_method='github'
        )
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    record_login(user.id, request.remote_addr)
    flash(f'Logged in as {github_username} via GitHub!', 'success')
    return redirect(url_for('home'))

# Helper functions
def validate_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

def record_login(user_id, ip_address):
    log = LoginActivity(user_id=user_id, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()
