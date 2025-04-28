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

        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Validate password
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            login_user(user, remember=True)
            record_login(user.id, request.remote_addr)
            return redirect(url_for('home'))  # Redirect to home after successful login
        else:
            flash('Invalid email or password', 'danger')  # Error message on failed login

    return render_template('login.html')

# Route for signup
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate password
        if not validate_password(password):
            flash('Password must be at least 8 characters and contain upper, lower, number, special char.', 'danger')
            return redirect(url_for('auth.signup'))

        # Check if the user already exists
        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Username or Email already exists.', 'danger')
            return redirect(url_for('auth.signup'))

        # Hash the password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create a new user
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            auth_method='manual'  # Track authentication method
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
    logout_user()  # Logout the user
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login'))

# Function to validate password complexity
def validate_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

# Function to record login activity
def record_login(user_id, ip_address):
    log = LoginActivity(user_id=user_id, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()

# GitHub OAuth login route
@auth_bp.route('/github_login')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))  # Redirect to GitHub OAuth login

    # Get the user's GitHub information
    user_info = github.get('/user')
    github_username = user_info.json()['login']
    github_email = user_info.json()['email']
    github_id = user_info.json()['id']

    # Check if user already exists
    user = User.query.filter_by(github_id=github_id).first()
    if user:
        login_user(user)
        record_login(user.id, request.remote_addr)
        flash(f"Welcome back, {github_username}!", 'success')
        return redirect(url_for('home'))

    # If user doesn't exist, create a new user
    new_user = User(
        username=github_username,
        email=github_email,
        github_id=github_id,
        auth_method='github'
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    record_login(new_user.id, request.remote_addr)
    flash(f"Welcome, {github_username}!", 'success')
    return redirect(url_for('home'))
