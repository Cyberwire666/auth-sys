from flask import Blueprint, render_template, redirect, url_for, request, flash
from models import db, User, LoginActivity
from flask_login import login_user, logout_user, login_required
import bcrypt
import re

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            login_user(user, remember=True)
            record_login(user.id, request.remote_addr)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not validate_password(password):
            flash('Password must be at least 8 characters and contain upper, lower, number, special char.', 'danger')
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

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login'))

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
