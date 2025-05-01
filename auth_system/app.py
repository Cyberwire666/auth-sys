from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_dance.contrib.github import make_github_blueprint, github
from auth import auth_bp
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Create GitHub OAuth blueprint
github_bp = make_github_blueprint(
    client_id=Config.GITHUB_CLIENT_ID,
    client_secret=Config.GITHUB_CLIENT_SECRET,
    scope="user:email",
    redirect_url='http://127.0.0.1:5000/github/authorized',  # Correct redirect URI
)
app.register_blueprint(github_bp, url_prefix="/github")

# Register your auth blueprint
app.register_blueprint(auth_bp)

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Prevent back navigation after logout
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('auth.login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html', name=current_user.username)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
