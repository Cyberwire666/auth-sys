from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
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

# Register Blueprint
app.register_blueprint(auth_bp)

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Prevent back navigation after logout (no cache headers)
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response

# Route for homepage, redirects based on user authentication
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('auth.login'))

# Route for user dashboard/home page (protected)
@app.route('/home')
@login_required
def home():
    return render_template('home.html', name=current_user.username)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure database tables are created
    app.run(debug=True)
