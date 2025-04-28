from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

# ================================
# User model for authentication
# ================================
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)  # Password stored as a hash
    github_id = db.Column(db.String(150), unique=True, nullable=True)
    auth_method = db.Column(db.String(50), nullable=False)  # e.g., 'manual' or 'github'
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships
    login_activities = db.relationship('LoginActivity', backref='user', lazy=True, cascade="all, delete")

# ========================================
# LoginActivity model for tracking logins
# ========================================
class LoginActivity(db.Model):
    __tablename__ = 'login_activity'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    ip_address = db.Column(db.String(100), nullable=False)
