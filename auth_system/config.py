import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'z2G@1X5#f!p9Rj8k7Y2wA6vB@qP#M0sd'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///auth_system.db'  # SQLite DB for simplicity
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # GitHub OAuth keys (set up in GitHub)
    GITHUB_CLIENT_ID = "Ov23liA2DNQPFLuHfZWF"
    GITHUB_CLIENT_SECRET = "7f139ea1186f791bc9214c70296ae59f12193a81"
