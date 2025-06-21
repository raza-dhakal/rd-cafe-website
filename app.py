# ==========================================================
# FINAL APP.PY FOR RENDER DEPLOYMENT
# Corrected order inside create_app()
# ==========================================================

import os
import random
import string
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.consumer import oauth_authorized
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

# --- Load Environment Variables ---
load_dotenv()

# --- Initialize Extensions ---
db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
csrf = CSRFProtect()

# --- Database Models ---
class User(db.Model):
    # ... (All your model classes are here, no change needed)
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    # ... etc

# (Add all your other model classes here: Menu, Order, Admin, OtpLog)

# ==========================================================
# APP FACTORY
# ==========================================================
def create_app():
    app = Flask(__name__)

    # --- Configurations ---
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.config['UPLOAD_FOLDER'] = 'static/images'
    
    # Database Config
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ... (Mail Config is here, no change needed) ...

    # --- Initialize extensions with the app ---
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # --- Register Blueprints ---
    google_blueprint = make_google_blueprint(
        client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
        scope=["profile", "email"]
    )
    app.register_blueprint(google_blueprint, url_prefix="/login")
    
    # ==========================================================
    # >> THE FIX IS HERE <<
    # We define the google_logged_in function FIRST...
    # ==========================================================
    def google_logged_in(blueprint, token):
        if not token:
            flash("Failed to log in with Google.", "danger")
            return False
        resp = blueprint.session.get("/oauth2/v2/userinfo")
        if not resp.ok: return False
        info = resp.json()
        user = User.query.filter_by(email=info['email']).first()
        if not user:
            unusable_pass = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
            user = User(email=info['email'], username=info['name'], password_hash=unusable_pass)
            db.session.add(user)
            db.session.commit()
            flash(f"Welcome, {info['name']}! Your account has been created.", "success")
        session['logged_in'], session['user_id'], session['username'] = True, user.id, user.username
        flash("Successfully logged in with Google!", "success")
        return False
        
    # ==========================================================
    # ... and THEN we connect it.
    # ==========================================================
    oauth_authorized.connect(google_logged_in, blueprint=google_blueprint)

    # --- Helper Functions ---
    # ... (generate_otp and allowed_file functions are here, no change) ...
    
    # ==========================================================
    # ALL ROUTES (Indented inside the create_app function)
    # ==========================================================
    with app.app_context():
        # --- Public & User Routes ---
        @app.route('/')
        def home(): return render_template('home.html')

        # ... (Add ALL your other @app.route functions here) ...
        # ... (menu, signup, login, dashboard, all admin routes, etc.) ...

    # --- Database Setup Command ---
    # ... (The @app.cli.command("init-db") function is here, no change) ...

    return app

# ==========================================================
# This is needed for Gunicorn to find the app
# ==========================================================
app = create_app()