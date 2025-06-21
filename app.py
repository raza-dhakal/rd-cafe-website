# ==========================================================
# FINAL APP.PY FOR RENDER DEPLOYMENT (Simplified and Corrected)
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
from flask_dance.contrib.google import make_google_blueprint, google
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
# (Your User, Menu, Order, Admin, OtpLog model classes go here. No changes needed.)
class User(db.Model):
    __tablename__ = 'users'
    # ... all columns ...
class Menu(db.Model):
    __tablename__ = 'menu'
    # ... all columns ...
class Order(db.Model):
    __tablename__ = 'orders'
    # ... all columns ...
class Admin(db.Model):
    __tablename__ = 'admin'
    # ... all columns ...
class OtpLog(db.Model):
    __tablename__ = 'otp_logs'
    # ... all columns ...

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

    # Mail Config
    # ... (Mail config is here, no change needed) ...

    # --- Initialize extensions with the app ---
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # --- Register Blueprints ---
    google_blueprint = make_google_blueprint(
        client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
        scope=["profile", "email"],
        # We add the redirect_to parameter to specify the callback function
        redirect_to='google.authorized'
    )
    app.register_blueprint(google_blueprint, url_prefix="/login")

    # --- Helper Functions ---
    # ... (generate_otp and allowed_file functions are here, no change) ...
    
    # ==========================================================
    # ALL ROUTES (Indented inside the create_app function)
    # ==========================================================
    with app.app_context():
        # --- Public & User Routes ---
        @app.route('/')
        def home(): return render_template('home.html')

        # ... (All your other routes: /menu, /signup, /login, etc.) ...
        
        # ==========================================================
        # >> THE FIX IS HERE <<
        # We create a dedicated route to handle the Google callback.
        # This is the most reliable method.
        # ==========================================================
        @app.route("/login/google/authorized")
        def google_authorized():
            if not google.authorized:
                flash("Failed to log in with Google.", "danger")
                return redirect(url_for("login"))

            resp = google.get("/oauth2/v2/userinfo")
            if not resp.ok:
                flash("Could not fetch user info from Google.", "danger")
                return redirect(url_for("login"))

            info = resp.json()
            user = User.query.filter_by(email=info['email']).first()
            if not user:
                unusable_pass = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
                user = User(email=info['email'], username=info['name'], password_hash=unusable_pass)
                db.session.add(user)
                db.session.commit()
                flash(f"Welcome, {info['name']}! Your account has been created.", "success")
            
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Successfully logged in with Google!", "success")
            return redirect(url_for('dashboard'))

        # ... (All your other admin routes, etc.) ...
    
    # --- Database Setup Command ---
    @app.cli.command("init-db")
    def init_db_command():
        # ... (This function is fine, no change needed) ...
        print("Database initialized.")

    return app

# ==========================================================
# This is needed for Gunicorn to find the app
# ==========================================================
app = create_app()

# =========================================================================
# >> TEMPORARY DEPLOYMENT HACK <<
# (This part is also fine, no change needed)
# =========================================================================
with app.app_context():
    # ... (the one-time setup code) ...