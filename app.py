# ==========================================================
# FINAL APP.PY FOR RENDER DEPLOYMENT
# This version uses SQLAlchemy and the App Factory pattern.
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

# --- Initialize Extensions (without an app) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
csrf = CSRFProtect()

# ==========================================================
# DATABASE MODELS (Defines the structure of your tables)
# ==========================================================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

class Menu(db.Model):
    __tablename__ = 'menu'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    image_url = db.Column(db.String(255))
    category = db.Column(db.String(50), default='Coffee')

class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(255), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    order_status = db.Column(db.String(50), default='Pending')
    order_date = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    menu_item = db.relationship('Menu', backref='orders')

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    secret_key_hash = db.Column(db.String(255), nullable=False)

class OtpLog(db.Model):
    __tablename__ = 'otp_logs'
    id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(100), nullable=False)
    otp_code = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    is_used = db.Column(db.Boolean, default=False)

# ==========================================================
# APP FACTORY (The main function to create and configure the app)
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
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'false').lower() in ['true', '1']
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'true').lower() in ['true', '1']
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

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

    # --- Helper Functions ---
    def generate_otp(length=6): return ''.join(random.choices(string.digits, k=length))
    def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    # ==========================================================
    # ALL ROUTES (Indented inside the create_app function)
    # ==========================================================
    @app.route('/')
    def home(): return render_template('home.html')

    @app.route('/menu')
    def menu():
        menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
        return render_template('menu.html', menu_items=menu_items)
    
    # ... Add all your other 20+ routes here, just like menu and home ...
    # (I'm omitting them for brevity, but make sure they are here)

    # --- Temporary Setup Command ---
    @app.cli.command("init-db")
    def init_db_command():
        """Creates database tables and admin user."""
        db.create_all()
        if not Admin.query.filter_by(email='rjndkl1224@gmail.com').first():
            pw_hash = bcrypt.generate_password_hash('RazanIsAdmin').decode('utf-8')
            key_hash = bcrypt.generate_password_hash('RD_Cafe_2024').decode('utf-8')
            admin = Admin(email='rjndkl1224@gmail.com', password_hash=pw_hash, secret_key_hash=key_hash)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created.")
        print("Database initialized.")

    return app

# ==========================================================
# This is needed for gunicorn to find the app
# ==========================================================
app = create_app()