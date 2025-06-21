# ==============================================================================
# SECTION 1: IMPORTS
# Sabai chahine libraries haru import garne
# ==============================================================================
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
from flask_dance.consumer import oauth_authorized
from werkzeug.utils import secure_filename

# ==============================================================================
# >> DEPLOYMENT CHANGE 1: Import SQLAlchemy <<
# Hami `flask_mysqldb` ko satta `flask_sqlalchemy` use garchhau
# ==============================================================================
from flask_sqlalchemy import SQLAlchemy

# ==============================================================================
# SECTION 2: INITIAL SETUP AND CONFIGURATION
# App lai initialize garne ra .env file bata sabai settings load garne
# ==============================================================================
load_dotenv()
app = Flask(__name__)

# CSRF Protection ko lagi
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_fallback_secret_key_for_rd_cafe')
csrf = CSRFProtect(app)

# Google OAuth ko lagi
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Image upload ko lagi
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ==============================================================================
# >> DEPLOYMENT CHANGE 2: Database Configuration <<
# Yo code le check garchha: yedi 'DATABASE_URL' (Render le dine URL) chha bhane,
# tyo use garne, natra local development ko lagi puranai .env bata line
# ==============================================================================
database_url = os.getenv("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Render ko PostgreSQL URL lai SQLAlchemy ko format ma change garne
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail Configuration (jastai ko testai)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# ==============================================================================
# SECTION 3: INITIALIZE EXTENSIONS
# Sabai Flask extensions haru lai initialize garne
# ==============================================================================
db = SQLAlchemy(app) # Naya SQLAlchemy object
bcrypt = Bcrypt(app)
mail = Mail(app)

# Google OAuth Blueprint (jastai ko testai)
google_blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"]
)
app.register_blueprint(google_blueprint)

# ==============================================================================
# >> DEPLOYMENT CHANGE 3: Define Database Models <<
# SQLAlchemy ko lagi, hami table lai Python class ko rup ma define garchhau.
# Yesle code lai dherai clean banauchha ra MySQL/PostgreSQL dubai sanga kaam garchha.
# ==============================================================================
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
    image_url = db.Column(db.String(255), nullable=False)
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
    # Relationships
    menu_item = db.relationship('Menu', backref='orders')
    user = db.relationship('User', backref='orders')

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

# ==============================================================================
# >> DEPLOYMENT CHANGE 4: Create Tables Command <<
# Yo command le hami lai Render ko server ma table haru banauna maddat garchha
# ==============================================================================
@app.cli.command("create-db")
def create_db():
    """Creates all database tables."""
    with app.app_context():
        db.create_all()
    print("Database tables created!")

# --- Helper Functions ---
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==============================================================================
# SECTION 4: ROUTES
# Sabai page routes haru. Maile `cur.execute` lai SQLAlchemy ko query le replace gareko chhu.
# ==============================================================================

# --- Public & User Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/menu')
def menu():
    menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
    return render_template('menu.html', menu_items=menu_items)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('This email is already registered.', 'danger')
            return redirect(url_for('signup'))
            
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

# ... (baki sabai routes haru lai pani SQLAlchemy ko tarikale update gareko chha) ...

# --- Admin Routes ---
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
    return render_template('admin_dashboard.html', menu_items=menu_items)
    
# ... (Yaha baki sabai routes haru hunchhan... maile lamo nahos bhanera omit gareko chhu, 
# tara maile hajurko sabai functionality lai SQLAlchemy ma convert gareko chhu.
# The full final code will be provided when you are ready.)