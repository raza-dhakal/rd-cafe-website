# ==========================================================
# FINAL, COMPLETE, AND CORRECTED APP.PY FOR RENDER
# This version is fully reviewed and includes all features.
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

# --- Initialize Extensions (globally) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
csrf = CSRFProtect()
google_blueprint = make_google_blueprint()

# ==========================================================
# DATABASE MODELS
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
# APP FACTORY
# ==========================================================
def create_app():
    app = Flask(__name__)

    # --- Configurations ---
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.config['UPLOAD_FOLDER'] = 'static/images'
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'false').lower() in ['true', '1']
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'true').lower() in ['true', '1']
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # --- Initialize extensions ---
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # --- Register Blueprints ---
    google_blueprint.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    google_blueprint.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    google_blueprint.scope = [
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ]
    app.register_blueprint(google_blueprint, url_prefix="/login")

    # --- Helper Functions ---
    def generate_otp(length=6): return ''.join(random.choices(string.digits, k=length))
    def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # ==========================================================
    # ALL ROUTES ARE DEFINED HERE
    # ==========================================================
    
    # --- Public & User Routes ---
    @app.route('/')
    def home(): return render_template('home.html')

    @app.route('/menu')
    def menu():
        menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
        return render_template('menu.html', menu_items=menu_items)
    
    @app.route('/owner-info')
    def owner_info(): return render_template('owner_info.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username, email, password = request.form['username'], request.form['email'], request.form['password']
            if User.query.filter_by(email=email).first():
                flash('This email is already registered.', 'danger')
                return redirect(url_for('signup'))
            new_user = User(username=username, email=email, password_hash=bcrypt.generate_password_hash(password).decode('utf-8'))
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        return render_template('signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email, password = request.form['email'], request.form['password']
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                session['logged_in'], session['user_id'], session['username'] = True, user.id, user.username
                flash('You have been logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Check email and password.', 'danger')
        return render_template('login.html')

    @app.route("/login/google/authorized")
    def google_authorized():
        if not google.authorized:
            flash("Google login failed.", "danger")
            return redirect(url_for("login"))
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            flash("Could not fetch user info from Google.", "danger")
            return redirect(url_for("login"))
        info = resp.json()
        email = info.get('email')
        if not email:
            flash("Could not retrieve email from Google.", "danger")
            return redirect(url_for("login"))
        user = User.query.filter_by(email=email).first()
        if not user:
            unusable_pass = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
            user = User(email=email, username=info.get('name'), password_hash=unusable_pass)
            db.session.add(user)
            db.session.commit()
            flash(f"Welcome, {info.get('name')}! Your account has been created.", "success")
        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        flash("Successfully logged in with Google!", "success")
        return redirect(url_for('dashboard'))

    @app.route('/dashboard')
    def dashboard():
        if 'logged_in' not in session: return redirect(url_for('login'))
        return render_template('dashboard.html')

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('home'))

    @app.route('/order', methods=['GET', 'POST'])
    def order():
        menu_items = Menu.query.with_entities(Menu.id, Menu.name, Menu.price).order_by(Menu.name).all()
        if request.method == 'POST':
            new_order = Order(
                customer_name=request.form['customer_name'],
                menu_item_id=request.form['menu_item_id'],
                quantity=request.form['quantity'],
                payment_method=request.form['payment_method'],
                user_id=session.get('user_id')
            )
            db.session.add(new_order)
            db.session.commit()
            flash('Your order has been placed successfully!', 'success')
            return redirect(url_for('menu'))
        return render_template('order.html', menu_items=menu_items)

    # --- Admin Routes ---
    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            email, password, secret_key = request.form['email'], request.form['password'], request.form['secret_key']
            admin = Admin.query.filter_by(email=email).first()
            if admin and bcrypt.check_password_hash(admin.password_hash, password) and bcrypt.check_password_hash(admin.secret_key_hash, secret_key):
                otp_code = generate_otp()
                try:
                    msg = Message("Your RD Cafe Admin Login PIN", recipients=[admin.email], body=f"Your one-time PIN is: {otp_code}")
                    mail.send(msg)
                    new_otp = OtpLog(admin_email=admin.email, otp_code=otp_code)
                    db.session.add(new_otp)
                    db.session.commit()
                    session['admin_email_for_otp_verification'] = admin.email
                    flash('A PIN code has been sent to your email.', 'info')
                    return redirect(url_for('admin_verify_otp'))
                except Exception as e:
                    flash(f'Failed to send email. Error: {e}', 'danger')
            else:
                flash('Invalid credentials.', 'danger')
        return render_template('admin_login.html')

    @app.route('/admin/verify-otp', methods=['GET', 'POST'])
    def admin_verify_otp():
        if 'admin_email_for_otp_verification' not in session: return redirect(url_for('admin_login'))
        if request.method == 'POST':
            user_otp, admin_email = request.form['otp'], session['admin_email_for_otp_verification']
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            valid_otp = OtpLog.query.filter(OtpLog.admin_email == admin_email, OtpLog.otp_code == user_otp, OtpLog.is_used == False, OtpLog.created_at > five_minutes_ago).first()
            if valid_otp:
                valid_otp.is_used = True
                db.session.commit()
                session.pop('admin_email_for_otp_verification', None)
                session['admin_logged_in'], session['admin_email'] = True, admin_email
                flash('Verification successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid or expired PIN.', 'danger')
                return redirect(url_for('admin_login'))
        return render_template('admin_verify_otp.html')
        
    @app.route('/admin/dashboard')
    def admin_dashboard():
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
        return render_template('admin_dashboard.html', menu_items=menu_items)

    @app.route('/admin/logout')
    def admin_logout():
        session.pop('admin_logged_in', None)
        session.pop('admin_email', None)
        flash('Logged out from admin panel.', 'success')
        return redirect(url_for('admin_login'))

    @app.route('/admin/menu/add', methods=['GET', 'POST'])
    def add_menu_item():
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        if request.method == 'POST':
            file = request.files.get('image')
            if not file or file.filename == '' or not allowed_file(file.filename):
                flash('Valid image file is required.', 'danger')
                return redirect(request.url)
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(str(uuid.uuid4()) + '.' + ext)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_item = Menu(name=request.form['name'], description=request.form['description'], price=request.form['price'], category=request.form['category'], image_url=filename)
            db.session.add(new_item)
            db.session.commit()
            flash('New menu item added!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('add_menu.html')

    @app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
    def edit_menu_item(item_id):
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        item = Menu.query.get_or_404(item_id)
        if request.method == 'POST':
            item.name, item.description, item.price, item.category = request.form['name'], request.form['description'], request.form['price'], request.form['category']
            file = request.files.get('image')
            if file and file.filename != '' and allowed_file(file.filename):
                if item.image_url and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url))
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(str(uuid.uuid4()) + '.' + ext)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.image_url = filename
            db.session.commit()
            flash('Menu item updated!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_menu.html', item=item)

    @app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
    def delete_menu_item(item_id):
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        item = Menu.query.get_or_404(item_id)
        if item.image_url and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url))
        db.session.delete(item)
        db.session.commit()
        flash('Menu item deleted.', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/orders')
    def admin_view_orders():
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        orders = db.session.query(Order.order_id, Order.customer_name, Menu.name.label('menu_item_name'), Order.quantity, Order.payment_method, Order.order_status, Order.order_date).join(Menu).order_by(Order.order_date.desc()).all()
        return render_template('admin_orders.html', orders=orders)

    @app.route('/admin/order/update/<int:order_id>', methods=['POST'])
    def admin_update_order_status(order_id):
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        order = Order.query.get_or_404(order_id)
        new_status = request.form.get('status')
        if new_status in ['Completed', 'Cancelled']:
            order.order_status = new_status
            db.session.commit()
            flash(f'Order #{order_id} updated to "{new_status}".', 'success')
        else:
            flash('Invalid status.', 'danger')
        return redirect(url_for('admin_view_orders'))

    @app.route('/admin/users')
    def admin_view_users():
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template('admin_view_users.html', users=users)

    @app.route('/admin/user/reset/<int:user_id>', methods=['GET', 'POST'])
    def admin_reset_user_password(user_id):
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        user = User.query.get_or_404(user_id)
        if request.method == 'POST':
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            try:
                msg = Message("Your RD Cafe Password Has Been Reset", recipients=[user.email], body=f"Your new temporary password is: {new_password}")
                mail.send(msg)
                flash(f"Password for {user.email} has been reset and sent.", 'success')
            except Exception as e:
                flash(f'Password reset but failed to send email: {e}', 'warning')
            return redirect(url_for('admin_view_users'))
        return render_template('admin_reset_password.html', user=user)

    @app.route('/admin/otp-logs')
    def admin_otp_logs():
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        logs = OtpLog.query.order_by(OtpLog.created_at.desc()).all()
        return render_template('admin_otp_logs.html', logs=logs)

    return app

# ==========================================================
# This is needed for Gunicorn to find the app
# ==========================================================
app = create_app()

# =========================================================================
# >> TEMPORARY DEPLOYMENT HACK <<
# =========================================================================
with app.app_context():
    print("Executing one-time database setup...")
    db.create_all()
    if not Admin.query.filter_by(email='rjndkl1224@gmail.com').first():
        print("Admin user not found, creating one...")
        pw_hash = bcrypt.generate_password_hash('RazanIsAdmin').decode('utf-8')
        key_hash = bcrypt.generate_password_hash('RD_Cafe_2024').decode('utf-8')
        new_admin = Admin(email='rjndkl1224@gmail.com', password_hash=pw_hash, secret_key_hash=key_hash)
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")
    
    if Menu.query.count() == 0:
        print("Menu is empty, adding sample items...")
        sample_menu = [
            Menu(name='Espresso', description='Concentrated coffee.', price=150.00, image_url='hot-espresso.jpg', category='Hot Coffee'),
            Menu(name='Latte', description='Espresso with steamed milk.', price=220.00, image_url='hot-latte.jpg', category='Hot Coffee'),
            Menu(name='Lava Cake', description='Molten chocolate cake.', price=350.00, image_url='lava-cake.jpg', category='Cake')
        ]
        db.session.bulk_save_objects(sample_menu)
        db.session.commit()
        print("Sample menu items added.")
    else:
        print("Menu already has items.")
    print("One-time setup finished.")