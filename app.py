# ==============================================================================
# FINAL, COMPLETE, AND CORRECTED APP.PY FOR RENDER DEPLOYMENT
# This version uses SQLAlchemy and the App Factory pattern.
# ==============================================================================

import os
import random
import string
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, session, flash, abort
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

# --- 1. Load Environment Variables ---
# Make sure you have a .env file locally with:
# DATABASE_URL, SECRET_KEY, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET
load_dotenv()

# --- 2. Initialize Extensions (globally, without an app) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
csrf = CSRFProtect()
google_blueprint = make_google_blueprint()

# ==============================================================================
# --- 3. DATABASE MODELS (Your table structures in Python) ---
# ==============================================================================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    
    # Relationship to Orders
    orders = db.relationship('Order', backref='user', lazy=True)

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
    
    # Relationship to Menu
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


# ==============================================================================
# --- 4. APP FACTORY (The main function to create and configure the app) ---
# ==============================================================================
def create_app():
    app = Flask(__name__)

    # --- Configurations ---
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key_123')
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Required for local development with Google OAuth
    app.config['UPLOAD_FOLDER'] = 'static/images'
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        # Fix for SQLAlchemy/Render compatibility for PostgreSQL
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///rd_cafe.db' # Fallback for local testing
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Flask-Mail configuration
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
    google_blueprint.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    google_blueprint.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    google_blueprint.scope = ["profile", "email"]
    app.register_blueprint(google_blueprint, url_prefix="/login")

    # --- Helper and Decorator Functions ---

    def generate_otp(length=6):
        return ''.join(random.choices(string.digits, k=length))
        
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                flash('You must log in to access this page.', 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                flash('You must log in as an administrator to access this page.', 'danger')
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated_function

    # --- ALL ROUTES GO INSIDE THIS FUNCTION ---
    
    # --- Public Routes ---
    @app.route('/')
    def home(): 
        return render_template('home.html')

    @app.route('/menu')
    def menu():
        menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
        return render_template('menu.html', menu_items=menu_items)
    
    @app.route('/owner-info')
    def owner_info(): 
        return render_template('owner_info.html')

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            message = request.form['message']
            
            try:
                msg = Message(f"New Contact Message from {name}",
                              recipients=[app.config['MAIL_DEFAULT_SENDER']],
                              body=f"Name: {name}\nEmail: {email}\nMessage:\n{message}")
                mail.send(msg)
                flash('Your message has been sent successfully!', 'success')
            except Exception as e:
                # Fallback in case email fails during local testing/config issue
                print(f"EMAIL SEND ERROR: {e}") 
                flash(f'Failed to send message. Please try again later. (Error: {e})', 'danger')
            
            return redirect(url_for('contact'))
        return render_template('contact.html')

    # --- User Authentication Routes ---
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username, email, password = request.form['username'], request.form['email'], request.form['password']
            if User.query.filter_by(email=email).first():
                flash('This email is already registered.', 'danger')
                return redirect(url_for('signup'))
            
            # Check if username is already taken (Optional, but good practice)
            if User.query.filter_by(username=username).first():
                flash('This username is already taken.', 'danger')
                return redirect(url_for('signup'))
            
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email, password = request.form['email'], request.form['password']
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                session['logged_in'], session['user_id'], session['username'] = True, user.id, user.username
                flash(f'Welcome, {user.username}! You have been logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Check email and password.', 'danger')
        return render_template('login.html')

    @app.route("/login/google/authorized")
    def google_authorized():
        if not google.authorized:
            flash("Failed to log in with Google.", "danger")
            return redirect(url_for("login"))
        
        try:
            resp = google.get("/oauth2/v2/userinfo")
            if not resp.ok:
                flash("Could not fetch user info from Google.", "danger")
                return redirect(url_for("login"))
            info = resp.json()
        except Exception as e:
             flash(f"Google OAuth Error: {e}", "danger")
             return redirect(url_for("login"))
             
        user = User.query.filter_by(email=info['email']).first()
        
        if not user:
            # Create a user with a long, unusable password (since they log in via Google)
            unusable_pass = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
            user = User(email=info['email'], username=info['name'], password_hash=unusable_pass)
            db.session.add(user)
            db.session.commit()
            flash(f"Welcome, {info['name']}! Your account has been created.", "success")
            
        session['logged_in'], session['user_id'], session['username'] = True, user.id, user.username
        flash("Successfully logged in with Google!", "success")
        return redirect(url_for('dashboard'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('home'))

    # --- Ordering Routes ---
    @app.route('/order', methods=['GET', 'POST'])
    def order():
        menu_items = Menu.query.with_entities(Menu.id, Menu.name, Menu.price).order_by(Menu.name).all()
        if request.method == 'POST':
            user_id = session.get('user_id')
            customer_name = session.get('username') if user_id else request.form['customer_name']
            
            # Basic validation
            if not customer_name:
                flash('Customer name is required.', 'danger')
                return redirect(url_for('order'))
            
            try:
                new_order = Order(
                    customer_name=customer_name,
                    menu_item_id=request.form['menu_item_id'],
                    quantity=int(request.form['quantity']),
                    payment_method=request.form['payment_method'],
                    user_id=user_id
                )
                db.session.add(new_order)
                db.session.commit()
                flash('Your order has been placed successfully!', 'success')
                # Redirect logged-in users to my_orders, others to menu
                return redirect(url_for('my_orders') if user_id else url_for('menu'))
            except Exception as e:
                flash(f'Failed to place order: {e}', 'danger')
                return redirect(url_for('order'))
                
        return render_template('order.html', menu_items=menu_items)

    @app.route('/my-orders')
    @login_required
    def my_orders():
        # Joins Order table with Menu table to get the item name
        orders = db.session.query(
            Order.order_id,
            Menu.name.label('menu_item_name'),
            Order.quantity,
            Order.payment_method,
            Order.order_status,
            Order.order_date
        ).join(Menu).filter(Order.user_id == session['user_id']).order_by(Order.order_date.desc()).all()
        
        return render_template('my_orders.html', orders=orders)


    # --- Admin Authentication Routes ---
    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            email, password, secret_key = request.form['email'], request.form['password'], request.form['secret_key']
            admin = Admin.query.filter_by(email=email).first()
            
            if admin and bcrypt.check_password_hash(admin.password_hash, password) and bcrypt.check_password_hash(admin.secret_key_hash, secret_key):
                otp_code = generate_otp()
                
                try:
                    msg = Message("Your RD Cafe Admin Login PIN", 
                                  recipients=[admin.email], 
                                  body=f"Your one-time PIN is: {otp_code}\nIt is valid for 5 minutes.")
                    mail.send(msg)
                    
                    new_otp = OtpLog(admin_email=admin.email, otp_code=otp_code)
                    db.session.add(new_otp)
                    db.session.commit()
                    
                    session['admin_email_for_otp_verification'] = admin.email
                    flash('A 6-digit PIN code has been sent to your admin email. Please enter it to log in.', 'info')
                    return redirect(url_for('admin_verify_otp'))
                except Exception as e:
                    flash(f'Failed to send email. Check your MAIL_ configuration. Error: {e}', 'danger')
            else:
                flash('Invalid credentials.', 'danger')
        return render_template('admin_login.html')

    @app.route('/admin/verify-otp', methods=['GET', 'POST'])
    def admin_verify_otp():
        if 'admin_email_for_otp_verification' not in session: 
            flash('Please start the PIN verification process.', 'warning')
            return redirect(url_for('admin_login'))
            
        if request.method == 'POST':
            user_otp, admin_email = request.form['otp'], session['admin_email_for_otp_verification']
            
            # OTP is valid for 5 minutes from its creation time
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            
            # Find the most recent, unused, and non-expired OTP
            valid_otp = OtpLog.query.filter(
                OtpLog.admin_email == admin_email, 
                OtpLog.otp_code == user_otp, 
                OtpLog.is_used == False, 
                OtpLog.created_at > five_minutes_ago
            ).order_by(OtpLog.created_at.desc()).first()

            if valid_otp:
                valid_otp.is_used = True
                db.session.commit()
                
                session.pop('admin_email_for_otp_verification', None)
                session['admin_logged_in'] = True
                session['admin_email'] = admin_email
                flash('Verification successful! Welcome to the Admin Dashboard.', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid or expired PIN.', 'danger')
                return redirect(url_for('admin_login')) 
        return render_template('admin_verify_otp.html')

    @app.route('/admin/dashboard')
    @admin_required
    def admin_dashboard():
        menu_items = Menu.query.order_by(Menu.category, Menu.id).all()
        return render_template('admin_dashboard.html', menu_items=menu_items)

    @app.route('/admin/logout')
    def admin_logout():
        session.pop('admin_logged_in', None)
        session.pop('admin_email', None)
        flash('Logged out from admin panel.', 'success')
        return redirect(url_for('admin_login'))

    # --- Admin Menu Management Routes ---
    @app.route('/admin/menu/add', methods=['GET', 'POST'])
    @admin_required
    def add_menu_item():
        if request.method == 'POST':
            file = request.files.get('image')
            
            if not file or file.filename == '' or not allowed_file(file.filename):
                flash('Valid image file is required.', 'danger')
                return redirect(request.url)
                
            try:
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(str(uuid.uuid4()) + '.' + ext)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                new_item = Menu(
                    name=request.form['name'], 
                    description=request.form['description'], 
                    price=request.form['price'], 
                    category=request.form['category'], 
                    image_url=filename
                )
                db.session.add(new_item)
                db.session.commit()
                flash(f'New menu item "{request.form["name"]}" added!', 'success')
                return redirect(url_for('admin_dashboard'))
            except Exception as e:
                 flash(f'Error adding item: {e}', 'danger')
                 return redirect(request.url)

        return render_template('add_menu.html')

    @app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
    @admin_required
    def edit_menu_item(item_id):
        item = Menu.query.get_or_404(item_id)
        if request.method == 'POST':
            item.name, item.description, item.price, item.category = \
                request.form['name'], request.form['description'], request.form['price'], request.form['category']
                
            file = request.files.get('image')
            if file and file.filename != '' and allowed_file(file.filename):
                # 1. Delete old file if it exists
                if item.image_url and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url))
                
                # 2. Save new file
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(str(uuid.uuid4()) + '.' + ext)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.image_url = filename
                
            db.session.commit()
            flash('Menu item updated!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_menu.html', item=item)

    @app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
    @admin_required
    def delete_menu_item(item_id):
        item = Menu.query.get_or_404(item_id)
        
        # Delete image file
        if item.image_url and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image_url))
            
        db.session.delete(item)
        db.session.commit()
        flash(f'Menu item "{item.name}" deleted.', 'success')
        return redirect(url_for('admin_dashboard'))

    # --- Admin Order Management Routes ---
    @app.route('/admin/orders')
    @admin_required
    def admin_view_orders():
        # Joins Order table with Menu table to get the item name
        orders = db.session.query(
            Order.order_id, 
            Order.customer_name, 
            Menu.name.label('menu_item_name'), 
            Order.quantity, 
            Order.payment_method, 
            Order.order_status, 
            Order.order_date
        ).join(Menu).order_by(Order.order_date.desc()).all()
        return render_template('admin_orders.html', orders=orders)

    @app.route('/admin/order/update/<int:order_id>', methods=['POST'])
    @admin_required
    def admin_update_order_status(order_id):
        order = Order.query.get_or_404(order_id)
        new_status = request.form.get('status')
        
        if new_status in ['Completed', 'Cancelled']:
            order.order_status = new_status
            db.session.commit()
            flash(f'Order #{order_id} updated to "{new_status}".', 'success')
        else:
            flash('Invalid status.', 'danger')
        return redirect(url_for('admin_view_orders'))

    # --- Admin User Management Routes ---
    @app.route('/admin/users')
    @admin_required
    def admin_view_users():
        # Only show standard users (not admin records in the Admin table)
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template('admin_view_users.html', users=users)

    @app.route('/admin/user/reset/<int:user_id>', methods=['GET', 'POST'])
    @admin_required
    def admin_reset_user_password(user_id):
        user = User.query.get_or_404(user_id)
        
        # Prevent accidentally resetting the admin's own account from the user list if it somehow exists in both tables.
        # This route should only handle the User table.
        if user.email == session.get('admin_email'):
             flash('You cannot reset your own admin password from the user management panel.', 'warning')
             return redirect(url_for('admin_view_users'))

        if request.method == 'POST':
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            
            try:
                msg = Message("Your RD Cafe Password Has Been Reset", 
                              recipients=[user.email], 
                              body=f"Your password has been reset by the administrator. Your new temporary password is: {new_password}\nPlease log in and change it immediately.")
                mail.send(msg)
                flash(f"Password for {user.email} has been reset and sent via email.", 'success')
            except Exception as e:
                print(f"EMAIL SEND ERROR: {e}")
                flash('Password reset successfully, but failed to send email. You must manually inform the user of their new password.', 'warning')
                
            return redirect(url_for('admin_view_users'))
        return render_template('admin_reset_password.html', user=user)

    # --- Admin OTP Logs Route ---
    @app.route('/admin/otp-logs')
    @admin_required
    def admin_otp_logs():
        logs = OtpLog.query.order_by(OtpLog.created_at.desc()).all()
        return render_template('admin_otp_logs.html', logs=logs)

    # --- Error Handlers ---
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404 # Assuming you have a 404.html template

    @app.errorhandler(403)
    def forbidden(e):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))


    return app

# ==========================================================
# This is needed for Gunicorn to find the app
# ==========================================================
app = create_app()

# =========================================================================
# >> TEMPORARY DEPLOYMENT HACK <<
# This code runs ONCE when the server starts.
# NOTE: REMOVE THIS BLOCK AFTER YOUR FIRST SUCCESSFUL DEPLOYMENT ON RENDER
# TO PREVENT DATA RE-POPULATION ON EVERY RESTART.
# =========================================================================
with app.app_context():
    print("Executing one-time database setup...")
    
    # 1. Create all tables
    db.create_all()
    
    # 2. Create 'static/images' folder
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        
    # 3. Create Admin User
    admin_email = 'rjndkl1224@gmail.com'
    if not Admin.query.filter_by(email=admin_email).first():
        print("Admin user not found, creating one...")
        pw_hash = bcrypt.generate_password_hash('RazanIsAdmin').decode('utf-8')
        # NOTE: 'RD_Cafe_2024' is the secret key required during admin login
        key_hash = bcrypt.generate_password_hash('RD_Cafe_2024').decode('utf-8') 
        new_admin = Admin(email=admin_email, password_hash=pw_hash, secret_key_hash=key_hash)
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user created successfully! Email: {admin_email} | Password: RazanIsAdmin | Secret Key: RD_Cafe_2024")
    else:
        print("Admin user already exists.")
    
    # 4. Add Sample Menu Items
    if Menu.query.count() == 0:
        print("Menu is empty, adding sample items...")
        sample_menu = [
            Menu(name='Espresso', description='Concentrated coffee.', price=150.00, image_url='hot-espresso.jpg', category='Hot Coffee'),
            Menu(name='Latte', description='Espresso with steamed milk.', price=220.00, image_url='hot-latte.jpg', category='Hot Coffee'),
            Menu(name='Iced Mocha', description='Espresso, milk, chocolate syrup, served over ice.', price=280.00, image_url='iced-mocha.jpg', category='Iced Coffee'),
            Menu(name='Lava Cake', description='Molten chocolate cake.', price=350.00, image_url='lava-cake.jpg', category='Cake'),
            Menu(name='RD Fine Wine', description='A carefully selected red wine.', price=650.00, image_url='red-wine.jpg', category='Wine'),
            Menu(name='Fresh Orange Juice', description='100% freshly squeezed oranges.', price=200.00, image_url='orange-juice.jpg', category='Juice')
        ]
        db.session.bulk_save_objects(sample_menu)
        db.session.commit()
        print("Sample menu items added.")
    else:
        print("Menu already has items.")
    print("One-time setup finished.")

# =========================================================================
# >> LOCAL DEVELOPMENT EXECUTION <<
# =========================================================================
if __name__ == '__main__':
    # Running locally in debug mode
    app.run(debug=True, host='0.0.0.0', port=5000)