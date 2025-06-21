# app.py (Complete updated version)
from werkzeug.utils import secure_filename
import uuid # For unique filenames
import os
import random
import string
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect


# --- Initial Setup ---
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
# Right after app = Flask(__name__)
csrf = CSRFProtect(app)

# --- Configurations ---
app.config['SECRET_KEY'] = 'a_very_secret_and_random_string_for_rd_cafe'
# ... (all other configs from .env) ...
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# --- Initialize Extensions ---
mysql = MySQL(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# --- Google OAuth Blueprint ---
google_blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"]
)
app.register_blueprint(google_blueprint)

# --- Helper Function ---
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# ============================
# --- ROUTES ---
# ============================

# --- Public & User Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/menu')
def menu():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM menu ORDER BY category, id")
    menu_items = cur.fetchall()
    cur.close()
    return render_template('menu.html', menu_items=menu_items)

# ... (other user routes like signup, login, dashboard, logout) ...
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (username, email, hashed_password))
            mysql.connection.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('This email is already registered.', 'danger')
            return redirect(url_for('signup'))
        finally:
            cur.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        cur.close()
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Check email and password.', 'danger')
    return render_template('login.html')

@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "danger")
        return
    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Could not fetch user info from Google.", "danger")
        return
    user_info = resp.json()
    user_email = user_info.get("email")
    user_name = user_info.get("name")
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", [user_email])
    user = cur.fetchone()
    if not user:
        unusable_password = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (user_name, user_email, unusable_password))
        mysql.connection.commit()
        cur.execute("SELECT * FROM users WHERE email = %s", [user_email])
        user = cur.fetchone()
        flash(f"Welcome, {user_name}! Your account has been created.", "success")
    cur.close()
    session['logged_in'] = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    flash("Successfully logged in with Google!", "success")
    return False

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# In app.py, add this new route function

# In app.py, add this new route for the admin to view orders

@app.route('/admin/orders')
def admin_view_orders():
    if 'admin_logged_in' not in session:
        flash('You must be an admin to view this page.', 'danger')
        return redirect(url_for('admin_login'))

    cur = mysql.connection.cursor()
    
    # Use a JOIN query to get the menu item's name along with the order details
    cur.execute("""
        SELECT 
            o.order_id, 
            o.customer_name, 
            m.name as menu_item_name,  -- Get the name from the menu table
            o.quantity, 
            o.payment_method, 
            o.order_status, 
            o.order_date
        FROM orders o
        JOIN menu m ON o.menu_item_id = m.id
        ORDER BY o.order_date DESC -- Show the newest orders first
    """)
    all_orders = cur.fetchall()
    cur.close()

    return render_template('admin_orders.html', orders=all_orders)



@app.route('/order', methods=['GET', 'POST'])
def order():
    # Fetch menu items for the dropdown
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, price FROM menu ORDER BY name")
    menu_items = cur.fetchall()
    
    if request.method == 'POST':
        # Get data from the form
        customer_name = request.form['customer_name']
        menu_item_id = request.form['menu_item_id']
        quantity = request.form['quantity']
        payment_method = request.form['payment_method']
        
        # Get the logged-in user's ID, if they are logged in
        user_id = session.get('user_id', None) # Use .get() to avoid errors if not logged in

        try:
            # Insert the order into the database
            cur.execute(
                """
                INSERT INTO orders (customer_name, menu_item_id, quantity, payment_method, user_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (customer_name, menu_item_id, quantity, payment_method, user_id)
            )
            mysql.connection.commit()
            flash('Your order has been placed successfully! We will prepare it shortly.', 'success')
            return redirect(url_for('menu')) # Redirect to menu page after ordering
        except Exception as e:
            flash(f'There was an error placing your order: {e}', 'danger')
        finally:
            cur.close()

    # For a GET request, just show the order page with menu items
    cur.close()
    return render_template('order.html', menu_items=menu_items)


# --- Admin Routes ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        secret_key = request.form['secret_key']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE email = %s", [email])
        admin = cur.fetchone()
        if admin and bcrypt.check_password_hash(admin['password_hash'], password) and bcrypt.check_password_hash(admin['secret_key_hash'], secret_key):
            otp_code = generate_otp()
            try:
                msg = Message("Your RD Cafe Admin Login PIN", recipients=[admin['email']])
                msg.body = f"Your one-time PIN for RD Cafe Admin is: {otp_code}\nThis code is valid for 5 minutes."
                mail.send(msg)
                cur.execute("INSERT INTO otp_logs (admin_email, otp_code) VALUES (%s, %s)", (admin['email'], otp_code))
                mysql.connection.commit()
                session['admin_email_for_otp_verification'] = admin['email']
                flash('A PIN code has been sent to your email.', 'info')
                return redirect(url_for('admin_verify_otp'))
            except Exception as e:
                flash(f'Failed to send email. Error: {e}', 'danger')
        else:
            flash('Invalid credentials. Please try again.', 'danger')
        cur.close()
    return render_template('admin_login.html')

@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():
    if 'admin_email_for_otp_verification' not in session: return redirect(url_for('admin_login'))
    if request.method == 'POST':
        user_otp = request.form['otp']
        admin_email = session['admin_email_for_otp_verification']
        cur = mysql.connection.cursor()
        five_minutes_ago = datetime.now() - timedelta(minutes=5)
        cur.execute("SELECT * FROM otp_logs WHERE admin_email = %s AND otp_code = %s AND is_used = FALSE AND created_at > %s", (admin_email, user_otp, five_minutes_ago))
        valid_otp = cur.fetchone()
        if valid_otp:
            cur.execute("UPDATE otp_logs SET is_used = TRUE WHERE id = %s", [valid_otp['id']])
            mysql.connection.commit()
            session.pop('admin_email_for_otp_verification', None)
            session['admin_logged_in'] = True
            session['admin_email'] = admin_email
            flash('Verification successful! Welcome, Admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid or expired PIN code. Please try again.', 'danger')
            return redirect(url_for('admin_login'))
        cur.close()
    return render_template('admin_verify_otp.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        flash('You must be an admin to view this page.', 'danger')
        return redirect(url_for('admin_login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM menu ORDER BY category, id")
    menu_items = cur.fetchall()
    cur.close()
    
    return render_template('admin_dashboard.html', menu_items=menu_items)

# In app.py, add this new route

# Configuration for file uploads
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/menu/add', methods=['GET', 'POST'])
def add_menu_item():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        category = request.form['category']
        
        # Check if an image file was uploaded
        if 'image' not in request.files:
            flash('No image file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['image']

        if file.filename == '':
            flash('No image selected for uploading', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Create a unique filename to avoid overwriting
            ext = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = str(uuid.uuid4()) + '.' + ext
            filename = secure_filename(unique_filename)
            
            # Save the file to the upload folder
            file.path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file.path)

            # Save item to database
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO menu (name, description, price, category, image_url) VALUES (%s, %s, %s, %s, %s)",
                (name, description, price, category, filename)
            )
            mysql.connection.commit()
            cur.close()

            flash('New menu item added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Allowed image types are -> png, jpg, jpeg, gif, webp', 'danger')
            return redirect(request.url)

    return render_template('add_menu.html')
# In app.py, add this new route

@app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
def delete_menu_item(item_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    try:
        cur = mysql.connection.cursor()

        # Optional but good practice: First, delete the image file from the server
        cur.execute("SELECT image_url FROM menu WHERE id = %s", [item_id])
        item = cur.fetchone()
        if item and item['image_url']:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], item['image_url'])
            if os.path.exists(image_path):
                os.remove(image_path)

        # Now, delete the record from the database
        cur.execute("DELETE FROM menu WHERE id = %s", [item_id])
        mysql.connection.commit()
        cur.close()
        
        flash('Menu item deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting item: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))


# In app.py, add this new route

@app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_menu_item(item_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        category = request.form['category']

        # Check if a new image was uploaded
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                # A new image is uploaded, so delete the old one
                cur.execute("SELECT image_url FROM menu WHERE id = %s", [item_id])
                old_image_name = cur.fetchone()['image_url']
                if old_image_name:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save the new image with a unique filename
                ext = file.filename.rsplit('.', 1)[1].lower()
                unique_filename = str(uuid.uuid4()) + '.' + ext
                filename = secure_filename(unique_filename)
                file.path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file.path)
                
                # Update database record with the new image
                cur.execute(
                    """
                    UPDATE menu 
                    SET name=%s, description=%s, price=%s, category=%s, image_url=%s
                    WHERE id=%s
                    """,
                    (name, description, price, category, filename, item_id)
                )
            else:
                # No new valid image, so update without changing the image_url
                cur.execute(
                    """
                    UPDATE menu 
                    SET name=%s, description=%s, price=%s, category=%s
                    WHERE id=%s
                    """,
                    (name, description, price, category, item_id)
                )
        
        mysql.connection.commit()
        cur.close()
        flash('Menu item updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    else: # This is a GET request, so show the form with existing data
        cur.execute("SELECT * FROM menu WHERE id = %s", [item_id])
        item = cur.fetchone()
        cur.close()
        if not item:
            flash('Item not found.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        return render_template('edit_menu.html', item=item)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_email', None)
    flash('You have been logged out from the admin panel.', 'success')
    return redirect(url_for('admin_login'))

# In app.py, add this new route for updating the order status

@app.route('/admin/order/update/<int:order_id>', methods=['POST'])
def admin_update_order_status(order_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    # Get the new status from the hidden input field in the form
    new_status = request.form.get('status')
    
    # Basic validation to ensure the status is one of the allowed values
    if new_status not in ['Completed', 'Cancelled']:
        flash('Invalid status provided.', 'danger')
        return redirect(url_for('admin_view_orders'))

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE orders SET order_status = %s WHERE order_id = %s",
            (new_status, order_id)
        )
        mysql.connection.commit()
        cur.close()
        flash(f'Order #{order_id} has been updated to "{new_status}".', 'success')
    except Exception as e:
        flash(f'Error updating order status: {e}', 'danger')

    return redirect(url_for('admin_view_orders'))


# In app.py, add this new route for the admin to view users

@app.route('/admin/users')
def admin_view_users():
    if 'admin_logged_in' not in session:
        flash('You must be an admin to view this page.', 'danger')
        return redirect(url_for('admin_login'))

    cur = mysql.connection.cursor()
    
    # Fetch all users, newest first
    cur.execute("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC")
    all_users = cur.fetchall()
    cur.close()

    return render_template('admin_view_users.html', users=all_users)

# In app.py, add this new route for resetting a user's password

@app.route('/admin/user/reset/<int:user_id>', methods=['GET', 'POST'])
def admin_reset_user_password(user_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        # Generate a new random password
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) # 10-character random pass
        
        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Get the user's email
        cur.execute("SELECT email FROM users WHERE id = %s", [user_id])
        user = cur.fetchone()
        
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_view_users'))

        user_email = user['email']

        try:
            # Update the user's password in the database
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user_id))
            mysql.connection.commit()
            
            # Email the new password to the user
            msg = Message("Your RD Cafe Password Has Been Reset", recipients=[user_email])
            msg.body = f"Hello,\n\nAn admin has reset your password for RD Cafe.\n\nYour new temporary password is: {new_password}\n\nPlease log in with this password and change it immediately from your profile settings (feature coming soon).\n\n- The RD Cafe Team"
            mail.send(msg)
            
            flash(f'Password for {user_email} has been reset and sent to the user.', 'success')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
        finally:
            cur.close()
            
        return redirect(url_for('admin_view_users'))

    else: # GET request: show the confirmation page
        cur.execute("SELECT id, username, email FROM users WHERE id = %s", [user_id])
        user_to_reset = cur.fetchone()
        cur.close()
        
        if not user_to_reset:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_view_users'))
        
        return render_template('admin_reset_password.html', user=user_to_reset)
    
    # In app.py
@app.route('/owner-info')
def owner_info():
    return render_template('owner_info.html')

# In app.py, add this new route for viewing OTP logs

@app.route('/admin/otp-logs')
def admin_otp_logs():
    if 'admin_logged_in' not in session:
        flash('You must be an admin to view this page.', 'danger')
        return redirect(url_for('admin_login'))

    cur = mysql.connection.cursor()
    
    # Fetch all OTP logs, newest first
    cur.execute("SELECT * FROM otp_logs ORDER BY created_at DESC")
    all_logs = cur.fetchall()
    cur.close()

    return render_template('admin_otp_logs.html', logs=all_logs)



