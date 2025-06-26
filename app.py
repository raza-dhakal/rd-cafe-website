import os
import random
import string
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.utils import secure_filename

# --- Load Environment Variables ---
load_dotenv()

# --- Initial Setup and Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
csrf = CSRFProtect(app)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['UPLOAD_FOLDER'] = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# MySQL Config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Mail Config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'false').lower() in ['true', '1']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'true').lower() in ['true', '1']
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
    scope=["profile", "email"],
    redirect_to='google_authorized'
)
app.register_blueprint(google_blueprint, url_prefix="/login")

# --- Helper Functions ---
def generate_otp(length=6): return ''.join(random.choices(string.digits, k=length))
def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==========================================================
# ALL ROUTES
# ==========================================================

# --- Public & User Routes ---
@app.route('/')
def home(): return render_template('home.html')

@app.route('/menu')
def menu():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM menu ORDER BY category, id")
    menu_items = cur.fetchall()
    cur.close()
    return render_template('menu.html', menu_items=menu_items)

@app.route('/owner-info')
def owner_info(): return render_template('owner_info.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        if cur.fetchone():
            flash('This email is already registered.', 'danger')
            cur.close()
            return redirect(url_for('signup'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        cur.close()
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session['logged_in'], session['user_id'], session['username'] = True, user['id'], user['username']
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Check email and password.', 'danger')
    return render_template('login.html')

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
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", [info['email']])
    user = cur.fetchone()
    if not user:
        unusable_pass = bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8')
        cur.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)", (info['email'], info['name'], unusable_pass))
        mysql.connection.commit()
        cur.execute("SELECT * FROM users WHERE email = %s", [info['email']])
        user = cur.fetchone()
        flash(f"Welcome, {info['name']}! Your account has been created.", "success")
    cur.close()
    session['logged_in'], session['user_id'], session['username'] = True, user['id'], user['username']
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
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, price FROM menu ORDER BY name")
    menu_items = cur.fetchall()
    if request.method == 'POST':
        customer_name, menu_item_id, quantity, payment_method = request.form['customer_name'], request.form['menu_item_id'], request.form['quantity'], request.form['payment_method']
        user_id = session.get('user_id')
        try:
            cur.execute("INSERT INTO orders (customer_name, menu_item_id, quantity, payment_method, user_id) VALUES (%s, %s, %s, %s, %s)", (customer_name, menu_item_id, quantity, payment_method, user_id))
            mysql.connection.commit()
            flash('Your order has been placed successfully!', 'success')
            return redirect(url_for('menu'))
        except Exception as e:
            flash(f'There was an error placing your order: {e}', 'danger')
        finally:
            cur.close()
    else:
        cur.close()
    return render_template('order.html', menu_items=menu_items)

# --- Admin Routes ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email, password, secret_key = request.form['email'], request.form['password'], request.form['secret_key']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE email = %s", [email])
        admin = cur.fetchone()
        if admin and bcrypt.check_password_hash(admin['password_hash'], password) and bcrypt.check_password_hash(admin['secret_key_hash'], secret_key):
            otp_code = generate_otp()
            try:
                msg = Message("Your RD Cafe Admin Login PIN", recipients=[admin.get('email')], body=f"Your one-time PIN is: {otp_code}")
                mail.send(msg)
                cur.execute("INSERT INTO otp_logs (admin_email, otp_code) VALUES (%s, %s)", (admin.get('email'), otp_code))
                mysql.connection.commit()
                session['admin_email_for_otp_verification'] = admin.get('email')
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
        user_otp, admin_email = request.form['otp'], session['admin_email_for_otp_verification']
        cur = mysql.connection.cursor()
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
        cur.execute("SELECT * FROM otp_logs WHERE admin_email = %s AND otp_code = %s AND is_used = FALSE AND created_at > %s", (admin_email, user_otp, five_minutes_ago))
        valid_otp = cur.fetchone()
        if valid_otp:
            cur.execute("UPDATE otp_logs SET is_used = TRUE WHERE id = %s", [valid_otp['id']])
            mysql.connection.commit()
            session.pop('admin_email_for_otp_verification', None)
            session['admin_logged_in'], session['admin_email'] = True, admin_email
            flash('Verification successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid or expired PIN.', 'danger')
            return redirect(url_for('admin_login'))
        cur.close()
    return render_template('admin_verify_otp.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM menu ORDER BY category, id")
    menu_items = cur.fetchall()
    cur.close()
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
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO menu (name, description, price, category, image_url) VALUES (%s, %s, %s, %s, %s)", (request.form['name'], request.form['description'], request.form['price'], request.form['category'], filename))
        mysql.connection.commit()
        cur.close()
        flash('New menu item added!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_menu.html')

@app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_menu_item(item_id):
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        name, description, price, category = request.form['name'], request.form['description'], request.form['price'], request.form['category']
        file = request.files.get('image')
        if file and file.filename != '' and allowed_file(file.filename):
            cur.execute("SELECT image_url FROM menu WHERE id = %s", [item_id])
            old_image_record = cur.fetchone()
            if old_image_record and old_image_record.get('image_url'):
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_record['image_url'])
                if os.path.exists(old_image_path): os.remove(old_image_path)
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(str(uuid.uuid4()) + '.' + ext)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cur.execute("UPDATE menu SET name=%s, description=%s, price=%s, category=%s, image_url=%s WHERE id=%s", (name, description, price, category, filename, item_id))
        else:
            cur.execute("UPDATE menu SET name=%s, description=%s, price=%s, category=%s WHERE id=%s", (name, description, price, category, item_id))
        mysql.connection.commit()
        cur.close()
        flash('Menu item updated!', 'success')
        return redirect(url_for('admin_dashboard'))
    cur.execute("SELECT * FROM menu WHERE id = %s", [item_id])
    item = cur.fetchone()
    cur.close()
    if not item:
        flash('Item not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_menu.html', item=item)

@app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
def delete_menu_item(item_id):
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT image_url FROM menu WHERE id = %s", [item_id])
    item = cur.fetchone()
    if item and item.get('image_url'):
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], item['image_url'])
        if os.path.exists(image_path): os.remove(image_path)
    cur.execute("DELETE FROM menu WHERE id = %s", [item_id])
    mysql.connection.commit()
    cur.close()
    flash('Menu item deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/orders')
def admin_view_orders():
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT o.order_id, o.customer_name, m.name as menu_item_name, o.quantity, o.payment_method, o.order_status, o.order_date
        FROM orders o JOIN menu m ON o.menu_item_id = m.id
        ORDER BY o.order_date DESC
    """)
    all_orders = cur.fetchall()
    cur.close()
    return render_template('admin_orders.html', orders=all_orders)

@app.route('/admin/order/update/<int:order_id>', methods=['POST'])
def admin_update_order_status(order_id):
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    new_status = request.form.get('status')
    if new_status in ['Completed', 'Cancelled']:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE orders SET order_status = %s WHERE order_id = %s", (new_status, order_id))
        mysql.connection.commit()
        cur.close()
        flash(f'Order #{order_id} updated to "{new_status}".', 'success')
    else:
        flash('Invalid status.', 'danger')
    return redirect(url_for('admin_view_orders'))

@app.route('/admin/users')
def admin_view_users():
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC")
    all_users = cur.fetchall()
    cur.close()
    return render_template('admin_view_users.html', users=all_users)

@app.route('/admin/user/reset/<int:user_id>', methods=['GET', 'POST'])
def admin_reset_user_password(user_id):
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cur.execute("SELECT email FROM users WHERE id = %s", [user_id])
        user = cur.fetchone()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_view_users'))
        user_email = user['email']
        try:
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user_id))
            mysql.connection.commit()
            msg = Message("Your RD Cafe Password Has Been Reset", recipients=[user_email], body=f"Your new temporary password is: {new_password}")
            mail.send(msg)
            flash(f"Password for {user_email} has been reset and sent.", 'success')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
        finally:
            cur.close()
        return redirect(url_for('admin_view_users'))
    cur.execute("SELECT id, username, email FROM users WHERE id = %s", [user_id])
    user_to_reset = cur.fetchone()
    cur.close()
    if not user_to_reset:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_view_users'))
    return render_template('admin_reset_password.html', user=user_to_reset)

@app.route('/admin/otp-logs')
def admin_otp_logs():
    if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM otp_logs ORDER BY created_at DESC")
    all_logs = cur.fetchall()
    cur.close()
    return render_template('admin_otp_logs.html', logs=all_logs)

# --- Final line to run the app on your computer ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)