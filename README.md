# RD Cafe - Advanced E-Commerce Website

Welcome to the RD Cafe project! This is a complete, professional-grade e-commerce web application for a modern cafe, built from the ground up with a secure and robust technology stack.

**Live Demo:** [https://rd-cafe-website.onrender.com/](https://rd-cafe-website.onrender.com/)

---

## 🌟 Key Features

This project is not just a simple website; it's a full-featured system with advanced capabilities:

### User-Facing Features:
- **Elegant Frontend:** A clean, responsive design with pages for Home, Menu, and About the Owner.
- **User Authentication:** Secure user sign-up and login system with password hashing (bcrypt).
- **Social Login:** Seamless one-click login/registration using Google OAuth.
- **Ordering System:** A functional order page where users can select items from the menu and place orders.
- **Multi-Language Support:** The "About the Owner" page is presented in English, Nepali, and Japanese.

### Admin Panel Features:
- **High-Security Login:** A three-factor admin login system requiring an email, password, and a secret key, followed by an Email-based OTP for final verification.
- **Menu Management (Full CRUD):**
    - **C**reate: Add new menu items with images, descriptions, prices, and categories.
    - **R**ead: View all menu items in an organized dashboard.
    - **U**pdate: Edit the details of any existing menu item.
    - **D**elete: Securely remove menu items (including their images from the server).
- **Order Management:**
    - View all customer orders in real-time.
    - Update the status of any order (e.g., from "Pending" to "Completed" or "Cancelled").
- **User Management:**
    - View a list of all registered users on the platform.
    - Securely reset any user's password, which sends a new temporary password to their email.
- **Security Auditing:** View a log of all admin login OTPs that have been generated.

---

## 🛠️ Technology Stack

- **Backend:** Python with the Flask web framework.
- **Database:** PostgreSQL (for production on Render) and MySQL (for local development). Database interactions are handled by the powerful **Flask-SQLAlchemy** ORM.
- **Frontend:** HTML, CSS, and vanilla JavaScript.
- **Authentication:**
    - Flask-Bcrypt for secure password hashing.
    - Flask-Dance for Google OAuth 2.0 integration.
- **Security:**
    - Flask-WTF for CSRF protection on all forms.
    - Secure file uploads and session management.
- **Email:** Flask-Mail with Gmail SMTP for sending OTPs and notifications.
- **Deployment:**
    - Version control with Git and GitHub.
    - Hosted on Render with a Gunicorn production server.

---

## 🚀 How to Run this Project Locally

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/raza-dhakal/rd-cafe-website.git
    cd rd-cafe-website
    ```

2.  **Create a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up the database:**
    - Make sure you have MySQL server running.
    - Create a new database (e.g., `rd_cafe_db`).
    - Create a `.env` file in the root directory and add your local database and other credentials. See `.env.example` if available.

5.  **Run the application:**
    ```bash
    flask run
    ```
    The application will be available at `http://127.0.0.1:5000`.

    'https://rd-cafe-website.onrender.com'
    

---

This project was built as a comprehensive learning experience and a portfolio piece to showcase full-stack web development skills.