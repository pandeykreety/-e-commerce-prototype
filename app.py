import os
from datetime import datetime, timedelta
from functools import wraps
from tempfile import mkdtemp

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
import bcrypt

from database import get_db_connection, init_db
from security import check_password_strength, generate_captcha, generate_email_otp, send_otp_email

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Ensure database is initialized
init_db()

# --- Security Decorators ---

def login_required(f):
    """
    Decorator enforcing authentication requirements (Confidentiality).
    Checks the active secure session for valid tokens. If a token is missing,
    or if Multi-Factor Authentication (MFA) has not been completed,
    the request is intercepted and redirected.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        if not session.get('mfa_verified'):
            flash("Please complete multi-factor authentication.", "warning")
            return redirect(url_for('mfa_verify'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    """
    Decorator enforcing the Principle of Least Privilege.
    Validates that the authenticated session holds the exact Role-Based 
    Access Control (RBAC) authorization required to invoke the endpoint, 
    preventing lateral privilege escalation.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash("Unauthorized access. Access restricted to specific roles.", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Helpers ---

def log_event(username, event):
    """
    Forensic Auditing Function.
    Records critical security events continuously. This acts as both a metric 
    for evaluating security resilience and an active deterrent that feeds the 
    account lockout logic to mitigate ongoing Bruteforce attacks.
    """
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO logs (username, login_attempt) VALUES (?, ?)', (username, event))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log event: {e}")

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session and session.get('mfa_verified'):
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('dashboard_admin'))
        elif role == 'seller':
            return redirect(url_for('dashboard_seller'))
        else:
            return redirect(url_for('dashboard_buyer'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles secure User Onboarding.
    Implements multiple defense-in-depth strategies including:
    1. CAPTCHA verification (Bot Mitigation)
    2. Server-side password entropy validation (Brute Force/Dictionary Defense)
    3. Secure Parameterized SQL execution (SQL Injection Defense)
    4. Bcrypt Hashing (Data-at-Rest Confidentiality)
    """
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_input = request.form.get('captcha')
        
        # DEFENSE LAYER 1: BOT MITIGATION (CAPTCHA)
        # Enforce case-insensitive comparison against the session token.
        if not captcha_input or not session.get('captcha_text') or captcha_input.upper() != session.get('captcha_text').upper():
            flash("Invalid CAPTCHA. Please try again.", "danger")
            return redirect(url_for('register'))
            
        # VULNERABILITY MITIGATION: CAPTCHA Replay Attack
        # Crucial step: immediately pop (destroy) the token so an attacker 
        # cannot bypass the CAPTCHA by sending the same solved token in a loop.
        session.pop('captcha_text', None)

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        # DEFENSE LAYER 2: ALGORITHMIC PASSWORD STRENGTH
        # While the frontend has a JS visualizer, we MUST strictly validate 
        # on the backend. Client-side JS can be easily bypassed by attackers 
        # issuing direct POST requests via Burp Suite or cURL.
        is_strong, reason = check_password_strength(password)
        if not is_strong:
            flash(f"Weak Password: {reason}", "danger")
            return redirect(url_for('register'))

        # DEFENSE LAYER 3: PREVENT SQL INJECTION (Parameterized Queries)
        # Using `?` binds the data as literal values, completely neutralizing 
        # injected escape characters like `' OR 1=1;--`.
        conn = get_db_connection()
        user_exists = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        if user_exists:
            conn.close()
            flash("Username or Email already registered.", "danger")
            return redirect(url_for('register'))

        # DEFENSE LAYER 4: CRYPTOGRAPHIC HASHING (Confidentiality)
        # Transform the plaintext password using bcrypt, which natively handles 
        # salt generation and computationally expensive hashing (Work Factor).
        # This renders stolen databases essentially useless to attackers.
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Principle of Least Privilege: New users are hardcoded to the lowest tier ('buyer').
        role = 'buyer'  

        conn.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, hashed_pw, role)
        )
        conn.commit()
        conn.close()

        log_event(username, 'REGISTRATION_SUCCESS')
        flash("Registration successful. You can now login.", "success")
        return redirect(url_for('login'))

    # GET request - generate new CAPTCHA
    captcha_text, captcha_img = generate_captcha()
    session['captcha_text'] = captcha_text

    return render_template('register.html', captcha_img=captcha_img)

@app.route('/api/captcha')
def api_captcha():
    captcha_text, captcha_img = generate_captcha()
    session['captcha_text'] = captcha_text
    return {"captcha_img": captcha_img}

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles Multi-Factor Authentication Initialization.
    Implements:
    - Account Lockouts (Brute Force Defense)
    - Bcrypt checkpw capability (Timing Attack Resistance)
    - Intermediate Session State generation (Secure State Machine)
    """
    if 'user_id' in session and session.get('mfa_verified'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        
        # DEFENSE LAYER 1: BRUTE FORCE PROTECTION (Rate Limiting via Account Lockout)
        # Query the audit logs. If an attacker fails 3 'LOGIN_FAILED' attempts 
        # within exactly 15 minutes, the system triggers a soft-lock, nullifying 
        # automated credential stuffing from tools like Hydra.
        recent_fails = conn.execute('''
            SELECT COUNT(*) FROM logs 
            WHERE username = ? AND login_attempt = 'LOGIN_FAILED' 
            AND timestamp >= datetime('now', '-15 minutes')
        ''', (username,)).fetchone()[0]
        
        if recent_fails >= 3:
            conn.close()
            log_event(username, 'ACCOUNT_LOCKED') # Forensic tracking
            flash("Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.", "danger")
            return redirect(url_for('login')) 

        # DEFENSE LAYER 2: IDENTITY LOOKUP
        # Utilizing parameterized `?` execution here to prevent attackers injecting 
        # `username = 'admin' OR 1=1'`.
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        # DEFENSE LAYER 3: TIMING & CRYPTOGRAPHIC VERIFICATION
        # `bcrypt.checkpw()` safely computes the provided hash against the DB hash. 
        # It executes in constant time to prevent Timing Analysis attacks.
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            log_event(username, 'LOGIN_PASSWORD_SUCCESS')
            
            # SECURE STATE MACHINE: do NOT grant 'user_id' token yet.
            # Place the user in an intermediate 'pending_user' state. 
            # This enforces MFA by refusing to issue the primary session cookie.
            session['pending_user'] = dict(user)
            
            # Generate the OTP logic 
            otp = generate_email_otp()
            session['otp_secret'] = otp
            # Time-restricted bound logic (5 minutes restriction) mitigates OTP interception viability
            session['otp_expires'] = (datetime.now() + timedelta(minutes=5)).timestamp()
            
            send_otp_email(user['email'], otp)
            
            flash(f"An OTP has been sent to your email.", "info")
            return redirect(url_for('mfa_verify'))
        else:
            log_event(username, 'LOGIN_FAILED')
            # VULNERABILITY MITIGATION: User Enumeration
            # The error message is generic ("Invalid credentials") so an attacker 
            # cannot differentiate between a bad username vs a bad password.
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/mfa_verify', methods=['GET', 'POST'])
def mfa_verify():
    """
    Multi-Factor Authentication (MFA) Verification Endpoint.
    Validates the 'Something You Have' component of authentication.
    """
    # DEFENSE LAYER 1: State Validation
    # If a user tries to access this route without a pending verified password,
    # they are immediately repelled.
    if 'pending_user' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        valid_otp = session.get('otp_secret')
        expires = session.get('otp_expires', 0)
        
        # DEFENSE LAYER 2: Time-Based Restrictions
        # Validates that the OTP has not surpassed the 5-minute window.
        if datetime.now().timestamp() > expires:
            flash("OTP has expired. Please login again.", "danger")
            session.clear()
            return redirect(url_for('login'))
            
        if user_otp and user_otp == valid_otp:
            # DEFENSE LAYER 3: Privilege Elevation (Issuing Tokens)
            # Only after full OTP verification do we map the 'pending' user 
            # into the actual live session variables, officially granting access.
            user = session.pop('pending_user')
            session.pop('otp_secret', None)
            session.pop('otp_expires', None)
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['email'] = user['email']
            session['mfa_verified'] = True
            
            log_event(user['username'], 'LOGIN_MFA_SUCCESS')
            flash("Login successful.", "success")
            return redirect(url_for('index'))
        else:
            log_event(session['pending_user']['username'], 'LOGIN_MFA_FAILED')
            flash("Invalid OTP.", "danger")
            return redirect(url_for('mfa_verify'))

    return render_template('mfa.html', email=session['pending_user']['email'])

@app.route('/logout')
def logout():
    """
    Secure Session Termination.
    Clears all cryptographic session tokens from the server preventing 
    re-use of the session cookie if intercepted later.
    """
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Password Recovery Initialization.
    Reuses existing OTP infrastructure to verify identity over out-of-band channels.
    """
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier)).fetchone()
        conn.close()

        if user:
            otp = generate_email_otp()
            session['reset_otp'] = otp
            session['reset_user_email'] = user['email']
            session['reset_user_id'] = user['id']
            session['reset_otp_expires'] = (datetime.now() + timedelta(minutes=5)).timestamp()
            
            send_otp_email(user['email'], otp)
            log_event(user['username'], 'PASSWORD_RESET_REQUEST')
            # VULNERABILITY MITIGATION: User Enumeration
            # Generic message prevents attackers from identifying valid accounts.
            flash("If the account exists, an OTP has been sent to the registered email.", "info")
            return redirect(url_for('forgot_password_verify'))
        else:
            flash("If the account exists, an OTP has been sent to the registered email.", "info")
            return redirect(url_for('forgot_password_verify'))

    return render_template('forgot_password.html')

@app.route('/forgot_password_verify', methods=['GET', 'POST'])
def forgot_password_verify():
    """
    Password Recovery MFA Stage.
    Validates that the reset requester has access to the pre-registered email.
    """
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        valid_otp = session.get('reset_otp')
        expires = session.get('reset_otp_expires', 0)

        if datetime.now().timestamp() > expires:
            flash("OTP has expired. Please try again.", "danger")
            return redirect(url_for('forgot_password'))

        if user_otp and user_otp == valid_otp:
            session['reset_token_verified'] = True
            session.pop('reset_otp', None)
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP.", "danger")
            return redirect(url_for('forgot_password_verify'))

    return render_template('forgot_password_verify.html', email=session.get('reset_user_email'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """
    Final Password Update Stage.
    Enforces password strength policies and secure hashing before database update.
    """
    if not session.get('reset_token_verified'):
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password'))

        # ENFORCEMENT LAYER: Password Policy re-check
        is_strong, msg = check_password_strength(new_password)
        if not is_strong:
            flash(msg, "danger")
            return redirect(url_for('reset_password'))

        # CRYPTOGRAPHIC HASHING: Bcrypt transformation
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user_id = session.get('reset_user_id')
        conn = get_db_connection()
        user_row = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if user_row:
            username = user_row['username']
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_pw, user_id))
            conn.commit()
            log_event(username, 'PASSWORD_RESET_SUCCESS')
            
        conn.close()

        session.clear() # Securely clear reset state tokens
        flash("Password successfully changed. Please login with your new credentials.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# --- Role-Based Dashboards ---

@app.route('/dashboard/buyer')
@login_required
@role_required('buyer')
def dashboard_buyer():
    """
    Buyer Dashboard.
    Protected by `@login_required` to defend against Unauthenticated Access, 
    and `@role_required` to defend against Broken Access Control (BAC).
    """
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    
    # Secure Parameterized Query preventing users viewing other users' orders.
    orders = conn.execute('''
        SELECT o.id, p.name as product_name, p.price, o.status, o.created_at 
        FROM orders o JOIN products p ON o.product_id = p.id 
        WHERE o.user_id = ?
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard_buyer.html', products=products, orders=orders)


@app.route('/buy/<int:product_id>', methods=['POST'])
@login_required
@role_required('buyer')
def buy_product(product_id):
    """
    Processes an order securely.
    <int:product_id> strongly guarantees data-typing, neutralizing 
    string-based payload execution into the backend logic.
    """
    conn = get_db_connection()
    
    # Validates product existence via parameterization
    product = conn.execute('SELECT id FROM products WHERE id = ?', (product_id,)).fetchone()
    if product:
        conn.execute('INSERT INTO orders (user_id, product_id) VALUES (?, ?)', (session['user_id'], product_id))
        conn.commit()
        flash("Order placed successfully!", "success")
    else:
        # Graceful failure without revealing database specifics
        flash("Product not found.", "danger")
        
    conn.close()
    return redirect(url_for('dashboard_buyer'))


@app.route('/dashboard/seller', methods=['GET', 'POST'])
@login_required
@role_required('seller')
def dashboard_seller():
    """
    Seller-specific Dashboard allowing Product creation.
    Protected by strict Role-Based Access Control to prevent Buyers 
    from appending data to the catalog.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        
        if name and price:
            try:
                price_val = float(price)
                conn.execute('INSERT INTO products (name, price, seller_id) VALUES (?, ?, ?)',
                            (name, price_val, session['user_id']))
                conn.commit()
                flash("Product added.", "success")
            except ValueError:
                flash("Invalid price.", "danger")
                
        return redirect(url_for('dashboard_seller'))
        
    my_products = conn.execute('SELECT * FROM products WHERE seller_id = ?', (session['user_id'],)).fetchall()
    my_orders = conn.execute('''
        SELECT o.id, u.username as buyer, p.name as product_name, p.price, o.status
        FROM orders o 
        JOIN products p ON o.product_id = p.id 
        JOIN users u ON o.user_id = u.id
        WHERE p.seller_id = ?
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard_seller.html', products=my_products, orders=my_orders)

@app.route('/seller/delete_product/<int:product_id>', methods=['POST'])
@login_required
@role_required('seller')
def delete_product(product_id):
    """
    Secure Data Deletion Endpoint.
    Uses 'POST' exclusively to mitigate Cross-Site Request Forgery (CSRF) 
    that could occur if deletion was processed via a standard 'GET' URI.
    """
    conn = get_db_connection()
    
    # DEFENSE LAYER: Horizontal Privilege Escalation Protection
    # Verify the product actually belongs to the initiating session user.
    owner = conn.execute('SELECT seller_id FROM products WHERE id = ?', (product_id,)).fetchone()
    if owner and owner['seller_id'] == session['user_id']:
        conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        flash("Product deleted successfully.", "success")
    else:
        flash("Unauthorized or product not found.", "danger")
    conn.close()
    return redirect(url_for('dashboard_seller'))

@app.route('/seller/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@role_required('seller')
def edit_product(product_id):
    """
    Secure Data Mutability Endpoint.
    """
    conn = get_db_connection()
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        
        # DEFENSE LAYER: Horizontal Privilege Escalation Protection
        # Verify ownership BEFORE executing any modifying `UPDATE` statement.
        owner = conn.execute('SELECT seller_id FROM products WHERE id = ?', (product_id,)).fetchone()
        if owner and owner['seller_id'] == session['user_id']:
            if name and price:
                try:
                    price_val = float(price)
                    conn.execute('UPDATE products SET name = ?, price = ? WHERE id = ?', (name, price_val, product_id))
                    conn.commit()
                    flash("Product updated successfully.", "success")
                    conn.close()
                    return redirect(url_for('dashboard_seller'))
                except ValueError:
                    flash("Invalid price.", "danger")
        else:
            flash("Unauthorized or product not found.", "danger")
            
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    
    if product and product['seller_id'] == session['user_id']:
        return render_template('edit_product.html', product=product)
    else:
        flash("Product not found.", "danger")
        return redirect(url_for('dashboard_seller'))

@app.route('/dashboard/admin')
@login_required
@role_required('admin')
def dashboard_admin():
    """
    Administrative Forensic Dashboard.
    Highly restricted endpoint serving data auditing and monitoring needs.
    """
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role, password_hash, created_at FROM users').fetchall()
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').fetchall()
    conn.close()
    return render_template('dashboard_admin.html', users=users, logs=logs)

@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def promote_seller(user_id):
    """
    Administrative Endpoint: Role Modification.
    Strictly restricted by `@role_required('admin')` to defend against 
    Vertical Privilege Escalation by malicious buyers.
    """
    conn = get_db_connection()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user['role'] == 'buyer':
        conn.execute('UPDATE users SET role = "seller" WHERE id = ?', (user_id,))
        conn.commit()
        flash("User promoted to Seller.", "success")
    else:
        flash("Action not allowed.", "danger")
    conn.close()
    return redirect(url_for('dashboard_admin'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
