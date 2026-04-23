SECURESHOP PRO | ADVANCED CYBERSECURITY           
Secure E-Commerce Web Application Prototype


1. [ PROJECT OVERVIEW ]

SecureShop Pro is a high-security, functional e-commerce prototype built 
to demonstrate Advanced CyberSecurity principles. The system implements 
a "Defense-in-Depth" strategy, ensuring that multiple security layers 
protect the data, even if one layer is compromised.

The application uses a professional "Midnight & Slate" dark theme to 
mimic a modern, premium marketplace while prioritizing the CIA Triad:
- CONFIDENTIALITY: Salted Hashing & Least Privilege RBAC.
- INTEGRITY: Parameterized Queries & Strong Password Algorithms.
- AVAILABILITY: Brute-Force Lockouts & Secure Session Management.
----------------------------------------------------------------------------


2. [ SYSTEM ARCHITECTURE ]

The platform follows a secure Model-View-Controller (MVC) pattern to 
ensure separation of concerns and a reduced attack surface:

- FRONTEND (VIEW): HTML5/CSS3 templates using Jinja2 for secure 
  server-side rendering. client-side JavaScript provides immediate 
  visual feedback for security checks (e.g., password strength).
- BACKEND (CONTROLLER): A Python Flask server that manages routing, 
  session security, and executes all authentication logic.
- DATABASE (MODEL): A persistent SQLite3 layer. All interactions 
  use Parameterized Queries to prevent SQL Injection (SQLi).
----------------------------------------------------------------------------


3. [ CORE SYSTEM MODULES ]

The system is modularized to ensure that security logic is isolated 
and can be audited independently:

- Authentication Gatekeeper (`app.py`): Manages the secure state 
  machine for login, registration, and role-based redirects.
- Security Core (`security.py`): Houses the high-entropy functions 
  for CAPTCHA generation, MFA dispatching, and Bcrypt hashing.
- Integrity Layer (`database.py`): Defines the hardened relational 
  schema and handles safe data persistence.
----------------------------------------------------------------------------


4. [ TECHNOLOGY STACK ]

To build this professional-grade prototype, I selected a stack known 
for its security-focused library support:

- LANGUAGE: Python 3.8+ (Chosen for its robust crypto libraries).
- FRAMEWORK: Flask (Lightweight to minimize the attack surface).
- CRYPTOGRAPHY: Bcrypt (Industry-standard salted hashing).
- IMAGE PROCESSING: Pillow (For generating custom CAPTCHA noise).
- DATABASE: SQLite3 (Serverless, local, and portable for prototypes).
- MFA BRIDGE: smtplib (SSL/TLS encrypted email delivery).
----------------------------------------------------------------------------


5. [ SECURITY FEATURES ]

To fulfill the highest rubric criteria, the following are implemented:

[#] MULTI-FACTOR AUTHENTICATION (MFA)
    Uses an SMTP bridge to dispatch 6-digit Secure OTPs to the user's 
    email address. This satisfies the "Something You Have" factor.

[#] BCRYPT SALTED HASHING
    Passwords are never stored in plaintext. We utilize Bcrypt with an 
    adaptive work factor to neutralize brute-force and rainbow tables.

[#] CUSTOM NOISE-INJECTED CAPTCHA
    A backend-generated image challenge using line-noise injection 
    and point distortions to prevent automated bot registration.

[#] ACCOUNT LOCKOUT MECHANISM
    Soft-locks accounts for 15 minutes after 3 consecutive failed 
    attempts, effectively stopping credential-stuffing tools.

[#] SECURITY AUDIT TRAIL
    Centralized logging (Admin SOC Dashboard) that tracks every success, 
    failure, and lockout event with forensic timestamps.

[#] PASSWORD STRENGTH VALIDATOR
    Dynamic, real-time UI feedback enforcing NIST-compliant complexity 
    (8+ chars, Case, Numbers, & Special Symbols).

[#] PASSWORD RECOVERY (FORGOT PASSWORD)
    Secure out-of-band recovery using email OTPs and strength-validated 
    password resetting logic.
----------------------------------------------------------------------------


6. [ ROLE-BASED ACCESS CONTROL (RBAC) ]

The platform implements a strict 'Least Privilege' model using four 
distinct security tiers:

- TIERS:
  1. ANONYMOUS: Access restricted to Login and Registration pages only.
  2. BUYER: Can browse the catalog, place secure orders, and view their 
     private purchase history. Prevented from accessing merchant tools.
  3. SELLER: Includes all Buyer privileges plus 'Product Management' 
     capabilities (Add/Edit/Delete products). Isolated to their own inventory.
  4. ADMIN (SOC): Full system oversight. Access to the 'Security Operations 
     Center' (Audit Logs and User Directory).

- ENFORCEMENT: 
  Security is enforced via server-side 'decorators' (@role_required) 
  which verify the session role before executing any business logic.
----------------------------------------------------------------------------


7. [ CORE SYSTEM FUNCTIONALITIES ]

- SECURE REGISTRATION:
  Captures PII (Email/Username) while enforcing high-entropy 
  passwords. Validates the human user via noise-injected CAPTCHA.

- DYNAMIC SECURITY HANDSHAKE (LOGIN):
  1. USER PROOF: User provides username/password.
  2. MFA CHALLENGE: System generates 6-digit OTP and pushes it to 
     the secure email channel while holding the session 'Pending.'
  3. AUTH COMPLETION: User enters OTP to finalize the secure session.

- E-COMMERCE WORKFLOW:
  * PRODUCT CATALOG: High-performance rendering of inventory.
  * SECURE PURCHASING: Transactional logic with NPR (Rs.) currency.
  * MERCHANT PORTAL: Specialized dashboard for seller-tier users.
  * SECURITY AUDIT: Real-time telemetry displayed for Administrators.
 
+- PASSWORD RECOVERY WORKFLOW:
+  1. REQUEST: User initiates recovery via username or email.
+  2. OTP VERIFY: Secure token verification over SMTP.
+  3. RESET: Strong password update with cryptographic hashing.
+----------------------------------------------------------------------------


8. [ SMTP & EMAIL OTP CONFIGURATION ]

To successfully test the Multi-Factor Authentication (MFA), follow 
these precise configuration steps:

FILE TO EDIT: `security.py`

LOCATIONS:
- Line 87: Change `SENDER_EMAIL` to your own Gmail address.
- Line 88: Change `SENDER_APP_PASSWORD` to your 16-character Google 
           App Password (DO NOT USE YOUR NORMAL ACCOUNT PASSWORD).

ADMIN RECEIVER: 
The default admin account is pre-configured to receive codes at 
`anushaaa626@gmail.com`. To change this, edit Line 76 in `database.py` 
before running the initial setup.

*TESTING TIP:*
If you do not wish to configure an email, the 6-digit OTP is also 
printed directly to the server terminal/console for easy grading.
----------------------------------------------------------------------------


9. [ QUICK START GUIDE ]

Prerequisites: Python 3.8+ installed on your system.

STEP 1: Initialize Virtual Environment
        Windows:   python -m venv venv
                   .\venv\Scripts\activate
        Mac/Linux: python3 -m venv venv
                   source venv/bin/activate

STEP 2: Install Dependencies
        pip install -r requirements.txt

STEP 3: Launch Implementation
        python app.py

STEP 4: Access System
        Open http://127.0.0.1:5000 in your web browser.
----------------------------------------------------------------------------


10. [ DEFAULT ADMINISTRATOR CREDENTIALS ]

The system is pre-seeded with an Administrator account for evaluation:

ROLE       | USERNAME | PASSWORD       | MFA METHOD
-----------|----------|----------------|-----------
Admin (SOC)| admin    | Admin@123xyz   | Terminal OTP / Email
----------------------------------------------------------------------------


11. [ DIRECTORY STRUCTURE ]

/app.py             - Main engine/routing (Enforces RBAC & Lockouts).
/security.py        - Security Core (MFA, CAPTCHA, & Hashing logic).
/database.py        - Persistent Layer (SQLi-safe schema definitions).
/requirements.txt   - Python package dependencies.
/templates/         - HTML views with secure output encoding (Jinja2).
/static/            - Design assets & Frontend JavaScript validations.
/README.txt         - System documentation and setup guide.


