import sqlite3
import bcrypt
import datetime
import os

DB_NAME = "ecommerce.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    

    # SCHEMA DEFINITION: USERS TABLE
    
    # This table stores the core identity parameters of the user. 
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('buyer', 'seller', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    

    # SCHEMA DEFINITION: PRODUCTS TABLE
    # This table holds the inventory. 
    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            seller_id INTEGER NOT NULL,
            FOREIGN KEY(seller_id) REFERENCES users(id)
        )
    ''')
    
    # SCHEMA DEFINITION: ORDERS TABLE
    # Stores the relational transactions between Buyers and Products.
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Completed', 'Cancelled')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')
    
    # SCHEMA DEFINITION: SECURITY LOGS TABLE (AUDIT TRAIL)
    # Dedicated table solely for security telemetry and forensic analysis.
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            login_attempt TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    

    # DEFAULT SYSTEM ADMINISTRATOR PROVISIONING
    c.execute("SELECT id FROM users WHERE role = 'admin'")
    if not c.fetchone():
        print("Admin account not found. Creating default admin account...")
        admin_username = "admin"
        admin_email = "anushaaa626@gmail.com"
        # Generate robust password: Admin@123xyz
        admin_pass_hash = bcrypt.hashpw("Admin@123xyz".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (admin_username, admin_email, admin_pass_hash, 'admin')
        )
        print("Admin account created (Username: admin, Password: Admin@123xyz)")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
