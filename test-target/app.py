from flask import Flask, request, render_template, redirect, url_for, session, make_response, jsonify, send_from_directory
import sqlite3
import os
import pickle
import json
import subprocess
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'
app.config['DEBUG'] = True  # Information Disclosure: Stack traces enabled
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Database setup
DATABASE = 'vulnerable.db'
UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Comments table for XSS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Documents table for IDOR
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            is_private INTEGER DEFAULT 1
        )
    ''')
    
    # Insert test data with hardcoded credentials (Weak Authentication)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, is_admin) VALUES (1, 'admin', 'admin123', 'admin@vulnerable.app', 1)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, is_admin) VALUES (2, 'user1', 'password123', 'user1@vulnerable.app', 0)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, is_admin) VALUES (3, 'user2', 'password456', 'user2@vulnerable.app', 0)")
    
    # Insert test documents for IDOR
    cursor.execute("INSERT OR IGNORE INTO documents (id, user_id, title, content, is_private) VALUES (1, 1, 'Admin Secret', 'This is a secret admin document', 1)")
    cursor.execute("INSERT OR IGNORE INTO documents (id, user_id, title, content, is_private) VALUES (2, 2, 'User1 Private Doc', 'User1 private content', 1)")
    cursor.execute("INSERT OR IGNORE INTO documents (id, user_id, title, content, is_private) VALUES (3, 2, 'User1 Public Doc', 'User1 public content', 0)")
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

# 1. SQL Injection - Vulnerable login form
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: Direct string concatenation in SQL query
        conn = get_db()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 2. Command Injection - Vulnerable ping utility
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    output = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        # VULNERABLE: Direct shell command execution with user input
        cmd = f"ping -c 4 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
    
    return render_template('ping.html', output=output)

# 3. XSS - Comment/feedback form without sanitization
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        user_id = session.get('user_id', 0)
        # VULNERABLE: No sanitization of user input
        cursor.execute("INSERT INTO comments (user_id, content) VALUES (?, ?)", (user_id, content))
        conn.commit()
    
    # VULNERABLE: Comments rendered without escaping
    cursor.execute("SELECT c.*, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC")
    comments = cursor.fetchall()
    conn.close()
    
    return render_template('comments.html', comments=comments)

# 4. Insecure Deserialization - Pickle/JSON loading user data
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    message = None
    user_data = None
    
    if request.method == 'POST':
        data = request.form.get('data', '')
        format_type = request.form.get('format', 'json')
        
        try:
            if format_type == 'pickle':
                # VULNERABLE: Insecure pickle deserialization
                user_data = pickle.loads(data.encode('latin1'))
            else:
                # VULNERABLE: Insecure JSON deserialization (can still be dangerous)
                user_data = json.loads(data)
            message = "Data loaded successfully!"
        except Exception as e:
            message = f"Error: {str(e)}"
    
    return render_template('profile.html', message=message, user_data=user_data)

# 5. IDOR - Direct object reference to other users' data
@app.route('/document/<int:doc_id>')
def document(doc_id):
    # VULNERABLE: No authorization check - any user can access any document
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()
    conn.close()
    
    if doc:
        return render_template('document.html', document=doc)
    else:
        return "Document not found", 404

@app.route('/documents')
def documents():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE user_id = ?", (session['user_id'],))
    user_docs = cursor.fetchall()
    conn.close()
    
    return render_template('documents.html', documents=user_docs)

# 6. Weak Authentication - Hardcoded credentials endpoint
@app.route('/api/login', methods=['POST'])
def api_login():
    # VULNERABLE: No rate limiting, weak credential validation
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Hardcoded backdoor credentials
    if username == 'backdoor' and password == 'backdoor123':
        return jsonify({"status": "success", "token": "admin_token_12345", "is_admin": True})
    
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "token": f"token_{user['id']}", "is_admin": bool(user['is_admin'])})
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# 7. File Upload - No extension validation
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file provided", 400
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
        
        # VULNERABLE: No file extension validation, no content type checking
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        return render_template('upload.html', message=f"File uploaded: {filename}", filename=filename)
    
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # VULNERABLE: No path traversal protection
    return send_from_directory(UPLOAD_FOLDER, filename)

# 8. XXE - XML parser with external entities enabled
@app.route('/xml', methods=['GET', 'POST'])
def xml_endpoint():
    result = None
    error = None
    
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        
        try:
            # VULNERABLE: External entities enabled
            parser = minidom.parseString(xml_data)
            result = parser.toxml()
        except Exception as e:
            error = str(e)
            # Information Disclosure: Detailed error messages
    
    return render_template('xml.html', result=result, error=error)

# 9. Information Disclosure - Stack traces enabled via DEBUG mode
# Also exposing .git directory
@app.route('/.git/<path:filename>')
def git_expose(filename):
    # VULNERABLE: Exposing .git directory
    git_dir = os.path.join(os.path.dirname(__file__), '.git')
    if os.path.exists(git_dir):
        return send_from_directory(git_dir, filename)
    return "Git directory not found", 404

@app.route('/debug')
def debug_info():
    # VULNERABLE: Exposing sensitive debug information
    info = {
        "app_config": {
            "secret_key": app.secret_key,
            "debug": app.debug,
            "database": DATABASE
        },
        "environment": dict(os.environ),
        "routes": [str(rule) for rule in app.url_map.iter_rules()]
    }
    return jsonify(info)

# 10. CORS Misconfiguration - Wildcard with credentials
@app.after_request
def after_request(response):
    # VULNERABLE: Wildcard CORS with credentials allowed
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Additional vulnerable endpoints
@app.route('/search')
def search():
    # VULNERABLE: Reflected XSS via search parameter
    query = request.args.get('q', '')
    return render_template('search.html', query=query)

@app.route('/users')
def list_users():
    # VULNERABLE: Information disclosure - listing all users
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('users.html', users=users)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)