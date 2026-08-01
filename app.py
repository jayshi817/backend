#!/usr/bin/env python3
"""
ULP GENERATOR — COMPLETE BACKEND
Flask | SQLite | JWT | Telegram API | Chunk Upload | Claim System | API Keys
"""

import os
import re
import sqlite3
import hashlib
import json
import random
import string
import time
import logging
import uuid
from datetime import datetime, timedelta
from functools import wraps

import requests
from flask import Flask, request, jsonify, send_file, g, Response
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# ============================================================
# LOAD ENV
# ============================================================
load_dotenv()

# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key')
app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', 'change-this-jwt-secret')
app.config['MAX_FILE_SIZE'] = int(os.getenv('MAX_FILE_SIZE', 524288000))
app.config['MAX_OUTPUT_LINES'] = int(os.getenv('MAX_OUTPUT_LINES', 1000))
app.config['CHUNK_SIZE'] = int(os.getenv('CHUNK_SIZE', 10485760))  # 10MB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['BACKUP_FOLDER'] = 'backups'
app.config['LOG_FOLDER'] = 'logs'
app.config['CORS_ORIGIN'] = os.getenv('CORS_ORIGIN', '*')

# ============================================================
# CORS
# ============================================================
CORS(app, origins=app.config['CORS_ORIGIN'], supports_credentials=True)

# ============================================================
# EXTENSIONS
# ============================================================
bcrypt = Bcrypt(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{os.getenv('RATE_LIMIT', 60)} per minute"],
    storage_uri="memory://"
)

# ============================================================
# LOGGING
# ============================================================
os.makedirs(app.config['LOG_FOLDER'], exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(app.config['LOG_FOLDER'], 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# DATABASE
# ============================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database.db')
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()

        # USERS
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                telegram_id TEXT UNIQUE,
                telegram_username TEXT UNIQUE,
                first_name TEXT,
                last_name TEXT,
                role TEXT DEFAULT 'USER',
                is_active INTEGER DEFAULT 1,
                is_banned INTEGER DEFAULT 0,
                ban_reason TEXT,
                banned_by INTEGER,
                banned_at TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                search_count INTEGER DEFAULT 0,
                download_count INTEGER DEFAULT 0,
                upload_count INTEGER DEFAULT 0,
                referral_code TEXT UNIQUE,
                free_keys_used_month INTEGER DEFAULT 0
            )
        ''')

        # ADMINS
        c.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                role TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                removed_by INTEGER,
                removed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # KEYS
        c.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_string TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                usage_count INTEGER DEFAULT 0,
                key_type TEXT DEFAULT 'ADMIN_CREATED',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # FREE KEY REQUESTS
        c.execute('''
            CREATE TABLE IF NOT EXISTS free_key_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT DEFAULT 'PENDING',
                approved_by INTEGER,
                approved_at TIMESTAMP,
                denied_by INTEGER,
                denied_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # FILES
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                total_chunks INTEGER DEFAULT 0,
                chunks_uploaded INTEGER DEFAULT 0,
                is_complete INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # CHUNKS
        c.execute('''
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_path TEXT NOT NULL,
                is_indexed INTEGER DEFAULT 0,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files(file_id)
            )
        ''')

        # ULP ENTRIES (indexed lines)
        c.execute('''
            CREATE TABLE IF NOT EXISTS ulp_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                chunk_id INTEGER NOT NULL,
                line TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                domain TEXT,
                is_claimed INTEGER DEFAULT 0,
                claimed_by INTEGER,
                claimed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files(file_id),
                FOREIGN KEY (chunk_id) REFERENCES chunks(id),
                FOREIGN KEY (claimed_by) REFERENCES users(id)
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ulp_username ON ulp_entries(username)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ulp_domain ON ulp_entries(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ulp_is_claimed ON ulp_entries(is_claimed)')

        # LOGS
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # ADMIN LOGS
        c.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users(id)
            )
        ''')

        # NOTES
        c.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # WHITELIST
        c.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by INTEGER NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (added_by) REFERENCES users(id)
            )
        ''')

        # BLACKLIST
        c.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_by INTEGER NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (added_by) REFERENCES users(id)
            )
        ''')

        # BACKUPS
        c.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_id TEXT UNIQUE NOT NULL,
                backup_path TEXT NOT NULL,
                backup_size INTEGER NOT NULL,
                status TEXT DEFAULT 'CREATED',
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restored_at TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')

        # FEEDBACK
        c.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                rating INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_resolved INTEGER DEFAULT 0,
                reply TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # API KEYS
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_string TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                permissions TEXT DEFAULT 'read-only',
                ip_whitelist TEXT,
                last_used_at TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # API KEY LOGS
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_key_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                response_status INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
            )
        ''')

        # MAINTENANCE LOG
        c.execute('''
            CREATE TABLE IF NOT EXISTS maintenance_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enabled INTEGER DEFAULT 0,
                message TEXT,
                updated_by INTEGER,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
        ''')
        c.execute('INSERT OR IGNORE INTO maintenance_log (id, enabled) VALUES (1, 0)')

        # Create default admin
        admin_user = os.getenv('ADMIN_USERNAME', 'soren')
        admin_pass = os.getenv('ADMIN_PASSWORD', 'soren')

        c.execute('SELECT id FROM users WHERE username = ?', (admin_user,))
        if not c.fetchone():
            hashed = bcrypt.generate_password_hash(admin_pass).decode('utf-8')
            c.execute('''
                INSERT INTO users (username, password_hash, role, telegram_id, telegram_username)
                VALUES (?, ?, 'SUPER_ADMIN', '123456789', 'admin')
            ''', (admin_user, hashed))
            uid = c.lastrowid
            c.execute('INSERT INTO admins (user_id, role, created_by) VALUES (?, 'SUPER_ADMIN', ?)', (uid, uid))

        db.commit()

        # Create folders
        for folder in ['uploads', 'backups', 'logs']:
            os.makedirs(folder, exist_ok=True)

        logger.info('✅ Database initialized')

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def generate_token(user_id, username, role):
    payload = {
        'id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
    except:
        return None

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def is_admin(user_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    return row and row['role'] in ['ADMIN', 'SUPER_ADMIN', 'MODERATOR']

def is_superadmin(user_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    return row and row['role'] == 'SUPER_ADMIN'

def log_action(user_id, action, details=None):
    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO logs (user_id, action, details, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, action, json.dumps(details) if details else None,
          request.remote_addr, request.headers.get('User-Agent')))
    db.commit()

def log_admin_action(admin_id, action, details=None):
    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO admin_logs (admin_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (admin_id, action, json.dumps(details) if details else None, request.remote_addr))
    db.commit()

# ============================================================
# DECORATORS
# ============================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check JWT first
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
            payload = verify_token(token)
            if payload:
                request.user = payload
                return f(*args, **kwargs)

        # Check API Key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            db = get_db()
            c = db.cursor()
            c.execute('''
                SELECT * FROM api_keys
                WHERE key_string = ? AND is_active = 1
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ''', (api_key,))
            key = c.fetchone()
            if key:
                # Check IP whitelist
                if key['ip_whitelist']:
                    whitelist = [ip.strip() for ip in key['ip_whitelist'].split(',')]
                    if request.remote_addr not in whitelist:
                        return jsonify({'error': 'IP not whitelisted'}), 403

                # Check permissions
                if request.path.startswith('/api/admin') and key['permissions'] not in ['read-write', 'admin']:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                if request.path.startswith('/api/superadmin') and key['permissions'] != 'admin':
                    return jsonify({'error': 'Admin permissions required'}), 403

                # Get user
                c.execute('SELECT * FROM users WHERE id = ?', (key['user_id'],))
                user = c.fetchone()
                if not user:
                    return jsonify({'error': 'User not found'}), 404

                request.user = dict(user)
                request.api_key_id = key['id']

                # Log usage
                c.execute('''
                    UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1
                    WHERE id = ?
                ''', (key['id'],))
                c.execute('''
                    INSERT INTO api_key_logs (api_key_id, endpoint, method, ip_address, user_agent, response_status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (key['id'], request.path, request.method, request.remote_addr,
                      request.headers.get('User-Agent'), 200))
                db.commit()

                return f(*args, **kwargs)

        return jsonify({'error': 'Authentication required'}), 401
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not is_admin(request.user['id']):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def superadmin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not is_superadmin(request.user['id']):
            return jsonify({'error': 'Superadmin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def maintenance_check(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        db = get_db()
        c = db.cursor()
        c.execute('SELECT enabled FROM maintenance_log WHERE id = 1')
        row = c.fetchone()
        if row and row['enabled'] == 1:
            return jsonify({
                'error': 'System under maintenance',
                'status': 'maintenance',
                'message': 'Please check back later'
            }), 503
        return f(*args, **kwargs)
    return decorated

# ============================================================
# TELEGRAM BOT
# ============================================================

class TelegramBot:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.admin_chat_id = os.getenv('TELEGRAM_ADMIN_CHAT_ID')
        self.api_url = f"https://api.telegram.org/bot{self.token}"

    def send_message(self, chat_id, message):
        if not self.token:
            return False
        try:
            requests.post(f"{self.api_url}/sendMessage", json={
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            })
            return True
        except:
            return False

    def send_admin(self, message):
        if self.admin_chat_id:
            return self.send_message(self.admin_chat_id, message)
        return False

    def send_user(self, telegram_id, message):
        if telegram_id:
            return self.send_message(telegram_id, message)

    def send_admin_buttons(self, text, buttons):
        if not self.token:
            return
        try:
            keyboard = {
                'inline_keyboard': [[{
                    'text': b['text'],
                    'callback_data': b['callback_data']
                } for b in buttons]]
            }
            requests.post(f"{self.api_url}/sendMessage", json={
                'chat_id': self.admin_chat_id,
                'text': text,
                'parse_mode': 'HTML',
                'reply_markup': keyboard
            })
        except:
            pass

telegram = TelegramBot()

# ============================================================
# API ROUTES — AUTH
# ============================================================

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
@maintenance_check
def login():
    data = request.get_json()
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (data['username'],))
    user = c.fetchone()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['is_banned']:
        return jsonify({'error': f'Banned: {user["ban_reason"]}'}), 403
    if not bcrypt.check_password_hash(user['password_hash'], data['password']):
        log_action(user['id'], 'LOGIN_FAILED', {'ip': request.remote_addr})
        return jsonify({'error': 'Invalid credentials'}), 401

    c.execute('''
        UPDATE users SET last_seen = CURRENT_TIMESTAMP, ip_address = ?, user_agent = ?
        WHERE id = ?
    ''', (request.remote_addr, request.headers.get('User-Agent'), user['id']))
    db.commit()

    token = generate_token(user['id'], user['username'], user['role'])
    log_action(user['id'], 'LOGIN', {'ip': request.remote_addr})

    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'telegram_id': user['telegram_id'],
            'telegram_username': user['telegram_username']
        }
    })

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
@maintenance_check
def register():
    data = request.get_json()
    required = ['username', 'password', 'telegram_id']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Missing: {field}'}), 400

    db = get_db()
    c = db.cursor()

    c.execute('SELECT id FROM users WHERE username = ?', (data['username'],))
    if c.fetchone():
        return jsonify({'error': 'Username taken'}), 400

    c.execute('SELECT id FROM users WHERE telegram_id = ?', (data['telegram_id'],))
    if c.fetchone():
        return jsonify({'error': 'Telegram ID already registered'}), 400

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    referral_code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    c.execute('''
        INSERT INTO users (username, password_hash, telegram_id, telegram_username,
                           first_name, last_name, ip_address, user_agent, referral_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (data['username'], hashed, data['telegram_id'], data.get('telegram_username'),
          data.get('first_name'), data.get('last_name'), request.remote_addr,
          request.headers.get('User-Agent'), referral_code))
    db.commit()

    user_id = c.lastrowid
    log_action(user_id, 'REGISTER', {'ip': request.remote_addr})

    # Notify admin
    telegram.send_admin(f"🔵 New user registered: @{data['username']} (TG ID: {data['telegram_id']})")

    return jsonify({'success': True, 'message': 'Registration successful', 'user_id': user_id})

@app.route('/api/verify-telegram', methods=['POST'])
@limiter.limit("5 per minute")
def verify_telegram():
    data = request.get_json()
    tg_id = data.get('telegram_id', '')
    tg_username = data.get('username', '')

    if not tg_id or not str(tg_id).isdigit():
        return jsonify({'error': 'Invalid Telegram ID'}), 400

    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        return jsonify({'valid': True, 'first_name': 'User', 'username': f'user_{tg_id[:4]}'})

    try:
        resp = requests.get(f"https://api.telegram.org/bot{token}/getChat",
                            params={'chat_id': tg_id}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('ok'):
                result = data['result']
                # Verify username if provided
                if tg_username:
                    bot_username = result.get('username', '')
                    if bot_username and bot_username.lower() != tg_username.lower():
                        return jsonify({'error': 'Telegram username does not match this ID'}), 400
                return jsonify({
                    'valid': True,
                    'first_name': result.get('first_name', 'User'),
                    'last_name': result.get('last_name', ''),
                    'username': result.get('username', ''),
                    'language_code': result.get('language_code', 'en')
                })
    except:
        pass

    return jsonify({'valid': True, 'first_name': 'User', 'username': f'user_{tg_id[:4]}'})

# ============================================================
# API ROUTES — USER
# ============================================================

@app.route('/api/user/profile', methods=['GET'])
@token_required
@maintenance_check
def get_profile():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, username, telegram_id, telegram_username, first_name, last_name,
               role, is_active, is_banned, created_at, last_seen,
               search_count, download_count, upload_count, free_keys_used_month
        FROM users WHERE id = ?
    ''', (request.user['id'],))
    user = c.fetchone()
    return jsonify(dict(user) if user else {'error': 'Not found'})

@app.route('/api/user/update', methods=['PUT'])
@token_required
@maintenance_check
def update_profile():
    data = request.get_json()
    db = get_db()
    c = db.cursor()

    updates = []
    values = []
    if data.get('first_name'):
        updates.append('first_name = ?')
        values.append(data['first_name'])
    if data.get('last_name'):
        updates.append('last_name = ?')
        values.append(data['last_name'])
    if data.get('telegram_username'):
        updates.append('telegram_username = ?')
        values.append(data['telegram_username'])

    if not updates:
        return jsonify({'error': 'No fields'}), 400

    values.append(request.user['id'])
    c.execute(f'UPDATE users SET {", ".join(updates)} WHERE id = ?', values)
    db.commit()

    log_action(request.user['id'], 'UPDATE_PROFILE', {'fields': updates})
    return jsonify({'success': True})

@app.route('/api/user/password', methods=['PUT'])
@token_required
@maintenance_check
def change_password():
    data = request.get_json()
    old = data.get('old_password')
    new = data.get('new_password')

    if not old or not new or len(new) < 6:
        return jsonify({'error': 'Invalid password'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT password_hash FROM users WHERE id = ?', (request.user['id'],))
    user = c.fetchone()

    if not bcrypt.check_password_hash(user['password_hash'], old):
        return jsonify({'error': 'Current password incorrect'}), 401

    hashed = bcrypt.generate_password_hash(new).decode('utf-8')
    c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed, request.user['id']))
    db.commit()

    log_action(request.user['id'], 'CHANGE_PASSWORD', {})
    return jsonify({'success': True})

# ============================================================
# API ROUTES — FREE KEY
# ============================================================

@app.route('/api/user/free-key/request', methods=['POST'])
@token_required
@limiter.limit("2 per minute")
@maintenance_check
def request_free_key():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()

    # Check if user already has active key
    c.execute('SELECT id FROM keys WHERE user_id = ? AND is_active = 1', (user_id,))
    if c.fetchone():
        return jsonify({'error': 'You already have an active key'}), 400

    # Check pending request
    c.execute('SELECT id FROM free_key_requests WHERE user_id = ? AND status = "PENDING"', (user_id,))
    if c.fetchone():
        return jsonify({'error': 'You already have a pending request'}), 400

    # Check monthly limit (10/month)
    c.execute('''
        SELECT COUNT(*) as count FROM free_key_requests
        WHERE user_id = ? AND status = 'APPROVED'
        AND strftime('%m', created_at) = strftime('%m', 'now')
    ''', (user_id,))
    row = c.fetchone()
    if row and row['count'] >= 10:
        return jsonify({'error': 'Monthly free key limit reached (10/month)'}), 400

    # Create request
    c.execute('''
        INSERT INTO free_key_requests (user_id, status, created_at)
        VALUES (?, 'PENDING', CURRENT_TIMESTAMP)
    ''', (user_id,))
    db.commit()

    request_id = c.lastrowid
    log_action(user_id, 'FREE_KEY_REQUESTED', {'request_id': request_id})

    # Notify admins
    c.execute('SELECT username, telegram_id FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    telegram.send_admin(f"""
🔑 FREE KEY REQUEST

User: @{user['username']}
Telegram ID: {user['telegram_id']}
Request ID: {request_id}

Approve: /approve {request_id}
Deny: /deny {request_id}
    """)

    # Inline keyboard
    telegram.send_admin_buttons(
        f"🔑 Free key request from @{user['username']}",
        [
            {'text': '✅ Approve', 'callback_data': f'approve_{request_id}'},
            {'text': '❌ Deny', 'callback_data': f'deny_{request_id}'}
        ]
    )

    return jsonify({
        'success': True,
        'message': 'Free key request sent to admin',
        'request_id': request_id
    })

@app.route('/api/user/free-key/status', methods=['GET'])
@token_required
def free_key_status():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()

    c.execute('''
        SELECT id, status, created_at, approved_at, denied_at
        FROM free_key_requests
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    ''', (user_id,))
    req = c.fetchone()

    if not req:
        return jsonify({'has_request': False})

    return jsonify({
        'has_request': True,
        'id': req['id'],
        'status': req['status'],
        'created_at': req['created_at'],
        'approved_at': req['approved_at'],
        'denied_at': req['denied_at']
    })

@app.route('/api/user/free-key/history', methods=['GET'])
@token_required
def free_key_history():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, status, created_at, approved_at, denied_at
        FROM free_key_requests
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
    ''', (user_id,))
    return jsonify([dict(r) for r in c.fetchall()])

@app.route('/api/user/keys/active', methods=['GET'])
@token_required
def get_active_key():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT key_string, expires_at, key_type
        FROM keys
        WHERE user_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        LIMIT 1
    ''', (user_id,))
    key = c.fetchone()
    return jsonify(dict(key) if key else {'active': False})

@app.route('/api/user/keys', methods=['GET'])
@token_required
def get_all_keys():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT key_string, created_at, expires_at, is_active, usage_count, key_type
        FROM keys
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    return jsonify([dict(k) for k in c.fetchall()])

# ============================================================
# API ROUTES — FILES (Search, Download, Claim)
# ============================================================

@app.route('/api/files/search', methods=['GET'])
@token_required
@limiter.limit("30 per minute")
@maintenance_check
def search_files():
    keyword = request.args.get('q', '')
    user_id = request.user['id']

    if not keyword:
        return jsonify({'error': 'Keyword required'}), 400

    db = get_db()
    c = db.cursor()

    # Search unclaimed entries
    c.execute('''
        SELECT id, line, username, password, domain, file_id
        FROM ulp_entries
        WHERE (username LIKE ? OR domain LIKE ? OR line LIKE ?)
        AND is_claimed = 0
        ORDER BY id
        LIMIT ?
    ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', app.config['MAX_OUTPUT_LINES']))

    results = c.fetchall()

    # Update search count
    c.execute('UPDATE users SET search_count = search_count + 1 WHERE id = ?', (user_id,))
    db.commit()

    log_action(user_id, 'SEARCH', {'keyword': keyword, 'count': len(results)})

    return jsonify({
        'results': [dict(r) for r in results],
        'count': len(results),
        'keyword': keyword,
        'max_lines': app.config['MAX_OUTPUT_LINES']
    })

@app.route('/api/files/download', methods=['POST'])
@token_required
@limiter.limit("20 per minute")
@maintenance_check
def download_files():
    data = request.get_json()
    entry_ids = data.get('entry_ids', [])
    keyword = data.get('keyword', 'search')
    user_id = request.user['id']

    if not entry_ids:
        return jsonify({'error': 'No entries selected'}), 400

    db = get_db()
    c = db.cursor()

    # Get unclaimed entries
    placeholders = ','.join(['?'] * len(entry_ids))
    c.execute(f'''
        SELECT id, line FROM ulp_entries
        WHERE id IN ({placeholders}) AND is_claimed = 0
    ''', entry_ids)

    entries = c.fetchall()

    if not entries:
        return jsonify({'error': 'No unclaimed entries found'}), 400

    # Build output
    output_lines = []
    entry_ids_claimed = []
    for entry in entries:
        output_lines.append(entry['line'])
        entry_ids_claimed.append(entry['id'])

    # Mark as claimed
    if entry_ids_claimed:
        placeholders2 = ','.join(['?'] * len(entry_ids_claimed))
        c.execute(f'''
            UPDATE ulp_entries
            SET is_claimed = 1, claimed_by = ?, claimed_at = CURRENT_TIMESTAMP
            WHERE id IN ({placeholders2})
        ''', (user_id, *entry_ids_claimed))
        db.commit()

    # Update download count
    c.execute('UPDATE users SET download_count = download_count + 1 WHERE id = ?', (user_id,))
    db.commit()

    # Strip URLs from output
    url_patterns = [
        r'https?://[^\s]+',
        r'www\.[^\s]+',
        r'ftp://[^\s]+',
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*'
    ]
    cleaned_lines = []
    for line in output_lines:
        clean = line
        for pattern in url_patterns:
            clean = re.sub(pattern, '', clean)
        if re.match(r'^[a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*!]+$', clean.strip()):
            cleaned_lines.append(clean.strip())

    output_text = '\n'.join(cleaned_lines)
    filename = f"kyxsoren_{keyword}.txt"

    log_action(user_id, 'DOWNLOAD_CLAIMED', {
        'keyword': keyword,
        'count': len(cleaned_lines),
        'entry_ids': entry_ids_claimed
    })

    return Response(
        output_text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@app.route('/api/files/list', methods=['GET'])
@token_required
@maintenance_check
def list_files():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT file_id, filename, file_size, uploaded_at, is_complete
        FROM files
        WHERE is_active = 1
        ORDER BY uploaded_at DESC
    ''')
    return jsonify([dict(f) for f in c.fetchall()])

@app.route('/api/user/claimed', methods=['GET'])
@token_required
def get_claimed():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, line, domain, claimed_at, file_id
        FROM ulp_entries
        WHERE claimed_by = ?
        ORDER BY claimed_at DESC
        LIMIT 1000
    ''', (user_id,))
    return jsonify({
        'claimed': [dict(r) for r in c.fetchall()],
        'count': len(c.fetchall())
    })

@app.route('/api/user/claimed-stats', methods=['GET'])
@token_required
def claimed_stats():
    user_id = request.user['id']
    db = get_db()
    c = db.cursor()
    c.execute('SELECT COUNT(*) as count FROM ulp_entries WHERE claimed_by = ?', (user_id,))
    return jsonify({'claimed_count': c.fetchone()['count']})

# ============================================================
# API ROUTES — ADMIN (Upload Chunks)
# ============================================================

@app.route('/api/files/upload-chunk', methods=['POST'])
@admin_required
@limiter.limit("10 per minute")
@maintenance_check
def upload_chunk():
    file_id = request.form.get('file_id')
    filename = secure_filename(request.form.get('filename'))
    chunk_index = request.form.get('chunk_index', type=int)
    total_chunks = request.form.get('total_chunks', type=int)
    chunk = request.files.get('chunk')

    if not file_id or not filename or chunk_index is None or not chunk:
        return jsonify({'error': 'Missing fields'}), 400

    # Create file record if new
    db = get_db()
    c = db.cursor()

    c.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
    file_record = c.fetchone()

    if not file_record:
        # New file
        c.execute('''
            INSERT INTO files (file_id, filename, file_path, file_size, file_hash, user_id, total_chunks)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_id, filename, f"uploads/{file_id}_{filename}", 0, '', request.user['id'], total_chunks))
        db.commit()

    # Save chunk
    temp_dir = os.path.join('uploads', 'temp', file_id)
    os.makedirs(temp_dir, exist_ok=True)

    chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index}')
    chunk.save(chunk_path)

    # Record chunk
    c.execute('''
        INSERT OR REPLACE INTO chunks (file_id, chunk_index, chunk_path)
        VALUES (?, ?, ?)
    ''', (file_id, chunk_index, chunk_path))
    db.commit()

    # Count uploaded chunks
    import glob
    chunks_uploaded = len(glob.glob(os.path.join(temp_dir, 'chunk_*')))

    # Update progress
    c.execute('''
        UPDATE files SET chunks_uploaded = ? WHERE file_id = ?
    ''', (chunks_uploaded, file_id))
    db.commit()

    remaining_days = total_chunks - chunks_uploaded

    if chunks_uploaded == total_chunks:
        # All chunks uploaded → assemble
        c.execute('UPDATE files SET is_complete = 1 WHERE file_id = ?', (file_id,))
        db.commit()

        # Trigger assembly in background
        assemble_file(file_id)

        return jsonify({
            'success': True,
            'message': 'All chunks uploaded. Assembling...',
            'chunks_uploaded': chunks_uploaded,
            'total_chunks': total_chunks,
            'is_complete': True
        })

    return jsonify({
        'success': True,
        'chunks_uploaded': chunks_uploaded,
        'total_chunks': total_chunks,
        'remaining_days': remaining_days,
        'is_complete': False,
        'message': f'Chunk {chunk_index+1}/{total_chunks} uploaded. {remaining_days} days remaining.'
    })

def assemble_file(file_id):
    """Assemble chunks and index file"""
    import glob
    import shutil

    db = get_db()
    c = db.cursor()
    c.execute('SELECT filename, total_chunks FROM files WHERE file_id = ?', (file_id,))
    file_record = c.fetchone()

    if not file_record:
        return

    temp_dir = os.path.join('uploads', 'temp', file_id)
    final_path = os.path.join('uploads', f"{file_id}_{file_record['filename']}")

    # Assemble
    try:
        with open(final_path, 'wb') as outfile:
            chunk_files = sorted(glob.glob(os.path.join(temp_dir, 'chunk_*')),
                               key=lambda x: int(x.split('_')[-1]))
            for chunk_file in chunk_files:
                with open(chunk_file, 'rb') as infile:
                    outfile.write(infile.read())
                os.remove(chunk_file)
        os.rmdir(temp_dir)

        # Update file record
        file_size = os.path.getsize(final_path)
        file_hash = hash_file(final_path)

        c.execute('''
            UPDATE files SET file_path = ?, file_size = ?, file_hash = ?, is_complete = 1
            WHERE file_id = ?
        ''', (final_path, file_size, file_hash, file_id))
        db.commit()

        # Index file
        index_file(file_id, final_path)

        log_action(request.user.get('id', 1), 'UPLOAD_COMPLETE', {'file_id': file_id})

        # Notify admins
        telegram.send_admin(f"📤 File uploaded: {file_record['filename']} ({file_size/1024/1024:.1f}MB)")

    except Exception as e:
        logger.error(f"Assembly failed for {file_id}: {e}")

def index_file(file_id, filepath):
    """Index file lines for search"""
    db = get_db()
    c = db.cursor()

    c.execute('SELECT id FROM chunks WHERE file_id = ? AND is_indexed = 0', (file_id,))
    chunks = c.fetchall()

    if not chunks:
        return

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Parse user:password
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password = ':'.join(parts[1:])

                    # Extract domain if present
                    domain = ''
                    for part in parts:
                        if '.' in part and len(part) > 3:
                            domain = part
                            break

                    # Store in ulp_entries
                    c.execute('''
                        INSERT INTO ulp_entries (file_id, chunk_id, line, username, password, domain)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (file_id, chunks[0]['id'], line, username, password, domain))

        # Mark chunks as indexed
        for chunk in chunks:
            c.execute('UPDATE chunks SET is_indexed = 1 WHERE id = ?', (chunk['id'],))

        db.commit()

    except Exception as e:
        logger.error(f"Indexing failed for {file_id}: {e}")

# ============================================================
# API ROUTES — ADMIN (Management)
# ============================================================

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_users():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, username, telegram_id, telegram_username, role, is_active, is_banned,
               created_at, last_seen, search_count, download_count, upload_count
        FROM users ORDER BY created_at DESC
    ''')
    return jsonify([dict(u) for u in c.fetchall()])

@app.route('/api/admin/users/search', methods=['GET'])
@admin_required
def admin_search_users():
    q = request.args.get('q', '')
    if not q:
        return jsonify({'users': []})
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, username, telegram_id, telegram_username, role, is_active, is_banned
        FROM users
        WHERE username LIKE ? OR telegram_id LIKE ? OR telegram_username LIKE ?
        LIMIT 50
    ''', (f'%{q}%', f'%{q}%', f'%{q}%'))
    return jsonify({'users': [dict(u) for u in c.fetchall()]})

@app.route('/api/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    if user_id == request.user['id']:
        return jsonify({'error': 'Cannot ban yourself'}), 400
    data = request.get_json()
    db = get_db()
    c = db.cursor()
    c.execute('''
        UPDATE users SET is_banned = 1, ban_reason = ?, banned_by = ?, banned_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (data.get('reason', 'Banned by admin'), request.user['id'], user_id))
    db.commit()

    log_admin_action(request.user['id'], 'BAN_USER', {'user_id': user_id})

    # Notify via Telegram
    c.execute('SELECT telegram_id, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user['telegram_id']:
        telegram.send_user(user['telegram_id'], f"🚫 You have been banned. Reason: {data.get('reason', 'No reason')}")

    telegram.send_admin(f"🚫 User @{user['username']} banned by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    db = get_db()
    c = db.cursor()
    c.execute('''
        UPDATE users SET is_banned = 0, ban_reason = NULL, banned_by = NULL, banned_at = NULL
        WHERE id = ?
    ''', (user_id,))
    db.commit()

    log_admin_action(request.user['id'], 'UNBAN_USER', {'user_id': user_id})

    c.execute('SELECT telegram_id, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user['telegram_id']:
        telegram.send_user(user['telegram_id'], "✅ You have been unbanned.")
    telegram.send_admin(f"✅ User @{user['username']} unbanned by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/admin/keys', methods=['GET'])
@admin_required
def admin_keys():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT k.*, u.username FROM keys k
        JOIN users u ON k.user_id = u.id
        ORDER BY k.created_at DESC
        LIMIT 100
    ''')
    return jsonify([dict(k) for k in c.fetchall()])

@app.route('/api/admin/keys', methods=['POST'])
@admin_required
def admin_create_key():
    data = request.get_json()
    user_id = data.get('user_id')
    hours = data.get('hours', 168)

    if not user_id:
        return jsonify({'error': 'user_id required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    if not c.fetchone():
        return jsonify({'error': 'User not found'}), 404

    # Revoke old key
    c.execute('UPDATE keys SET is_active = 0 WHERE user_id = ? AND is_active = 1', (user_id,))

    key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    expires_at = datetime.utcnow() + timedelta(hours=hours)

    c.execute('''
        INSERT INTO keys (key_string, user_id, created_by, expires_at, key_type)
        VALUES (?, ?, ?, ?, 'ADMIN_CREATED')
    ''', (key_string, user_id, request.user['id'], expires_at))
    db.commit()

    log_admin_action(request.user['id'], 'CREATE_KEY', {'user_id': user_id, 'hours': hours})

    c.execute('SELECT telegram_id, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user['telegram_id']:
        telegram.send_user(user['telegram_id'], f"""
🔑 NEW KEY GENERATED

Your key: {key_string}
Duration: {hours} hours
Expires: {expires_at.strftime('%Y-%m-%d %H:%M')}

Login: your-site.com
        """)

    telegram.send_admin(f"🔑 Key created for @{user['username']} by @{request.user['username']} ({hours}h)")

    return jsonify({
        'success': True,
        'key': key_string,
        'expires_at': expires_at.isoformat()
    })

@app.route('/api/admin/keys/<int:key_id>/revoke', methods=['POST'])
@admin_required
def admin_revoke_key(key_id):
    db = get_db()
    c = db.cursor()
    c.execute('UPDATE keys SET is_active = 0 WHERE id = ?', (key_id,))
    db.commit()

    log_admin_action(request.user['id'], 'REVOKE_KEY', {'key_id': key_id})
    return jsonify({'success': True})

@app.route('/api/admin/free-key/pending', methods=['GET'])
@admin_required
def admin_pending_keys():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT fr.*, u.username, u.telegram_id, u.telegram_username
        FROM free_key_requests fr
        JOIN users u ON fr.user_id = u.id
        WHERE fr.status = 'PENDING'
        ORDER BY fr.created_at ASC
    ''')
    return jsonify([dict(r) for r in c.fetchall()])

@app.route('/api/admin/free-key/approve/<int:request_id>', methods=['POST'])
@admin_required
def admin_approve_key(request_id):
    db = get_db()
    c = db.cursor()

    c.execute('SELECT * FROM free_key_requests WHERE id = ? AND status = "PENDING"', (request_id,))
    req = c.fetchone()
    if not req:
        return jsonify({'error': 'Request not found'}), 404

    user_id = req['user_id']

    # Revoke old key
    c.execute('UPDATE keys SET is_active = 0 WHERE user_id = ? AND is_active = 1', (user_id,))

    # Generate key (5 hours)
    key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    expires_at = datetime.utcnow() + timedelta(hours=int(os.getenv('FREE_KEY_DURATION', 5)))

    c.execute('''
        INSERT INTO keys (key_string, user_id, created_by, expires_at, key_type)
        VALUES (?, ?, ?, ?, 'FREE')
    ''', (key_string, user_id, request.user['id'], expires_at))

    c.execute('''
        UPDATE free_key_requests
        SET status = 'APPROVED', approved_by = ?, approved_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (request.user['id'], request_id))
    db.commit()

    log_admin_action(request.user['id'], 'APPROVE_FREE_KEY', {'user_id': user_id, 'request_id': request_id})

    c.execute('SELECT username, telegram_id FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user['telegram_id']:
        telegram.send_user(user['telegram_id'], f"""
✅ FREE KEY APPROVED!

Your free key has been approved and generated.

🔑 Key: {key_string}
⏰ Expires: 5 hours

Login: your-site.com
        """)

    telegram.send_admin(f"✅ Free key approved for @{user['username']} by @{request.user['username']}")

    return jsonify({
        'success': True,
        'key': key_string,
        'expires_at': expires_at.isoformat()
    })

@app.route('/api/admin/free-key/deny/<int:request_id>', methods=['POST'])
@admin_required
def admin_deny_key(request_id):
    db = get_db()
    c = db.cursor()

    c.execute('SELECT * FROM free_key_requests WHERE id = ? AND status = "PENDING"', (request_id,))
    req = c.fetchone()
    if not req:
        return jsonify({'error': 'Request not found'}), 404

    c.execute('''
        UPDATE free_key_requests
        SET status = 'DENIED', denied_by = ?, denied_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (request.user['id'], request_id))
    db.commit()

    log_admin_action(request.user['id'], 'DENY_FREE_KEY', {'request_id': request_id})

    c.execute('SELECT username, telegram_id FROM users WHERE id = ?', (req['user_id'],))
    user = c.fetchone()
    if user and user['telegram_id']:
        telegram.send_user(user['telegram_id'], "❌ Your free key request has been denied.")

    telegram.send_admin(f"❌ Free key denied for @{user['username']} by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    db = get_db()
    c = db.cursor()
    stats = {}

    c.execute('SELECT COUNT(*) as c FROM users'); stats['total_users'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM users WHERE is_active = 1'); stats['active_users'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM users WHERE is_banned = 1'); stats['banned_users'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM files WHERE is_active = 1'); stats['total_files'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM keys WHERE is_active = 1'); stats['active_keys'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM admins WHERE is_active = 1'); stats['total_admins'] = c.fetchone()['c']
    c.execute('SELECT COUNT(*) as c FROM free_key_requests WHERE status = "PENDING"'); stats['pending_keys'] = c.fetchone()['c']

    return jsonify(stats)

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def admin_logs():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT l.*, u.username
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.created_at DESC
        LIMIT 100
    ''')
    return jsonify([dict(l) for l in c.fetchall()])

@app.route('/api/admin/claimed-stats', methods=['GET'])
@admin_required
def admin_claimed_stats():
    db = get_db()
    c = db.cursor()

    c.execute('SELECT COUNT(*) as total FROM ulp_entries')
    total = c.fetchone()['total']

    c.execute('SELECT COUNT(*) as claimed FROM ulp_entries WHERE is_claimed = 1')
    claimed = c.fetchone()['claimed']

    c.execute('SELECT COUNT(*) as unclaimed FROM ulp_entries WHERE is_claimed = 0')
    unclaimed = c.fetchone()['unclaimed']

    c.execute('''
        SELECT u.username, COUNT(e.id) as claimed_count
        FROM ulp_entries e
        JOIN users u ON e.claimed_by = u.id
        WHERE e.is_claimed = 1
        GROUP BY e.claimed_by
        ORDER BY claimed_count DESC
        LIMIT 10
    ''')
    top = c.fetchall()

    return jsonify({
        'total': total,
        'claimed': claimed,
        'unclaimed': unclaimed,
        'claimed_percent': round((claimed / total) * 100, 2) if total > 0 else 0,
        'top_claimers': [dict(t) for t in top]
    })

# ============================================================
# API ROUTES — SUPERADMIN
# ============================================================

@app.route('/api/superadmin/admins', methods=['GET'])
@superadmin_required
def superadmin_admins():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT a.*, u.username
        FROM admins a
        JOIN users u ON a.user_id = u.id
        WHERE a.is_active = 1
    ''')
    return jsonify([dict(a) for a in c.fetchall()])

@app.route('/api/superadmin/admins', methods=['POST'])
@superadmin_required
def superadmin_create_admin():
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role', 'ADMIN')

    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    if role not in ['ADMIN', 'MODERATOR']:
        return jsonify({'error': 'Invalid role'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    if not c.fetchone():
        return jsonify({'error': 'User not found'}), 404

    c.execute('SELECT id FROM admins WHERE user_id = ? AND is_active = 1', (user_id,))
    if c.fetchone():
        return jsonify({'error': 'Already admin'}), 400

    c.execute('''
        INSERT INTO admins (user_id, role, created_by)
        VALUES (?, ?, ?)
    ''', (user_id, role, request.user['id']))
    db.commit()

    c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    db.commit()

    log_admin_action(request.user['id'], 'CREATE_ADMIN', {'user_id': user_id, 'role': role})

    c.execute('SELECT username, telegram_id FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    telegram.send_admin(f"👑 @{user['username']} promoted to {role} by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/superadmin/admins/<int:user_id>', methods=['DELETE'])
@superadmin_required
def superadmin_remove_admin(user_id):
    if user_id == request.user['id']:
        return jsonify({'error': 'Cannot remove yourself'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('''
        UPDATE admins SET is_active = 0, removed_by = ?, removed_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    ''', (request.user['id'], user_id))
    c.execute('UPDATE users SET role = "USER" WHERE id = ?', (user_id,))
    db.commit()

    log_admin_action(request.user['id'], 'REMOVE_ADMIN', {'user_id': user_id})

    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    telegram.send_admin(f"👑 @{user['username']} removed as admin by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/superadmin/notes', methods=['GET'])
@superadmin_required
def superadmin_notes():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT n.*, u.username as user_username, c.username as creator_username
        FROM notes n
        LEFT JOIN users u ON n.user_id = u.id
        LEFT JOIN users c ON n.created_by = c.id
        ORDER BY n.created_at DESC
    ''')
    return jsonify([dict(n) for n in c.fetchall()])

@app.route('/api/superadmin/notes', methods=['POST'])
@superadmin_required
def superadmin_create_note():
    data = request.get_json()
    user_id = data.get('user_id')
    note = data.get('note')

    if not user_id or not note:
        return jsonify({'error': 'user_id and note required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO notes (user_id, note, created_by)
        VALUES (?, ?, ?)
    ''', (user_id, note, request.user['id']))
    db.commit()

    log_admin_action(request.user['id'], 'ADD_NOTE', {'user_id': user_id})
    return jsonify({'success': True})

@app.route('/api/superadmin/notes/<int:note_id>', methods=['DELETE'])
@superadmin_required
def superadmin_delete_note(note_id):
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM notes WHERE id = ?', (note_id,))
    db.commit()

    log_admin_action(request.user['id'], 'DELETE_NOTE', {'note_id': note_id})
    return jsonify({'success': True})

@app.route('/api/superadmin/whitelist', methods=['GET'])
@superadmin_required
def superadmin_whitelist():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
    return jsonify([dict(w) for w in c.fetchall()])

@app.route('/api/superadmin/whitelist', methods=['POST'])
@superadmin_required
def superadmin_add_whitelist():
    data = request.get_json()
    ip = data.get('ip_address')
    if not ip:
        return jsonify({'error': 'ip_address required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('INSERT OR REPLACE INTO whitelist (ip_address, added_by) VALUES (?, ?)', (ip, request.user['id']))
    db.commit()

    log_admin_action(request.user['id'], 'ADD_WHITELIST', {'ip': ip})
    return jsonify({'success': True})

@app.route('/api/superadmin/whitelist/<ip>', methods=['DELETE'])
@superadmin_required
def superadmin_remove_whitelist(ip):
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM whitelist WHERE ip_address = ?', (ip,))
    db.commit()

    log_admin_action(request.user['id'], 'REMOVE_WHITELIST', {'ip': ip})
    return jsonify({'success': True})

@app.route('/api/superadmin/blacklist', methods=['GET'])
@superadmin_required
def superadmin_blacklist():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM blacklist ORDER BY added_at DESC')
    return jsonify([dict(b) for b in c.fetchall()])

@app.route('/api/superadmin/blacklist', methods=['POST'])
@superadmin_required
def superadmin_add_blacklist():
    data = request.get_json()
    ip = data.get('ip_address')
    reason = data.get('reason', 'Blocked by admin')

    if not ip:
        return jsonify({'error': 'ip_address required'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('INSERT OR REPLACE INTO blacklist (ip_address, reason, added_by) VALUES (?, ?, ?)',
              (ip, reason, request.user['id']))
    db.commit()

    log_admin_action(request.user['id'], 'ADD_BLACKLIST', {'ip': ip, 'reason': reason})
    return jsonify({'success': True})

@app.route('/api/superadmin/blacklist/<ip>', methods=['DELETE'])
@superadmin_required
def superadmin_remove_blacklist(ip):
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM blacklist WHERE ip_address = ?', (ip,))
    db.commit()

    log_admin_action(request.user['id'], 'REMOVE_BLACKLIST', {'ip': ip})
    return jsonify({'success': True})

@app.route('/api/superadmin/backups', methods=['GET'])
@superadmin_required
def superadmin_backups():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM backups ORDER BY created_at DESC')
    return jsonify([dict(b) for b in c.fetchall()])

@app.route('/api/superadmin/backup', methods=['POST'])
@superadmin_required
def superadmin_create_backup():
    import shutil
    backup_id = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(app.config['BACKUP_FOLDER'], f'backup_{backup_id}.db')

    shutil.copy2('database.db', backup_path)
    size = os.path.getsize(backup_path)

    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO backups (backup_id, backup_path, backup_size, created_by)
        VALUES (?, ?, ?, ?)
    ''', (backup_id, backup_path, size, request.user['id']))
    db.commit()

    log_admin_action(request.user['id'], 'BACKUP_CREATED', {'backup_id': backup_id})
    telegram.send_admin(f"💾 Backup created: {backup_id} ({size/1024/1024:.1f}MB)")

    return jsonify({'success': True, 'backup_id': backup_id, 'size': size})

@app.route('/api/superadmin/backups/<backup_id>/restore', methods=['POST'])
@superadmin_required
def superadmin_restore_backup(backup_id):
    import shutil

    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM backups WHERE backup_id = ?', (backup_id,))
    backup = c.fetchone()

    if not backup or not os.path.exists(backup['backup_path']):
        return jsonify({'error': 'Backup not found'}), 404

    # Create pre-restore backup
    pre_id = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    pre_path = os.path.join(app.config['BACKUP_FOLDER'], f'pre_restore_{pre_id}.db')
    shutil.copy2('database.db', pre_path)

    # Restore
    shutil.copy2(backup['backup_path'], 'database.db')

    c.execute('UPDATE backups SET restored_at = CURRENT_TIMESTAMP WHERE backup_id = ?', (backup_id,))
    db.commit()

    log_admin_action(request.user['id'], 'BACKUP_RESTORED', {'backup_id': backup_id})
    telegram.send_admin(f"♻️ Database restored from backup {backup_id}")

    return jsonify({'success': True, 'pre_restore_backup': pre_id})

@app.route('/api/superadmin/settings', methods=['GET'])
@superadmin_required
def superadmin_settings():
    return jsonify({
        'free_key_duration': int(os.getenv('FREE_KEY_DURATION', 5)),
        'free_key_cooldown': int(os.getenv('FREE_KEY_COOLDOWN', 24)),
        'free_key_monthly_limit': int(os.getenv('FREE_KEY_MONTHLY_LIMIT', 10)),
        'max_file_size': app.config['MAX_FILE_SIZE'],
        'max_output_lines': app.config['MAX_OUTPUT_LINES'],
        'chunk_size': app.config['CHUNK_SIZE'],
        'rate_limit': int(os.getenv('RATE_LIMIT', 60)),
        'api_rate_limit': int(os.getenv('API_RATE_LIMIT', 100))
    })

@app.route('/api/superadmin/settings', methods=['PUT'])
@superadmin_required
def superadmin_update_settings():
    data = request.get_json()

    # Update env vars (in production, use a config file)
    if 'free_key_duration' in data:
        os.environ['FREE_KEY_DURATION'] = str(data['free_key_duration'])
    if 'free_key_cooldown' in data:
        os.environ['FREE_KEY_COOLDOWN'] = str(data['free_key_cooldown'])
    if 'free_key_monthly_limit' in data:
        os.environ['FREE_KEY_MONTHLY_LIMIT'] = str(data['free_key_monthly_limit'])
    if 'max_output_lines' in data:
        app.config['MAX_OUTPUT_LINES'] = data['max_output_lines']

    log_admin_action(request.user['id'], 'UPDATE_SETTINGS', data)
    telegram.send_admin(f"⚙️ Settings updated by @{request.user['username']}")

    return jsonify({'success': True})

@app.route('/api/superadmin/emergency', methods=['POST'])
@superadmin_required
def superadmin_emergency():
    data = request.get_json()
    action = data.get('action')

    if action == 'shutdown':
        db = get_db()
        c = db.cursor()
        c.execute('UPDATE maintenance_log SET enabled = 1, message = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
                  ('Emergency shutdown activated', request.user['id']))
        db.commit()
        telegram.send_admin(f"🚨 EMERGENCY SHUTDOWN activated by @{request.user['username']}")
        return jsonify({'success': True, 'message': 'Emergency shutdown activated'})

    elif action == 'lockout':
        db = get_db()
        c = db.cursor()
        c.execute('UPDATE users SET is_active = 0 WHERE role = "USER"')
        db.commit()
        telegram.send_admin(f"🔒 EMERGENCY LOCKOUT activated by @{request.user['username']}")
        return jsonify({'success': True, 'message': 'All users locked out'})

    elif action == 'backup':
        import shutil
        backup_id = datetime.utcnow().strftime('emergency_%Y%m%d_%H%M%S')
        backup_path = os.path.join(app.config['BACKUP_FOLDER'], f'backup_{backup_id}.db')
        shutil.copy2('database.db', backup_path)
        telegram.send_admin(f"💾 EMERGENCY BACKUP created by @{request.user['username']}")
        return jsonify({'success': True, 'backup_id': backup_id})

    return jsonify({'error': 'Invalid action'}), 400

# ============================================================
# API ROUTES — API KEYS
# ============================================================

@app.route('/api/user/api-keys', methods=['GET'])
@token_required
def get_api_keys():
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT id, name, permissions, ip_whitelist, last_used_at, usage_count, expires_at, is_active, created_at
        FROM api_keys
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (request.user['id'],))
    return jsonify([dict(k) for k in c.fetchall()])

@app.route('/api/user/api-keys', methods=['POST'])
@token_required
def create_api_key():
    data = request.get_json()
    name = data.get('name')
    permissions = data.get('permissions', 'read-only')
    ip_whitelist = data.get('ip_whitelist')
    expires_at = data.get('expires_at')

    if not name:
        return jsonify({'error': 'Name required'}), 400
    if permissions not in ['read-only', 'read-write', 'admin']:
        return jsonify({'error': 'Invalid permissions'}), 400

    if permissions == 'admin' and not is_admin(request.user['id']):
        return jsonify({'error': 'Admin permissions required'}), 403

    key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO api_keys (user_id, key_string, name, permissions, ip_whitelist, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (request.user['id'], key_string, name, permissions, ip_whitelist, expires_at))
    db.commit()

    log_action(request.user['id'], 'API_KEY_CREATED', {'name': name})

    return jsonify({
        'success': True,
        'id': c.lastrowid,
        'key': key_string,
        'name': name,
        'permissions': permissions
    })

@app.route('/api/user/api-keys/<int:key_id>', methods=['DELETE'])
@token_required
def revoke_api_key(key_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
    key = c.fetchone()

    if not key or key['user_id'] != request.user['id']:
        return jsonify({'error': 'API key not found'}), 404

    c.execute('UPDATE api_keys SET is_active = 0 WHERE id = ?', (key_id,))
    db.commit()

    log_action(request.user['id'], 'API_KEY_REVOKED', {'key_id': key_id})
    return jsonify({'success': True})

@app.route('/api/user/api-keys/<int:key_id>/logs', methods=['GET'])
@token_required
def api_key_logs(key_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
    key = c.fetchone()

    if not key or key['user_id'] != request.user['id']:
        return jsonify({'error': 'API key not found'}), 404

    c.execute('''
        SELECT endpoint, method, ip_address, response_status, created_at
        FROM api_key_logs
        WHERE api_key_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    ''', (key_id,))
    return jsonify([dict(l) for l in c.fetchall()])

# ============================================================
# MAINTENANCE MODE
# ============================================================

@app.route('/api/admin/maintenance', methods=['GET'])
@admin_required
def maintenance_status():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT enabled, message FROM maintenance_log WHERE id = 1')
    row = c.fetchone()
    return jsonify({
        'enabled': row['enabled'] == 1 if row else False,
        'message': row['message'] if row else None
    })

@app.route('/api/superadmin/maintenance', methods=['POST'])
@superadmin_required
def toggle_maintenance():
    data = request.get_json()
    enabled = 1 if data.get('enabled') else 0
    message = data.get('message', 'System under maintenance')

    db = get_db()
    c = db.cursor()
    c.execute('''
        UPDATE maintenance_log
        SET enabled = ?, message = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
    ''', (enabled, message, request.user['id']))
    db.commit()

    status = 'ENABLED' if enabled else 'DISABLED'
    log_admin_action(request.user['id'], f'MAINTENANCE_{status}', {'message': message})
    telegram.send_admin(f"🛠️ Maintenance mode {status} by @{request.user['username']}")

    return jsonify({'success': True, 'enabled': bool(enabled), 'message': message})

# ============================================================
# HEALTH CHECK
# ============================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })

# ============================================================
# INIT & START
# ============================================================

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)