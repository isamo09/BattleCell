from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import os
import io

import sqlite3
import secrets

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

SERVER_ENCRYPTION_KEY = b'supercell-server-key-2024-secure-encryption-system'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

DB_PATH = 'database.db'
REQUIRED_SCHEMA_VERSION = '2.0.0'


def _conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS encryption_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        username TEXT NOT NULL,
        encryption_key BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username_encrypted BLOB NOT NULL,
        password_hash TEXT NOT NULL,
        master_password_hash TEXT,
        user_key BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title_encrypted BLOB NOT NULL,
        username_encrypted BLOB NOT NULL,
        password_encrypted BLOB NOT NULL,
        url_encrypted BLOB,
        notes_encrypted BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename_encrypted BLOB NOT NULL,
        original_filename_encrypted BLOB NOT NULL,
        file_size INTEGER NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER
    )''')
    conn.commit()

    cursor.execute('SELECT value FROM metadata WHERE key = ?', ('schema_version',))
    row = cursor.fetchone()
    if not row:
        cursor.execute('INSERT INTO metadata (key, value) VALUES (?, ?)', ('schema_version', REQUIRED_SCHEMA_VERSION))
        conn.commit()
        print(f"[INIT] Schema version set to {REQUIRED_SCHEMA_VERSION}")
    elif row[0] != REQUIRED_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version mismatch. Expected {REQUIRED_SCHEMA_VERSION}. Found {row[0]}"
        )

    conn.close()
    return True


def _derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode())


def _server_key():
    import hashlib
    return hashlib.sha256(SERVER_ENCRYPTION_KEY).digest()


def generate_user_key():
    return secrets.token_bytes(64)


def generate_encryption_key():
    return secrets.token_bytes(32)


def encrypt_user_key(user_key: bytes, master_password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, user_key, None)
    return salt + nonce + ct


def decrypt_user_key(encrypted_user_key: bytes, master_password: str) -> bytes:
    if not encrypted_user_key:
        return None
    salt = encrypted_user_key[:16]
    nonce = encrypted_user_key[16:28]
    ct = encrypted_user_key[28:]
    key = _derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def create_user_encryption_key(user_id, username):
    encryption_key = generate_encryption_key()
    sk = _server_key()
    aesgcm = AESGCM(sk)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, encryption_key, None)
    encrypted_key = nonce + ct
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO encryption_keys (user_id, username, encryption_key) VALUES (?, ?, ?)',
                   (user_id, username, encrypted_key))
    conn.commit()
    conn.close()
    return encryption_key


def get_user_encryption_key(user_id):
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT encryption_key FROM encryption_keys WHERE user_id = ?', (user_id,))
    r = cursor.fetchone()
    conn.close()
    return r[0] if r else None


def get_decrypted_encryption_key(user_id):
    enc = get_user_encryption_key(user_id)
    if not enc:
        return None
    sk = _server_key()
    nonce = enc[:12]
    ct = enc[12:]
    aesgcm = AESGCM(sk)
    return aesgcm.decrypt(nonce, ct, None)


def _aead_encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def _aead_decrypt(blob: bytes, key: bytes) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def encrypt_data(data, user_id):
    ek = get_decrypted_encryption_key(user_id)
    if not ek:
        raise ValueError('Encryption key not found')
    key = ek if len(ek) == 32 else ek[:32]
    b = data.encode() if isinstance(data, str) else data
    return _aead_encrypt(b, key)


def decrypt_data(encrypted_data, user_id):
    ek = get_decrypted_encryption_key(user_id)
    if not ek:
        raise ValueError('Encryption key not found')
    key = ek if len(ek) == 32 else ek[:32]
    return _aead_decrypt(encrypted_data, key)


class User(UserMixin):
    def __init__(self, id, username, master_password_hash=None):
        self.id = id
        self.username = username
        self.master_password_hash = master_password_hash


@login_manager.user_loader
def load_user(user_id):
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username_encrypted, master_password_hash FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        username = decrypt_data(row[1], int(user_id)).decode()
    except:
        username = None
    return User(row[0], username, row[2])


@app.route('/manifest.json')
def manifest():
    try:
        return send_file(os.path.join(app.root_path, 'static', 'manifest.json'),
                         mimetype='application/json')
    except FileNotFoundError:
        from flask import jsonify
        return jsonify({"error": "manifest.json not found"}), 404


@app.route('/sw.js')
def service_worker():
    try:
        return send_file(os.path.join(app.root_path, 'static', 'js', 'sw.js'),
                         mimetype='application/javascript')
    except FileNotFoundError:
        from flask import jsonify
        return jsonify({"error": "sw.js not found"}), 404


@app.route('/offline.html')
def offline():
    return render_template('offline.html')


@app.route('/generator')
def generator():
    return render_template('generator.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required')
            return render_template('register.html')
        conn = _conn()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username_encrypted FROM users')
        rows = cursor.fetchall()
        for r in rows:
            try:
                if decrypt_data(r[1], r[0]).decode().lower() == username.lower():
                    flash('User exists')
                    conn.close()
                    return render_template('register.html')
            except:
                continue
        password_hash = generate_password_hash(password)
        temp = b'temp_' + username.encode()
        cursor.execute('INSERT INTO users (username_encrypted, password_hash) VALUES (?, ?)', (temp, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        create_user_encryption_key(user_id, username)
        try:
            encrypted_username = encrypt_data(username, user_id)
            cursor.execute('UPDATE users SET username_encrypted = ? WHERE id = ?', (encrypted_username, user_id))
        except Exception:
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            flash('Error creating user')
            return render_template('register.html')
        cursor.execute('INSERT INTO user_settings (user_id) VALUES (?)', (user_id,))
        conn.commit()
        conn.close()
        user = User(user_id, username)
        login_user(user)
        flash('Registered')
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required')
            return render_template('login.html')
        conn = _conn()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username_encrypted, password_hash, master_password_hash FROM users')
        rows = cursor.fetchall()
        for r in rows:
            try:
                if decrypt_data(r[1], r[0]).decode().lower() == username.lower() and check_password_hash(r[2], password):
                    user = User(r[0], username, r[3])
                    login_user(user)
                    conn.close()
                    return redirect(url_for('dashboard'))
            except:
                continue
        conn.close()
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/set_master_password', methods=['POST'])
@login_required
def set_master_password():
    master_password = request.form.get('master_password')
    if not master_password or len(master_password) < 8:
        return jsonify({'error': 'Master password must be >=8 chars'}), 400
    user_key = generate_user_key()
    encrypted_user_key = encrypt_user_key(user_key, master_password)
    master_password_hash = generate_password_hash(master_password)
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET master_password_hash = ?, user_key = ? WHERE id = ?',
                   (master_password_hash, encrypted_user_key, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    title = request.form['title']
    username = request.form['username']
    password = request.form['password']
    url = request.form.get('url', '')
    notes = request.form.get('notes', '')
    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row or not check_password_hash(row[0], master_password):
        conn.close()
        return jsonify({'error': 'Invalid master password'}), 400
    try:
        user_key = decrypt_user_key(row[1], master_password)
    except:
        conn.close()
        return jsonify({'error': 'Error decrypting user key'}), 400
    try:
        et = encrypt_data(title, current_user.id)
        eu = encrypt_data(username, current_user.id)
        ep = encrypt_data(password, current_user.id)
        eur = encrypt_data(url, current_user.id) if url else None
        en = encrypt_data(notes, current_user.id) if notes else None
    except ValueError as e:
        conn.close()
        return jsonify({'error': str(e)}), 400
    cursor.execute('INSERT INTO passwords (user_id, title_encrypted, username_encrypted, password_encrypted, url_encrypted, notes_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
                   (current_user.id, et, eu, ep, eur, en))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Password added'})


@app.route('/get_password/<int:password_id>', methods=['POST'])
@login_required
def get_password(password_id):
    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row or not check_password_hash(row[0], master_password):
        conn.close()
        return jsonify({'error': 'Invalid master password'}), 400
    try:
        user_key = decrypt_user_key(row[1], master_password)
    except:
        conn.close()
        return jsonify({'error': 'Error decrypting user key'}), 400
    cursor.execute('SELECT title_encrypted, username_encrypted, password_encrypted, url_encrypted, notes_encrypted FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
    prow = cursor.fetchone()
    conn.close()
    if not prow:
        return jsonify({'error': 'Not found'}), 404
    try:
        title = decrypt_data(prow[0], current_user.id).decode()
        username = decrypt_data(prow[1], current_user.id).decode()
        password = decrypt_data(prow[2], current_user.id).decode()
        url = decrypt_data(prow[3], current_user.id).decode() if prow[3] else None
        notes = decrypt_data(prow[4], current_user.id).decode() if prow[4] else None
        return jsonify({'title': title, 'username': username, 'password': password, 'url': url, 'notes': notes})
    except Exception as e:
        return jsonify({'error': f'Decryption error: {str(e)}'}), 400


@app.route('/files')
@login_required
def files():
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    has_master = bool(row and row[0])
    try:
        cursor.execute('SELECT id, original_filename_encrypted, file_size, created_at FROM files WHERE user_id = ?', (current_user.id,))
        rows = cursor.fetchall()
    except:
        rows = []
    conn.close()
    files_list = []
    for r in rows:
        try:
            name = decrypt_data(r[1], current_user.id).decode()
        except:
            name = '[decryption error]'
        files_list.append({'id': r[0], 'filename': name, 'size': r[2], 'created_at': r[3]})
    return render_template('files.html', files=files_list, storage_info={}, has_master_password=has_master)


@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    file.seek(0,2)
    file_size = file.tell()
    file.seek(0)
    if file_size == 0 or file_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'Invalid file size'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT user_key, master_password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row or not check_password_hash(row[1], master_password):
        conn.close()
        return jsonify({'error': 'Invalid master password'}), 400
    try:
        user_key = decrypt_user_key(row[0], master_password)
    except:
        conn.close()
        return jsonify({'error': 'Error decrypting user key'}), 400
    data = file.read()
    orig = file.filename
    secure_name = secure_filename(orig)
    try:
        encrypted_data = encrypt_data(data, current_user.id)
        encrypted_filename = encrypt_data(secure_name, current_user.id)
        encrypted_original = encrypt_data(orig, current_user.id)
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Encryption error: {str(e)}'}), 400
    cursor.execute('INSERT INTO files (user_id, filename_encrypted, original_filename_encrypted, file_size, encrypted_data) VALUES (?, ?, ?, ?, ?)',
                   (current_user.id, encrypted_filename, encrypted_original, len(data), encrypted_data))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/download_file/<int:file_id>', methods=['POST'])
@login_required
def download_file(file_id):
    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT user_key, master_password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row or not check_password_hash(row[1], master_password):
        conn.close()
        return jsonify({'error': 'Invalid master password'}), 400
    try:
        user_key = decrypt_user_key(row[0], master_password)
    except:
        conn.close()
        return jsonify({'error': 'Error decrypting user key'}), 400
    cursor.execute('SELECT original_filename_encrypted, encrypted_data FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
    frow = cursor.fetchone()
    conn.close()
    if not frow:
        return jsonify({'error': 'Not found'}), 404
    try:
        filename = decrypt_data(frow[0], current_user.id).decode()
        data = decrypt_data(frow[1], current_user.id)
        response = send_file(io.BytesIO(data), as_attachment=True, download_name=filename)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        return jsonify({'error': f'Decryption error: {str(e)}'}), 400


@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    account_password = request.form.get('account_password')
    if not account_password:
        return jsonify({'error': 'Account password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_row = cursor.fetchone()
    if not user_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 400
    if not check_password_hash(user_row[0], account_password):
        conn.close()
        return jsonify({'error': 'Invalid account password'}), 400
    cursor.execute('DELETE FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'File deleted'})


@app.route('/passwords')
@login_required
def passwords():
    conn = _conn()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, title_encrypted, username_encrypted, url_encrypted, notes_encrypted, created_at FROM passwords WHERE user_id = ?', (current_user.id,))
        rows = cursor.fetchall()
    except Exception:
        rows = []
    conn.close()
    passwords_list = []
    for r in rows:
        try:
            title = decrypt_data(r[1], current_user.id).decode()
            username = decrypt_data(r[2], current_user.id).decode()
            url = decrypt_data(r[3], current_user.id).decode() if r[3] else None
            notes = decrypt_data(r[4], current_user.id).decode() if r[4] else None
            passwords_list.append({'id': r[0], 'title': title, 'username': username, 'url': url, 'notes': notes, 'created_at': r[5]})
        except Exception as e:
            passwords_list.append({'id': r[0], 'title': '[decryption error]', 'username': '[decryption error]', 'url': None, 'notes': f'Error: {str(e)[:50]}...', 'created_at': r[5]})
    return render_template('passwords.html', passwords=passwords_list)


@app.route('/edit_password/<int:password_id>', methods=['POST'])
@login_required
def edit_password(password_id):
    title = request.form['title']
    username = request.form['username']
    password = request.form['password']
    url = request.form.get('url', '')
    notes = request.form.get('notes', '')
    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 400
    if not check_password_hash(row[0], master_password):
        conn.close()
        return jsonify({'error': 'Invalid master password'}), 400
    try:
        _ = decrypt_user_key(row[1], master_password)
        et = encrypt_data(title, current_user.id)
        eu = encrypt_data(username, current_user.id)
        ep = encrypt_data(password, current_user.id)
        eur = encrypt_data(url, current_user.id) if url else None
        en = encrypt_data(notes, current_user.id) if notes else None
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Encryption error: {str(e)}'}), 400
    cursor.execute('UPDATE passwords SET title_encrypted = ?, username_encrypted = ?, password_encrypted = ?, url_encrypted = ?, notes_encrypted = ? WHERE id = ? AND user_id = ?', (et, eu, ep, eur, en, password_id, current_user.id))
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Password entry not found'}), 404
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Password updated'})


@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    account_password = request.form.get('account_password')
    if not account_password:
        return jsonify({'error': 'Account password required'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 400
    if not check_password_hash(row[0], account_password):
        conn.close()
        return jsonify({'error': 'Invalid account password'}), 400
    cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Password entry not found'}), 404
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Password deleted'})


@app.route('/check_master_password', methods=['POST'])
@login_required
def check_master_password():
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    conn.close()
    has_master_password = bool(row and row[0])
    return jsonify({'has_master_password': has_master_password})


@app.route('/change_master_password', methods=['POST'])
@login_required
def change_master_password():
    current_master_password = request.form['current_master_password']
    new_master_password = request.form['new_master_password']
    confirm_new_master_password = request.form['confirm_new_master_password']
    if new_master_password != confirm_new_master_password:
        return jsonify({'error': 'New master passwords do not match'}), 400
    if len(new_master_password) < 8:
        return jsonify({'error': 'New master password must be at least 8 characters'}), 400
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 400
    if not check_password_hash(row[0], current_master_password):
        conn.close()
        return jsonify({'error': 'Invalid current master password'}), 400
    encrypted_user_key = row[1]
    if not encrypted_user_key:
        conn.close()
        return jsonify({'error': 'User key not found'}), 400
    try:
        user_key = decrypt_user_key(encrypted_user_key, current_master_password)
    except Exception:
        conn.close()
        return jsonify({'error': 'Error decrypting user key'}), 400
    new_encrypted_user_key = encrypt_user_key(user_key, new_master_password)
    new_master_password_hash = generate_password_hash(new_master_password)
    cursor.execute('UPDATE users SET master_password_hash = ?, user_key = ? WHERE id = ?', (new_master_password_hash, new_encrypted_user_key, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Master password changed'})


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_new_password']
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('settings'))
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if row and check_password_hash(row[0], current_password):
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, current_user.id))
        conn.commit()
        conn.close()
        flash('Password changed')
    else:
        conn.close()
        flash('Invalid current password')
    return redirect(url_for('settings'))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    delete_confirm = request.form.get('delete_confirm')
    delete_password = request.form.get('delete_password')
    if delete_confirm != 'DELETE':
        flash('Invalid delete confirmation')
        return redirect(url_for('settings'))
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if row and check_password_hash(row[0], delete_password):
        cursor.execute('DELETE FROM passwords WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM files WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM user_settings WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM encryption_keys WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
        conn.commit()
        conn.close()
        logout_user()
        flash('Account deleted')
        return redirect(url_for('index'))
    else:
        conn.close()
        flash('Invalid password')
        return redirect(url_for('settings'))


@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    new_username = request.form['new_username']
    current_password = request.form['current_password']
    if not new_username or len(new_username) < 3:
        flash('Username must be at least 3 characters')
        return redirect(url_for('settings'))
    conn = _conn()
    cursor = conn.cursor()
    # Ensure not taken: try comparing encrypted value for current scheme
    try:
        encrypted_new_username = encrypt_data(new_username, current_user.id)
        cursor.execute('SELECT id FROM users WHERE username_encrypted = ? AND id != ?', (encrypted_new_username, current_user.id))
        if cursor.fetchone():
            conn.close()
            flash('Username is already taken')
            return redirect(url_for('settings'))
    except Exception:
        pass
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    if row and check_password_hash(row[0], current_password):
        try:
            encrypted_new_username = encrypt_data(new_username, current_user.id)
            cursor.execute('UPDATE users SET username_encrypted = ? WHERE id = ?', (encrypted_new_username, current_user.id))
            cursor.execute('UPDATE encryption_keys SET username = ? WHERE user_id = ?', (new_username, current_user.id))
            conn.commit()
            conn.close()
            current_user.username = new_username
            flash('Username changed')
        except Exception:
            conn.close()
            flash('Error encrypting username')
    else:
        conn.close()
        flash('Invalid password')
    return redirect(url_for('settings'))


@app.errorhandler(Exception)
def handle_exception(e):
    return render_template('error.html', error=f'An error occurred: {str(e)}'), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    resp = redirect(url_for('index'))
    resp.delete_cookie('session')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Not found'), 404


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
