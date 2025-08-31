from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import base64
import io
import math
import time
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# Серверный ключ шифрования (в реальном проекте должен храниться в безопасном месте)
SERVER_ENCRYPTION_KEY = b'supercell-server-key-2024-secure-encryption-system'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Создаем таблицу для хранения ключей шифрования
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encryption_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            username TEXT NOT NULL,
            encryption_key BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_encrypted BLOB NOT NULL,
            password_hash TEXT NOT NULL,
            master_password_hash TEXT,
            user_key BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title_encrypted BLOB NOT NULL,
            username_encrypted BLOB NOT NULL,
            password_encrypted BLOB NOT NULL,
            url_encrypted BLOB,
            notes_encrypted BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename_encrypted BLOB NOT NULL,
            original_filename_encrypted BLOB NOT NULL,
            file_size INTEGER NOT NULL,
            encrypted_data BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Добавляем поле user_key если его нет
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN user_key BLOB')
        print("Добавлено поле user_key в таблицу users")
    except sqlite3.OperationalError:
        print("Поле user_key уже существует")
    
    conn.commit()
    conn.close()

def derive_master_key(master_password, salt):
    # Создаем ключ на основе мастер-пароля
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def generate_user_key():
    """Генерирует случайный ключ пользователя размером 512 байт (0.5 КБ)"""
    return secrets.token_bytes(512)

def generate_encryption_key():
    """Генерирует случайный ключ шифрования размером 256 байт"""
    return secrets.token_bytes(256)

def encrypt_user_key(user_key, master_password):
    """Шифрует пользовательский ключ мастер-паролем"""
    salt = os.urandom(16)
    master_key = derive_master_key(master_password, salt)
    f = Fernet(master_key)
    encrypted_key = f.encrypt(user_key)
    return salt + encrypted_key

def decrypt_user_key(encrypted_user_key, master_password):
    """Дешифрует пользовательский ключ мастер-паролем"""
    if not encrypted_user_key:
        return None
    
    salt = encrypted_user_key[:16]
    encrypted_data = encrypted_user_key[16:]
    master_key = derive_master_key(master_password, salt)
    f = Fernet(master_key)
    decrypted_key = f.decrypt(encrypted_data)
    return decrypted_key

def get_user_encryption_key(user_id):
    """Получает ключ шифрования пользователя из базы данных"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT encryption_key FROM encryption_keys WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def create_user_encryption_key(user_id, username):
    """Создает новый ключ шифрования для пользователя"""
    encryption_key = generate_encryption_key()
    
    # Шифруем ключ серверным ключом
    server_fernet = Fernet(base64.urlsafe_b64encode(SERVER_ENCRYPTION_KEY[:32]))
    encrypted_key = server_fernet.encrypt(encryption_key)
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO encryption_keys (user_id, username, encryption_key) VALUES (?, ?, ?)',
                  (user_id, username, encrypted_key))
    conn.commit()
    conn.close()
    
    return encryption_key

def get_decrypted_encryption_key(user_id):
    """Получает и дешифрует ключ шифрования пользователя"""
    encrypted_key = get_user_encryption_key(user_id)
    if not encrypted_key:
        return None
    
    # Дешифруем ключ серверным ключом
    server_fernet = Fernet(base64.urlsafe_b64encode(SERVER_ENCRYPTION_KEY[:32]))
    decrypted_key = server_fernet.decrypt(encrypted_key)
    return decrypted_key

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def format_size(size_bytes):
    """Форматирует размер в байтах в читаемый вид"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def encrypt_data(data, user_id):
    """Шифрует данные ключом шифрования пользователя"""
    encryption_key = get_decrypted_encryption_key(user_id)
    if not encryption_key:
        raise ValueError("Ключ шифрования не найден")
    
    # Используем первые 32 байта ключа шифрования для Fernet
    fernet_key = base64.urlsafe_b64encode(encryption_key[:32])
    f = Fernet(fernet_key)
    encrypted_data = f.encrypt(data.encode() if isinstance(data, str) else data)
    return encrypted_data

def decrypt_data(encrypted_data, user_id):
    """Дешифрует данные ключом шифрования пользователя"""
    encryption_key = get_decrypted_encryption_key(user_id)
    if not encryption_key:
        raise ValueError("Ключ шифрования не найден")
    
    # Используем первые 32 байта ключа шифрования для Fernet
    fernet_key = base64.urlsafe_b64encode(encryption_key[:32])
    f = Fernet(fernet_key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data



class User(UserMixin):
    def __init__(self, id, username, master_password_hash=None):
        self.id = id
        self.username = username
        self.master_password_hash = master_password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        # Пробуем получить по старой структуре
        cursor.execute('SELECT id, username, master_password_hash FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            conn.close()
            return User(user_id, user_data[1], user_data[2])
    except:
        pass
    
    try:
        # Пробуем получить по новой структуре
        cursor.execute('SELECT id, username_encrypted, master_password_hash FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            try:
                decrypted_username = decrypt_data(user_data[1], user_id).decode()
                conn.close()
                return User(user_id, decrypted_username, user_data[2])
            except:
                pass
    except:
        pass
    
    conn.close()
    return None

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
            flash('Имя пользователя и пароль обязательны')
            return render_template('register.html')
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Проверяем username без учета регистра
        user_exists = False
        
        # Проверяем по старой структуре
        try:
            cursor.execute('SELECT id FROM users WHERE LOWER(username) = LOWER(?)', (username,))
            if cursor.fetchone():
                user_exists = True
        except sqlite3.OperationalError:
            pass
        
        # Проверяем по новой структуре
        if not user_exists:
            try:
                cursor.execute('SELECT id FROM users')
                all_users = cursor.fetchall()
                
                for user_row in all_users:
                    try:
                        # Проверяем, есть ли ключ шифрования для этого пользователя
                        encryption_key = get_decrypted_encryption_key(user_row[0])
                        if encryption_key:
                            fernet_key = base64.urlsafe_b64encode(encryption_key[:32])
                            f = Fernet(fernet_key)
                            
                            # Получаем зашифрованное имя пользователя
                            cursor.execute('SELECT username_encrypted FROM users WHERE id = ?', (user_row[0],))
                            encrypted_username_data = cursor.fetchone()
                            if encrypted_username_data and encrypted_username_data[0]:
                                decrypted_username = f.decrypt(encrypted_username_data[0]).decode()
                                if decrypted_username.lower() == username.lower():
                                    user_exists = True
                                    break
                    except:
                        continue
            except:
                pass
        
        if user_exists:
            flash('Пользователь уже существует')
            conn.close()
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        
        # Создаем пользователя с временным зашифрованным именем
        temp_encrypted = b'temp_' + username.encode()
        cursor.execute('INSERT INTO users (username_encrypted, password_hash) VALUES (?, ?)',
                      (temp_encrypted, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        
        # Создаем ключ шифрования для пользователя
        create_user_encryption_key(user_id, username)
        
        # Теперь шифруем имя пользователя и обновляем запись
        try:
            encrypted_username = encrypt_data(username, user_id)
            cursor.execute('UPDATE users SET username_encrypted = ? WHERE id = ?',
                          (encrypted_username, user_id))
        except Exception as e:
            # Если не удалось зашифровать, удаляем пользователя
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            flash('Ошибка создания пользователя. Попробуйте еще раз.')
            return render_template('register.html')
        
        # Создаем настройки пользователя
        try:
            cursor.execute('INSERT INTO user_settings (user_id) VALUES (?)', (user_id,))
        except Exception as e:
            # Если не удалось создать настройки, удаляем пользователя
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            cursor.execute('DELETE FROM encryption_keys WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            flash('Ошибка создания настроек пользователя. Попробуйте еще раз.')
            return render_template('register.html')
        
        conn.commit()
        conn.close()
        
        # Автоматический вход после регистрации
        user = User(user_id, username)
        login_user(user)
        flash('Регистрация успешна! Добро пожаловать в BattleCell Security.')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash('Имя пользователя и пароль обязательны')
            return render_template('login.html')
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Ищем пользователя по зашифрованному имени
        try:
            # Сначала пробуем найти по старой структуре
            cursor.execute('SELECT id, username, password_hash, master_password_hash FROM users WHERE LOWER(username) = LOWER(?)', (username,))
            user_data = cursor.fetchone()
            if user_data:
                user = User(user_data[0], user_data[1], user_data[3])
                if check_password_hash(user_data[2], password):
                    login_user(user)
                    conn.close()
                    return redirect(url_for('dashboard'))
        except:
            pass
        
        # Если не нашли по старой структуре, ищем по новой
        try:
            # Получаем всех пользователей и проверяем их имена
            cursor.execute('SELECT id, username_encrypted, password_hash, master_password_hash FROM users')
            all_users = cursor.fetchall()
            
            for user_row in all_users:
                try:
                    decrypted_username = decrypt_data(user_row[1], user_row[0])
                    if decrypted_username.decode().lower() == username.lower():
                        if check_password_hash(user_row[2], password):
                            user = User(user_row[0], decrypted_username.decode(), user_row[3])
                            login_user(user)
                            conn.close()
                            return redirect(url_for('dashboard'))
                except:
                    continue
        except:
            pass
        
        conn.close()
        flash('Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/manifest.json')
def manifest():
    try:
        response = send_file(os.path.join(app.root_path, 'static', 'manifest.json'), mimetype='application/json')
        response.headers['Cache-Control'] = 'public, max-age=3600'  # Кэшировать на 1 час
        return response
    except FileNotFoundError:
        return jsonify({'error': 'Manifest not found'}), 404

@app.route('/sw.js')
def service_worker():
    try:
        response = send_file(os.path.join(app.root_path, 'static', 'js', 'sw.js'), mimetype='application/javascript')
        response.headers['Cache-Control'] = 'no-cache'  # Не кэшировать Service Worker
        return response
    except FileNotFoundError:
        return jsonify({'error': 'Service worker not found'}), 404

@app.route('/offline.html')
def offline():
    return render_template('offline.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/passwords')
@login_required
def passwords():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Проверяем структуру таблицы
    try:
        cursor.execute('SELECT id, title_encrypted, username_encrypted, url_encrypted, notes_encrypted, created_at FROM passwords WHERE user_id = ?', (current_user.id,))
        passwords_data = cursor.fetchall()
    except sqlite3.OperationalError:
        # Если новая структура не существует, используем старую
        try:
            cursor.execute('SELECT id, title, username, url, notes, created_at FROM passwords WHERE user_id = ?', (current_user.id,))
            passwords_data = cursor.fetchall()
            conn.close()
            
            passwords_list = []
            for pwd in passwords_data:
                passwords_list.append({
                    'id': pwd[0],
                    'title': pwd[1],
                    'username': pwd[2],
                    'url': pwd[3],
                    'notes': pwd[4],
                    'created_at': pwd[5]
                })
            return render_template('passwords.html', passwords=passwords_list)
        except:
            passwords_data = []
    
    conn.close()
    
    passwords_list = []
    for pwd in passwords_data:
        try:
            decrypted_title = decrypt_data(pwd[1], current_user.id).decode()
            decrypted_username = decrypt_data(pwd[2], current_user.id).decode()
            decrypted_url = decrypt_data(pwd[3], current_user.id).decode() if pwd[3] else None
            decrypted_notes = decrypt_data(pwd[4], current_user.id).decode() if pwd[4] else None
            
            passwords_list.append({
                'id': pwd[0],
                'title': decrypted_title,
                'username': decrypted_username,
                'url': decrypted_url,
                'notes': decrypted_notes,
                'created_at': pwd[5]
            })
        except Exception as e:
            # Если не удалось дешифровать, добавляем запись с ошибкой
            passwords_list.append({
                'id': pwd[0],
                'title': '[Ошибка дешифровки]',
                'username': '[Ошибка дешифровки]',
                'url': None,
                'notes': f'Ошибка: {str(e)[:50]}...',
                'created_at': pwd[5]
            })
    
    return render_template('passwords.html', passwords=passwords_list)

@app.route('/check_master_password', methods=['POST'])
@login_required
def check_master_password():
    """Проверяет, установлен ли мастер-пароль у пользователя"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash FROM users WHERE id = ?', (current_user.id,))
    result = cursor.fetchone()
    conn.close()
    
    has_master_password = bool(result and result[0])
    return jsonify({'has_master_password': has_master_password})







@app.route('/set_master_password', methods=['POST'])
@login_required
def set_master_password():
    """Устанавливает мастер-пароль для пользователя и генерирует пользовательский ключ"""
    master_password = request.form.get('master_password')
    
    if not master_password or len(master_password) < 8:
        return jsonify({'error': 'Мастер-пароль должен содержать минимум 8 символов'}), 400
    
    # Генерируем пользовательский ключ
    user_key = generate_user_key()
    
    # Шифруем пользовательский ключ мастер-паролем
    encrypted_user_key = encrypt_user_key(user_key, master_password)
    
    master_password_hash = generate_password_hash(master_password)
    
    conn = sqlite3.connect('database.db')
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
        return jsonify({'error': 'Мастер-пароль обязателен'}), 400
    
    # Проверяем мастер-пароль и получаем пользовательский ключ
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(result[0], master_password):
        return jsonify({'error': 'Неверный мастер-пароль'}), 400
    
    encrypted_user_key = result[1]
    
    if not encrypted_user_key:
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, master_password)
        if not user_key:
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    # Шифруем все данные ключом шифрования пользователя
    try:
        encrypted_title = encrypt_data(title, current_user.id)
        encrypted_username = encrypt_data(username, current_user.id)
        encrypted_password = encrypt_data(password, current_user.id)
        encrypted_url = encrypt_data(url, current_user.id) if url else None
        encrypted_notes = encrypt_data(notes, current_user.id) if notes else None
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO passwords (user_id, title_encrypted, username_encrypted, password_encrypted, url_encrypted, notes_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
                  (current_user.id, encrypted_title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Пароль добавлен'})

@app.route('/get_password/<int:password_id>', methods=['POST'])
@login_required
def get_password(password_id):
    master_password = request.form.get('master_password')
    
    if not master_password:
        return jsonify({'error': 'Мастер-пароль обязателен'}), 400
    
    # Проверяем мастер-пароль и получаем пользовательский ключ
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    user_result = cursor.fetchone()
    
    if not user_result:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(user_result[0], master_password):
        conn.close()
        return jsonify({'error': 'Неверный мастер-пароль'}), 400
    
    encrypted_user_key = user_result[1]
    
    if not encrypted_user_key:
        conn.close()
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, master_password)
        if not user_key:
            conn.close()
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        conn.close()
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    # Получаем все данные пароля
    try:
        cursor.execute('SELECT title_encrypted, username_encrypted, password_encrypted, url_encrypted, notes_encrypted FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
        password_result = cursor.fetchone()
    except sqlite3.OperationalError:
        # Если новая структура не существует, используем старую
        cursor.execute('SELECT title, username, password, url, notes FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
        password_result = cursor.fetchone()
        
        if password_result:
            title, username, password, url, notes = password_result
            return jsonify({
                'title': title,
                'username': username,
                'password': password,
                'url': url,
                'notes': notes
            })
    
    conn.close()
    
    if not password_result:
        return jsonify({'error': 'Пароль не найден'}), 404
    
    encrypted_title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes = password_result
    
    try:
        decrypted_title = decrypt_data(encrypted_title, current_user.id).decode()
        decrypted_username = decrypt_data(encrypted_username, current_user.id).decode()
        decrypted_password = decrypt_data(encrypted_password, current_user.id).decode()
        decrypted_url = decrypt_data(encrypted_url, current_user.id).decode() if encrypted_url else None
        decrypted_notes = decrypt_data(encrypted_notes, current_user.id).decode() if encrypted_notes else None
        
        return jsonify({
            'title': decrypted_title,
            'username': decrypted_username,
            'password': decrypted_password,
            'url': decrypted_url,
            'notes': decrypted_notes
        })
    except ValueError as e:
        return jsonify({'error': f'Ошибка дешифровки: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Ошибка дешифровки пароля: {str(e)}'}), 400

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
        return jsonify({'error': 'Мастер-пароль обязателен'}), 400
    
    # Проверяем мастер-пароль и получаем пользовательский ключ
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(result[0], master_password):
        conn.close()
        return jsonify({'error': 'Неверный мастер-пароль'}), 400
    
    encrypted_user_key = result[1]
    
    if not encrypted_user_key:
        conn.close()
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, master_password)
        if not user_key:
            conn.close()
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        conn.close()
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    # Шифруем все данные ключом шифрования пользователя
    try:
        encrypted_title = encrypt_data(title, current_user.id)
        encrypted_username = encrypt_data(username, current_user.id)
        encrypted_password = encrypt_data(password, current_user.id)
        encrypted_url = encrypt_data(url, current_user.id) if url else None
        encrypted_notes = encrypt_data(notes, current_user.id) if notes else None
    except ValueError as e:
        conn.close()
        return jsonify({'error': str(e)}), 400
    
    # Обновляем пароль в базе данных
    cursor.execute('UPDATE passwords SET title_encrypted = ?, username_encrypted = ?, password_encrypted = ?, url_encrypted = ?, notes_encrypted = ? WHERE id = ? AND user_id = ?',
                  (encrypted_title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes, password_id, current_user.id))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Пароль не найден'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Пароль обновлен'})

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    account_password = request.form.get('account_password')
    
    if not account_password:
        return jsonify({'error': 'Пароль от аккаунта обязателен'}), 400
    
    # Проверяем пароль от аккаунта
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_result = cursor.fetchone()
    
    if not user_result:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(user_result[0], account_password):
        conn.close()
        return jsonify({'error': 'Неверный пароль от аккаунта'}), 400
    
    # Удаляем пароль
    cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Пароль не найден'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Пароль удален'})

@app.route('/files')
@login_required
def files():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Проверяем структуру таблицы
    try:
        cursor.execute('SELECT id, original_filename_encrypted, file_size, created_at FROM files WHERE user_id = ?', (current_user.id,))
        files_data = cursor.fetchall()
    except sqlite3.OperationalError:
        # Если новая структура не существует, используем старую
        try:
            cursor.execute('SELECT id, original_filename, file_size, created_at FROM files WHERE user_id = ?', (current_user.id,))
            files_data = cursor.fetchall()
            conn.close()
            
            files_list = []
            for file_data in files_data:
                files_list.append({
                    'id': file_data[0],
                    'filename': file_data[1],
                    'size': file_data[2],
                    'created_at': file_data[3]
                })
            
            # Получаем информацию о занятом пространстве
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = ?', (current_user.id,))
            used_storage = cursor.fetchone()[0]
            conn.close()
            
            max_storage = 500 * 1024 * 1024  # 500MB в байтах
            storage_percentage = (used_storage / max_storage) * 100 if max_storage > 0 else 0
            
            storage_info = {
                'used': used_storage,
                'max': max_storage,
                'percentage': storage_percentage,
                'used_formatted': format_size(used_storage),
                'max_formatted': format_size(max_storage),
                'available_formatted': format_size(max_storage - used_storage)
            }
            
            return render_template('files.html', files=files_list, storage_info=storage_info)
        except:
            files_data = []
    
    # Получаем информацию о занятом пространстве
    cursor.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = ?', (current_user.id,))
    used_storage = cursor.fetchone()[0]
    conn.close()
    
    max_storage = 500 * 1024 * 1024  # 500MB в байтах
    storage_percentage = (used_storage / max_storage) * 100 if max_storage > 0 else 0
    
    files_list = []
    for file_data in files_data:
        try:
            decrypted_filename = decrypt_data(file_data[1], current_user.id).decode()
            files_list.append({
                'id': file_data[0],
                'filename': decrypted_filename,
                'size': file_data[2],
                'created_at': file_data[3]
            })
        except Exception as e:
            # Если не удалось дешифровать, добавляем файл с ошибкой
            files_list.append({
                'id': file_data[0],
                'filename': f'[Ошибка дешифровки] - {str(e)[:30]}...',
                'size': file_data[2],
                'created_at': file_data[3]
            })
    
    storage_info = {
        'used': used_storage,
        'max': max_storage,
        'percentage': storage_percentage,
        'used_formatted': format_size(used_storage),
        'max_formatted': format_size(max_storage),
        'available_formatted': format_size(max_storage - used_storage)
    }
    
    return render_template('files.html', files=files_list, storage_info=storage_info)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не выбран'}), 400
    
    file = request.files['file']
    master_password = request.form.get('master_password')
    
    if not master_password:
        return jsonify({'error': 'Мастер-пароль обязателен'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    
    # Проверяем мастер-пароль и получаем пользовательский ключ
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(result[0], master_password):
        return jsonify({'error': 'Неверный мастер-пароль'}), 400
    
    encrypted_user_key = result[1]
    
    if not encrypted_user_key:
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, master_password)
        if not user_key:
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    if file:
        original_filename = file.filename
        secure_filename_for_storage = secure_filename(file.filename)
        file_data = file.read()
        
        # Проверяем общий размер всех файлов пользователя
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = ?', (current_user.id,))
        current_storage = cursor.fetchone()[0]
        conn.close()
        
        total_storage_after_upload = current_storage + len(file_data)
        max_storage = 500 * 1024 * 1024  # 500MB в байтах
        
        if total_storage_after_upload > max_storage:
            return jsonify({'error': f'Недостаточно места. Доступно: {format_size(max_storage - current_storage)}, требуется: {format_size(len(file_data))}'}), 400
        
        # Шифруем файл и имена файлов ключом шифрования пользователя
        try:
            encrypted_data = encrypt_data(file_data, current_user.id)
            encrypted_filename = encrypt_data(secure_filename_for_storage, current_user.id)
            encrypted_original_filename = encrypt_data(original_filename, current_user.id)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO files (user_id, filename_encrypted, original_filename_encrypted, file_size, encrypted_data) VALUES (?, ?, ?, ?, ?)',
                      (current_user.id, encrypted_filename, encrypted_original_filename, len(file_data), encrypted_data))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Файл загружен'})
    
    return jsonify({'error': 'Ошибка обработки файла'}), 400

@app.route('/download_file/<int:file_id>', methods=['POST'])
@login_required
def download_file(file_id):
    master_password = request.form.get('master_password')
    
    if not master_password:
        return jsonify({'error': 'Мастер-пароль обязателен'}), 400
    
    # Проверяем мастер-пароль и получаем пользовательский ключ
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    user_result = cursor.fetchone()
    
    if not user_result:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(user_result[0], master_password):
        conn.close()
        return jsonify({'error': 'Неверный мастер-пароль'}), 400
    
    encrypted_user_key = user_result[1]
    
    if not encrypted_user_key:
        conn.close()
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, master_password)
        if not user_key:
            conn.close()
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        conn.close()
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    # Получаем зашифрованный файл
    try:
        cursor.execute('SELECT original_filename_encrypted, encrypted_data FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
        file_result = cursor.fetchone()
    except sqlite3.OperationalError:
        # Если новая структура не существует, используем старую
        cursor.execute('SELECT original_filename, encrypted_data FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
        file_result = cursor.fetchone()
        
        if file_result:
            filename, encrypted_data = file_result
            try:
                decrypted_data = decrypt_data(encrypted_data, current_user.id)
                response = send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=filename
                )
                response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            except Exception as e:
                return jsonify({'error': f'Ошибка дешифровки файла: {str(e)}'}), 400
    
    conn.close()
    
    if not file_result:
        return jsonify({'error': 'Файл не найден'}), 404
    
    encrypted_filename, encrypted_data = file_result
    
    try:
        decrypted_filename = decrypt_data(encrypted_filename, current_user.id).decode()
        decrypted_data = decrypt_data(encrypted_data, current_user.id)
        response = send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=decrypted_filename
        )
        response.headers['Content-Disposition'] = f'attachment; filename="{decrypted_filename}"'
        return response
    except ValueError as e:
        return jsonify({'error': f'Ошибка дешифровки: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Ошибка дешифровки файла: {str(e)}'}), 400

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    account_password = request.form.get('account_password')
    
    if not account_password:
        return jsonify({'error': 'Пароль от аккаунта обязателен'}), 400
    
    # Проверяем пароль от аккаунта
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_result = cursor.fetchone()
    
    if not user_result:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    if not check_password_hash(user_result[0], account_password):
        conn.close()
        return jsonify({'error': 'Неверный пароль от аккаунта'}), 400
    
    # Удаляем файл
    cursor.execute('DELETE FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Файл не найден'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Файл удален'})



@app.route('/generator')
def generator():
    return render_template('generator.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/change_master_password', methods=['POST'])
@login_required
def change_master_password():
    current_master_password = request.form['current_master_password']
    new_master_password = request.form['new_master_password']
    confirm_new_master_password = request.form['confirm_new_master_password']
    
    if new_master_password != confirm_new_master_password:
        return jsonify({'error': 'Новые мастер-пароли не совпадают'}), 400
    
    if len(new_master_password) < 8:
        return jsonify({'error': 'Новый мастер-пароль должен содержать минимум 8 символов'}), 400
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT master_password_hash, user_key FROM users WHERE id = ?', (current_user.id,))
    user_data = cursor.fetchone()
    
    if not user_data:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 400
    
    # Проверяем текущий мастер-пароль
    if not check_password_hash(user_data[0], current_master_password):
        conn.close()
        return jsonify({'error': 'Неверный текущий мастер-пароль'}), 400
    
    encrypted_user_key = user_data[1]
    
    if not encrypted_user_key:
        conn.close()
        return jsonify({'error': 'Пользовательский ключ не найден'}), 400
    
    # Дешифруем пользовательский ключ текущим мастер-паролем
    try:
        user_key = decrypt_user_key(encrypted_user_key, current_master_password)
        if not user_key:
            conn.close()
            return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    except:
        conn.close()
        return jsonify({'error': 'Ошибка дешифровки пользовательского ключа'}), 400
    
    # Шифруем пользовательский ключ новым мастер-паролем
    new_encrypted_user_key = encrypt_user_key(user_key, new_master_password)
    
    new_master_password_hash = generate_password_hash(new_master_password)
    
    cursor.execute('UPDATE users SET master_password_hash = ?, user_key = ? WHERE id = ?', 
                  (new_master_password_hash, new_encrypted_user_key, current_user.id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Мастер-пароль успешно изменен'})

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_new_password']
    
    if new_password != confirm_password:
        flash('Новые пароли не совпадают')
        return redirect(url_for('settings'))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_data = cursor.fetchone()
    
    if user_data and check_password_hash(user_data[0], current_password):
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, current_user.id))
        conn.commit()
        conn.close()
        flash('Пароль успешно изменен.')
    else:
        conn.close()
        flash('Неверный текущий пароль')
    
    return redirect(url_for('settings'))



@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    delete_confirm = request.form.get('delete_confirm')
    delete_password = request.form.get('delete_password')
    
    if delete_confirm != 'УДАЛИТЬ':
        flash('Неверное подтверждение удаления')
        return redirect(url_for('settings'))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_data = cursor.fetchone()
    
    if user_data and check_password_hash(user_data[0], delete_password):
        # Удаляем все данные пользователя
        cursor.execute('DELETE FROM passwords WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM files WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM user_settings WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM encryption_keys WHERE user_id = ?', (current_user.id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
        conn.commit()
        conn.close()
        
        logout_user()
        flash('Аккаунт успешно удален')
        return redirect(url_for('index'))
    else:
        conn.close()
        flash('Неверный пароль')
        return redirect(url_for('settings'))



@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    new_username = request.form['new_username']
    current_password = request.form['current_password']
    
    if not new_username or len(new_username) < 3:
        flash('Имя пользователя должно содержать минимум 3 символа')
        return redirect(url_for('settings'))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Проверяем, не занято ли новое имя пользователя
    try:
        # Проверяем по старой структуре
        cursor.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, current_user.id))
        if cursor.fetchone():
            conn.close()
            flash('Это имя пользователя уже занято')
            return redirect(url_for('settings'))
    except:
        # Проверяем по новой структуре
        try:
            encrypted_new_username = encrypt_data(new_username, current_user.id)
            cursor.execute('SELECT id FROM users WHERE username_encrypted = ? AND id != ?', (encrypted_new_username, current_user.id))
            if cursor.fetchone():
                conn.close()
                flash('Это имя пользователя уже занято')
                return redirect(url_for('settings'))
        except:
            pass
    
    # Проверяем текущий пароль
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
    user_data = cursor.fetchone()
    
    if user_data and check_password_hash(user_data[0], current_password):
        old_username = current_user.username
        
        # Шифруем новое имя пользователя
        try:
            encrypted_new_username = encrypt_data(new_username, current_user.id)
            cursor.execute('UPDATE users SET username_encrypted = ? WHERE id = ?', (encrypted_new_username, current_user.id))
            cursor.execute('UPDATE encryption_keys SET username = ? WHERE user_id = ?', (new_username, current_user.id))
            conn.commit()
            conn.close()
            
            # Обновляем имя пользователя в объекте current_user
            current_user.username = new_username
            
            flash('Имя пользователя успешно изменено.')
        except ValueError as e:
            conn.close()
            flash('Ошибка шифрования имени пользователя')
    else:
        conn.close()
        flash('Неверный пароль')
    
    return redirect(url_for('settings'))



@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Внутренняя ошибка сервера'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Страница не найдена'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    return render_template('error.html', error=f'Произошла ошибка: {str(e)}'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
