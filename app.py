import os
import sqlite3
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

DB_PATH = os.environ.get("DB_PATH", "/tmp/secure_chat.db")

app = Flask(__name__)
app.secret_key = os.environ.get(
    'SECRET_KEY', 'your-secret-key-change-this-in-production')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Database initialization


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Contacts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (contact_user_id) REFERENCES users (id),
            UNIQUE(user_id, contact_user_id)
        )
    ''')

    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

# Encryption utilities


def generate_key_from_password(password):
    """Generate encryption key from password"""
    password_bytes = password.encode()
    salt = b'salt_for_encryption'  # In production, use random salt per user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key


def encrypt_message(message, key):
    """Encrypt message using Fernet"""
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted_message).decode()


def decrypt_message(encrypted_message, key):
    """Decrypt message using Fernet"""
    try:
        f = Fernet(key)
        decoded_message = base64.urlsafe_b64decode(encrypted_message.encode())
        decrypted_message = f.decrypt(decoded_message)
        return decrypted_message.decode()
    except:
        return "[Error: Could not decrypt message]"

# Database helper functions


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?',
                        (user_id,)).fetchone()
    conn.close()
    return user

# Routes


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        if get_user_by_username(username):
            flash('Username already exists')
            return render_template('register.html')

        # Generate encryption key from password
        encryption_key = generate_key_from_password(password)

        # Hash password for storage
        password_hash = generate_password_hash(password)

        # Save user to database
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, email, password_hash, encryption_key) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, encryption_key.decode())
            )
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['encryption_key'] = user['encryption_key']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get user's contacts
    conn = get_db_connection()
    contacts = conn.execute('''
        SELECT u.id, u.username, c.added_at
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ?
        ORDER BY c.added_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('dashboard.html', contacts=contacts)


@app.route('/add_contact', methods=['GET', 'POST'])
def add_contact():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        contact_username = request.form['contact_username']

        # Find the user to add as contact
        contact_user = get_user_by_username(contact_username)

        if not contact_user:
            flash('User not found')
            return render_template('add_contact.html')

        if contact_user['id'] == session['user_id']:
            flash('You cannot add yourself as a contact')
            return render_template('add_contact.html')

        # Add contact
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO contacts (user_id, contact_user_id) VALUES (?, ?)',
                (session['user_id'], contact_user['id'])
            )
            conn.commit()
            flash(f'Successfully added {contact_username} as contact')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Contact already exists')
        finally:
            conn.close()

    return render_template('add_contact.html')


@app.route('/chat/<int:contact_id>')
def chat(contact_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Verify contact relationship
    conn = get_db_connection()
    contact = conn.execute('''
        SELECT u.id, u.username
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ? AND c.contact_user_id = ?
    ''', (session['user_id'], contact_id)).fetchone()

    if not contact:
        flash('Contact not found')
        return redirect(url_for('dashboard'))

    # Get messages between users
    messages = conn.execute('''
        SELECT m.*, u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
    ''', (session['user_id'], contact_id, contact_id, session['user_id'])).fetchall()

    conn.close()

    # Decrypt messages
    decrypted_messages = []
    for msg in messages:
        if msg['sender_id'] == session['user_id']:
            # Decrypt with current user's key
            decrypted_text = decrypt_message(
                msg['encrypted_message'], session['encryption_key'].encode())
        else:
            # For received messages, we need the sender's key
            sender = get_user_by_id(msg['sender_id'])
            decrypted_text = decrypt_message(
                msg['encrypted_message'], sender['encryption_key'].encode())

        decrypted_messages.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_username': msg['sender_username'],
            'message': decrypted_text,
            'timestamp': msg['timestamp']
        })

    return render_template('chat.html', contact=contact, messages=decrypted_messages)


@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message = data.get('message')

    if not receiver_id or not message:
        return jsonify({'error': 'Missing data'}), 400

    # Encrypt message with sender's key
    encrypted_message = encrypt_message(
        message, session['encryption_key'].encode())

    # Save to database
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender_id, receiver_id, encrypted_message) VALUES (?, ?, ?)',
        (session['user_id'], receiver_id, encrypted_message)
    )
    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/get_messages/<int:contact_id>')
def get_messages(contact_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    messages = conn.execute('''
        SELECT m.*, u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
    ''', (session['user_id'], contact_id, contact_id, session['user_id'])).fetchall()
    conn.close()

    # Decrypt messages
    decrypted_messages = []
    for msg in messages:
        if msg['sender_id'] == session['user_id']:
            decrypted_text = decrypt_message(
                msg['encrypted_message'], session['encryption_key'].encode())
        else:
            sender = get_user_by_id(msg['sender_id'])
            decrypted_text = decrypt_message(
                msg['encrypted_message'], sender['encryption_key'].encode())

        decrypted_messages.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_username': msg['sender_username'],
            'message': decrypted_text,
            'timestamp': msg['timestamp']
        })

    return jsonify(decrypted_messages)

# WebSocket event handlers


@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    # We'll handle user authentication in join_chat


@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


@socketio.on('join_chat')
def handle_join_chat(data):
    # Get user info from the request
    user_id = data.get('user_id')
    contact_id = data.get('contact_id')

    if not user_id or not contact_id:
        print("Missing user_id or contact_id in join_chat")
        return

    room_name = f"chat_{min(user_id, contact_id)}_{max(user_id, contact_id)}"
    join_room(room_name)
    print(f"User {user_id} joined chat room: {room_name}")


@socketio.on('leave_chat')
def handle_leave_chat(data):
    user_id = data.get('user_id')
    contact_id = data.get('contact_id')

    if user_id and contact_id:
        room_name = f"chat_{min(user_id, contact_id)}_{max(user_id, contact_id)}"
        leave_room(room_name)
        print(f"User {user_id} left chat room: {room_name}")


@socketio.on('send_message')
def handle_send_message(data):
    user_id = data.get('user_id')
    receiver_id = data.get('receiver_id')
    message = data.get('message')

    if not user_id or not receiver_id or not message:
        print("Missing required data in send_message")
        return

    # Get user info from database
    user = get_user_by_id(user_id)
    if not user:
        print(f"User {user_id} not found")
        return

    # Encrypt message with sender's key
    encrypted_message = encrypt_message(
        message, user['encryption_key'].encode())

    # Save to database
    conn = get_db_connection()
    cursor = conn.execute(
        'INSERT INTO messages (sender_id, receiver_id, encrypted_message) VALUES (?, ?, ?)',
        (user_id, receiver_id, encrypted_message)
    )
    message_id = cursor.lastrowid
    conn.commit()

    # Create room name for this chat
    room_name = f"chat_{min(user_id, receiver_id)}_{max(user_id, receiver_id)}"

    # Emit message to all users in the chat room
    emit('new_message', {
        'id': message_id,
        'sender_id': user_id,
        'sender_username': user['username'],
        'message': message,  # Send decrypted message for real-time display
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }, room=room_name)

    print(f"Message sent from {user_id} to {receiver_id} in room {room_name}")
    conn.close()


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
