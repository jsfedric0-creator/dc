from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import json
import hashlib
import datetime
from functools import wraps
import threading
import time
import requests
from urllib.parse import urlparse
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['DATABASE'] = '/app/data/iptv.db'

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  email TEXT,
                  role TEXT DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP,
                  max_connections INTEGER DEFAULT 1,
                  is_active INTEGER DEFAULT 1)''')
    
    # Streams table
    c.execute('''CREATE TABLE IF NOT EXISTS streams
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT,
                  source_url TEXT,
                  proxy_url TEXT,
                  category TEXT,
                  type TEXT,
                  is_active INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  user_id INTEGER,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Server stats
    c.execute('''CREATE TABLE IF NOT EXISTS server_stats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  cpu_usage REAL,
                  memory_usage REAL,
                  bandwidth_in REAL,
                  bandwidth_out REAL,
                  active_streams INTEGER,
                  active_users INTEGER)''')
    
    # Logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  user_id INTEGER,
                  action TEXT,
                  details TEXT,
                  ip_address TEXT)''')
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ? AND is_active = 1", 
                 (username, hashed_password))
        user = c.fetchone()
        conn.close()
        
        if user:
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            log_action(user[0], 'login', request.remote_addr)
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, 'logout', request.remote_addr)
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Get user stats
    c.execute("SELECT COUNT(*) FROM streams WHERE user_id = ?", (current_user.id,))
    stream_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM logs WHERE user_id = ? AND date(timestamp) = date('now')", (current_user.id,))
    today_activity = c.fetchone()[0]
    
    # Get recent streams
    c.execute("SELECT name, category, type, created_at FROM streams WHERE user_id = ? ORDER BY created_at DESC LIMIT 10", 
             (current_user.id,))
    recent_streams = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         stream_count=stream_count,
                         today_activity=today_activity,
                         recent_streams=recent_streams)

# API Routes
@app.route('/api/m3u')
def generate_m3u():
    """Generate M3U playlist with proxy URLs"""
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    output = request.args.get('output', 'ts')
    
    # Validate credentials
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_active = 1", 
             (username, hashed_password))
    user = c.fetchone()
    
    if not user:
        return "#EXTM3U\n# Invalid credentials\n", 401
    
    user_id = user[0]
    
    # Get user's streams
    c.execute("""
        SELECT name, proxy_url, category, type 
        FROM streams 
        WHERE user_id = ? AND is_active = 1
        ORDER BY category, name
    """, (user_id,))
    
    streams = c.fetchall()
    conn.close()
    
    # Generate M3U content
    m3u_content = "#EXTM3U\n"
    m3u_content += f"# Generated: {datetime.datetime.now()}\n"
    m3u_content += f"# User: {username}\n\n"
    
    current_category = ""
    for stream in streams:
        name, url, category, stream_type = stream
        
        if category != current_category:
            m3u_content += f"\n#EXTINF:-1 group-title=\"{category}\",{category}\n"
            m3u_content += f"#EXTVLCOPT:network-caching=1000\n"
            current_category = category
        
        m3u_content += f"#EXTINF:-1 tvg-id=\"{name}\" tvg-name=\"{name}\" group-title=\"{category}\",{name}\n"
        
        if output == 'ts':
            m3u_content += f"{request.host_url}live/{username}/{password}/{hashlib.md5(name.encode()).hexdigest()}\n"
        elif output == 'hls':
            m3u_content += f"{request.host_url}hls/{hashlib.md5(name.encode()).hexdigest()}.m3u8\n"
        else:
            m3u_content += f"{url}\n"
    
    log_action(user_id, 'm3u_generated', f"Playlist downloaded: {len(streams)} streams")
    
    response = app.response_class(
        response=m3u_content,
        status=200,
        mimetype='audio/x-mpegurl'
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{username}.m3u"'
    return response

@app.route('/api/xtream', methods=['GET', 'POST'])
def xtream_api():
    """Xtream Codes API emulation"""
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    action = request.args.get('action', '')
    
    # Validate user
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_active = 1", 
             (username, hashed_password))
    user = c.fetchone()
    
    if not user:
        return jsonify({"user_info": {"auth": 0}}), 401
    
    user_id = user[0]
    
    if action == 'get_live_categories':
        # Get categories
        c.execute("SELECT DISTINCT category FROM streams WHERE user_id = ? AND is_active = 1", (user_id,))
        categories = c.fetchall()
        
        return jsonify({
            "categories": [{"category_id": i+1, "category_name": cat[0]} for i, cat in enumerate(categories)]
        })
    
    elif action == 'get_live_streams':
        category_id = request.args.get('category_id', '')
        
        c.execute("""
            SELECT name, proxy_url 
            FROM streams 
            WHERE user_id = ? AND category = ? AND is_active = 1
        """, (user_id, category_id))
        
        streams = c.fetchall()
        
        return jsonify({
            "streams": [
                {
                    "num": i+1,
                    "name": stream[0],
                    "stream_type": "live",
                    "stream_id": i+1,
                    "stream_icon": "",
                    "epg_channel_id": "",
                    "added": "0000-00-00 00:00:00",
                    "category_id": category_id,
                    "custom_sid": "",
                    "tv_archive": 0,
                    "direct_source": stream[1]
                }
                for i, stream in enumerate(streams)
            ]
        })
    
    elif action == 'get_short_epg':
        # Return EPG data
        return jsonify({"epg_listings": []})
    
    else:
        # User info
        c.execute("""
            SELECT username, created_at, expires_at, max_connections 
            FROM users WHERE id = ?
        """, (user_id,))
        
        user_data = c.fetchone()
        
        return jsonify({
            "user_info": {
                "username": user_data[0],
                "password": "********",
                "message": "Welcome to IPTV Proxy",
                "auth": 1,
                "status": "Active",
                "exp_date": user_data[2] or "2099-12-31",
                "is_trial": 0,
                "active_cons": 0,
                "created_at": user_data[1],
                "max_connections": user_data[3],
                "allowed_output_formats": ["m3u8", "ts", "rtmp"]
            }
        })

@app.route('/api/streams', methods=['GET', 'POST'])
@login_required
def manage_streams():
    if request.method == 'GET':
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT id, name, source_url, proxy_url, category, type, is_active FROM streams WHERE user_id = ?", 
                 (current_user.id,))
        streams = c.fetchall()
        conn.close()
        
        return jsonify([
            {
                'id': s[0],
                'name': s[1],
                'source_url': s[2],
                'proxy_url': s[3],
                'category': s[4],
                'type': s[5],
                'is_active': bool(s[6])
            }
            for s in streams
        ])
    
    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        source_url = data.get('source_url')
        category = data.get('category')
        stream_type = data.get('type')
        
        # Generate proxy URL
        proxy_url = f"{request.host_url}proxy/{hashlib.md5(source_url.encode()).hexdigest()}"
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("""
            INSERT INTO streams (name, source_url, proxy_url, category, type, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, source_url, proxy_url, category, stream_type, current_user.id))
        conn.commit()
        stream_id = c.lastrowid
        conn.close()
        
        log_action(current_user.id, 'stream_added', f"Stream: {name}")
        
        return jsonify({'success': True, 'stream_id': stream_id})

@app.route('/api/stats')
@login_required
def get_stats():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # User stats
    c.execute("SELECT COUNT(*) FROM streams WHERE user_id = ?", (current_user.id,))
    total_streams = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM streams WHERE user_id = ? AND is_active = 1", (current_user.id,))
    active_streams = c.fetchone()[0]
    
    # Recent activity
    c.execute("""
        SELECT action, timestamp, details 
        FROM logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 20
    """, (current_user.id,))
    recent_activity = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_streams': total_streams,
        'active_streams': active_streams,
        'recent_activity': recent_activity
    })

@app.route('/api/admin/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def manage_users():
    if request.method == 'GET':
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT id, username, email, role, created_at, expires_at, max_connections, is_active FROM users")
        users = c.fetchall()
        conn.close()
        
        return jsonify([
            {
                'id': u[0],
                'username': u[1],
                'email': u[2],
                'role': u[3],
                'created_at': u[4],
                'expires_at': u[5],
                'max_connections': u[6],
                'is_active': bool(u[7])
            }
            for u in users
        ])
    
    elif request.method == 'POST':
        data = request.json
        hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (username, password, email, role, expires_at, max_connections)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (data['username'], hashed_password, data['email'], data['role'], 
              data.get('expires_at'), data.get('max_connections', 1)))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})

def log_action(user_id, action, details):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("INSERT INTO logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
             (user_id, action, details, request.remote_addr))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Create admin user if not exists
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    admin_exists = c.fetchone()
    
    if not admin_exists:
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                 ('admin', admin_password, 'admin@iptv.com', 'admin'))
        conn.commit()
    
    conn.close()
    
    app.run(host='0.0.0.0', port=5000, debug=False)
