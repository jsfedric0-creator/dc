from flask import Blueprint, render_template, jsonify, request, current_app
from flask_login import login_required, current_user
import sqlite3
import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/users')
@admin_required
def user_management():
    """User management page"""
    return render_template('admin/users.html')

@admin_bp.route('/api/users')
@admin_required
def get_users():
    """Get all users"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    offset = (page - 1) * limit
    
    # Get users with stats
    c.execute("""
        SELECT 
            u.*,
            COUNT(s.id) as stream_count,
            SUM(CASE WHEN s.is_active = 1 THEN 1 ELSE 0 END) as active_streams,
            MAX(l.timestamp) as last_login
        FROM users u
        LEFT JOIN streams s ON u.id = s.user_id
        LEFT JOIN logs l ON u.id = l.user_id AND l.action = 'login'
        GROUP BY u.id
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    
    users = [dict(row) for row in c.fetchall()]
    
    # Get total count
    c.execute("SELECT COUNT(*) FROM users")
    total = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'users': users,
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit
    })

@admin_bp.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def manage_user(user_id):
    """Manage individual user"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    if request.method == 'GET':
        c.execute("""
            SELECT u.*, 
                   COUNT(s.id) as stream_count,
                   MAX(l.timestamp) as last_activity
            FROM users u
            LEFT JOIN streams s ON u.id = s.user_id
            LEFT JOIN logs l ON u.id = l.user_id
            WHERE u.id = ?
            GROUP BY u.id
        """, (user_id,))
        
        user = c.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's streams
        c.execute("""
            SELECT id, name, category, type, is_active, created_at
            FROM streams WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        """, (user_id,))
        
        streams = [dict(row) for row in c.fetchall()]
        
        # Get user's recent activity
        c.execute("""
            SELECT action, details, timestamp, ip_address
            FROM logs WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 20
        """, (user_id,))
        
        activity = [dict(row) for row in c.fetchall()]
        
        conn.close()
        
        return jsonify({
            'user': dict(user),
            'streams': streams,
            'activity': activity
        })
    
    elif request.method == 'PUT':
        data = request.json
        updates = []
        params = []
        
        if 'username' in data:
            updates.append("username = ?")
            params.append(data['username'])
        
        if 'email' in data:
            updates.append("email = ?")
            params.append(data['email'])
        
        if 'role' in data:
            updates.append("role = ?")
            params.append(data['role'])
        
        if 'max_connections' in data:
            updates.append("max_connections = ?")
            params.append(data['max_connections'])
        
        if 'expires_at' in data:
            updates.append("expires_at = ?")
            params.append(data['expires_at'])
        
        if 'is_active' in data:
            updates.append("is_active = ?")
            params.append(1 if data['is_active'] else 0)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            params.append(user_id)
            c.execute(query, params)
            conn.commit()
        
        conn.close()
        return jsonify({'success': True, 'message': 'User updated'})
    
    elif request.method == 'DELETE':
        # Check if user has streams
        c.execute("SELECT COUNT(*) FROM streams WHERE user_id = ?", (user_id,))
        stream_count = c.fetchone()[0]
        
        if stream_count > 0:
            conn.close()
            return jsonify({'error': 'Cannot delete user with existing streams'}), 400
        
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User deleted'})

@admin_bp.route('/servers')
@admin_required
def server_management():
    """Server management page"""
    return render_template('admin/servers.html')

@admin_bp.route('/api/servers')
@admin_required
def get_servers():
    """Get server information"""
    import psutil
    import platform
    
    # System information
    system_info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version()
    }
    
    # Resource usage
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Network
    net_io = psutil.net_io_counters()
    
    # Processes
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            if proc.info['cpu_percent'] > 0 or proc.info['memory_percent'] > 0:
                processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Limit processes list
    processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:20]
    
    return jsonify({
        'system': system_info,
        'cpu': {
            'percent': cpu_percent,
            'count': psutil.cpu_count(),
            'count_logical': psutil.cpu_count(logical=True)
        },
        'memory': {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used
        },
        'disk': {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        },
        'network': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        },
        'processes': processes
    })

@admin_bp.route('/logs')
@admin_required
def system_logs():
    """System logs page"""
    return render_template('admin/logs.html')

@admin_bp.route('/api/logs')
@admin_required
def get_logs():
    """Get system logs"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    offset = (page - 1) * limit
    
    # Get logs with user info
    c.execute("""
        SELECT l.*, u.username
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.timestamp DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    
    logs = [dict(row) for row in c.fetchall()]
    
    # Get total count
    c.execute("SELECT COUNT(*) FROM logs")
    total = c.fetchone()[0]
    
    # Get log statistics
    c.execute("""
        SELECT 
            COUNT(*) as total_logs,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT ip_address) as unique_ips,
            MIN(timestamp) as first_log,
            MAX(timestamp) as last_log
        FROM logs
    """)
    
    stats = dict(c.fetchone())
    
    # Get activity by action
    c.execute("""
        SELECT action, COUNT(*) as count
        FROM logs
        GROUP BY action
        ORDER BY count DESC
        LIMIT 10
    """)
    
    activity_by_action = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        'logs': logs,
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit,
        'stats': stats,
        'activity_by_action': activity_by_action
    })

@admin_bp.route('/settings')
@admin_required
def admin_settings():
    """Admin settings page"""
    return render_template('admin/settings.html')

@admin_bp.route('/api/settings', methods=['GET', 'POST'])
@admin_required
def manage_settings():
    """Manage system settings"""
    if request.method == 'GET':
        # Load settings from database or config file
        settings = {
            'site_name': 'IPTV Proxy Panel',
            'site_url': request.host_url.rstrip('/'),
            'registration_enabled': True,
            'max_streams_per_user': 100,
            'max_connections_per_user': 3,
            'stream_timeout': 30,
            'backup_interval': 24,
            'log_retention_days': 30,
            'allowed_stream_types': ['m3u8', 'ts', 'rtmp', 'http', 'https'],
            'default_stream_quality': 'HD',
            'epg_update_interval': 12
        }
        
        return jsonify(settings)
    
    elif request.method == 'POST':
        data = request.json
        
        # Save settings (in real app, save to database)
        # For now, just return success
        return jsonify({
            'success': True,
            'message': 'Settings saved successfully'
        })
