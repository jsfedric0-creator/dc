from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from functools import wraps
import sqlite3
import json
import hashlib
import datetime
import subprocess
import psutil
import os

api_bp = Blueprint('api', __name__)

def get_db():
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Server Statistics
@api_bp.route('/server/stats')
@login_required
def server_stats():
    """Get server statistics"""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        # Network usage
        net_io = psutil.net_io_counters()
        bandwidth_out = net_io.bytes_sent / 1024 / 1024  # MB
        
        # Active streams
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM streams WHERE is_active = 1")
        active_streams = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        total_users = c.fetchone()[0]
        
        # Get user's stream count
        c.execute("SELECT COUNT(*) FROM streams WHERE user_id = ?", (current_user.id,))
        user_streams = c.fetchone()[0]
        
        conn.close()
        
        # Process uptime
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        
        return jsonify({
            'cpu': round(cpu_percent, 1),
            'ram': round(memory.percent, 1),
            'disk': round(disk.percent, 1),
            'bandwidth': round(bandwidth_out, 2),
            'active_streams': active_streams,
            'total_users': total_users,
            'user_streams': user_streams,
            'online_users': 1,  # In real app, track sessions
            'uptime': int(uptime.total_seconds()),
            'timestamp': datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Stream Management API
@api_bp.route('/streams/list')
@login_required
def list_streams():
    """List streams with pagination and filtering"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit
        
        category = request.args.get('category')
        status = request.args.get('status')
        search = request.args.get('search')
        
        conn = get_db()
        c = conn.cursor()
        
        # Build query
        query = "SELECT * FROM streams WHERE user_id = ?"
        params = [current_user.id]
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        if status == 'active':
            query += " AND is_active = 1"
        elif status == 'inactive':
            query += " AND is_active = 0"
        
        if search:
            query += " AND (name LIKE ? OR category LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        # Get total count
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        c.execute(count_query, params)
        total = c.fetchone()[0]
        
        # Get paginated data
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, params)
        rows = c.fetchall()
        
        streams = []
        for row in rows:
            stream = dict(row)
            # Check if stream is actually playing
            stream['status'] = check_stream_status(stream['source_url'])
            streams.append(stream)
        
        # Get stats for this page
        c.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active,
                COUNT(DISTINCT category) as categories
            FROM streams WHERE user_id = ?
        """, (current_user.id,))
        
        stats = dict(c.fetchone())
        conn.close()
        
        return jsonify({
            'success': True,
            'streams': streams,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit,
            'stats': stats
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def check_stream_status(url):
    """Check if a stream URL is accessible"""
    try:
        # Simple check - could be enhanced with actual stream testing
        import urllib.request
        request = urllib.request.Request(url)
        request.get_method = lambda: 'HEAD'
        urllib.request.urlopen(request, timeout=5)
        return 'playing'
    except:
        return 'offline'

# Bulk Stream Operations
@api_bp.route('/streams/bulk', methods=['POST'])
@login_required
def bulk_stream_operations():
    """Perform bulk operations on streams"""
    try:
        data = request.json
        action = data.get('action')
        stream_ids = data.get('stream_ids', [])
        
        if not stream_ids:
            return jsonify({'success': False, 'error': 'No streams selected'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        placeholders = ','.join('?' * len(stream_ids))
        query = f"SELECT id FROM streams WHERE id IN ({placeholders}) AND user_id = ?"
        
        # Verify ownership
        c.execute(query, stream_ids + [current_user.id])
        valid_streams = [row[0] for row in c.fetchall()]
        
        if len(valid_streams) != len(stream_ids):
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 403
        
        if action == 'activate':
            c.execute(f"UPDATE streams SET is_active = 1 WHERE id IN ({placeholders})", stream_ids)
            message = f"Activated {len(stream_ids)} streams"
        
        elif action == 'deactivate':
            c.execute(f"UPDATE streams SET is_active = 0 WHERE id IN ({placeholders})", stream_ids)
            message = f"Deactivated {len(stream_ids)} streams"
        
        elif action == 'delete':
            c.execute(f"DELETE FROM streams WHERE id IN ({placeholders})", stream_ids)
            message = f"Deleted {len(stream_ids)} streams"
        
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        conn.commit()
        conn.close()
        
        # Log action
        log_action(current_user.id, 'bulk_operation', 
                  f"{action}: {len(stream_ids)} streams")
        
        return jsonify({'success': True, 'message': message})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Stream Testing
@api_bp.route('/streams/<int:stream_id>/test')
@login_required
def test_stream(stream_id):
    """Test a stream for availability"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Get stream
        c.execute("SELECT source_url FROM streams WHERE id = ? AND user_id = ?", 
                 (stream_id, current_user.id))
        stream = c.fetchone()
        
        if not stream:
            return jsonify({'success': False, 'error': 'Stream not found'}), 404
        
        source_url = stream['source_url']
        
        # Test stream with FFmpeg
        try:
            cmd = ['ffmpeg', '-i', source_url, '-t', '5', '-f', 'null', '-']
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                status = 'working'
                message = 'Stream is working properly'
            else:
                status = 'error'
                message = result.stderr.decode('utf-8')[:200]
        
        except subprocess.TimeoutExpired:
            status = 'timeout'
            message = 'Stream test timed out'
        except Exception as e:
            status = 'error'
            message = str(e)
        
        # Update stream status
        c.execute("UPDATE streams SET last_tested = CURRENT_TIMESTAMP WHERE id = ?", 
                 (stream_id,))
        conn.commit()
        conn.close()
        
        log_action(current_user.id, 'test_stream', 
                  f"Tested stream {stream_id}: {status}")
        
        return jsonify({
            'success': True,
            'status': status,
            'message': message,
            'tested_at': datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Export/Import Streams
@api_bp.route('/streams/export')
@login_required
def export_streams():
    """Export streams as JSON"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute("""
            SELECT name, source_url, category, type, is_active
            FROM streams WHERE user_id = ?
        """, (current_user.id,))
        
        streams = [dict(row) for row in c.fetchall()]
        conn.close()
        
        export_data = {
            'version': '1.0',
            'export_date': datetime.datetime.now().isoformat(),
            'user': current_user.username,
            'total_streams': len(streams),
            'streams': streams
        }
        
        response = jsonify(export_data)
        response.headers['Content-Disposition'] = f'attachment; filename="iptv_export_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        
        log_action(current_user.id, 'export_streams', 
                  f"Exported {len(streams)} streams")
        
        return response
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/streams/import', methods=['POST'])
@login_required
def import_streams():
    """Import streams from JSON"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.json'):
            return jsonify({'success': False, 'error': 'File must be JSON'}), 400
        
        import_data = json.load(file)
        
        if 'streams' not in import_data:
            return jsonify({'success': False, 'error': 'Invalid import format'}), 400
        
        streams = import_data['streams']
        imported = 0
        skipped = 0
        
        conn = get_db()
        c = conn.cursor()
        
        for stream in streams:
            # Check if stream already exists
            c.execute("SELECT id FROM streams WHERE source_url = ? AND user_id = ?", 
                     (stream['source_url'], current_user.id))
            
            if c.fetchone():
                skipped += 1
                continue
            
            # Insert new stream
            c.execute("""
                INSERT INTO streams (name, source_url, category, type, is_active, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                stream['name'],
                stream['source_url'],
                stream['category'],
                stream.get('type', 'live'),
                stream.get('is_active', 1),
                current_user.id
            ))
            imported += 1
        
        conn.commit()
        conn.close()
        
        log_action(current_user.id, 'import_streams', 
                  f"Imported {imported} streams, skipped {skipped}")
        
        return jsonify({
            'success': True,
            'imported': imported,
            'skipped': skipped,
            'total': len(streams)
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# EPG Management
@api_bp.route('/epg/sources')
@login_required
def list_epg_sources():
    """Get available EPG sources"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        SELECT DISTINCT epg_id FROM streams 
        WHERE user_id = ? AND epg_id IS NOT NULL AND epg_id != ''
    """, (current_user.id,))
    
    epg_ids = [row[0] for row in c.fetchall()]
    
    # Default EPG sources
    default_sources = [
        {
            'name': 'IPTV-org',
            'url': 'https://epg.iptv-org.net/epg.xml.gz',
            'format': 'xmltv'
        },
        {
            'name': 'XMLTV',
            'url': 'http://xmltv.xmltv.se/xmltv.xml',
            'format': 'xmltv'
        }
    ]
    
    conn.close()
    
    return jsonify({
        'epg_ids': epg_ids,
        'sources': default_sources
    })

@api_bp.route('/epg/update', methods=['POST'])
@login_required
def update_epg():
    """Update EPG data"""
    try:
        source_url = request.json.get('source_url')
        
        if not source_url:
            return jsonify({'success': False, 'error': 'Source URL required'}), 400
        
        # Download and process EPG
        import requests
        import gzip
        import xml.etree.ElementTree as ET
        
        response = requests.get(source_url, timeout=30)
        
        if source_url.endswith('.gz'):
            epg_data = gzip.decompress(response.content)
        else:
            epg_data = response.content
        
        # Parse XML
        root = ET.fromstring(epg_data)
        
        # Store EPG data
        epg_file = f"/app/data/epg_{current_user.id}.xml"
        with open(epg_file, 'wb') as f:
            f.write(epg_data)
        
        log_action(current_user.id, 'update_epg', 
                  f"Updated EPG from {source_url}")
        
        return jsonify({
            'success': True,
            'message': 'EPG updated successfully',
            'channels': len(root.findall('.//channel')),
            'programs': len(root.findall('.//programme'))
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# System Backup
@api_bp.route('/system/backup')
@login_required
def create_backup():
    """Create system backup"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    
    try:
        import zipfile
        import io
        
        # Create backup archive
        backup_data = io.BytesIO()
        
        with zipfile.ZipFile(backup_data, 'w') as backup_zip:
            # Backup database
            if os.path.exists(current_app.config['DATABASE']):
                backup_zip.write(current_app.config['DATABASE'], 'iptv.db')
            
            # Backup configs
            config_files = ['/app/dashboard/app.py', '/app/proxy/stream_manager.py']
            for config_file in config_files:
                if os.path.exists(config_file):
                    backup_zip.write(config_file, os.path.basename(config_file))
        
        backup_data.seek(0)
        
        response = current_app.response_class(
            backup_data.getvalue(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="iptv_backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'
            }
        )
        
        log_action(current_user.id, 'create_backup', 'Created system backup')
        
        return response
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Helper function to log actions
def log_action(user_id, action, details):
    try:
        conn = sqlite3.connect(current_app.config['DATABASE'])
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        """, (user_id, action, details, request.remote_addr))
        conn.commit()
        conn.close()
    except:
        pass
