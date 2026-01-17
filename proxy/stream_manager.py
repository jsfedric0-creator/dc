import subprocess
import time
import threading
import sqlite3
import json
from flask import Flask, request, jsonify

class StreamManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.active_streams = {}
        self.lock = threading.Lock()
        
    def start_stream(self, stream_id, source_url, output_url):
        """Start FFmpeg restreaming process"""
        try:
            # FFmpeg command for restreaming
            cmd = [
                'ffmpeg',
                '-i', source_url,
                '-c', 'copy',
                '-f', 'flv',
                output_url,
                '-loglevel', 'quiet'
            ]
            
            process = subprocess.Popen(cmd)
            
            with self.lock:
                self.active_streams[stream_id] = {
                    'process': process,
                    'source': source_url,
                    'output': output_url,
                    'start_time': time.time()
                }
            
            return True
        except Exception as e:
            print(f"Error starting stream {stream_id}: {e}")
            return False
    
    def stop_stream(self, stream_id):
        """Stop a running stream"""
        with self.lock:
            if stream_id in self.active_streams:
                process = self.active_streams[stream_id]['process']
                process.terminate()
                process.wait()
                del self.active_streams[stream_id]
                return True
        return False
    
    def get_status(self):
        """Get status of all streams"""
        with self.lock:
            return {
                'active_streams': len(self.active_streams),
                'streams': [
                    {
                        'id': sid,
                        'source': info['source'],
                        'uptime': time.time() - info['start_time']
                    }
                    for sid, info in self.active_streams.items()
                ]
            }

stream_manager = StreamManager('/app/data/iptv.db')
