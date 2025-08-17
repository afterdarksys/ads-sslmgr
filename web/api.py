#!/usr/bin/env python3
"""
Flask API for SSL Certificate Manager
RESTful API endpoints for certificate management and authentication
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from typing import Dict, List, Optional

from auth.oauth2_handler import OAuth2Handler
from core.certificate_manager import CertificateManager
from core.renewal_router import RenewalRouter
from notifications.email_notifier import EmailNotifier
from notifications.snmp_notifier import SNMPNotifier


class SSLManagerAPI:
    """Flask API for SSL Certificate Manager"""
    
    def __init__(self, config_path: str = None):
        """Initialize Flask API with configuration"""
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Load configuration
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        self.config = self._load_config()
        
        # Initialize components
        self.oauth = OAuth2Handler(self.config_path)
        self.cert_manager = CertificateManager(self.config)
        self.renewal_router = RenewalRouter(self.config, self.cert_manager.db_manager)
        self.email_notifier = EmailNotifier(self.config, self.cert_manager.db_manager)
        self.snmp_notifier = SNMPNotifier(self.config, self.cert_manager.db_manager)
        
        # Setup routes
        self._setup_routes()
        
    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            return {}
    
    def _setup_routes(self):
        """Setup all API routes"""
        
        # Authentication routes
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
            
            result = self.oauth.login(username, password)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 401
        
        @self.app.route('/api/auth/refresh', methods=['POST'])
        def refresh_token():
            data = request.get_json()
            refresh_token = data.get('refresh_token')
            
            if not refresh_token:
                return jsonify({'error': 'Refresh token required'}), 400
            
            result = self.oauth.refresh_access_token(refresh_token)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 401
        
        @self.app.route('/api/auth/logout', methods=['POST'])
        @self.oauth.require_auth()
        def logout():
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ', 1)[1]
            
            result = self.oauth.logout(token)
            return jsonify(result), 200
        
        @self.app.route('/api/auth/profile', methods=['GET'])
        @self.oauth.require_auth()
        def get_profile():
            user = request.current_user
            result = self.oauth.get_user_profile(user['id'])
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 404
        
        @self.app.route('/api/auth/change-password', methods=['POST'])
        @self.oauth.require_auth()
        def change_password():
            user = request.current_user
            data = request.get_json()
            
            old_password = data.get('old_password')
            new_password = data.get('new_password')
            
            if not old_password or not new_password:
                return jsonify({'error': 'Old and new passwords required'}), 400
            
            result = self.oauth.change_password(user['id'], old_password, new_password)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 400
        
        # Certificate management routes
        @self.app.route('/api/certificates', methods=['GET'])
        @self.oauth.require_auth()
        def list_certificates():
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            search = request.args.get('search', '')
            expiring_days = request.args.get('expiring_days', type=int)
            
            result = self.cert_manager.list_certificates(
                page=page, 
                per_page=per_page, 
                search=search,
                expiring_days=expiring_days
            )
            
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/<int:cert_id>', methods=['GET'])
        @self.oauth.require_auth()
        def get_certificate(cert_id):
            result = self.cert_manager.get_certificate_details(cert_id)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 404
        
        @self.app.route('/api/certificates/scan', methods=['POST'])
        @self.oauth.require_auth()
        def scan_directory():
            data = request.get_json()
            directory = data.get('directory')
            update_ownership = data.get('update_ownership', False)
            
            if not directory:
                return jsonify({'error': 'Directory path required'}), 400
            
            result = self.cert_manager.scan_directory(directory, update_ownership)
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/<int:cert_id>/renew', methods=['POST'])
        @self.oauth.require_auth()
        def renew_certificate(cert_id):
            data = request.get_json() or {}
            force_ca = data.get('force_ca')
            renewal_options = data.get('renewal_options', {})
            
            result = self.renewal_router.renew_certificate_by_id(
                cert_id, force_ca, renewal_options
            )
            
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/batch-renew', methods=['POST'])
        @self.oauth.require_auth()
        def batch_renew():
            data = request.get_json()
            cert_ids = data.get('cert_ids', [])
            force_ca = data.get('force_ca')
            renewal_options = data.get('renewal_options', {})
            
            if not cert_ids:
                return jsonify({'error': 'Certificate IDs required'}), 400
            
            result = self.renewal_router.batch_renew(cert_ids, force_ca, renewal_options)
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/<int:cert_id>/ownership', methods=['PUT'])
        @self.oauth.require_auth()
        def update_ownership(cert_id):
            data = request.get_json()
            ownership_data = {
                'owner_email': data.get('owner_email'),
                'owner_url': data.get('owner_url'),
                'owner_username': data.get('owner_username')
            }
            
            result = self.cert_manager.update_certificate_ownership(cert_id, ownership_data)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 400
        
        # Statistics and reporting
        @self.app.route('/api/statistics', methods=['GET'])
        @self.oauth.require_auth()
        def get_statistics():
            result = self.cert_manager.get_statistics()
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/expiring', methods=['GET'])
        @self.oauth.require_auth()
        def get_expiring_certificates():
            days = request.args.get('days', 30, type=int)
            result = self.cert_manager.get_expiring_certificates(days)
            return jsonify(result), 200
        
        # Notification management
        @self.app.route('/api/notifications/test-email', methods=['POST'])
        @self.oauth.require_auth('admin')
        def test_email():
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return jsonify({'error': 'Email address required'}), 400
            
            result = self.email_notifier.test_email_config(email)
            return jsonify(result), 200
        
        @self.app.route('/api/notifications/send', methods=['POST'])
        @self.oauth.require_auth('admin')
        def send_notifications():
            data = request.get_json()
            days_before = data.get('days_before', 30)
            dry_run = data.get('dry_run', False)
            
            result = self.email_notifier.send_expiration_notifications(days_before)
            
            if not dry_run and result['success']:
                # Also send SNMP notifications
                snmp_result = self.snmp_notifier.send_batch_expiration_notifications(days_before)
                result['snmp_notifications'] = snmp_result
            
            return jsonify(result), 200
        
        # Configuration and health
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0'
            }), 200
        
        @self.app.route('/api/config/test', methods=['POST'])
        @self.oauth.require_auth('admin')
        def test_configuration():
            results = {}
            
            # Test database connection
            try:
                db_result = self.cert_manager.test_database_connection()
                results['database'] = db_result
            except Exception as e:
                results['database'] = {'success': False, 'error': str(e)}
            
            # Test email configuration
            try:
                email_result = self.email_notifier.test_email_config()
                results['email'] = email_result
            except Exception as e:
                results['email'] = {'success': False, 'error': str(e)}
            
            # Test SNMP configuration
            try:
                snmp_result = self.snmp_notifier.test_configuration()
                results['snmp'] = snmp_result
            except Exception as e:
                results['snmp'] = {'success': False, 'error': str(e)}
            
            return jsonify(results), 200
        
        # User management (admin only)
        @self.app.route('/api/users', methods=['GET'])
        @self.oauth.require_auth('admin')
        def list_users():
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            
            result = self.oauth.list_users(page, per_page)
            return jsonify(result), 200
        
        @self.app.route('/api/users', methods=['POST'])
        @self.oauth.require_auth('admin')
        def create_user():
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'user')
            
            if not username or not email or not password:
                return jsonify({'error': 'Username, email, and password required'}), 400
            
            result = self.oauth.create_user(username, email, password, role)
            
            if result['success']:
                return jsonify(result), 201
            else:
                return jsonify({'error': result['error']}), 400
        
        # Static file serving for SPA
        @self.app.route('/')
        def serve_spa():
            return send_from_directory('static', 'index.html')
        
        @self.app.route('/<path:path>')
        def serve_static(path):
            try:
                return send_from_directory('static', path)
            except:
                # Fallback to SPA for client-side routing
                return send_from_directory('static', 'index.html')
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Run the Flask application"""
        print(f"Starting SSL Certificate Manager API on {host}:{port}")
        print(f"Debug mode: {debug}")
        self.app.run(host=host, port=port, debug=debug)


def create_app(config_path: str = None) -> Flask:
    """Factory function to create Flask app"""
    api = SSLManagerAPI(config_path)
    return api.app


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SSL Certificate Manager API')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--config', help='Path to config file')
    
    args = parser.parse_args()
    
    api = SSLManagerAPI(args.config)
    api.run(host=args.host, port=args.port, debug=args.debug)
