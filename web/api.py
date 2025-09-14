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

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "'"))

from auth.oauth2_handler import OAuth2Handler
from certificate_manager import CertificateManager
from renewal_router import RenewalRouter
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
            owner_email = request.args.get('owner_email')
            owner_username = request.args.get('owner_username')
            issuer_category = request.args.get('issuer_category')
            certificate_type = request.args.get('certificate_type')
            is_expired = request.args.get('is_expired', type=bool)

            result = self.cert_manager.list_certificates(
                page=page,
                per_page=per_page,
                search=search,
                expiring_days=expiring_days,
                owner_email=owner_email,
                owner_username=owner_username,
                issuer_category=issuer_category,
                certificate_type=certificate_type,
                is_expired=is_expired
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
                'owner_username': data.get('owner_username'),
                'department': data.get('department'),
                'contact_phone': data.get('contact_phone'),
                'environment': data.get('environment'),
                'application_name': data.get('application_name'),
                'description': data.get('description')
            }

            result = self.cert_manager.update_certificate_ownership(cert_id, ownership_data)

            if result:
                return jsonify({'success': True, 'message': 'Ownership updated successfully'}), 200
            else:
                return jsonify({'error': 'Failed to update ownership'}), 400

        # My Certificates - User-owned certificates
        @self.app.route('/api/certificates/mine', methods=['GET'])
        @self.oauth.require_auth()
        def get_my_certificates():
            user = request.current_user
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            search = request.args.get('search', '')
            expiring_days = request.args.get('expiring_days', type=int)
            issuer_category = request.args.get('issuer_category')
            certificate_type = request.args.get('certificate_type')
            is_expired = request.args.get('is_expired', type=bool)

            # Filter by current user's email or username
            result = self.cert_manager.list_certificates(
                page=page,
                per_page=per_page,
                search=search,
                expiring_days=expiring_days,
                owner_email=user['email'],  # Primary filter by user's email
                issuer_category=issuer_category,
                certificate_type=certificate_type,
                is_expired=is_expired
            )

            return jsonify(result), 200

        @self.app.route('/api/certificates/by-owner', methods=['GET'])
        @self.oauth.require_auth()
        def get_certificates_by_owner():
            owner_email = request.args.get('owner_email')
            owner_username = request.args.get('owner_username')
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)

            if not owner_email and not owner_username:
                return jsonify({'error': 'Either owner_email or owner_username required'}), 400

            result = self.cert_manager.get_certificates_by_owner(
                owner_email=owner_email,
                owner_username=owner_username,
                page=page,
                per_page=per_page
            )

            return jsonify(result), 200

        @self.app.route('/api/certificates/upload', methods=['POST'])
        @self.oauth.require_auth()
        def upload_certificate():
            if 'certificate' not in request.files:
                return jsonify({'error': 'No certificate file provided'}), 400

            file = request.files['certificate']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Get ownership data from form
            user = request.current_user
            ownership_data = {
                'owner_email': request.form.get('owner_email', user['email']),
                'owner_username': request.form.get('owner_username', user['username']),
                'department': request.form.get('department'),
                'environment': request.form.get('environment', 'production'),
                'application_name': request.form.get('application_name'),
                'description': request.form.get('description', f'Uploaded by {user["username"]}')
            }

            try:
                file_content = file.read()
                result = self.cert_manager.create_certificate_from_upload(
                    file_content=file_content,
                    file_name=file.filename,
                    ownership_data=ownership_data
                )

                if result['success']:
                    return jsonify(result), 201
                else:
                    return jsonify({'error': result['error']}), 400

            except Exception as e:
                return jsonify({'error': f'Upload failed: {str(e)}'}), 500

        @self.app.route('/api/certificates/<int:cert_id>/revoke', methods=['POST'])
        @self.oauth.require_auth('admin')  # Only admins can revoke
        def revoke_certificate(cert_id):
            data = request.get_json() or {}
            reason = data.get('reason', 'Revoked via API')

            result = self.cert_manager.revoke_certificate(cert_id, reason)

            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 400

        @self.app.route('/api/certificates/bulk-update-ownership', methods=['POST'])
        @self.oauth.require_auth()
        def bulk_update_ownership():
            data = request.get_json()
            cert_ids = data.get('cert_ids', [])
            ownership_data = data.get('ownership_data', {})

            if not cert_ids:
                return jsonify({'error': 'Certificate IDs required'}), 400

            result = self.cert_manager.bulk_update_ownership(cert_ids, ownership_data)
            return jsonify(result), 200

        @self.app.route('/api/certificates/bulk-revoke', methods=['POST'])
        @self.oauth.require_auth('admin')
        def bulk_revoke_certificates():
            data = request.get_json()
            cert_ids = data.get('cert_ids', [])
            reason = data.get('reason', 'Bulk revocation')

            if not cert_ids:
                return jsonify({'error': 'Certificate IDs required'}), 400

            result = self.cert_manager.bulk_revoke_certificates(cert_ids, reason)
            return jsonify(result), 200

        @self.app.route('/api/users/<int:user_id>/certificates/statistics', methods=['GET'])
        @self.oauth.require_auth()
        def get_user_certificate_statistics(user_id):
            # Users can only see their own stats unless they're admin
            current_user = request.current_user
            if current_user['id'] != user_id and current_user['role'] != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            # Get target user info
            user_profile = self.oauth.get_user_profile(user_id)
            if not user_profile['success']:
                return jsonify({'error': 'User not found'}), 404

            target_user = user_profile['user']
            result = self.cert_manager.get_user_certificate_statistics(
                owner_email=target_user['email']
            )

            return jsonify(result), 200

        # Certificate format and export endpoints
        @self.app.route('/api/certificates/formats', methods=['GET'])
        @self.oauth.require_auth()
        def get_supported_formats():
            result = self.cert_manager.get_supported_formats()
            return jsonify(result), 200

        @self.app.route('/api/certificates/<int:cert_id>/export', methods=['POST'])
        @self.oauth.require_auth()
        def export_certificate(cert_id):
            data = request.get_json() or {}
            format_type = data.get('format', 'pkcs10_pem')

            result = self.cert_manager.export_certificate_modern_format(cert_id, format_type)

            if result['success']:
                response_data = {
                    'success': True,
                    'export_format': result['export_format'],
                    'filename': result['filename'],
                    'data': result['exported_data']
                }
                return jsonify(response_data), 200
            else:
                return jsonify({'error': result['error']}), 400

        @self.app.route('/api/certificates/scan-pkcs11', methods=['POST'])
        @self.oauth.require_auth('admin')
        def scan_pkcs11_certificates():
            result = self.cert_manager.scan_pkcs11_certificates()

            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify({'error': result['error']}), 400
        
        # Statistics and reporting
        @self.app.route('/api/statistics', methods=['GET'])
        @self.oauth.require_auth()
        def get_statistics():
            result = self.cert_manager.get_certificate_statistics()
            return jsonify(result), 200
        
        @self.app.route('/api/certificates/expiring', methods=['GET'])
        @self.oauth.require_auth()
        def get_expiring_certificates():
            days = request.args.get('days', 30, type=int)
            result = self.cert_manager.get_expiring_certificates(days)
            return jsonify(result), 200

        @self.app.route('/api/certificates/cose/create', methods=['POST'])
        @self.oauth.require_auth()
        def create_cose_certificate():
            """Create a new COSE (CBOR Object Signing and Encryption) certificate"""
            try:
                data = request.get_json() or {}

                # Required fields for COSE certificate creation
                subject = data.get('subject', {})
                algorithm = data.get('algorithm', 'ES256')  # Default to ES256
                embed_x509 = data.get('embed_x509_certificates', False)

                if not subject.get('common_name'):
                    return jsonify({'error': 'Subject common name is required'}), 400

                # Create COSE certificate using the certificate manager
                result = self.cert_manager.create_cose_certificate(
                    subject=subject,
                    algorithm=algorithm,
                    embed_x509=embed_x509,
                    user_id=self.oauth.get_current_user()['id']
                )

                if result['success']:
                    return jsonify({
                        'success': True,
                        'certificate_id': result['certificate_id'],
                        'format': 'cose',
                        'message': 'COSE certificate created successfully'
                    }), 201
                else:
                    return jsonify({'error': result.get('error', 'Failed to create COSE certificate')}), 400

            except Exception as e:
                return jsonify({'error': f'COSE certificate creation failed: {str(e)}'}), 500

        @self.app.route('/api/certificates/cwt/create', methods=['POST'])
        @self.oauth.require_auth()
        def create_cwt_token():
            """Create a new CWT (CBOR Web Token) certificate"""
            try:
                data = request.get_json() or {}

                # CWT claims
                issuer = data.get('issuer', 'SSL Certificate Manager')
                subject = data.get('subject')
                audience = data.get('audience', 'certificate-system')
                expiry_days = data.get('expiry_days', 365)

                if not subject:
                    return jsonify({'error': 'Subject is required for CWT token'}), 400

                # Create CWT token using the certificate manager
                result = self.cert_manager.create_cwt_token(
                    issuer=issuer,
                    subject=subject,
                    audience=audience,
                    expiry_days=expiry_days,
                    user_id=self.oauth.get_current_user()['id']
                )

                if result['success']:
                    return jsonify({
                        'success': True,
                        'certificate_id': result['certificate_id'],
                        'format': 'cwt',
                        'message': 'CWT token created successfully'
                    }), 201
                else:
                    return jsonify({'error': result.get('error', 'Failed to create CWT token')}), 400

            except Exception as e:
                return jsonify({'error': f'CWT token creation failed: {str(e)}'}), 500

        @self.app.route('/api/certificates/<int:cert_id>/cose-info', methods=['GET'])
        @self.oauth.require_auth()
        def get_cose_certificate_info(cert_id):
            """Get detailed COSE certificate information"""
            try:
                result = self.cert_manager.get_cose_certificate_details(cert_id)

                if result['success']:
                    return jsonify(result), 200
                else:
                    return jsonify({'error': result.get('error', 'Certificate not found')}), 404

            except Exception as e:
                return jsonify({'error': f'Failed to get COSE certificate info: {str(e)}'}), 500

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
        
        # API Documentation endpoint
        @self.app.route('/api', methods=['GET'])
        def api_documentation():
            """API Documentation endpoint showing available endpoints and methods"""

            # Get server info
            host = request.host
            protocol = 'https' if request.is_secure else 'http'
            base_url = f"{protocol}://{host}/api"

            api_docs = {
                "title": "SSL Certificate Manager API",
                "version": "1.0.0",
                "description": "REST API for managing SSL certificates, users, and notifications",
                "base_url": base_url,
                "authentication": {
                    "type": "Bearer Token (JWT)",
                    "header": "Authorization: Bearer <token>",
                    "login_endpoint": f"{base_url}/auth/login"
                },
                "endpoints": {
                    "Authentication": {
                        "POST /auth/login": {
                            "description": "Login with username/password",
                            "body": {"username": "string", "password": "string"},
                            "returns": "access_token, refresh_token, user info"
                        },
                        "POST /auth/refresh": {
                            "description": "Refresh access token",
                            "body": {"refresh_token": "string"}
                        },
                        "POST /auth/logout": {
                            "description": "Logout (invalidate token)",
                            "auth_required": True
                        },
                        "GET /auth/profile": {
                            "description": "Get current user profile",
                            "auth_required": True
                        },
                        "POST /auth/change-password": {
                            "description": "Change user password",
                            "auth_required": True
                        }
                    },
                    "Certificate Management": {
                        "GET /certificates": {
                            "description": "List certificates with filtering and pagination",
                            "auth_required": True,
                            "params": [
                                "page (int) - Page number",
                                "per_page (int) - Items per page",
                                "search (string) - Search in CN, file path, serial number",
                                "expiring_days (int) - Certificates expiring within days",
                                "owner_email (string) - Filter by owner email",
                                "owner_username (string) - Filter by owner username",
                                "issuer_category (string) - Filter by issuer",
                                "certificate_type (string) - Filter by certificate type",
                                "is_expired (bool) - Filter by expiration status"
                            ]
                        },
                        "GET /certificates/{id}": {
                            "description": "Get detailed certificate information",
                            "auth_required": True
                        },
                        "GET /certificates/mine": {
                            "description": "Get certificates owned by current user",
                            "auth_required": True,
                            "params": "Same as /certificates"
                        },
                        "GET /certificates/by-owner": {
                            "description": "Get certificates by specific owner",
                            "auth_required": True,
                            "params": ["owner_email or owner_username required"]
                        },
                        "POST /certificates/upload": {
                            "description": "Upload certificate file (multiple formats supported)",
                            "auth_required": True,
                            "content_type": "multipart/form-data",
                            "body": "certificate file + ownership info + optional password",
                            "supported_formats": "PEM, DER, PKCS#7, PKCS#10, PKCS#12, PVK (legacy)"
                        },
                        "POST /certificates/scan": {
                            "description": "Scan directory for certificates",
                            "auth_required": True
                        },
                        "PUT /certificates/{id}/ownership": {
                            "description": "Update certificate ownership",
                            "auth_required": True
                        },
                        "POST /certificates/{id}/renew": {
                            "description": "Renew specific certificate",
                            "auth_required": True
                        },
                        "POST /certificates/batch-renew": {
                            "description": "Bulk renew certificates",
                            "auth_required": True
                        },
                        "POST /certificates/{id}/revoke": {
                            "description": "Revoke certificate (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        },
                        "POST /certificates/bulk-update-ownership": {
                            "description": "Bulk update certificate ownership",
                            "auth_required": True
                        },
                        "POST /certificates/bulk-revoke": {
                            "description": "Bulk revoke certificates (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        },
                        "GET /certificates/formats": {
                            "description": "Get supported certificate formats and configuration",
                            "auth_required": True,
                            "returns": "List of supported formats with descriptions"
                        },
                        "POST /certificates/{id}/export": {
                            "description": "Export certificate in modern format (default PKCS#10)",
                            "auth_required": True,
                            "body": {"format": "pkcs10_pem or pkcs10_der"},
                            "returns": "Exported certificate data"
                        },
                        "POST /certificates/scan-pkcs11": {
                            "description": "Scan PKCS#11 tokens for certificates (EXPERIMENTAL)",
                            "auth_required": True,
                            "admin_required": True,
                            "warning": "Requires PKCS#11 configuration and hardware token"
                        }
                    },
                    "Statistics & Reporting": {
                        "GET /statistics": {
                            "description": "Get overall certificate statistics",
                            "auth_required": True
                        },
                        "GET /certificates/expiring": {
                            "description": "Get expiring certificates",
                            "auth_required": True,
                            "params": ["days (int) - Days threshold"]
                        },
                        "GET /users/{id}/certificates/statistics": {
                            "description": "Get user-specific certificate statistics",
                            "auth_required": True
                        }
                    },
                    "User Management": {
                        "GET /users": {
                            "description": "List all users (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        },
                        "POST /users": {
                            "description": "Create new user (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        }
                    },
                    "Notifications": {
                        "POST /notifications/test-email": {
                            "description": "Test email configuration (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        },
                        "POST /notifications/send": {
                            "description": "Send expiration notifications (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        }
                    },
                    "System": {
                        "GET /health": {
                            "description": "System health check",
                            "auth_required": False
                        },
                        "POST /config/test": {
                            "description": "Test system configuration (admin only)",
                            "auth_required": True,
                            "admin_required": True
                        }
                    }
                },
                "examples": {
                    "Login": {
                        "request": f'curl -X POST {base_url}/auth/login -H \'Content-Type: application/json\' -d \'{{"username":"admin","password":"password"}}\'',
                        "response": {"access_token": "jwt_token", "user": {"username": "admin"}}
                    },
                    "List Certificates": {
                        "request": f"curl -X GET '{base_url}/certificates?page=1&per_page=10&search=example.com' -H 'Authorization: Bearer jwt_token'",
                        "response": {"certificates": [], "pagination": {}}
                    },
                    "Get My Certificates": {
                        "request": f"curl -X GET '{base_url}/certificates/mine' -H 'Authorization: Bearer jwt_token'",
                        "response": {"certificates": [], "pagination": {}}
                    },
                    "Upload PKCS#12 Certificate": {
                        "request": f"curl -X POST {base_url}/certificates/upload -H 'Authorization: Bearer jwt_token' -F 'certificate=@mycert.p12' -F 'password=secret123' -F 'owner_email=user@example.com'",
                        "response": {"success": True, "certificate_id": 123}
                    },
                    "Export Certificate as PKCS#10": {
                        "request": f'curl -X POST {base_url}/certificates/123/export -H \'Authorization: Bearer jwt_token\' -H \'Content-Type: application/json\' -d \'{{"format":"pkcs10_pem"}}\'',
                        "response": {"success": True, "export_format": "pkcs10_pem", "data": "-----BEGIN CERTIFICATE REQUEST-----..."}
                    },
                    "Get Supported Formats": {
                        "request": f"curl -X GET '{base_url}/certificates/formats' -H 'Authorization: Bearer jwt_token'",
                        "response": {"success": True, "supported_formats": {}}
                    }
                },
                "response_formats": {
                    "success": {
                        "structure": {"success": True, "data": "varies"},
                        "http_codes": [200, 201]
                    },
                    "error": {
                        "structure": {"error": "error message"},
                        "http_codes": [400, 401, 403, 404, 500]
                    }
                },
                "links": {
                    "Web Interface": f"{protocol}://{host}/",
                    "Health Check": f"{base_url}/health",
                    "GitHub Repository": "https://github.com/your-org/ssl-certificate-manager",
                    "Documentation": f"{base_url}"
                }
            }

            # Return HTML formatted documentation for browsers
            if 'text/html' in request.headers.get('Accept', ''):
                return self._format_api_docs_html(api_docs)
            else:
                return jsonify(api_docs)

        def _format_api_docs_html(self, api_docs):
            """Format API documentation as HTML"""
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{api_docs['title']}</title>
                <style>
                    body {{ font-family: 'Arial', sans-serif; margin: 40px; line-height: 1.6; color: #333; }}
                    h1, h2, h3 {{ color: #2c3e50; }}
                    .endpoint {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }}
                    .method {{ color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
                    .get {{ background: #28a745; }}
                    .post {{ background: #007bff; }}
                    .put {{ background: #ffc107; color: #000; }}
                    .delete {{ background: #dc3545; }}
                    .auth {{ color: #dc3545; font-size: 12px; }}
                    .admin {{ color: #6f42c1; font-size: 12px; }}
                    code {{ background: #f1f1f1; padding: 2px 4px; border-radius: 3px; }}
                    pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                    .nav {{ background: #2c3e50; color: white; padding: 20px; margin: -40px -40px 40px -40px; }}
                    .nav h1 {{ margin: 0; color: white; }}
                    .section {{ margin: 30px 0; }}
                    .links a {{ display: inline-block; margin: 5px 10px 5px 0; padding: 8px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }}
                    .links a:hover {{ background: #0056b3; }}
                    .example {{ background: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="nav">
                    <h1>{api_docs['title']}</h1>
                    <p>{api_docs['description']}</p>
                    <p><strong>Version:</strong> {api_docs['version']} | <strong>Base URL:</strong> {api_docs['base_url']}</p>
                </div>

                <div class="section">
                    <h2>🔐 Authentication</h2>
                    <p>This API uses Bearer Token authentication with JWT tokens.</p>
                    <div class="example">
                        <strong>Header:</strong> <code>Authorization: Bearer your_jwt_token</code><br>
                        <strong>Login Endpoint:</strong> <code>POST {api_docs['base_url']}/auth/login</code>
                    </div>
                </div>

                <div class="section">
                    <h2>📋 API Endpoints</h2>
            """

            # Add endpoints by category
            for category, endpoints in api_docs['endpoints'].items():
                html += f"<h3>{category}</h3>"
                for endpoint, details in endpoints.items():
                    method, path = endpoint.split(' ', 1)
                    method_class = method.lower()

                    auth_badge = '<span class="auth">🔐 Auth Required</span>' if details.get('auth_required') else ''
                    admin_badge = '<span class="admin">👑 Admin Only</span>' if details.get('admin_required') else ''

                    html += f"""
                    <div class="endpoint">
                        <strong><span class="method {method_class}">{method}</span> {path}</strong>
                        {auth_badge} {admin_badge}
                        <br><em>{details['description']}</em>
                    """

                    if 'params' in details:
                        if isinstance(details['params'], list):
                            html += "<br><strong>Parameters:</strong><ul>"
                            for param in details['params']:
                                html += f"<li>{param}</li>"
                            html += "</ul>"
                        else:
                            html += f"<br><strong>Parameters:</strong> {details['params']}"

                    if 'body' in details:
                        html += f"<br><strong>Request Body:</strong> <code>{details['body']}</code>"

                    if 'content_type' in details:
                        html += f"<br><strong>Content-Type:</strong> <code>{details['content_type']}</code>"

                    if 'returns' in details:
                        html += f"<br><strong>Returns:</strong> {details['returns']}"

                    html += "</div>"

            # Add examples section
            html += f"""
                </div>

                <div class="section">
                    <h2>💡 Examples</h2>
            """

            for example_name, example in api_docs['examples'].items():
                html += f"""
                <h4>{example_name}</h4>
                <div class="example">
                    <strong>Request:</strong>
                    <pre>{example['request']}</pre>
                    <strong>Response:</strong>
                    <pre>{json.dumps(example['response'], indent=2)}</pre>
                </div>
                """

            # Add links section
            html += f"""
                </div>

                <div class="section">
                    <h2>🔗 Quick Links</h2>
                    <div class="links">
            """

            for link_name, link_url in api_docs['links'].items():
                html += f'<a href="{link_url}" target="_blank">{link_name}</a>'

            html += """
                    </div>
                </div>

                <div class="section">
                    <h2>📊 Response Formats</h2>
                    <h4>Success Response</h4>
                    <pre>{"success": true, "data": {...}}</pre>
                    <h4>Error Response</h4>
                    <pre>{"error": "Error message describing the issue"}</pre>
                </div>
            </body>
            </html>
            """

            return html

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
