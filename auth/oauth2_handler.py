#!/usr/bin/env python3
"""
OAuth2 Authentication Handler for SSL Certificate Manager
Handles OAuth2 authentication with JWT tokens, user management, and session handling.
"""

import os
import sys
import json
import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
from functools import wraps
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from flask import request, jsonify, current_app
except ImportError:
    # Flask not required for standalone testing
    pass

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

from database.models import User, DatabaseManager


class OAuth2Handler:
    """OAuth2 authentication handler with JWT token management"""
    
    def __init__(self, config_path: str = None):
        """Initialize OAuth2 handler with configuration"""
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
        self.config = self._load_config()
        self.db_manager = DatabaseManager(self.config.get('database', {}))
        
        # JWT configuration
        self.jwt_secret = self.config.get('oauth2', {}).get('jwt_secret', self._generate_jwt_secret())
        self.jwt_algorithm = self.config.get('oauth2', {}).get('jwt_algorithm', 'HS256')
        self.access_token_expires = timedelta(
            hours=self.config.get('oauth2', {}).get('access_token_expires_hours', 24)
        )
        self.refresh_token_expires = timedelta(
            days=self.config.get('oauth2', {}).get('refresh_token_expires_days', 30)
        )
        
    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            return {}
    
    def _generate_jwt_secret(self) -> str:
        """Generate a secure JWT secret key"""
        return secrets.token_urlsafe(64)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict:
        """Create a new user account"""
        session = self.db_manager.get_session()
        try:
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                return {
                    'success': False,
                    'error': 'User with this username or email already exists'
                }
            
            # Create new user
            hashed_password = self.hash_password(password)
            user = User(
                username=username,
                email=email,
                password_hash=hashed_password,
                role=role,
                is_active=True
            )
            
            session.add(user)
            session.commit()
            
            return {
                'success': True,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
            
        except Exception as e:
            session.rollback()
            return {
                'success': False,
                'error': f'Failed to create user: {str(e)}'
            }
        finally:
            session.close()
    
    def authenticate_user(self, username: str, password: str) -> Dict:
        """Authenticate user credentials"""
        session = self.db_manager.get_session()
        try:
            user = session.query(User).filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if not user or not user.is_active:
                return {
                    'success': False,
                    'error': 'Invalid credentials or inactive user'
                }
            
            if not self.verify_password(password, user.password_hash):
                return {
                    'success': False,
                    'error': 'Invalid credentials'
                }
            
            # Update last login
            user.last_login = datetime.utcnow()
            session.commit()
            
            return {
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Authentication failed: {str(e)}'
            }
        finally:
            session.close()
    
    def generate_tokens(self, user_data: Dict) -> Dict:
        """Generate access and refresh tokens"""
        now = datetime.utcnow()
        
        # Access token payload
        access_payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'email': user_data['email'],
            'role': user_data['role'],
            'type': 'access',
            'iat': now,
            'exp': now + self.access_token_expires
        }
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'type': 'refresh',
            'iat': now,
            'exp': now + self.refresh_token_expires
        }
        
        access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': int(self.access_token_expires.total_seconds()),
            'expires_at': (now + self.access_token_expires).isoformat()
        }
    
    def verify_token(self, token: str, token_type: str = 'access') -> Dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            if payload.get('type') != token_type:
                return {
                    'valid': False,
                    'error': f'Invalid token type. Expected {token_type}'
                }
            
            # Check if token is expired
            if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
                return {
                    'valid': False,
                    'error': 'Token has expired'
                }
            
            return {
                'valid': True,
                'payload': payload
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'valid': False,
                'error': 'Token has expired'
            }
        except jwt.InvalidTokenError as e:
            return {
                'valid': False,
                'error': f'Invalid token: {str(e)}'
            }
    
    def refresh_access_token(self, refresh_token: str) -> Dict:
        """Generate new access token using refresh token"""
        verification = self.verify_token(refresh_token, 'refresh')
        
        if not verification['valid']:
            return {
                'success': False,
                'error': verification['error']
            }
        
        payload = verification['payload']
        user_id = payload['user_id']
        
        # Get current user data
        session = self.db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user or not user.is_active:
                return {
                    'success': False,
                    'error': 'User not found or inactive'
                }
            
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
            
            tokens = self.generate_tokens(user_data)
            
            return {
                'success': True,
                **tokens
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to refresh token: {str(e)}'
            }
        finally:
            session.close()
    
    def get_user_from_token(self, token: str) -> Optional[Dict]:
        """Get user information from access token"""
        verification = self.verify_token(token, 'access')
        
        if not verification['valid']:
            return None
        
        payload = verification['payload']
        return {
            'id': payload['user_id'],
            'username': payload['username'],
            'email': payload['email'],
            'role': payload['role']
        }
    
    def require_auth(self, required_role: str = None):
        """Decorator to require authentication for Flask routes"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                auth_header = request.headers.get('Authorization')
                
                if not auth_header:
                    return jsonify({'error': 'Authorization header required'}), 401
                
                try:
                    token_type, token = auth_header.split(' ', 1)
                    if token_type.lower() != 'bearer':
                        return jsonify({'error': 'Invalid authorization header format'}), 401
                except ValueError:
                    return jsonify({'error': 'Invalid authorization header format'}), 401
                
                user = self.get_user_from_token(token)
                if not user:
                    return jsonify({'error': 'Invalid or expired token'}), 401
                
                # Check role if required
                if required_role and user['role'] != required_role and user['role'] != 'admin':
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                # Add user to request context
                request.current_user = user
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def login(self, username: str, password: str) -> Dict:
        """Complete login process with token generation"""
        auth_result = self.authenticate_user(username, password)
        
        if not auth_result['success']:
            return auth_result
        
        tokens = self.generate_tokens(auth_result['user'])
        
        return {
            'success': True,
            'user': auth_result['user'],
            **tokens
        }
    
    def logout(self, token: str) -> Dict:
        """Logout user (token blacklisting would be implemented here)"""
        # In a production system, you would add the token to a blacklist
        # For now, we just verify the token is valid
        verification = self.verify_token(token, 'access')
        
        if verification['valid']:
            return {
                'success': True,
                'message': 'Successfully logged out'
            }
        else:
            return {
                'success': False,
                'error': 'Invalid token'
            }
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict:
        """Change user password"""
        session = self.db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            if not self.verify_password(old_password, user.password_hash):
                return {
                    'success': False,
                    'error': 'Current password is incorrect'
                }
            
            # Update password
            user.password_hash = self.hash_password(new_password)
            user.updated_at = datetime.utcnow()
            session.commit()
            
            return {
                'success': True,
                'message': 'Password changed successfully'
            }
            
        except Exception as e:
            session.rollback()
            return {
                'success': False,
                'error': f'Failed to change password: {str(e)}'
            }
        finally:
            session.close()
    
    def get_user_profile(self, user_id: int) -> Dict:
        """Get user profile information"""
        session = self.db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            return {
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_active': user.is_active,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'updated_at': user.updated_at.isoformat() if user.updated_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get user profile: {str(e)}'
            }
        finally:
            session.close()
    
    def list_users(self, page: int = 1, per_page: int = 50) -> Dict:
        """List all users (admin only)"""
        session = self.db_manager.get_session()
        try:
            offset = (page - 1) * per_page
            users = session.query(User).offset(offset).limit(per_page).all()
            total = session.query(User).count()
            
            user_list = []
            for user in users:
                user_list.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_active': user.is_active,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                })
            
            return {
                'success': True,
                'users': user_list,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to list users: {str(e)}'
            }
        finally:
            session.close()


def create_default_admin(oauth_handler: OAuth2Handler, username: str = 'admin', 
                        password: str = 'admin123', email: str = 'admin@localhost') -> Dict:
    """Create default admin user if it doesn't exist"""
    result = oauth_handler.create_user(username, email, password, 'admin')
    
    if result['success']:
        print(f"✓ Default admin user created: {username}")
        print(f"  Email: {email}")
        print(f"  Password: {password}")
        print("  Please change the default password after first login!")
    elif 'already exists' in result.get('error', ''):
        print(f"✓ Admin user already exists: {username}")
    else:
        print(f"✗ Failed to create admin user: {result.get('error')}")
    
    return result


if __name__ == '__main__':
    # Test OAuth2 handler
    oauth = OAuth2Handler()
    
    # Create default admin user
    create_default_admin(oauth)
    
    print("\nOAuth2 Handler initialized successfully!")
    print(f"JWT Secret: {oauth.jwt_secret[:20]}...")
    print(f"Access Token Expires: {oauth.access_token_expires}")
    print(f"Refresh Token Expires: {oauth.refresh_token_expires}")
