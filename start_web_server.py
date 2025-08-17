#!/usr/bin/env python3
"""
SSL Certificate Manager - Web Server Startup Script
Starts the Flask web application with OAuth2 authentication and SPA interface
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from web.api import SSLManagerAPI
from auth.oauth2_handler import create_default_admin


def main():
    parser = argparse.ArgumentParser(description='SSL Certificate Manager Web Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--create-admin', action='store_true', help='Create default admin user')
    
    args = parser.parse_args()
    
    # Initialize API
    try:
        api = SSLManagerAPI(args.config)
        
        # Create default admin user if requested
        if args.create_admin:
            print("Creating default admin user...")
            create_default_admin(api.oauth)
            print()
        
        print("=" * 60)
        print("SSL Certificate Manager Web Interface")
        print("=" * 60)
        print(f"Starting server on http://{args.host}:{args.port}")
        print(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
        print()
        print("Default admin credentials (if created):")
        print("  Username: admin")
        print("  Password: admin123")
        print("  ⚠️  Please change the default password after first login!")
        print()
        print("Available endpoints:")
        print("  Web Interface: http://{args.host}:{args.port}")
        print("  API Documentation: http://{args.host}:{args.port}/api/health")
        print()
        print("Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Start the server
        api.run(host=args.host, port=args.port, debug=args.debug)
        
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
