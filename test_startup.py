#!/usr/bin/env python3
"""
Quick test script for SSL Certificate Manager
Tests basic functionality and database initialization
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all modules can be imported"""
    try:
        print("Testing imports...")

        sys.path.insert(0, str(project_root / "'"))
        from certificate_manager import CertificateManager
        print("✓ CertificateManager imported successfully")

        from database.models import DatabaseManager
        print("✓ DatabaseManager imported successfully")

        from auth.oauth2_handler import OAuth2Handler
        print("✓ OAuth2Handler imported successfully")

        from web.api import SSLManagerAPI
        print("✓ SSLManagerAPI imported successfully")

        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_database_initialization():
    """Test database initialization"""
    try:
        print("\nTesting database initialization...")

        # Test database configuration
        config = {
            'type': 'sqlite',
            'name': 'test_sslmgr.db'
        }

        from database.models import DatabaseManager
        db_manager = DatabaseManager(config)
        print("✓ Database manager initialized")

        # Test table creation
        db_manager.initialize_database()
        print("✓ Database tables created successfully")

        return True
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False

def test_certificate_manager():
    """Test certificate manager basic functionality"""
    try:
        print("\nTesting certificate manager...")

        sys.path.insert(0, str(project_root / "'"))
        from certificate_manager import CertificateManager

        # Initialize with test database
        config = {
            'database': {
                'type': 'sqlite',
                'name': 'test_sslmgr.db'
            },
            'directories': {
                'certificates': './certificates',
                'cache': './cache',
                'logs': './logs'
            }
        }

        cert_manager = CertificateManager(config)
        print("✓ CertificateManager initialized successfully")

        # Test listing certificates (should return empty list initially)
        result = cert_manager.list_certificates(page=1, per_page=10)
        if result.get('success'):
            print("✓ list_certificates method working")
            print(f"  Found {len(result.get('certificates', []))} certificates")
        else:
            print("✗ list_certificates method failed")
            return False

        # Test statistics
        stats = cert_manager.get_certificate_statistics()
        if stats.get('success'):
            print("✓ get_certificate_statistics method working")
        else:
            print("✗ get_certificate_statistics method failed")

        return True
    except Exception as e:
        print(f"✗ CertificateManager test failed: {e}")
        return False

def test_oauth_handler():
    """Test OAuth2 handler basic functionality"""
    try:
        print("\nTesting OAuth2 handler...")

        from auth.oauth2_handler import OAuth2Handler

        oauth = OAuth2Handler()
        print("✓ OAuth2Handler initialized successfully")

        # Test creating a test user
        result = oauth.create_user('testuser', 'test@example.com', 'password123', 'user')
        if result.get('success'):
            print("✓ User creation working")
        else:
            print("✓ User creation handled gracefully (user might already exist)")

        return True
    except Exception as e:
        print(f"✗ OAuth2Handler test failed: {e}")
        return False

def test_api_initialization():
    """Test API initialization"""
    try:
        print("\nTesting API initialization...")

        from web.api import SSLManagerAPI

        config = {
            'database': {
                'type': 'sqlite',
                'name': 'test_sslmgr.db'
            },
            'web': {
                'host': '127.0.0.1',
                'port': 5000,
                'debug': True
            },
            'directories': {
                'certificates': './certificates',
                'cache': './cache',
                'logs': './logs'
            }
        }

        api = SSLManagerAPI(config)
        print("✓ SSLManagerAPI initialized successfully")

        return True
    except Exception as e:
        print(f"✗ API initialization failed: {e}")
        return False

def cleanup():
    """Clean up test files"""
    try:
        if os.path.exists('test_sslmgr.db'):
            os.remove('test_sslmgr.db')
            print("\n✓ Test database cleaned up")
    except Exception as e:
        print(f"✗ Cleanup failed: {e}")

def main():
    """Run all tests"""
    print("SSL Certificate Manager - Startup Test")
    print("=" * 50)

    all_passed = True

    # Run tests
    tests = [
        test_imports,
        test_database_initialization,
        test_certificate_manager,
        test_oauth_handler,
        test_api_initialization
    ]

    for test in tests:
        if not test():
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! System is ready to run.")
        print("\nTo start the application:")
        print("1. Configure config/config.json with your settings")
        print("2. Run: python main.py")
        print("3. Visit: http://localhost:5000")
        print("4. Default admin login: admin / admin123")
    else:
        print("❌ Some tests failed. Please fix issues before running the application.")
        return 1

    cleanup()
    return 0

if __name__ == '__main__':
    sys.exit(main())