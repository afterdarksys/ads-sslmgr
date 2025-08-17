#!/usr/bin/env python3
"""
SSL Certificate Manager Setup Script
Initializes the database and sets up the system
"""

import os
import sys
import json
import sqlite3
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from database.models import DatabaseManager, get_database_url


def create_config_if_not_exists():
    """Create configuration file from example if it doesn't exist."""
    config_file = project_root / "config" / "config.json"
    example_file = project_root / "config" / "config.example.json"
    
    if not config_file.exists() and example_file.exists():
        print("Creating config.json from example...")
        with open(example_file) as f:
            config = json.load(f)
        
        # Set default SQLite database path
        config['database']['name'] = str(project_root / "sslmgr.db")
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✓ Configuration created at {config_file}")
        print("Please review and update the configuration as needed.")
        return config
    elif config_file.exists():
        with open(config_file) as f:
            return json.load(f)
    else:
        print("Error: No configuration file found and no example to copy from")
        sys.exit(1)


def setup_database(config):
    """Initialize the database with required tables."""
    print("Setting up database...")
    
    try:
        db_manager = DatabaseManager(get_database_url(config))
        db_manager.create_tables()
        print("✓ Database tables created successfully")
        
        # Test database connection
        session = db_manager.get_session()
        session.close()
        print("✓ Database connection test successful")
        
    except Exception as e:
        print(f"✗ Database setup failed: {e}")
        sys.exit(1)


def create_directories(config):
    """Create required directories."""
    print("Creating required directories...")
    
    directories = [
        config.get('directories', {}).get('cache', './cache'),
        config.get('directories', {}).get('logs', './logs'),
        './temp'
    ]
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.is_absolute():
            dir_path = project_root / directory
        
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {dir_path}")


def make_scripts_executable():
    """Make CLI scripts executable."""
    print("Making scripts executable...")
    
    scripts = [
        project_root / "cli" / "ssl_manager.py",
        project_root / "cli" / "ssl_manager.php",
        project_root / "scripts" / "send_notifications.py"
    ]
    
    for script in scripts:
        if script.exists():
            script.chmod(0o755)
            print(f"✓ Made executable: {script}")


def test_dependencies():
    """Test that required dependencies are available."""
    print("Testing dependencies...")
    
    # Test Python dependencies
    python_deps = [
        'cryptography',
        'sqlalchemy',
        'click',
        'requests',
        'jinja2'
    ]
    
    missing_deps = []
    for dep in python_deps:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)
    
    if missing_deps:
        print(f"✗ Missing Python dependencies: {', '.join(missing_deps)}")
        print("Please run: pip install -r requirements.txt")
        return False
    else:
        print("✓ All Python dependencies available")
    
    # Test OpenSSL
    try:
        import OpenSSL
        print("✓ pyOpenSSL available")
    except ImportError:
        print("✗ pyOpenSSL not available")
        return False
    
    return True


def show_next_steps():
    """Show next steps to the user."""
    print("\n" + "="*60)
    print("SSL Certificate Manager Setup Complete!")
    print("="*60)
    
    print("\nNext Steps:")
    print("1. Review and update config/config.json with your settings")
    print("2. Configure email settings for notifications")
    print("3. Set up CA API credentials (Let's Encrypt, DigiCert, etc.)")
    print("4. Test the system:")
    print("   python cli/ssl_manager.py config test")
    print("5. Scan your first directory:")
    print("   python cli/ssl_manager.py scan directory /path/to/certificates")
    print("6. Set up notification cron jobs:")
    print("   python cli/ssl_manager.py notify setup")
    
    print("\nUseful Commands:")
    print("- List certificates: python cli/ssl_manager.py list certificates")
    print("- Show statistics: python cli/ssl_manager.py list statistics")
    print("- Test notifications: python cli/ssl_manager.py notify test")
    print("- Renew certificate: python cli/ssl_manager.py renew certificate <id>")
    
    print("\nPHP CLI (if using PHP):")
    print("- Install dependencies: composer install")
    print("- List certificates: php cli/ssl_manager.php list")
    print("- Show statistics: php cli/ssl_manager.php stats")


def main():
    """Main setup function."""
    print("SSL Certificate Manager Setup")
    print("=" * 40)
    
    # Test dependencies first
    if not test_dependencies():
        print("\nPlease install missing dependencies and run setup again.")
        sys.exit(1)
    
    # Create configuration
    config = create_config_if_not_exists()
    
    # Setup database
    setup_database(config)
    
    # Create directories
    create_directories(config)
    
    # Make scripts executable
    make_scripts_executable()
    
    # Show next steps
    show_next_steps()


if __name__ == "__main__":
    main()
