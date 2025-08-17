# SSL Certificate Management System

A comprehensive SSL certificate management system that provides automated certificate monitoring, renewal, and notification capabilities.

## Features

- **Certificate Parsing**: Read SSL certificates in PEM and P7B formats
- **Certificate Analysis**: Extract issuer, subject, subjectAltName, CN, and expiration dates
- **Database Storage**: Store certificate data with ownership information
- **Automated Notifications**: Email alerts at 120, 90, 60, 30, 15, 5, 2, and 1 days before expiration
- **SNMP Support**: SNMP notifications for monitoring systems
- **Multi-CA Support**: Integration with Let's Encrypt, DigiCert, Comodo
- **Cloud Integration**: AWS and Cloudflare certificate renewal
- **Multiple Interfaces**: Python CLI, PHP CLI, and web SPA
- **OAuth2 Authentication**: Secure access control

## Installation

### Python Dependencies
```bash
pip install -r requirements.txt
```

### PHP Dependencies
```bash
composer install
```

### Database Setup
```bash
python scripts/setup_database.py
```

## Usage

### Python CLI
```bash
python cli/ssl_manager.py --help
```

### PHP CLI
```bash
php cli/ssl_manager.php --help
```

### Web Interface
```bash
python app.py
```

## Configuration

Copy `config/config.example.json` to `config/config.json` and update with your settings.

## Directory Structure

- `core/` - Core certificate management logic
- `parsers/` - Certificate parsers for different formats
- `database/` - Database models and migrations
- `notifications/` - Email and SNMP notification handlers
- `integrations/` - CA and cloud provider integrations
- `cli/` - Command line interfaces
- `web/` - Web application and SPA
- `config/` - Configuration files
- `scripts/` - Utility scripts
- `tests/` - Test suites
