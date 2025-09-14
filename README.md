# SSL Certificate Management System

A comprehensive SSL certificate management system that provides automated certificate monitoring, renewal, and notification capabilities.

## Features

- **Extended Certificate Format Support**: Read SSL certificates in multiple formats including PEM, P7B, DER, PKCS#10, PKCS#12, PVK, COSE, CWT, and more
- **Advanced Certificate Analysis**: Extract issuer, subject, subjectAltName, CN, expiration dates, and extended certificate properties
- **Database Storage**: Enhanced certificate data storage with ownership tracking and metadata
- **Automated Notifications**: Email alerts at 120, 90, 60, 30, 15, 5, 2, and 1 days before expiration
- **SNMP Support**: SNMP notifications for monitoring systems integration
- **Multi-CA Support**: Integration with Let's Encrypt, DigiCert, Comodo, and other certificate authorities
- **Cloud Integration**: AWS and Cloudflare certificate management and renewal
- **Multiple Interfaces**: Python CLI, PHP CLI, and modern web SPA interface
- **OAuth2 Authentication**: Secure access control with modern authentication
- **PKCS#11 Smart Card Support**: Experimental smart card and hardware security module integration
- **Modern Certificate Standards**: Support for COSE (CBOR Object Signing) and CWT (CBOR Web Token) formats

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
python start_web_server.py
```

## Configuration

Copy `config/config.example.json` to `config/config.json` and update with your settings.

## Directory Structure

- `database/` - Database models and migrations
- `notifications/` - Email and SNMP notification handlers
- `integrations/` - CA and cloud provider integrations
- `cli/` - Command line interfaces
- `web/` - Web application and modern SPA interface
- `config/` - Configuration files and examples
- `scripts/` - Utility scripts and setup tools
- `auth/` - Authentication and authorization modules
- `cache/` - Certificate caching system
- `logs/` - System and application logs
- `temp/` - Temporary files and processing
