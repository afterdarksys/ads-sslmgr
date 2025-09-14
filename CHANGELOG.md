# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-09-14

### Added
- Extended certificate format support with new configuration options
- COSE (CBOR Object Signing and Encryption) certificate support
- CWT (CBOR Web Token) certificate support
- PKCS#11 smart card integration (experimental)
- Legacy PVK format import support
- Advanced certificate format detection capabilities
- New supported certificate extensions: .der, .p7b, .p7c, .p10, .csr, .req, .p12, .pfx, .pvk, .cose, .cbor, .cwt

### Changed
- Updated configuration schema with new certificate format settings
- Enhanced database models for improved certificate tracking
- Modernized web interface with updated styling and functionality
- Improved certificate management API endpoints
- Updated JavaScript frontend with new certificate handling features

### Removed
- Deprecated core Python certificate manager modules
- Legacy certificate parser implementation
- Old renewal router system
- Removed core/__init__.py, certificate_manager.py, certificate_parser.py, renewal_router.py

### Security
- Added experimental warning for PKCS#11 support
- Disabled PVK export by default (security recommendation)
- Enhanced certificate validation and format verification

### Technical
- Updated Python dependencies in requirements.txt
- Modernized web application structure
- Enhanced CSS styling for better user experience
- Improved JavaScript error handling and user feedback