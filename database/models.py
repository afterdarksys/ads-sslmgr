"""
Database models for SSL Certificate Management System
"""

import os
from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import uuid

Base = declarative_base()

# ── Secret encryption helpers ────────────────────────────────────────────────
# Set SSLMGR_ENCRYPTION_KEY in environment (generate once with Fernet.generate_key()).
# Secrets stored in CAConfiguration.api_key / api_secret are always encrypted at rest.

def _fernet():
    try:
        from cryptography.fernet import Fernet
        key = os.environ.get('SSLMGR_ENCRYPTION_KEY', '')
        if not key:
            raise RuntimeError(
                "SSLMGR_ENCRYPTION_KEY environment variable is not set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return Fernet(key.encode() if isinstance(key, str) else key)
    except ImportError:
        raise RuntimeError("cryptography package is required for secret encryption")


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string for storage. Returns empty string for empty input."""
    if not plaintext:
        return plaintext
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored secret. Returns empty string for empty input."""
    if not ciphertext:
        return ciphertext
    return _fernet().decrypt(ciphertext.encode()).decode()


class Certificate(Base):
    """Certificate model storing parsed certificate information."""
    
    __tablename__ = 'certificates'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    # File information
    file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64))  # SHA256 hash of file content
    
    # Certificate basic info
    serial_number = Column(String(100), nullable=False)
    version = Column(String(20))
    common_name = Column(String(255))
    
    # Validity period
    not_valid_before = Column(DateTime, nullable=False)
    not_valid_after = Column(DateTime, nullable=False)
    days_until_expiry = Column(Integer)
    
    # Certificate details
    signature_algorithm = Column(String(100))
    certificate_type = Column(String(50))  # server, client, code_signing, email
    issuer_category = Column(String(50))   # letsencrypt, digicert, comodo, etc.
    
    # JSON fields for complex data
    issuer_info = Column(JSON)
    subject_info = Column(JSON)
    subject_alt_names = Column(JSON)
    key_usage = Column(JSON)
    extended_key_usage = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_expired = Column(Boolean, default=False)
    
    # Relationships
    ownership = relationship("CertificateOwnership", back_populates="certificate", cascade="all, delete-orphan")
    notifications = relationship("NotificationLog", back_populates="certificate", cascade="all, delete-orphan")
    renewal_attempts = relationship("RenewalAttempt", back_populates="certificate", cascade="all, delete-orphan")


class CertificateOwnership(Base):
    """Certificate ownership information."""
    
    __tablename__ = 'certificate_ownership'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=False)
    
    # Ownership details
    owner_email = Column(String(255))
    owner_username = Column(String(100))
    owner_url = Column(String(500))
    department = Column(String(100))
    contact_phone = Column(String(50))
    
    # Additional metadata
    environment = Column(String(50))  # production, staging, development
    application_name = Column(String(200))
    description = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    certificate = relationship("Certificate", back_populates="ownership")


class NotificationLog(Base):
    """Log of sent notifications."""
    
    __tablename__ = 'notification_logs'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=False)
    
    # Notification details
    notification_type = Column(String(50))  # email, snmp
    days_before_expiry = Column(Integer)
    recipient = Column(String(255))
    subject = Column(String(500))
    message = Column(Text)
    
    # Status
    sent_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50))  # sent, failed, pending
    error_message = Column(Text)
    
    # Relationships
    certificate = relationship("Certificate", back_populates="notifications")


class RenewalAttempt(Base):
    """Log of certificate renewal attempts."""
    
    __tablename__ = 'renewal_attempts'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=False)
    
    # Renewal details
    ca_provider = Column(String(50))  # letsencrypt, digicert, comodo, etc.
    renewal_method = Column(String(50))  # api, manual, automated
    
    # Status
    attempted_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50))  # success, failed, pending, cancelled
    error_message = Column(Text)
    
    # New certificate info (if successful)
    new_certificate_path = Column(String(500))
    new_expiry_date = Column(DateTime)
    
    # Relationships
    certificate = relationship("Certificate", back_populates="renewal_attempts")


class CAConfiguration(Base):
    """Certificate Authority configuration."""

    __tablename__ = 'ca_configurations'

    id = Column(Integer, primary_key=True)

    # CA details
    ca_name = Column(String(100), unique=True, nullable=False)  # letsencrypt, digicert, etc.
    ca_type = Column(String(50))  # public, private, internal

    # Link to PrivateCA record (set for ca_type='private', NULL for public CAs)
    private_ca_id = Column(Integer, ForeignKey('private_cas.id'), nullable=True)
    
    # Configuration
    is_enabled = Column(Boolean, default=True)
    api_endpoint = Column(String(500))
    api_key = Column(String(500))  # Encrypted
    api_secret = Column(String(500))  # Encrypted
    
    # Settings
    default_validity_days = Column(Integer, default=90)
    auto_renewal_enabled = Column(Boolean, default=False)
    renewal_threshold_days = Column(Integer, default=30)
    
    # Additional config as JSON
    configuration = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    private_ca = relationship('PrivateCA', foreign_keys=[private_ca_id])


class CAConfigurationManager:
    """
    CRUD helper for CAConfiguration that transparently encrypts/decrypts
    api_key and api_secret using Fernet (SSLMGR_ENCRYPTION_KEY env var).

    Usage:
        mgr = CAConfigurationManager(db_manager)
        mgr.set(session, ca_name='digicert', api_key='plain', api_secret='plain', ...)
        api_key = mgr.get_api_key(session, ca_name='digicert')
    """

    def __init__(self, db_manager: 'DatabaseManager'):
        self.db = db_manager

    def set(self, ca_name: str, api_key: str = None, api_secret: str = None,
            **kwargs) -> 'CAConfiguration':
        """Create or update a CAConfiguration, encrypting credentials."""
        session = self.db.get_session()
        try:
            rec = session.query(CAConfiguration).filter_by(ca_name=ca_name).first()
            if rec is None:
                rec = CAConfiguration(ca_name=ca_name)
                session.add(rec)

            for field, value in kwargs.items():
                if hasattr(rec, field):
                    setattr(rec, field, value)

            if api_key is not None:
                rec.api_key = encrypt_secret(api_key)
            if api_secret is not None:
                rec.api_secret = encrypt_secret(api_secret)

            session.commit()
            session.refresh(rec)
            return rec
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_api_key(self, ca_name: str) -> str:
        """Return plaintext api_key for the named CA."""
        session = self.db.get_session()
        try:
            rec = session.query(CAConfiguration).filter_by(ca_name=ca_name).first()
            return decrypt_secret(rec.api_key) if rec and rec.api_key else ''
        finally:
            session.close()

    def get_api_secret(self, ca_name: str) -> str:
        """Return plaintext api_secret for the named CA."""
        session = self.db.get_session()
        try:
            rec = session.query(CAConfiguration).filter_by(ca_name=ca_name).first()
            return decrypt_secret(rec.api_secret) if rec and rec.api_secret else ''
        finally:
            session.close()

    def get(self, ca_name: str) -> dict:
        """Return a dict with plaintext credentials for the named CA."""
        session = self.db.get_session()
        try:
            rec = session.query(CAConfiguration).filter_by(ca_name=ca_name).first()
            if not rec:
                return {}
            return {
                'ca_name': rec.ca_name,
                'ca_type': rec.ca_type,
                'is_enabled': rec.is_enabled,
                'api_endpoint': rec.api_endpoint,
                'api_key': decrypt_secret(rec.api_key) if rec.api_key else '',
                'api_secret': decrypt_secret(rec.api_secret) if rec.api_secret else '',
                'default_validity_days': rec.default_validity_days,
                'auto_renewal_enabled': rec.auto_renewal_enabled,
                'renewal_threshold_days': rec.renewal_threshold_days,
                'configuration': rec.configuration,
            }
        finally:
            session.close()


class ScanJob(Base):
    """Certificate scanning job history."""
    
    __tablename__ = 'scan_jobs'
    
    id = Column(Integer, primary_key=True)
    
    # Job details
    job_id = Column(String(100), unique=True)
    scan_path = Column(String(500), nullable=False)
    scan_type = Column(String(50))  # directory, file, url
    
    # Results
    certificates_found = Column(Integer, default=0)
    certificates_added = Column(Integer, default=0)
    certificates_updated = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)
    
    # Status
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String(50))  # running, completed, failed, cancelled
    error_message = Column(Text)
    
    # Results as JSON
    scan_results = Column(JSON)


class User(Base):
    """User model for authentication."""
    
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    
    # User details
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255))
    
    # Profile
    first_name = Column(String(100))
    last_name = Column(String(100))
    department = Column(String(100))
    phone = Column(String(50))
    
    # Status
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(String(50), default='user')  # user, admin, manager
    last_login = Column(DateTime)
    
    # OAuth2 integration
    oauth_provider = Column(String(50))
    oauth_id = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PrivateCA(Base):
    """Private Certificate Authority — stores CA cert PEM and key file path."""

    __tablename__ = 'private_cas'

    id   = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))

    # Identity
    name    = Column(String(200), unique=True, nullable=False)
    ca_type = Column(String(50), nullable=False)   # root | intermediate | issuing
    common_name = Column(String(255), nullable=False)

    # Hierarchy — root CAs have parent_id=NULL
    parent_id = Column(Integer, ForeignKey('private_cas.id'), nullable=True)

    # Subject attributes
    organization        = Column(String(255))
    organizational_unit = Column(String(255))
    country             = Column(String(2))
    state               = Column(String(100))
    locality            = Column(String(100))

    # Cert material (public cert is safe to store in DB; private key is on disk)
    cert_pem      = Column(Text, nullable=False)
    key_file_path = Column(String(500))   # path to PEM key file (chmod 0600)

    # CRL
    crl_pem               = Column(Text)
    crl_last_generated    = Column(DateTime)
    crl_next_update       = Column(DateTime)
    crl_distribution_url  = Column(String(500))

    # OCSP
    ocsp_url = Column(String(500))

    # Settings
    validity_years   = Column(Integer)
    key_type         = Column(String(20), default='rsa')
    key_size         = Column(Integer,    default=4096)
    path_length      = Column(Integer)

    # Validity
    not_valid_before = Column(DateTime)
    not_valid_after  = Column(DateTime)

    # Status
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    parent           = relationship('PrivateCA', remote_side=[id], backref='sub_cas')
    issued_certs     = relationship('PrivatelyIssuedCertificate', back_populates='ca',
                                    cascade='all, delete-orphan')


class PrivatelyIssuedCertificate(Base):
    """Certificates issued by a PrivateCA."""

    __tablename__ = 'privately_issued_certificates'

    id   = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))

    # Issuing CA
    ca_id = Column(Integer, ForeignKey('private_cas.id'), nullable=False)

    # Certificate identity
    serial_number = Column(String(100), nullable=False)
    common_name   = Column(String(255))
    cert_type     = Column(String(50))   # server | client | code_signing | email | ocsp | timestamping

    # PEM storage
    cert_pem      = Column(Text)
    key_file_path = Column(String(500))  # path to encrypted PEM key file (chmod 0600)

    # Subject / SAN
    subject_info   = Column(JSON)
    san_dns        = Column(JSON)
    san_ips        = Column(JSON)
    san_emails     = Column(JSON)

    # Extensions
    key_usage          = Column(JSON)
    extended_key_usage = Column(JSON)

    # Validity
    not_valid_before = Column(DateTime)
    not_valid_after  = Column(DateTime)
    days_validity    = Column(Integer)

    # Revocation
    is_revoked         = Column(Boolean, default=False)
    revocation_reason  = Column(String(100))
    revoked_at         = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    ca = relationship('PrivateCA', back_populates='issued_certs')


class EnrollmentToken(Base):
    """Short-lived, hashed bootstrap credential for first agent enrollment."""

    __tablename__ = 'enrollment_tokens'

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    ca_id = Column(Integer, ForeignKey('private_cas.id'), nullable=False)
    cert_type = Column(String(50), default='server', nullable=False)
    pkinit_principal = Column(String(500))
    expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, default=1, nullable=False)
    uses = Column(Integer, default=0, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ManagedAgent(Base):
    """A host identity managed by the enrollment service."""

    __tablename__ = 'managed_agents'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    name = Column(String(255), nullable=False)
    ca_id = Column(Integer, ForeignKey('private_cas.id'), nullable=False)
    certificate_id = Column(Integer, ForeignKey('privately_issued_certificates.id'), nullable=False)
    cert_type = Column(String(50), default='server', nullable=False)
    pkinit_principal = Column(String(500))
    certificate_fingerprint = Column(String(64), unique=True, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    last_seen_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DatabaseManager:
    """Database connection and session management."""
    
    def __init__(self, database_config):
        if isinstance(database_config, str):
            database_url = database_config
        else:
            database_url = get_database_url({'database': database_config})
        
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self):
        """Get a database session."""
        return self.SessionLocal()

    def initialize_database(self):
        """Initialize database tables"""
        try:
            # Create all tables
            Base.metadata.create_all(self.engine)
            return True
        except Exception as e:
            print(f"Error initializing database: {e}")
            return False
    
    def drop_tables(self):
        """Drop all database tables."""
        Base.metadata.drop_all(bind=self.engine)


def get_database_url(config: dict) -> str:
    """Generate database URL from configuration."""
    db_config = config.get('database', {})
    db_type = db_config.get('type', 'sqlite')
    
    if db_type == 'sqlite':
        db_name = db_config.get('name', 'sslmgr.db')
        return f"sqlite:///{db_name}"
    
    elif db_type == 'postgresql':
        host = db_config.get('host', 'localhost')
        port = db_config.get('port', 5432)
        name = db_config.get('name', 'sslmgr')
        username = db_config.get('username', '')
        password = db_config.get('password', '')
        return f"postgresql://{username}:{password}@{host}:{port}/{name}"
    
    elif db_type == 'mysql':
        host = db_config.get('host', 'localhost')
        port = db_config.get('port', 3306)
        name = db_config.get('name', 'sslmgr')
        username = db_config.get('username', '')
        password = db_config.get('password', '')
        return f"mysql+pymysql://{username}:{password}@{host}:{port}/{name}"
    
    else:
        raise ValueError(f"Unsupported database type: {db_type}")
