"""
Database models for SSL Certificate Management System
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

Base = declarative_base()


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
