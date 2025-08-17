"""
Certificate Manager - Core business logic for certificate management
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path

from database.models import (
    Certificate, CertificateOwnership, DatabaseManager, 
    ScanJob, get_database_url
)
from core.certificate_parser import CertificateParser


class CertificateManager:
    """Main certificate management class."""
    
    def __init__(self, config: dict):
        self.config = config
        self.db_manager = DatabaseManager(get_database_url(config))
        self.parser = CertificateParser()
        
        # Ensure database tables exist
        self.db_manager.create_tables()
    
    def scan_directory(self, directory_path: str, update_ownership: bool = False) -> Dict:
        """
        Scan a directory for certificates and store them in the database.
        
        Args:
            directory_path: Path to scan for certificates
            update_ownership: Whether to update existing ownership info
            
        Returns:
            Dictionary with scan results
        """
        job_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create scan job record
        session = self.db_manager.get_session()
        scan_job = ScanJob(
            job_id=job_id,
            scan_path=directory_path,
            scan_type='directory',
            status='running'
        )
        session.add(scan_job)
        session.commit()
        
        try:
            # Parse certificates from directory
            parsed_certs = self.parser.parse_directory(directory_path)
            
            certificates_added = 0
            certificates_updated = 0
            errors = []
            
            for cert_data in parsed_certs:
                try:
                    result = self._store_certificate(session, cert_data, update_ownership)
                    if result == 'added':
                        certificates_added += 1
                    elif result == 'updated':
                        certificates_updated += 1
                except Exception as e:
                    errors.append(f"Error storing certificate {cert_data.get('file_path', 'unknown')}: {e}")
            
            # Update scan job
            scan_job.certificates_found = len(parsed_certs)
            scan_job.certificates_added = certificates_added
            scan_job.certificates_updated = certificates_updated
            scan_job.errors_count = len(errors)
            scan_job.completed_at = datetime.utcnow()
            scan_job.status = 'completed' if not errors else 'completed_with_errors'
            scan_job.scan_results = {
                'errors': errors,
                'summary': f"Found {len(parsed_certs)} certificates, added {certificates_added}, updated {certificates_updated}"
            }
            
            session.commit()
            
            return {
                'job_id': job_id,
                'status': 'completed',
                'certificates_found': len(parsed_certs),
                'certificates_added': certificates_added,
                'certificates_updated': certificates_updated,
                'errors': errors
            }
            
        except Exception as e:
            # Update scan job with error
            scan_job.status = 'failed'
            scan_job.error_message = str(e)
            scan_job.completed_at = datetime.utcnow()
            session.commit()
            raise
        
        finally:
            session.close()
    
    def _store_certificate(self, session, cert_data: Dict, update_ownership: bool = False) -> str:
        """Store a single certificate in the database."""
        
        # Calculate file hash for duplicate detection
        file_path = cert_data['file_path']
        file_hash = self._calculate_file_hash(file_path)
        
        # Check if certificate already exists
        existing_cert = session.query(Certificate).filter_by(
            serial_number=cert_data['serial_number'],
            file_path=file_path
        ).first()
        
        if existing_cert:
            # Update existing certificate
            existing_cert.file_hash = file_hash
            existing_cert.days_until_expiry = cert_data['days_until_expiry']
            existing_cert.last_scanned = datetime.utcnow()
            existing_cert.updated_at = datetime.utcnow()
            existing_cert.is_expired = cert_data['days_until_expiry'] <= 0
            
            # Update JSON fields
            existing_cert.issuer_info = cert_data['issuer']
            existing_cert.subject_info = cert_data['subject']
            existing_cert.subject_alt_names = cert_data['subject_alt_names']
            existing_cert.key_usage = cert_data['key_usage']
            existing_cert.extended_key_usage = cert_data['extended_key_usage']
            
            return 'updated'
        
        else:
            # Create new certificate
            new_cert = Certificate(
                file_path=file_path,
                file_hash=file_hash,
                serial_number=cert_data['serial_number'],
                version=cert_data['version'],
                common_name=cert_data['common_name'],
                not_valid_before=datetime.fromisoformat(cert_data['not_valid_before'].replace('Z', '+00:00')),
                not_valid_after=datetime.fromisoformat(cert_data['not_valid_after'].replace('Z', '+00:00')),
                days_until_expiry=cert_data['days_until_expiry'],
                signature_algorithm=cert_data['signature_algorithm'],
                certificate_type=cert_data['certificate_type'],
                issuer_category=cert_data['issuer_category'],
                issuer_info=cert_data['issuer'],
                subject_info=cert_data['subject'],
                subject_alt_names=cert_data['subject_alt_names'],
                key_usage=cert_data['key_usage'],
                extended_key_usage=cert_data['extended_key_usage'],
                is_expired=cert_data['days_until_expiry'] <= 0
            )
            
            session.add(new_cert)
            session.flush()  # Get the ID
            
            # Create default ownership record if it doesn't exist
            if not update_ownership:
                ownership = CertificateOwnership(
                    certificate_id=new_cert.id,
                    environment='unknown',
                    description=f"Auto-discovered certificate from {file_path}"
                )
                session.add(ownership)
            
            return 'added'
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file content."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def get_expiring_certificates(self, days_threshold: int = 30) -> List[Certificate]:
        """Get certificates expiring within the specified number of days."""
        session = self.db_manager.get_session()
        try:
            threshold_date = datetime.utcnow() + timedelta(days=days_threshold)
            
            expiring_certs = session.query(Certificate).filter(
                Certificate.not_valid_after <= threshold_date,
                Certificate.is_active == True,
                Certificate.is_expired == False
            ).all()
            
            return expiring_certs
        finally:
            session.close()
    
    def get_certificate_by_id(self, cert_id: int) -> Optional[Certificate]:
        """Get certificate by ID."""
        session = self.db_manager.get_session()
        try:
            return session.query(Certificate).filter_by(id=cert_id).first()
        finally:
            session.close()
    
    def update_certificate_ownership(self, cert_id: int, ownership_data: Dict) -> bool:
        """Update certificate ownership information."""
        session = self.db_manager.get_session()
        try:
            # Get or create ownership record
            ownership = session.query(CertificateOwnership).filter_by(
                certificate_id=cert_id
            ).first()
            
            if not ownership:
                ownership = CertificateOwnership(certificate_id=cert_id)
                session.add(ownership)
            
            # Update ownership fields
            for field, value in ownership_data.items():
                if hasattr(ownership, field):
                    setattr(ownership, field, value)
            
            ownership.updated_at = datetime.utcnow()
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def search_certificates(self, query: str = "", filters: Dict = None) -> List[Certificate]:
        """Search certificates with optional filters."""
        session = self.db_manager.get_session()
        try:
            query_obj = session.query(Certificate)
            
            # Apply text search
            if query:
                query_obj = query_obj.filter(
                    Certificate.common_name.contains(query) |
                    Certificate.file_path.contains(query) |
                    Certificate.serial_number.contains(query)
                )
            
            # Apply filters
            if filters:
                if 'issuer_category' in filters:
                    query_obj = query_obj.filter(Certificate.issuer_category == filters['issuer_category'])
                
                if 'certificate_type' in filters:
                    query_obj = query_obj.filter(Certificate.certificate_type == filters['certificate_type'])
                
                if 'is_expired' in filters:
                    query_obj = query_obj.filter(Certificate.is_expired == filters['is_expired'])
                
                if 'days_until_expiry_max' in filters:
                    query_obj = query_obj.filter(Certificate.days_until_expiry <= filters['days_until_expiry_max'])
                
                if 'days_until_expiry_min' in filters:
                    query_obj = query_obj.filter(Certificate.days_until_expiry >= filters['days_until_expiry_min'])
            
            return query_obj.all()
            
        finally:
            session.close()
    
    def get_certificate_statistics(self) -> Dict:
        """Get certificate statistics."""
        session = self.db_manager.get_session()
        try:
            total_certs = session.query(Certificate).filter(Certificate.is_active == True).count()
            expired_certs = session.query(Certificate).filter(
                Certificate.is_active == True,
                Certificate.is_expired == True
            ).count()
            
            # Certificates expiring in different timeframes
            expiring_30 = len(self.get_expiring_certificates(30))
            expiring_60 = len(self.get_expiring_certificates(60))
            expiring_90 = len(self.get_expiring_certificates(90))
            
            # Group by issuer category
            issuer_stats = {}
            issuers = session.query(Certificate.issuer_category).filter(
                Certificate.is_active == True
            ).distinct().all()
            
            for (issuer,) in issuers:
                count = session.query(Certificate).filter(
                    Certificate.is_active == True,
                    Certificate.issuer_category == issuer
                ).count()
                issuer_stats[issuer] = count
            
            return {
                'total_certificates': total_certs,
                'expired_certificates': expired_certs,
                'expiring_30_days': expiring_30,
                'expiring_60_days': expiring_60,
                'expiring_90_days': expiring_90,
                'by_issuer': issuer_stats,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def export_certificates_json(self, filters: Dict = None) -> str:
        """Export certificates to JSON format."""
        certificates = self.search_certificates(filters=filters)
        
        export_data = []
        for cert in certificates:
            cert_data = {
                'id': cert.id,
                'uuid': cert.uuid,
                'file_path': cert.file_path,
                'serial_number': cert.serial_number,
                'common_name': cert.common_name,
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'days_until_expiry': cert.days_until_expiry,
                'certificate_type': cert.certificate_type,
                'issuer_category': cert.issuer_category,
                'issuer_info': cert.issuer_info,
                'subject_info': cert.subject_info,
                'subject_alt_names': cert.subject_alt_names,
                'is_expired': cert.is_expired,
                'created_at': cert.created_at.isoformat(),
                'updated_at': cert.updated_at.isoformat()
            }
            
            # Add ownership information if available
            if cert.ownership:
                ownership = cert.ownership[0]  # Assuming one ownership record per cert
                cert_data['ownership'] = {
                    'owner_email': ownership.owner_email,
                    'owner_username': ownership.owner_username,
                    'owner_url': ownership.owner_url,
                    'department': ownership.department,
                    'environment': ownership.environment,
                    'application_name': ownership.application_name,
                    'description': ownership.description
                }
            
            export_data.append(cert_data)
        
        return json.dumps(export_data, indent=2, default=str)
