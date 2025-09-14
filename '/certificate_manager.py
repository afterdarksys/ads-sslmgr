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
from certificate_parser import CertificateParser, PKCS11Config, CertificateFormat


class CertificateManager:
    """Main certificate management class."""
    
    def __init__(self, config: dict):
        self.config = config
        self.db_manager = DatabaseManager(get_database_url(config))

        # Initialize PKCS11 configuration if enabled
        pkcs11_config = None
        if config.get('pkcs11', {}).get('enabled', False):
            pkcs11_config = PKCS11Config(
                library_path=config['pkcs11'].get('library_path'),
                token_label=config['pkcs11'].get('token_label'),
                pin=config['pkcs11'].get('pin'),
                enabled=True
            )
            print(f"⚠️  EXPERIMENTAL: PKCS11 support enabled for token: {config['pkcs11'].get('token_label')}")

        self.parser = CertificateParser(pkcs11_config)
        
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
                'success': True,
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
    
    def list_certificates(self, page: int = 1, per_page: int = 50, search: str = "",
                         expiring_days: int = None, owner_email: str = None,
                         owner_username: str = None, issuer_category: str = None,
                         certificate_type: str = None, is_expired: bool = None) -> Dict:
        """List certificates with pagination, search, and filtering."""
        session = self.db_manager.get_session()
        try:
            # Build base query with joins to get ownership info
            query_obj = session.query(Certificate).outerjoin(CertificateOwnership)

            # Apply text search
            if search:
                search_filter = (
                    Certificate.common_name.contains(search) |
                    Certificate.file_path.contains(search) |
                    Certificate.serial_number.contains(search)
                )

                # Search in Subject Alt Names (JSON field)
                if hasattr(Certificate.subject_alt_names, 'contains'):
                    search_filter |= Certificate.subject_alt_names.contains(search)

                query_obj = query_obj.filter(search_filter)

            # Apply filters
            if expiring_days:
                query_obj = query_obj.filter(Certificate.days_until_expiry <= expiring_days)

            if owner_email:
                query_obj = query_obj.filter(CertificateOwnership.owner_email == owner_email)

            if owner_username:
                query_obj = query_obj.filter(CertificateOwnership.owner_username == owner_username)

            if issuer_category:
                query_obj = query_obj.filter(Certificate.issuer_category == issuer_category)

            if certificate_type:
                query_obj = query_obj.filter(Certificate.certificate_type == certificate_type)

            if is_expired is not None:
                query_obj = query_obj.filter(Certificate.is_expired == is_expired)

            # Apply active filter
            query_obj = query_obj.filter(Certificate.is_active == True)

            # Get total count
            total = query_obj.count()

            # Apply pagination
            offset = (page - 1) * per_page
            certificates = query_obj.order_by(Certificate.not_valid_after).offset(offset).limit(per_page).all()

            # Format response
            cert_list = []
            for cert in certificates:
                cert_data = {
                    'id': cert.id,
                    'uuid': cert.uuid,
                    'file_path': cert.file_path,
                    'serial_number': cert.serial_number,
                    'common_name': cert.common_name,
                    'issuer': cert.issuer_info.get('common_name', 'Unknown') if cert.issuer_info else 'Unknown',
                    'issuer_category': cert.issuer_category,
                    'not_before': cert.not_valid_before.isoformat(),
                    'not_after': cert.not_valid_after.isoformat(),
                    'days_until_expiry': cert.days_until_expiry,
                    'certificate_type': cert.certificate_type,
                    'is_expired': cert.is_expired,
                    'signature_algorithm': cert.signature_algorithm,
                    'subject_alt_names': cert.subject_alt_names,
                    'key_usage': cert.key_usage,
                    'extended_key_usage': cert.extended_key_usage,
                    'created_at': cert.created_at.isoformat(),
                    'updated_at': cert.updated_at.isoformat(),
                    'last_scanned': cert.last_scanned.isoformat() if cert.last_scanned else None
                }

                # Add ownership information if available
                if cert.ownership:
                    ownership = cert.ownership[0]
                    cert_data['ownership'] = {
                        'owner_email': ownership.owner_email,
                        'owner_username': ownership.owner_username,
                        'owner_url': ownership.owner_url,
                        'department': ownership.department,
                        'contact_phone': ownership.contact_phone,
                        'environment': ownership.environment,
                        'application_name': ownership.application_name,
                        'description': ownership.description
                    }
                else:
                    cert_data['ownership'] = None

                cert_list.append(cert_data)

            return {
                'success': True,
                'certificates': cert_list,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                },
                'filters_applied': {
                    'search': search,
                    'expiring_days': expiring_days,
                    'owner_email': owner_email,
                    'owner_username': owner_username,
                    'issuer_category': issuer_category,
                    'certificate_type': certificate_type,
                    'is_expired': is_expired
                }
            }

        finally:
            session.close()

    def get_certificate_details(self, cert_id: int) -> Dict:
        """Get detailed certificate information by ID."""
        session = self.db_manager.get_session()
        try:
            certificate = session.query(Certificate).outerjoin(CertificateOwnership).filter(
                Certificate.id == cert_id,
                Certificate.is_active == True
            ).first()

            if not certificate:
                return {
                    'success': False,
                    'error': 'Certificate not found or inactive'
                }

            # Build detailed response
            cert_data = {
                'id': certificate.id,
                'uuid': certificate.uuid,
                'file_path': certificate.file_path,
                'file_hash': certificate.file_hash,
                'serial_number': certificate.serial_number,
                'version': certificate.version,
                'common_name': certificate.common_name,
                'not_valid_before': certificate.not_valid_before.isoformat(),
                'not_valid_after': certificate.not_valid_after.isoformat(),
                'days_until_expiry': certificate.days_until_expiry,
                'signature_algorithm': certificate.signature_algorithm,
                'certificate_type': certificate.certificate_type,
                'issuer_category': certificate.issuer_category,
                'issuer_info': certificate.issuer_info,
                'subject_info': certificate.subject_info,
                'subject_alt_names': certificate.subject_alt_names,
                'key_usage': certificate.key_usage,
                'extended_key_usage': certificate.extended_key_usage,
                'is_active': certificate.is_active,
                'is_expired': certificate.is_expired,
                'created_at': certificate.created_at.isoformat(),
                'updated_at': certificate.updated_at.isoformat(),
                'last_scanned': certificate.last_scanned.isoformat() if certificate.last_scanned else None
            }

            # Add ownership information
            if certificate.ownership:
                ownership = certificate.ownership[0]
                cert_data['ownership'] = {
                    'id': ownership.id,
                    'owner_email': ownership.owner_email,
                    'owner_username': ownership.owner_username,
                    'owner_url': ownership.owner_url,
                    'department': ownership.department,
                    'contact_phone': ownership.contact_phone,
                    'environment': ownership.environment,
                    'application_name': ownership.application_name,
                    'description': ownership.description,
                    'created_at': ownership.created_at.isoformat(),
                    'updated_at': ownership.updated_at.isoformat()
                }
            else:
                cert_data['ownership'] = None

            # Add notification history
            cert_data['notifications'] = []
            for notification in certificate.notifications:
                cert_data['notifications'].append({
                    'id': notification.id,
                    'notification_type': notification.notification_type,
                    'days_before_expiry': notification.days_before_expiry,
                    'recipient': notification.recipient,
                    'subject': notification.subject,
                    'sent_at': notification.sent_at.isoformat(),
                    'status': notification.status,
                    'error_message': notification.error_message
                })

            # Add renewal history
            cert_data['renewal_attempts'] = []
            for renewal in certificate.renewal_attempts:
                cert_data['renewal_attempts'].append({
                    'id': renewal.id,
                    'ca_provider': renewal.ca_provider,
                    'renewal_method': renewal.renewal_method,
                    'attempted_at': renewal.attempted_at.isoformat(),
                    'status': renewal.status,
                    'error_message': renewal.error_message,
                    'new_certificate_path': renewal.new_certificate_path,
                    'new_expiry_date': renewal.new_expiry_date.isoformat() if renewal.new_expiry_date else None
                })

            return {
                'success': True,
                'certificate': cert_data
            }

        finally:
            session.close()

    def get_certificates_by_owner(self, owner_email: str = None, owner_username: str = None,
                                 page: int = 1, per_page: int = 50) -> Dict:
        """Get certificates filtered by ownership."""
        filters = {}
        if owner_email:
            filters['owner_email'] = owner_email
        if owner_username:
            filters['owner_username'] = owner_username

        return self.list_certificates(page=page, per_page=per_page, **filters)

    def get_user_certificate_statistics(self, owner_email: str = None, owner_username: str = None) -> Dict:
        """Get certificate statistics for specific user."""
        session = self.db_manager.get_session()
        try:
            base_query = session.query(Certificate).join(CertificateOwnership).filter(
                Certificate.is_active == True
            )

            if owner_email:
                base_query = base_query.filter(CertificateOwnership.owner_email == owner_email)
            if owner_username:
                base_query = base_query.filter(CertificateOwnership.owner_username == owner_username)

            total_certs = base_query.count()
            expired_certs = base_query.filter(Certificate.is_expired == True).count()
            expiring_30 = base_query.filter(Certificate.days_until_expiry <= 30, Certificate.is_expired == False).count()
            expiring_60 = base_query.filter(Certificate.days_until_expiry <= 60, Certificate.is_expired == False).count()
            expiring_90 = base_query.filter(Certificate.days_until_expiry <= 90, Certificate.is_expired == False).count()

            return {
                'success': True,
                'statistics': {
                    'total_certificates': total_certs,
                    'expired_certificates': expired_certs,
                    'valid_certificates': total_certs - expired_certs,
                    'expiring_30_days': expiring_30,
                    'expiring_60_days': expiring_60,
                    'expiring_90_days': expiring_90,
                    'owner_email': owner_email,
                    'owner_username': owner_username
                }
            }
        finally:
            session.close()

    def create_certificate_from_upload(self, file_content: bytes, file_name: str,
                                     ownership_data: Dict = None) -> Dict:
        """Create certificate from uploaded file content."""
        import tempfile
        import os

        try:
            # Save uploaded content to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as temp_file:
                temp_file.write(file_content)
                temp_path = temp_file.name

            try:
                # Parse the certificate
                parsed_certs = self.parser.parse_file(temp_path)

                if not parsed_certs:
                    return {
                        'success': False,
                        'error': 'No valid certificates found in uploaded file'
                    }

                # Store the first certificate (assuming single cert per file)
                cert_data = parsed_certs[0]
                cert_data['file_path'] = file_name  # Use original filename

                session = self.db_manager.get_session()
                try:
                    result = self._store_certificate(session, cert_data, update_ownership=False)
                    session.commit()

                    # Get the stored certificate
                    stored_cert = session.query(Certificate).filter(
                        Certificate.serial_number == cert_data['serial_number'],
                        Certificate.file_path == file_name
                    ).first()

                    if stored_cert and ownership_data:
                        # Update ownership
                        ownership_result = self.update_certificate_ownership(stored_cert.id, ownership_data)
                        if not ownership_result:
                            # Log warning but don't fail the operation
                            pass

                    return {
                        'success': True,
                        'certificate_id': stored_cert.id if stored_cert else None,
                        'message': f'Certificate uploaded successfully: {file_name}',
                        'action': result
                    }

                finally:
                    session.close()

            finally:
                # Clean up temp file
                os.unlink(temp_path)

        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to upload certificate: {str(e)}'
            }

    def revoke_certificate(self, cert_id: int, reason: str = "unspecified") -> Dict:
        """Mark certificate as revoked (deactivated)."""
        session = self.db_manager.get_session()
        try:
            certificate = session.query(Certificate).filter(Certificate.id == cert_id).first()

            if not certificate:
                return {
                    'success': False,
                    'error': 'Certificate not found'
                }

            # Mark as inactive (revoked)
            certificate.is_active = False
            certificate.updated_at = datetime.utcnow()

            # Update ownership description to include revocation reason
            if certificate.ownership:
                ownership = certificate.ownership[0]
                current_desc = ownership.description or ""
                ownership.description = f"{current_desc}\nREVOKED: {reason} on {datetime.utcnow().isoformat()}"
                ownership.updated_at = datetime.utcnow()

            session.commit()

            return {
                'success': True,
                'message': f'Certificate {certificate.common_name} has been revoked',
                'certificate_id': cert_id,
                'reason': reason
            }

        except Exception as e:
            session.rollback()
            return {
                'success': False,
                'error': f'Failed to revoke certificate: {str(e)}'
            }
        finally:
            session.close()

    def bulk_update_ownership(self, cert_ids: List[int], ownership_data: Dict) -> Dict:
        """Update ownership for multiple certificates."""
        session = self.db_manager.get_session()
        try:
            updated_count = 0
            failed_updates = []

            for cert_id in cert_ids:
                try:
                    # Get or create ownership record
                    ownership = session.query(CertificateOwnership).filter_by(
                        certificate_id=cert_id
                    ).first()

                    if not ownership:
                        # Verify certificate exists first
                        cert_exists = session.query(Certificate).filter(
                            Certificate.id == cert_id,
                            Certificate.is_active == True
                        ).first()

                        if not cert_exists:
                            failed_updates.append(f"Certificate ID {cert_id}: not found")
                            continue

                        ownership = CertificateOwnership(certificate_id=cert_id)
                        session.add(ownership)

                    # Update ownership fields
                    for field, value in ownership_data.items():
                        if hasattr(ownership, field) and value is not None:
                            setattr(ownership, field, value)

                    ownership.updated_at = datetime.utcnow()
                    updated_count += 1

                except Exception as e:
                    failed_updates.append(f"Certificate ID {cert_id}: {str(e)}")

            session.commit()

            return {
                'success': True,
                'updated_count': updated_count,
                'failed_updates': failed_updates,
                'total_requested': len(cert_ids)
            }

        except Exception as e:
            session.rollback()
            return {
                'success': False,
                'error': f'Bulk update failed: {str(e)}'
            }
        finally:
            session.close()

    def bulk_revoke_certificates(self, cert_ids: List[int], reason: str = "bulk revocation") -> Dict:
        """Revoke multiple certificates."""
        session = self.db_manager.get_session()
        try:
            revoked_count = 0
            failed_revocations = []

            for cert_id in cert_ids:
                try:
                    certificate = session.query(Certificate).filter(Certificate.id == cert_id).first()

                    if not certificate:
                        failed_revocations.append(f"Certificate ID {cert_id}: not found")
                        continue

                    if not certificate.is_active:
                        failed_revocations.append(f"Certificate ID {cert_id}: already revoked")
                        continue

                    # Mark as inactive
                    certificate.is_active = False
                    certificate.updated_at = datetime.utcnow()

                    # Update ownership description
                    if certificate.ownership:
                        ownership = certificate.ownership[0]
                        current_desc = ownership.description or ""
                        ownership.description = f"{current_desc}\nBULK REVOKED: {reason} on {datetime.utcnow().isoformat()}"
                        ownership.updated_at = datetime.utcnow()

                    revoked_count += 1

                except Exception as e:
                    failed_revocations.append(f"Certificate ID {cert_id}: {str(e)}")

            session.commit()

            return {
                'success': True,
                'revoked_count': revoked_count,
                'failed_revocations': failed_revocations,
                'total_requested': len(cert_ids),
                'reason': reason
            }

        except Exception as e:
            session.rollback()
            return {
                'success': False,
                'error': f'Bulk revocation failed: {str(e)}'
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

    def scan_pkcs11_certificates(self) -> Dict:
        """Scan PKCS11 tokens for certificates (experimental)."""
        if not self.config.get('pkcs11', {}).get('enabled', False):
            return {
                'success': False,
                'error': 'PKCS11 support not enabled in configuration'
            }

        try:
            pkcs11_certs = self.parser.list_pkcs11_certificates()

            session = self.db_manager.get_session()
            try:
                stored_count = 0
                for cert_data in pkcs11_certs:
                    result = self._store_certificate(session, cert_data, update_ownership=False)
                    if result == "inserted":
                        stored_count += 1

                session.commit()

                return {
                    'success': True,
                    'certificates_found': len(pkcs11_certs),
                    'certificates_stored': stored_count,
                    'message': f'EXPERIMENTAL: Scanned PKCS11 token and found {len(pkcs11_certs)} certificates',
                    'warning': 'PKCS11 support is experimental - verify results carefully'
                }

            finally:
                session.close()

        except Exception as e:
            return {
                'success': False,
                'error': f'PKCS11 scan failed: {str(e)}'
            }

    def export_certificate_modern_format(self, cert_id: int, format_type: str = 'pkcs10_pem') -> Dict:
        """Export certificate in modern format (default PKCS#10)."""
        session = self.db_manager.get_session()
        try:
            certificate = session.query(Certificate).filter(Certificate.id == cert_id).first()

            if not certificate:
                return {
                    'success': False,
                    'error': 'Certificate not found'
                }

            # Build certificate data for export
            cert_data = {
                'id': certificate.id,
                'common_name': certificate.common_name,
                'serial_number': certificate.serial_number,
                'format': getattr(certificate, 'format', 'unknown'),
                'subject_info': certificate.subject_info,
                'issuer_info': certificate.issuer_info,
                'not_valid_before': certificate.not_valid_before.isoformat(),
                'not_valid_after': certificate.not_valid_after.isoformat()
            }

            # Export using parser
            try:
                export_format = CertificateFormat.PKCS10_PEM
                if format_type == 'pkcs10_der':
                    export_format = CertificateFormat.PKCS10_DER

                exported_data = self.parser.export_certificate(cert_data, export_format)

                return {
                    'success': True,
                    'export_format': format_type,
                    'exported_data': exported_data.decode('utf-8') if isinstance(exported_data, bytes) else exported_data,
                    'filename': f"{certificate.common_name.replace('*', 'wildcard')}_{format_type}.{format_type.split('_')[1]}",
                    'message': f'Certificate exported in {format_type} format'
                }

            except Exception as e:
                return {
                    'success': False,
                    'error': f'Export failed: {str(e)}'
                }

        finally:
            session.close()

    def get_supported_formats(self) -> Dict:
        """Get information about supported certificate formats."""
        formats = self.parser.get_supported_formats()

        # Add configuration info
        config_info = {
            'pkcs11_enabled': self.config.get('pkcs11', {}).get('enabled', False),
            'pkcs11_experimental': True,
            'pvk_import_only': True,
            'default_export_format': self.config.get('certificate_formats', {}).get('default_export_format', 'pkcs10_pem'),
            'legacy_conversion_recommended': self.config.get('legacy_formats', {}).get('legacy_conversion_recommended', True)
        }

        return {
            'success': True,
            'supported_formats': formats,
            'configuration': config_info,
            'notes': {
                'pkcs11': 'EXPERIMENTAL - Requires PyKCS11 library and proper hardware token setup',
                'pvk': 'LEGACY - Import only, exports converted to modern PKCS#10 format',
                'export_default': 'All exports default to PKCS#10 PEM format for modern compatibility'
            }
        }
