"""
AWS Certificate Manager integration for certificate renewal
"""

import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError

from database.models import Certificate, RenewalAttempt, DatabaseManager


class AWSCertificateIntegration:
    """Handle AWS Certificate Manager operations."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.aws_config = config.get('cloud_providers', {}).get('aws', {})
        
        self.enabled = self.aws_config.get('enabled', False)
        self.access_key_id = self.aws_config.get('access_key_id', '')
        self.secret_access_key = self.aws_config.get('secret_access_key', '')
        self.region = self.aws_config.get('region', 'us-east-1')
        
        # Initialize AWS clients
        self.acm_client = None
        self.route53_client = None
        
        if self.enabled and self.access_key_id and self.secret_access_key:
            try:
                self.acm_client = boto3.client(
                    'acm',
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    region_name=self.region
                )
                
                self.route53_client = boto3.client(
                    'route53',
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    region_name=self.region
                )
            except Exception as e:
                print(f"AWS client initialization failed: {e}")
    
    def renew_certificate(self, cert: Certificate, domains: List[str] = None, 
                         validation_method: str = 'DNS') -> Dict:
        """
        Renew/request a new certificate in AWS ACM.
        
        Args:
            cert: Certificate object to renew
            domains: List of domains to include in certificate
            validation_method: DNS or EMAIL validation
            
        Returns:
            Dictionary with renewal results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'AWS integration is disabled'
            }
        
        if not self.acm_client:
            return {
                'success': False,
                'error': 'AWS ACM client not initialized'
            }
        
        session = self.db_manager.get_session()
        
        # Create renewal attempt record
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='aws',
            renewal_method='api',
            status='pending'
        )
        session.add(attempt)
        session.commit()
        
        try:
            # Extract domains from certificate
            if not domains:
                domains = self._extract_domains_from_cert(cert)
            
            if not domains:
                raise ValueError("No domains found for certificate renewal")
            
            # Request new certificate
            result = self._request_certificate(domains[0], domains[1:], validation_method)
            
            if result['success']:
                attempt.status = 'success'
                attempt.new_certificate_path = f"AWS ACM ARN: {result['certificate_arn']}"
                # AWS certificates are automatically renewed, so set a future expiry
                attempt.new_expiry_date = datetime.utcnow() + timedelta(days=365)
            else:
                attempt.status = 'failed'
                attempt.error_message = result.get('error', 'Unknown error')
            
            session.commit()
            return result
            
        except Exception as e:
            attempt.status = 'failed'
            attempt.error_message = str(e)
            session.commit()
            
            return {
                'success': False,
                'error': str(e)
            }
        
        finally:
            session.close()
    
    def _request_certificate(self, domain_name: str, subject_alternative_names: List[str],
                           validation_method: str) -> Dict:
        """Request a new certificate from AWS ACM."""
        try:
            request_params = {
                'DomainName': domain_name,
                'ValidationMethod': validation_method,
                'Options': {
                    'CertificateTransparencyLoggingPreference': 'ENABLED'
                }
            }
            
            if subject_alternative_names:
                request_params['SubjectAlternativeNames'] = subject_alternative_names
            
            response = self.acm_client.request_certificate(**request_params)
            
            certificate_arn = response['CertificateArn']
            
            # If DNS validation, attempt to create Route53 records
            if validation_method == 'DNS' and self.route53_client:
                dns_result = self._handle_dns_validation(certificate_arn)
                if not dns_result['success']:
                    return {
                        'success': False,
                        'error': f'Certificate requested but DNS validation failed: {dns_result["error"]}'
                    }
            
            return {
                'success': True,
                'certificate_arn': certificate_arn,
                'validation_method': validation_method,
                'message': f'Certificate requested successfully: {certificate_arn}'
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': f'AWS ACM error: {e.response["Error"]["Message"]}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _handle_dns_validation(self, certificate_arn: str) -> Dict:
        """Handle DNS validation by creating Route53 records."""
        try:
            # Get certificate validation details
            response = self.acm_client.describe_certificate(CertificateArn=certificate_arn)
            
            certificate = response['Certificate']
            domain_validations = certificate.get('DomainValidationOptions', [])
            
            created_records = []
            
            for validation in domain_validations:
                if 'ResourceRecord' in validation:
                    record = validation['ResourceRecord']
                    domain = validation['DomainName']
                    
                    # Find the hosted zone for this domain
                    hosted_zone = self._find_hosted_zone(domain)
                    if not hosted_zone:
                        continue
                    
                    # Create the validation record
                    record_result = self._create_dns_record(
                        hosted_zone['Id'],
                        record['Name'],
                        record['Type'],
                        record['Value']
                    )
                    
                    if record_result['success']:
                        created_records.append(record['Name'])
            
            if created_records:
                return {
                    'success': True,
                    'records_created': created_records
                }
            else:
                return {
                    'success': False,
                    'error': 'No DNS records could be created'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _find_hosted_zone(self, domain: str) -> Optional[Dict]:
        """Find Route53 hosted zone for a domain."""
        try:
            response = self.route53_client.list_hosted_zones()
            
            for zone in response['HostedZones']:
                zone_name = zone['Name'].rstrip('.')
                if domain.endswith(zone_name):
                    return zone
            
            return None
            
        except Exception:
            return None
    
    def _create_dns_record(self, hosted_zone_id: str, name: str, 
                          record_type: str, value: str) -> Dict:
        """Create a DNS record in Route53."""
        try:
            response = self.route53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    'Changes': [{
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': record_type,
                            'TTL': 300,
                            'ResourceRecords': [{'Value': value}]
                        }
                    }]
                }
            )
            
            return {
                'success': True,
                'change_id': response['ChangeInfo']['Id']
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidChangeBatch':
                # Record might already exist
                return {'success': True, 'message': 'Record already exists'}
            else:
                return {
                    'success': False,
                    'error': e.response['Error']['Message']
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_domains_from_cert(self, cert: Certificate) -> List[str]:
        """Extract domains from certificate for renewal."""
        domains = []
        
        # Add common name
        if cert.common_name:
            domains.append(cert.common_name)
        
        # Add subject alternative names
        if cert.subject_alt_names:
            for san in cert.subject_alt_names:
                if san.startswith('DNS:'):
                    domain = san[4:]  # Remove 'DNS:' prefix
                    if domain not in domains:
                        domains.append(domain)
        
        return domains
    
    def list_certificates(self) -> Dict:
        """List all certificates in AWS ACM."""
        if not self.acm_client:
            return {
                'success': False,
                'error': 'AWS ACM client not initialized'
            }
        
        try:
            response = self.acm_client.list_certificates()
            
            certificates = []
            for cert_summary in response['CertificateSummaryList']:
                # Get detailed certificate info
                detail_response = self.acm_client.describe_certificate(
                    CertificateArn=cert_summary['CertificateArn']
                )
                certificates.append(detail_response['Certificate'])
            
            return {
                'success': True,
                'certificates': certificates
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_certificate_details(self, certificate_arn: str) -> Dict:
        """Get details of a specific AWS certificate."""
        if not self.acm_client:
            return {
                'success': False,
                'error': 'AWS ACM client not initialized'
            }
        
        try:
            response = self.acm_client.describe_certificate(CertificateArn=certificate_arn)
            
            return {
                'success': True,
                'certificate': response['Certificate']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        """Check if a certificate is eligible for AWS renewal."""
        
        # Check if certificate was issued by AWS
        if cert.issuer_category != 'aws':
            return {
                'eligible': False,
                'reason': 'Certificate was not issued by AWS'
            }
        
        # Check AWS configuration
        if not self.access_key_id or not self.secret_access_key:
            return {
                'eligible': False,
                'reason': 'AWS credentials not configured'
            }
        
        # AWS certificates auto-renew, but we can request new ones
        domains = self._extract_domains_from_cert(cert)
        if not domains:
            return {
                'eligible': False,
                'reason': 'No valid domains found in certificate'
            }
        
        return {
            'eligible': True,
            'domains': domains,
            'note': 'AWS certificates auto-renew, but new certificate can be requested'
        }
    
    def test_configuration(self) -> Dict:
        """Test AWS configuration."""
        tests = {
            'credentials_configured': bool(self.access_key_id and self.secret_access_key),
            'acm_accessible': False,
            'route53_accessible': False
        }
        
        errors = []
        
        if not self.access_key_id or not self.secret_access_key:
            errors.append("AWS credentials not configured")
        
        if self.acm_client:
            # Test ACM access
            try:
                self.acm_client.list_certificates(MaxItems=1)
                tests['acm_accessible'] = True
            except NoCredentialsError:
                errors.append("Invalid AWS credentials")
            except ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    errors.append("AWS credentials lack ACM permissions")
                else:
                    errors.append(f"ACM access failed: {e.response['Error']['Message']}")
            except Exception as e:
                errors.append(f"ACM test failed: {e}")
        
        if self.route53_client:
            # Test Route53 access
            try:
                self.route53_client.list_hosted_zones(MaxItems='1')
                tests['route53_accessible'] = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    errors.append("AWS credentials lack Route53 permissions")
                else:
                    # Route53 access is optional
                    pass
            except Exception:
                # Route53 access is optional
                pass
        
        return {
            'enabled': self.enabled,
            'tests': tests,
            'errors': errors,
            'all_tests_passed': len(errors) == 0
        }
