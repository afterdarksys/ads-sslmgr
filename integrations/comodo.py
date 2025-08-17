"""
Comodo/Sectigo API integration for certificate management
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from database.models import Certificate, RenewalAttempt, DatabaseManager


class ComodoIntegration:
    """Handle Comodo/Sectigo API operations for certificate management."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.comodo_config = config.get('certificate_authorities', {}).get('comodo', {})
        
        self.enabled = self.comodo_config.get('enabled', False)
        self.api_key = self.comodo_config.get('api_key', '')
        self.customer_uri = self.comodo_config.get('customer_uri', '')
        
        # API configuration
        self.base_url = 'https://hard.cert-manager.com/api'
        self.headers = {
            'Content-Type': 'application/json',
            'customerUri': self.customer_uri
        }
    
    def renew_certificate(self, cert: Certificate, domains: List[str] = None) -> Dict:
        """
        Renew a certificate using Comodo API.
        
        Args:
            cert: Certificate object to renew
            domains: List of domains to include in certificate
            
        Returns:
            Dictionary with renewal results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'Comodo integration is disabled'
            }
        
        if not self.api_key or not self.customer_uri:
            return {
                'success': False,
                'error': 'Comodo API credentials not configured'
            }
        
        session = self.db_manager.get_session()
        
        # Create renewal attempt record
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='comodo',
            renewal_method='api',
            status='pending'
        )
        session.add(attempt)
        session.commit()
        
        try:
            # Find the original certificate in Comodo
            cert_info = self._find_certificate(cert)
            if not cert_info['success']:
                raise Exception(f"Could not find Comodo certificate: {cert_info['error']}")
            
            # Renew the certificate
            renewal_result = self._renew_certificate_api(cert_info['certificate_id'], domains)
            
            if renewal_result['success']:
                attempt.status = 'success'
                attempt.new_certificate_path = renewal_result.get('certificate_path', '')
                attempt.new_expiry_date = renewal_result.get('expiry_date')
            else:
                attempt.status = 'failed'
                attempt.error_message = renewal_result.get('error', 'Unknown error')
            
            session.commit()
            return renewal_result
            
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
    
    def _find_certificate(self, cert: Certificate) -> Dict:
        """Find the Comodo certificate ID by serial number."""
        try:
            url = f"{self.base_url}/ssl/v1/list"
            params = {
                'customerUri': self.customer_uri,
                'serialNumber': cert.serial_number
            }
            
            response = requests.get(url, headers=self.headers, params=params, 
                                  auth=(self.api_key, ''))
            
            if response.status_code == 200:
                data = response.json()
                certificates = data.get('certificates', [])
                
                if certificates:
                    return {
                        'success': True,
                        'certificate_id': certificates[0]['id'],
                        'certificate_data': certificates[0]
                    }
                else:
                    return {
                        'success': False,
                        'error': 'No matching certificates found'
                    }
            else:
                return {
                    'success': False,
                    'error': f'API request failed: {response.status_code} - {response.text}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _renew_certificate_api(self, certificate_id: str, domains: List[str] = None) -> Dict:
        """Renew certificate using Comodo API."""
        try:
            url = f"{self.base_url}/ssl/v1/renew"
            
            # Get original certificate details
            cert_details = self._get_certificate_details(certificate_id)
            if not cert_details['success']:
                return cert_details
            
            original_cert = cert_details['certificate']
            
            # Prepare renewal data
            renewal_data = {
                'customerUri': self.customer_uri,
                'certificateId': certificate_id,
                'csr': self._generate_csr(original_cert['commonName'], domains or []),
                'term': original_cert.get('term', 365),  # Certificate validity period
                'serverType': original_cert.get('serverType', -1),  # Server type ID
                'comments': f'Automated renewal - {datetime.utcnow().isoformat()}'
            }
            
            response = requests.post(url, headers=self.headers, json=renewal_data,
                                   auth=(self.api_key, ''))
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'renewal_id': data.get('renewalId'),
                    'message': 'Certificate renewal initiated'
                }
            else:
                return {
                    'success': False,
                    'error': f'Renewal failed: {response.status_code} - {response.text}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_certificate_details(self, certificate_id: str) -> Dict:
        """Get details of a Comodo certificate."""
        try:
            url = f"{self.base_url}/ssl/v1/{certificate_id}"
            params = {'customerUri': self.customer_uri}
            
            response = requests.get(url, headers=self.headers, params=params,
                                  auth=(self.api_key, ''))
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'certificate': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get certificate details: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_csr(self, common_name: str, san_domains: List[str]) -> str:
        """Generate a Certificate Signing Request."""
        # This is a placeholder - in production you'd generate a proper CSR
        # using cryptography library with private key generation
        return f"-----BEGIN CERTIFICATE REQUEST-----\n[CSR for {common_name}]\n-----END CERTIFICATE REQUEST-----"
    
    def list_certificates(self, limit: int = 100) -> Dict:
        """List Comodo certificates."""
        try:
            url = f"{self.base_url}/ssl/v1/list"
            params = {
                'customerUri': self.customer_uri,
                'size': limit
            }
            
            response = requests.get(url, headers=self.headers, params=params,
                                  auth=(self.api_key, ''))
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'certificates': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to list certificates: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_account_info(self) -> Dict:
        """Get Comodo account information."""
        try:
            url = f"{self.base_url}/account/v1/info"
            params = {'customerUri': self.customer_uri}
            
            response = requests.get(url, headers=self.headers, params=params,
                                  auth=(self.api_key, ''))
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'account': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get account info: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def download_certificate(self, certificate_id: str, format_type: str = 'x509') -> Dict:
        """Download certificate in specified format."""
        try:
            url = f"{self.base_url}/ssl/v1/collect/{certificate_id}/{format_type}"
            params = {'customerUri': self.customer_uri}
            
            response = requests.get(url, headers=self.headers, params=params,
                                  auth=(self.api_key, ''))
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'certificate_data': response.text,
                    'format': format_type
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to download certificate: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        """Check if a certificate is eligible for Comodo renewal."""
        
        # Check if certificate was issued by Comodo
        if cert.issuer_category not in ['comodo', 'sectigo']:
            return {
                'eligible': False,
                'reason': 'Certificate was not issued by Comodo/Sectigo'
            }
        
        # Check API configuration
        if not self.api_key or not self.customer_uri:
            return {
                'eligible': False,
                'reason': 'Comodo API credentials not configured'
            }
        
        # Check if certificate is expiring soon
        days_until_expiry = cert.days_until_expiry
        if days_until_expiry > 90:
            return {
                'eligible': False,
                'reason': f'Certificate expires in {days_until_expiry} days (renewal recommended at 90 days)'
            }
        
        return {
            'eligible': True,
            'days_until_expiry': days_until_expiry,
            'serial_number': cert.serial_number
        }
    
    def test_configuration(self) -> Dict:
        """Test Comodo API configuration."""
        tests = {
            'api_key_configured': bool(self.api_key),
            'customer_uri_configured': bool(self.customer_uri),
            'api_accessible': False,
            'account_valid': False
        }
        
        errors = []
        
        if not self.api_key:
            errors.append("Comodo API key not configured")
        
        if not self.customer_uri:
            errors.append("Comodo customer URI not configured")
        
        if self.api_key and self.customer_uri:
            # Test API access
            try:
                account_info = self.get_account_info()
                
                if account_info['success']:
                    tests['api_accessible'] = True
                    tests['account_valid'] = True
                else:
                    tests['api_accessible'] = True
                    errors.append(f"Account validation failed: {account_info['error']}")
                    
            except Exception as e:
                errors.append(f"API connection failed: {e}")
        
        return {
            'enabled': self.enabled,
            'tests': tests,
            'errors': errors,
            'all_tests_passed': len(errors) == 0
        }
