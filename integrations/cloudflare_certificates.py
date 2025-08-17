"""
Cloudflare API integration for certificate management
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from database.models import Certificate, RenewalAttempt, DatabaseManager


class CloudflareIntegration:
    """Handle Cloudflare API operations for certificate management."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.cf_config = config.get('cloud_providers', {}).get('cloudflare', {})
        
        self.enabled = self.cf_config.get('enabled', False)
        self.api_token = self.cf_config.get('api_token', '')
        self.zone_id = self.cf_config.get('zone_id', '')
        
        # API configuration
        self.base_url = 'https://api.cloudflare.com/client/v4'
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
    
    def renew_certificate(self, cert: Certificate, domains: List[str] = None) -> Dict:
        """
        Renew/order a certificate using Cloudflare API.
        
        Args:
            cert: Certificate object to renew
            domains: List of domains to include in certificate
            
        Returns:
            Dictionary with renewal results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'Cloudflare integration is disabled'
            }
        
        if not self.api_token:
            return {
                'success': False,
                'error': 'Cloudflare API token not configured'
            }
        
        session = self.db_manager.get_session()
        
        # Create renewal attempt record
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='cloudflare',
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
            
            # Order new certificate
            result = self._order_certificate(domains)
            
            if result['success']:
                attempt.status = 'success'
                attempt.new_certificate_path = f"Cloudflare Certificate ID: {result['certificate_id']}"
                attempt.new_expiry_date = result.get('expiry_date')
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
    
    def _order_certificate(self, hostnames: List[str]) -> Dict:
        """Order a new certificate from Cloudflare."""
        try:
            url = f"{self.base_url}/certificates"
            
            # Prepare certificate order data
            order_data = {
                'type': 'origin-rsa',
                'hostnames': hostnames,
                'requested_validity': 365,  # Days
                'csr': self._generate_csr(hostnames[0], hostnames[1:])
            }
            
            response = requests.post(url, headers=self.headers, json=order_data)
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    result = data['result']
                    return {
                        'success': True,
                        'certificate_id': result['id'],
                        'certificate': result['certificate'],
                        'private_key': result['private_key'],
                        'expiry_date': datetime.fromisoformat(result['expires_on'].replace('Z', '+00:00')),
                        'message': 'Certificate ordered successfully'
                    }
                else:
                    return {
                        'success': False,
                        'error': f"API errors: {data.get('errors', [])}"
                    }
            else:
                return {
                    'success': False,
                    'error': f'Certificate order failed: {response.status_code} - {response.text}'
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
        """List all Cloudflare certificates."""
        try:
            url = f"{self.base_url}/certificates"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    return {
                        'success': True,
                        'certificates': data['result']
                    }
                else:
                    return {
                        'success': False,
                        'error': f"API errors: {data.get('errors', [])}"
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
    
    def get_certificate_details(self, certificate_id: str) -> Dict:
        """Get details of a specific certificate."""
        try:
            url = f"{self.base_url}/certificates/{certificate_id}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    return {
                        'success': True,
                        'certificate': data['result']
                    }
                else:
                    return {
                        'success': False,
                        'error': f"API errors: {data.get('errors', [])}"
                    }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get certificate: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def revoke_certificate(self, certificate_id: str) -> Dict:
        """Revoke a certificate."""
        try:
            url = f"{self.base_url}/certificates/{certificate_id}"
            response = requests.delete(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    return {
                        'success': True,
                        'message': 'Certificate revoked successfully'
                    }
                else:
                    return {
                        'success': False,
                        'error': f"API errors: {data.get('errors', [])}"
                    }
            else:
                return {
                    'success': False,
                    'error': f'Failed to revoke certificate: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_zone_info(self) -> Dict:
        """Get Cloudflare zone information."""
        try:
            if self.zone_id:
                url = f"{self.base_url}/zones/{self.zone_id}"
            else:
                url = f"{self.base_url}/zones"
            
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    return {
                        'success': True,
                        'zones': data['result'] if isinstance(data['result'], list) else [data['result']]
                    }
                else:
                    return {
                        'success': False,
                        'error': f"API errors: {data.get('errors', [])}"
                    }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get zone info: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        """Check if a certificate is eligible for Cloudflare renewal."""
        
        # Check if certificate was issued by Cloudflare
        if cert.issuer_category != 'cloudflare':
            return {
                'eligible': False,
                'reason': 'Certificate was not issued by Cloudflare'
            }
        
        # Check API configuration
        if not self.api_token:
            return {
                'eligible': False,
                'reason': 'Cloudflare API token not configured'
            }
        
        # Extract domains
        domains = self._extract_domains_from_cert(cert)
        if not domains:
            return {
                'eligible': False,
                'reason': 'No valid domains found in certificate'
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
            'domains': domains,
            'days_until_expiry': days_until_expiry
        }
    
    def test_configuration(self) -> Dict:
        """Test Cloudflare API configuration."""
        tests = {
            'api_token_configured': bool(self.api_token),
            'api_accessible': False,
            'zone_accessible': False
        }
        
        errors = []
        
        if not self.api_token:
            errors.append("Cloudflare API token not configured")
        
        if self.api_token:
            # Test API access
            try:
                url = f"{self.base_url}/user/tokens/verify"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data['success']:
                        tests['api_accessible'] = True
                    else:
                        errors.append(f"Token verification failed: {data.get('errors', [])}")
                elif response.status_code == 401:
                    errors.append("Invalid API token")
                else:
                    errors.append(f"API test failed: {response.status_code}")
                    
            except Exception as e:
                errors.append(f"API connection failed: {e}")
            
            # Test zone access if zone_id is configured
            if self.zone_id and tests['api_accessible']:
                try:
                    zone_info = self.get_zone_info()
                    if zone_info['success']:
                        tests['zone_accessible'] = True
                    else:
                        errors.append(f"Zone access failed: {zone_info['error']}")
                except Exception as e:
                    errors.append(f"Zone test failed: {e}")
        
        return {
            'enabled': self.enabled,
            'tests': tests,
            'errors': errors,
            'all_tests_passed': len(errors) == 0
        }
