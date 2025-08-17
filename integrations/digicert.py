"""
DigiCert API integration for certificate management
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from database.models import Certificate, RenewalAttempt, DatabaseManager


class DigiCertIntegration:
    """Handle DigiCert API operations for certificate management."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.dc_config = config.get('certificate_authorities', {}).get('digicert', {})
        
        self.enabled = self.dc_config.get('enabled', False)
        self.api_key = self.dc_config.get('api_key', '')
        self.organization_id = self.dc_config.get('organization_id', '')
        
        # API configuration
        self.base_url = 'https://www.digicert.com/services/v2'
        self.headers = {
            'X-DC-DEVKEY': self.api_key,
            'Content-Type': 'application/json'
        }
    
    def renew_certificate(self, cert: Certificate, domains: List[str] = None) -> Dict:
        """
        Renew a certificate using DigiCert API.
        
        Args:
            cert: Certificate object to renew
            domains: List of domains to include in certificate
            
        Returns:
            Dictionary with renewal results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'DigiCert integration is disabled'
            }
        
        if not self.api_key:
            return {
                'success': False,
                'error': 'DigiCert API key not configured'
            }
        
        session = self.db_manager.get_session()
        
        # Create renewal attempt record
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='digicert',
            renewal_method='api',
            status='pending'
        )
        session.add(attempt)
        session.commit()
        
        try:
            # Find the original DigiCert order
            order_info = self._find_certificate_order(cert)
            if not order_info['success']:
                raise Exception(f"Could not find DigiCert order: {order_info['error']}")
            
            order_id = order_info['order_id']
            
            # Duplicate the order for renewal
            renewal_result = self._duplicate_order(order_id, domains)
            
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
    
    def _find_certificate_order(self, cert: Certificate) -> Dict:
        """Find the DigiCert order ID for a certificate."""
        try:
            # Search for orders by serial number
            url = f"{self.base_url}/order/certificate"
            params = {
                'filters[serial_number]': cert.serial_number
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                orders = data.get('orders', [])
                
                if orders:
                    order_id = orders[0]['id']
                    return {
                        'success': True,
                        'order_id': order_id,
                        'order_data': orders[0]
                    }
                else:
                    return {
                        'success': False,
                        'error': 'No matching orders found'
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
    
    def _duplicate_order(self, order_id: str, domains: List[str] = None) -> Dict:
        """Duplicate an existing DigiCert order for renewal."""
        try:
            url = f"{self.base_url}/order/{order_id}/duplicate"
            
            # Get original order details
            order_details = self._get_order_details(order_id)
            if not order_details['success']:
                return order_details
            
            original_order = order_details['order']
            
            # Prepare duplicate order data
            duplicate_data = {
                'certificate': {
                    'common_name': original_order['certificate']['common_name'],
                    'dns_names': domains or original_order['certificate'].get('dns_names', []),
                    'csr': self._generate_csr(original_order['certificate']['common_name'], domains or [])
                },
                'organization': {
                    'id': self.organization_id or original_order['organization']['id']
                },
                'validity_years': original_order.get('validity_years', 1),
                'auto_renew': original_order.get('auto_renew', 0)
            }
            
            response = requests.post(url, headers=self.headers, json=duplicate_data)
            
            if response.status_code == 201:
                data = response.json()
                new_order_id = data['id']
                
                # Wait for certificate issuance (simplified - in production you'd poll)
                return {
                    'success': True,
                    'order_id': new_order_id,
                    'message': f'Renewal order created: {new_order_id}'
                }
            else:
                return {
                    'success': False,
                    'error': f'Duplicate order failed: {response.status_code} - {response.text}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_order_details(self, order_id: str) -> Dict:
        """Get details of a DigiCert order."""
        try:
            url = f"{self.base_url}/order/{order_id}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'order': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get order details: {response.status_code}'
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
    
    def get_account_balance(self) -> Dict:
        """Get DigiCert account balance and limits."""
        try:
            url = f"{self.base_url}/account/balance"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'balance': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to get balance: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_orders(self, limit: int = 100) -> Dict:
        """List DigiCert orders."""
        try:
            url = f"{self.base_url}/order/certificate"
            params = {'limit': limit}
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'orders': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to list orders: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_certificate_details(self, certificate_id: str) -> Dict:
        """Get details of a specific certificate."""
        try:
            url = f"{self.base_url}/certificate/{certificate_id}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'certificate': response.json()
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
    
    def download_certificate(self, certificate_id: str, format_type: str = 'pem') -> Dict:
        """Download certificate in specified format."""
        try:
            url = f"{self.base_url}/certificate/{certificate_id}/download/format/{format_type}"
            response = requests.get(url, headers=self.headers)
            
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
        """Check if a certificate is eligible for DigiCert renewal."""
        
        # Check if certificate was issued by DigiCert
        if cert.issuer_category != 'digicert':
            return {
                'eligible': False,
                'reason': 'Certificate was not issued by DigiCert'
            }
        
        # Check API configuration
        if not self.api_key or not self.organization_id:
            return {
                'eligible': False,
                'reason': 'DigiCert API credentials not configured'
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
        """Test DigiCert API configuration."""
        tests = {
            'api_key_configured': bool(self.api_key),
            'organization_configured': bool(self.organization_id),
            'api_accessible': False,
            'account_valid': False
        }
        
        errors = []
        
        if not self.api_key:
            errors.append("DigiCert API key not configured")
        
        if not self.organization_id:
            errors.append("DigiCert organization ID not configured")
        
        if self.api_key:
            # Test API access
            try:
                url = f"{self.base_url}/user/me"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    tests['api_accessible'] = True
                    tests['account_valid'] = True
                elif response.status_code == 401:
                    tests['api_accessible'] = True
                    errors.append("Invalid API key")
                else:
                    errors.append(f"API test failed: {response.status_code}")
                    
            except Exception as e:
                errors.append(f"API connection failed: {e}")
        
        return {
            'enabled': self.enabled,
            'tests': tests,
            'errors': errors,
            'all_tests_passed': len(errors) == 0
        }
