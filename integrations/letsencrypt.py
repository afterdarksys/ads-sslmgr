"""
Let's Encrypt integration for automatic certificate renewal
"""

import os
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from database.models import Certificate, RenewalAttempt, DatabaseManager
from providers.config import ProviderConfig


class LetsEncryptIntegration:
    """Handle Let's Encrypt certificate operations."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.le_config = config.get('certificate_authorities', {}).get('letsencrypt', {})
        resolved = ProviderConfig(config)

        self.enabled = resolved.ca('letsencrypt', 'enabled', False)
        self.staging = resolved.ca('letsencrypt', 'staging', False)
        self.email = resolved.ca('letsencrypt', 'email', '')
        
        # Certbot configuration
        self.certbot_cmd = resolved.ca('letsencrypt', 'certbot_cmd', 'certbot')
        self.config_dir = Path(resolved.ca('letsencrypt', 'config_dir', Path.home() / '.config' / 'letsencrypt'))
        self.work_dir = Path(resolved.ca('letsencrypt', 'work_dir', Path.home() / '.local' / 'share' / 'letsencrypt'))
        self.logs_dir = Path(resolved.ca('letsencrypt', 'logs_dir', Path.home() / '.local' / 'share' / 'letsencrypt' / 'logs'))
        self.dns_provider = resolved.ca('letsencrypt', 'dns_provider', '')
        self.certbot_plugin = resolved.ca('letsencrypt', 'certbot_plugin', '')
        self.certbot_plugin_options = resolved.ca('letsencrypt', 'certbot_plugin_options', {})
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def issue_certificate(self, domains: List[str], challenge_type: str = 'http') -> Dict:
        """Issue a new certificate without requiring an inventory DB record."""
        if not self.enabled:
            return {'success': False, 'error': "Let's Encrypt integration is disabled"}
        if not domains:
            return {'success': False, 'error': 'At least one domain is required'}
        if challenge_type == 'http':
            return self._renew_http_challenge(domains)
        if challenge_type == 'dns':
            return self._renew_dns_challenge(domains)
        return {'success': False, 'error': 'Unsupported challenge type: {}'.format(challenge_type)}
    
    def renew_certificate(self, cert: Certificate, domains: List[str] = None, 
                         challenge_type: str = 'http') -> Dict:
        """
        Renew a certificate using Let's Encrypt.
        
        Args:
            cert: Certificate object to renew
            domains: List of domains to include in certificate
            challenge_type: Challenge type (http, dns, manual)
            
        Returns:
            Dictionary with renewal results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'Let\'s Encrypt integration is disabled'
            }
        
        session = self.db_manager.get_session()
        
        # Create renewal attempt record
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='letsencrypt',
            renewal_method='automated',
            status='pending'
        )
        session.add(attempt)
        session.commit()
        
        try:
            # Determine domains to renew
            if not domains:
                domains = self._extract_domains_from_cert(cert)
            
            if not domains:
                raise ValueError("No domains found for certificate renewal")
            
            # Perform renewal based on challenge type
            if challenge_type == 'http':
                result = self._renew_http_challenge(domains)
            elif challenge_type == 'dns':
                result = self._renew_dns_challenge(domains)
            elif challenge_type == 'manual':
                result = self._renew_manual_challenge(domains)
            else:
                raise ValueError(f"Unsupported challenge type: {challenge_type}")
            
            # Update renewal attempt
            if result['success']:
                attempt.status = 'success'
                attempt.new_certificate_path = result.get('cert_path', '')
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
    
    def _renew_http_challenge(self, domains: List[str]) -> Dict:
        """Renew certificate using HTTP-01 challenge."""
        try:
            cmd = self._build_certbot_command(domains, 'http')
            
            # Execute certbot
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Find the certificate files
                cert_path = self._find_certificate_path(domains[0])
                expiry_date = self._get_certificate_expiry(cert_path)
                
                return {
                    'success': True,
                    'cert_path': cert_path,
                    'expiry_date': expiry_date,
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'output': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Certbot command timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _renew_dns_challenge(self, domains: List[str]) -> Dict:
        """Renew certificate using DNS-01 challenge."""
        try:
            cmd = self._build_certbot_command(domains, 'dns')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                cert_path = self._find_certificate_path(domains[0])
                expiry_date = self._get_certificate_expiry(cert_path)
                
                return {
                    'success': True,
                    'cert_path': cert_path,
                    'expiry_date': expiry_date,
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'output': result.stdout
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _renew_manual_challenge(self, domains: List[str]) -> Dict:
        """Renew certificate using manual challenge (requires user interaction)."""
        return {
            'success': False,
            'error': 'Manual challenge renewal requires interactive mode'
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
                domain = san[4:] if san.startswith('DNS:') else san
                if domain and domain not in domains:
                    domains.append(domain)
        
        return domains
    
    def _find_certificate_path(self, domain: str) -> str:
        """Find the path to the renewed certificate."""
        cert_dir = self.config_dir / 'live' / domain
        cert_file = cert_dir / 'fullchain.pem'
        
        if cert_file.exists():
            return str(cert_file)
        
        return ""
    
    def _get_certificate_expiry(self, cert_path: str) -> Optional[datetime]:
        """Get expiry date of a certificate file."""
        if not cert_path or not Path(cert_path).exists():
            return None
        
        try:
            from cryptography import x509
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data)
            return cert.not_valid_after
            
        except Exception:
            return None
    
    def _build_certbot_command(self, domains: List[str], challenge_type: str) -> List[str]:
        if not self.email:
            raise ValueError("Let's Encrypt email is required")
        command = [self.certbot_cmd, 'certonly']
        if challenge_type == 'http':
            command.append('--standalone')
        elif challenge_type == 'dns' and self.certbot_plugin:
            command.extend(['--authenticator', self.certbot_plugin])
            for name, value in sorted(self.certbot_plugin_options.items()):
                command.extend(['--' + name.replace('_', '-'), str(value)])
        elif challenge_type == 'dns':
            if self.dns_provider not in ('cloudflare', 'bunny'):
                raise ValueError("dns_provider must be cloudflare, bunny, or a certbot_plugin")
            provider_config = self.config_dir / 'dns_provider.json'
            resolver = ProviderConfig(self.config)
            keys = ('enabled', 'api_token', 'api_key', 'zone_id', 'zone_name', 'ttl', 'timeout', 'base_url')
            dns_config = {
                key: resolver.dns(self.dns_provider, key)
                for key in keys if resolver.dns(self.dns_provider, key) is not None
            }
            provider_config.write_text(json.dumps({'dns_providers': {self.dns_provider: dns_config}}))
            provider_config.chmod(0o600)
            state_dir = self.config_dir / 'dns-hook-state'
            state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            base = [
                sys.executable, '-m', 'providers.dns.hook',
                '--provider', self.dns_provider,
                '--config', str(provider_config),
                '--state-dir', str(state_dir),
            ]
            auth = base[:3] + ['present'] + base[3:]
            cleanup = base[:3] + ['cleanup'] + base[3:]
            command.extend([
                '--manual', '--preferred-challenges', 'dns',
                '--manual-auth-hook', ' '.join(shlex.quote(part) for part in auth),
                '--manual-cleanup-hook', ' '.join(shlex.quote(part) for part in cleanup),
            ])
        else:
            raise ValueError("Unsupported challenge type: {}".format(challenge_type))
        command.extend([
            '--non-interactive', '--agree-tos', '--email', self.email,
            '--config-dir', str(self.config_dir), '--work-dir', str(self.work_dir),
            '--logs-dir', str(self.logs_dir),
        ])
        if self.staging:
            command.append('--staging')
        for domain in domains:
            command.extend(['-d', domain])
        return command
    
    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        """Check if a certificate is eligible for Let's Encrypt renewal."""
        
        # Check if certificate was issued by Let's Encrypt
        if cert.issuer_category != 'letsencrypt':
            return {
                'eligible': False,
                'reason': 'Certificate was not issued by Let\'s Encrypt'
            }
        
        # Check if certificate is expiring soon
        days_until_expiry = cert.days_until_expiry
        if days_until_expiry > 30:
            return {
                'eligible': False,
                'reason': f'Certificate expires in {days_until_expiry} days (renewal recommended at 30 days)'
            }
        
        # Check if domains are valid
        domains = self._extract_domains_from_cert(cert)
        if not domains:
            return {
                'eligible': False,
                'reason': 'No valid domains found in certificate'
            }
        
        return {
            'eligible': True,
            'domains': domains,
            'days_until_expiry': days_until_expiry
        }
    
    def get_account_info(self) -> Dict:
        """Get Let's Encrypt account information."""
        try:
            cmd = [
                self.certbot_cmd, 'show_account',
                '--config-dir', str(self.config_dir)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'account_info': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_certificates(self) -> Dict:
        """List all Let's Encrypt certificates."""
        try:
            cmd = [
                self.certbot_cmd, 'certificates',
                '--config-dir', str(self.config_dir)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'certificates': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def test_configuration(self) -> Dict:
        """Test Let's Encrypt configuration."""
        tests = {
            'certbot_available': False,
            'email_configured': False,
            'directories_writable': False,
            'staging_mode': self.staging
        }
        
        errors = []
        
        executable = self.certbot_cmd if os.path.isabs(self.certbot_cmd) else shutil.which(self.certbot_cmd)
        if executable and (not os.path.isabs(executable) or Path(executable).exists()):
            tests['certbot_available'] = True
        else:
            errors.append("certbot executable not found")
        
        # Test email configuration
        if self.email:
            tests['email_configured'] = True
        else:
            errors.append("email not configured")
        
        # Test directory permissions
        try:
            test_file = self.config_dir / 'test_write'
            test_file.touch()
            test_file.unlink()
            tests['directories_writable'] = True
        except Exception as e:
            errors.append(f"Directory not writable: {e}")
        
        return {
            'enabled': self.enabled,
            'tests': tests,
            'errors': errors,
            'all_tests_passed': len(errors) == 0
        }
