"""
OpenSSL Helper
Utilities for OpenSSL operations and certificate manipulation
Wraps common OpenSSL commands with Python interface
"""

import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple


class OpenSSLHelper:
    """Helper class for OpenSSL operations"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.openssl_path = 'openssl'  # Assumes openssl is in PATH

    def verify_certificate(self, cert_path: str, ca_bundle_path: str = None) -> Dict:
        """
        Verify certificate using OpenSSL

        Args:
            cert_path: Path to certificate file
            ca_bundle_path: Optional path to CA bundle

        Returns:
            Verification result
        """
        cmd = [self.openssl_path, 'verify']

        if ca_bundle_path:
            cmd.extend(['-CAfile', ca_bundle_path])

        cmd.append(cert_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Verification timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def check_private_key_match(self, cert_path: str, key_path: str) -> bool:
        """
        Check if private key matches certificate

        Args:
            cert_path: Path to certificate file
            key_path: Path to private key file

        Returns:
            True if key matches certificate
        """
        try:
            # Get certificate modulus
            cert_cmd = [self.openssl_path, 'x509', '-noout', '-modulus', '-in', cert_path]
            cert_result = subprocess.run(cert_cmd, capture_output=True, text=True, timeout=10)

            if cert_result.returncode != 0:
                return False

            cert_modulus = cert_result.stdout.strip()

            # Get key modulus
            key_cmd = [self.openssl_path, 'rsa', '-noout', '-modulus', '-in', key_path]
            key_result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=10)

            if key_result.returncode != 0:
                return False

            key_modulus = key_result.stdout.strip()

            # Compare moduli
            return cert_modulus == key_modulus

        except Exception as e:
            self.logger.error(f"Error checking key match: {e}")
            return False

    def convert_format(self, input_path: str, input_format: str,
                      output_path: str, output_format: str,
                      password: str = None) -> bool:
        """
        Convert certificate between formats

        Args:
            input_path: Input file path
            input_format: Input format (pem, der, pkcs12)
            output_path: Output file path
            output_format: Output format (pem, der, pkcs12)
            password: Optional password for encrypted formats

        Returns:
            True if conversion successful
        """
        try:
            cmd = [self.openssl_path]

            # Determine conversion command
            if input_format == 'pkcs12':
                cmd.append('pkcs12')
                cmd.extend(['-in', input_path])

                if password:
                    cmd.extend(['-passin', f'pass:{password}'])
                else:
                    cmd.extend(['-passin', 'pass:'])

                if output_format == 'pem':
                    cmd.extend(['-out', output_path, '-nodes'])
                elif output_format == 'der':
                    cmd.extend(['-out', output_path, '-outform', 'DER'])

            elif input_format == 'der' and output_format == 'pem':
                cmd.extend(['x509', '-inform', 'DER', '-in', input_path,
                           '-out', output_path, '-outform', 'PEM'])

            elif input_format == 'pem' and output_format == 'der':
                cmd.extend(['x509', '-inform', 'PEM', '-in', input_path,
                           '-out', output_path, '-outform', 'DER'])

            else:
                self.logger.error(f"Unsupported conversion: {input_format} to {output_format}")
                return False

            result = subprocess.run(cmd, capture_output=True, timeout=30)

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f"Error converting format: {e}")
            return False

    def extract_from_pkcs12(self, pkcs12_path: str, password: str = None) -> Dict:
        """
        Extract certificate and key from PKCS#12 file

        Args:
            pkcs12_path: Path to PKCS#12 file
            password: Password for PKCS#12 file

        Returns:
            Dictionary with cert_path and key_path
        """
        try:
            # Create temp files for output
            cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)

            cert_path = cert_file.name
            key_path = key_file.name

            cert_file.close()
            key_file.close()

            # Extract certificate
            cert_cmd = [
                self.openssl_path, 'pkcs12',
                '-in', pkcs12_path,
                '-clcerts', '-nokeys',
                '-out', cert_path
            ]

            if password:
                cert_cmd.extend(['-passin', f'pass:{password}'])
            else:
                cert_cmd.extend(['-passin', 'pass:'])

            cert_result = subprocess.run(cert_cmd, capture_output=True, timeout=30)

            if cert_result.returncode != 0:
                return {
                    'success': False,
                    'error': 'Failed to extract certificate'
                }

            # Extract private key
            key_cmd = [
                self.openssl_path, 'pkcs12',
                '-in', pkcs12_path,
                '-nocerts', '-nodes',
                '-out', key_path
            ]

            if password:
                key_cmd.extend(['-passin', f'pass:{password}'])
            else:
                key_cmd.extend(['-passin', 'pass:'])

            key_result = subprocess.run(key_cmd, capture_output=True, timeout=30)

            if key_result.returncode != 0:
                return {
                    'success': False,
                    'error': 'Failed to extract private key'
                }

            return {
                'success': True,
                'cert_path': cert_path,
                'key_path': key_path
            }

        except Exception as e:
            self.logger.error(f"Error extracting from PKCS#12: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_csr(self, key_path: str, subject: Dict, output_path: str) -> bool:
        """
        Create Certificate Signing Request

        Args:
            key_path: Path to private key
            subject: Subject dictionary with fields (C, ST, L, O, OU, CN)
            output_path: Output CSR path

        Returns:
            True if CSR created successfully
        """
        try:
            # Build subject string
            subject_parts = []
            if 'C' in subject:
                subject_parts.append(f"/C={subject['C']}")
            if 'ST' in subject:
                subject_parts.append(f"/ST={subject['ST']}")
            if 'L' in subject:
                subject_parts.append(f"/L={subject['L']}")
            if 'O' in subject:
                subject_parts.append(f"/O={subject['O']}")
            if 'OU' in subject:
                subject_parts.append(f"/OU={subject['OU']}")
            if 'CN' in subject:
                subject_parts.append(f"/CN={subject['CN']}")

            subject_str = ''.join(subject_parts)

            cmd = [
                self.openssl_path, 'req',
                '-new',
                '-key', key_path,
                '-out', output_path,
                '-subj', subject_str
            ]

            result = subprocess.run(cmd, capture_output=True, timeout=30)

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f"Error creating CSR: {e}")
            return False

    def test_ssl_connection(self, hostname: str, port: int = 443) -> Dict:
        """
        Test SSL/TLS connection to server

        Args:
            hostname: Server hostname
            port: Server port (default 443)

        Returns:
            Connection test result
        """
        try:
            cmd = [
                self.openssl_path, 's_client',
                '-connect', f'{hostname}:{port}',
                '-servername', hostname,
                '-showcerts'
            ]

            # Send EOF to exit s_client
            result = subprocess.run(
                cmd,
                input='',
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout + result.stderr

            # Parse output for connection status
            success = 'Verify return code: 0' in output

            return {
                'success': success,
                'output': output,
                'connected': 'CONNECTED' in output
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Connection timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_certificate_fingerprint(self, cert_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Get certificate fingerprint

        Args:
            cert_path: Path to certificate
            algorithm: Hash algorithm (md5, sha1, sha256)

        Returns:
            Fingerprint string or None
        """
        try:
            cmd = [
                self.openssl_path, 'x509',
                '-noout',
                '-fingerprint',
                f'-{algorithm}',
                '-in', cert_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Parse output: "SHA256 Fingerprint=XX:XX:XX..."
                output = result.stdout.strip()
                if '=' in output:
                    return output.split('=')[1].strip()

            return None

        except Exception as e:
            self.logger.error(f"Error getting fingerprint: {e}")
            return None

    def check_openssl_version(self) -> Dict:
        """Get OpenSSL version information"""
        try:
            cmd = [self.openssl_path, 'version', '-a']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            return {
                'success': True,
                'version': result.stdout,
                'available': True
            }

        except FileNotFoundError:
            return {
                'success': False,
                'error': 'OpenSSL not found in PATH',
                'available': False
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'available': False
            }


def main():
    """CLI interface for OpenSSL helper"""
    import argparse

    parser = argparse.ArgumentParser(description='OpenSSL Helper Utility')
    parser.add_argument('--verify', help='Verify certificate')
    parser.add_argument('--ca-bundle', help='CA bundle for verification')
    parser.add_argument('--check-match', nargs=2, metavar=('CERT', 'KEY'),
                       help='Check if certificate and key match')
    parser.add_argument('--test-connection', help='Test SSL connection to host')
    parser.add_argument('--port', type=int, default=443, help='Port for connection test')
    parser.add_argument('--version', action='store_true', help='Show OpenSSL version')

    args = parser.parse_args()

    helper = OpenSSLHelper()

    if args.version:
        result = helper.check_openssl_version()
        print(result['version'] if result['success'] else result['error'])

    elif args.verify:
        result = helper.verify_certificate(args.verify, args.ca_bundle)
        print("✓ Certificate valid" if result['success'] else f"✗ {result['error']}")

    elif args.check_match:
        match = helper.check_private_key_match(args.check_match[0], args.check_match[1])
        print("✓ Key matches certificate" if match else "✗ Key does not match certificate")

    elif args.test_connection:
        result = helper.test_ssl_connection(args.test_connection, args.port)
        print("✓ Connection successful" if result['success'] else f"✗ {result['error']}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
