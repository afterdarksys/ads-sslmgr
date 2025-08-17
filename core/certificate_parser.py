"""
SSL Certificate Parser Module
Handles parsing of PEM and P7B format certificates to extract key information.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Union
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtensionOID
import OpenSSL


class CertificateParser:
    """Parse SSL certificates and extract relevant information."""
    
    def __init__(self):
        self.supported_formats = ['.pem', '.crt', '.cer', '.p7b', '.p7c']
    
    def parse_directory(self, directory_path: str) -> List[Dict]:
        """
        Parse all certificates in a directory.
        
        Args:
            directory_path: Path to directory containing certificates
            
        Returns:
            List of certificate information dictionaries
        """
        certificates = []
        directory = Path(directory_path)
        
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in self.supported_formats:
                try:
                    cert_info = self.parse_certificate_file(str(file_path))
                    if cert_info:
                        certificates.extend(cert_info)
                except Exception as e:
                    print(f"Error parsing {file_path}: {e}")
                    continue
        
        return certificates
    
    def parse_certificate_file(self, file_path: str) -> List[Dict]:
        """
        Parse a single certificate file.
        
        Args:
            file_path: Path to certificate file
            
        Returns:
            List of certificate information (can contain multiple certs for P7B)
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            cert_data = f.read()
        
        # Determine file format and parse accordingly
        if file_path.suffix.lower() in ['.p7b', '.p7c']:
            return self._parse_p7b_certificate(cert_data, str(file_path))
        else:
            return self._parse_pem_certificate(cert_data, str(file_path))
    
    def _parse_pem_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse PEM format certificate."""
        certificates = []
        
        try:
            # Try to parse as a single certificate first
            cert = x509.load_pem_x509_certificate(cert_data)
            cert_info = self._extract_certificate_info(cert, file_path)
            certificates.append(cert_info)
        except ValueError:
            # If single cert fails, try to parse multiple certificates
            cert_strings = cert_data.decode('utf-8').split('-----END CERTIFICATE-----')
            
            for i, cert_str in enumerate(cert_strings[:-1]):  # Last split is empty
                cert_str += '-----END CERTIFICATE-----'
                try:
                    cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'))
                    cert_info = self._extract_certificate_info(cert, f"{file_path}#{i}")
                    certificates.append(cert_info)
                except Exception as e:
                    print(f"Error parsing certificate {i} in {file_path}: {e}")
                    continue
        
        return certificates
    
    def _parse_p7b_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse P7B/PKCS#7 format certificate."""
        certificates = []
        
        try:
            # Try DER format first
            try:
                p7 = x509.load_der_pkcs7_certificates(cert_data)
            except ValueError:
                # If DER fails, try PEM format
                p7 = x509.load_pem_pkcs7_certificates(cert_data)
            
            for i, cert in enumerate(p7):
                cert_info = self._extract_certificate_info(cert, f"{file_path}#{i}")
                certificates.append(cert_info)
                
        except Exception as e:
            print(f"Error parsing P7B certificate {file_path}: {e}")
        
        return certificates
    
    def _extract_certificate_info(self, cert: x509.Certificate, file_path: str) -> Dict:
        """Extract relevant information from a certificate object."""
        
        # Basic certificate information
        cert_info = {
            'file_path': file_path,
            'serial_number': str(cert.serial_number),
            'version': cert.version.name,
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'days_until_expiry': (cert.not_valid_after - datetime.now()).days,
            'signature_algorithm': cert.signature_algorithm_oid._name,
        }
        
        # Extract issuer information
        issuer_info = {}
        for attribute in cert.issuer:
            if attribute.oid == NameOID.COMMON_NAME:
                issuer_info['common_name'] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                issuer_info['organization'] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                issuer_info['organizational_unit'] = attribute.value
            elif attribute.oid == NameOID.COUNTRY_NAME:
                issuer_info['country'] = attribute.value
            elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                issuer_info['state'] = attribute.value
            elif attribute.oid == NameOID.LOCALITY_NAME:
                issuer_info['locality'] = attribute.value
        
        cert_info['issuer'] = issuer_info
        
        # Extract subject information
        subject_info = {}
        for attribute in cert.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                subject_info['common_name'] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                subject_info['organization'] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject_info['organizational_unit'] = attribute.value
            elif attribute.oid == NameOID.COUNTRY_NAME:
                subject_info['country'] = attribute.value
            elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                subject_info['state'] = attribute.value
            elif attribute.oid == NameOID.LOCALITY_NAME:
                subject_info['locality'] = attribute.value
        
        cert_info['subject'] = subject_info
        cert_info['common_name'] = subject_info.get('common_name', '')
        
        # Extract Subject Alternative Names
        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = []
            for name in san_extension.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_list.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_list.append(f"email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_list.append(f"URI:{name.value}")
            cert_info['subject_alt_names'] = san_list
        except x509.ExtensionNotFound:
            cert_info['subject_alt_names'] = []
        
        # Extract Key Usage
        try:
            key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            cert_info['key_usage'] = {
                'digital_signature': key_usage.value.digital_signature,
                'key_encipherment': key_usage.value.key_encipherment,
                'key_agreement': key_usage.value.key_agreement,
                'key_cert_sign': key_usage.value.key_cert_sign,
                'crl_sign': key_usage.value.crl_sign,
            }
        except x509.ExtensionNotFound:
            cert_info['key_usage'] = {}
        
        # Extract Extended Key Usage
        try:
            ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            cert_info['extended_key_usage'] = [usage._name for usage in ext_key_usage.value]
        except x509.ExtensionNotFound:
            cert_info['extended_key_usage'] = []
        
        # Determine certificate type and issuer category
        cert_info['certificate_type'] = self._determine_cert_type(cert_info)
        cert_info['issuer_category'] = self._categorize_issuer(issuer_info.get('common_name', ''))
        
        return cert_info
    
    def _determine_cert_type(self, cert_info: Dict) -> str:
        """Determine the type of certificate based on its properties."""
        extended_key_usage = cert_info.get('extended_key_usage', [])
        
        if 'serverAuth' in extended_key_usage:
            return 'server'
        elif 'clientAuth' in extended_key_usage:
            return 'client'
        elif 'codeSigning' in extended_key_usage:
            return 'code_signing'
        elif 'emailProtection' in extended_key_usage:
            return 'email'
        else:
            return 'unknown'
    
    def _categorize_issuer(self, issuer_cn: str) -> str:
        """Categorize the certificate issuer."""
        issuer_cn_lower = issuer_cn.lower()
        
        if 'let\'s encrypt' in issuer_cn_lower or 'letsencrypt' in issuer_cn_lower:
            return 'letsencrypt'
        elif 'digicert' in issuer_cn_lower:
            return 'digicert'
        elif 'comodo' in issuer_cn_lower or 'sectigo' in issuer_cn_lower:
            return 'comodo'
        elif 'symantec' in issuer_cn_lower:
            return 'symantec'
        elif 'godaddy' in issuer_cn_lower:
            return 'godaddy'
        elif 'globalsign' in issuer_cn_lower:
            return 'globalsign'
        elif 'entrust' in issuer_cn_lower:
            return 'entrust'
        elif 'amazon' in issuer_cn_lower or 'aws' in issuer_cn_lower:
            return 'aws'
        elif 'cloudflare' in issuer_cn_lower:
            return 'cloudflare'
        else:
            return 'other'
    
    def to_json(self, certificates: List[Dict], pretty: bool = True) -> str:
        """Convert certificate list to JSON string."""
        if pretty:
            return json.dumps(certificates, indent=2, default=str)
        return json.dumps(certificates, default=str)
    
    def save_to_cache(self, certificates: List[Dict], cache_file: str) -> None:
        """Save certificates to cache file."""
        cache_path = Path(cache_file)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(cache_path, 'w') as f:
            f.write(self.to_json(certificates))
    
    def load_from_cache(self, cache_file: str) -> List[Dict]:
        """Load certificates from cache file."""
        cache_path = Path(cache_file)
        
        if not cache_path.exists():
            return []
        
        with open(cache_path, 'r') as f:
            return json.load(f)


def main():
    """Example usage of the certificate parser."""
    parser = CertificateParser()
    
    # Example: Parse a directory of certificates
    try:
        certificates = parser.parse_directory('/path/to/certificates')
        print(f"Found {len(certificates)} certificates")
        
        # Convert to JSON and save to cache
        json_output = parser.to_json(certificates)
        parser.save_to_cache(certificates, 'cache/certificates.json')
        
        print("Sample certificate info:")
        if certificates:
            print(json.dumps(certificates[0], indent=2, default=str))
            
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
