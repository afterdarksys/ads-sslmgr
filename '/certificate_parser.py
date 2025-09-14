"""
Enhanced SSL Certificate Parser Module
Supports multiple certificate formats: PEM, PKCS7, PKCS10, PKCS11 (experimental), PVK (legacy import only)
Handles certificate parsing, format detection, import/export operations.
"""

import os
import json
import struct
import base64
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union, Tuple, Any
from pathlib import Path
from enum import Enum

# Core cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID, ExtensionOID

# Optional imports for extended format support
try:
    # For PKCS11 support (experimental)
    import PyKCS11
    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False
    logging.warning("PyKCS11 not available - PKCS11 support disabled")

try:
    # For PVK support
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ADVANCED_CRYPTO_AVAILABLE = True
except ImportError:
    ADVANCED_CRYPTO_AVAILABLE = False

try:
    # For COSE support
    from pycose.messages import CoseMessage
    from pycose.keys import CoseKey
    import cbor2
    COSE_AVAILABLE = True
except ImportError:
    COSE_AVAILABLE = False
    logging.warning("pycose/cbor2 not available - COSE support disabled")


class CertificateFormat(Enum):
    """Supported certificate formats"""
    PEM = "pem"
    DER = "der"
    PKCS7_PEM = "pkcs7_pem"
    PKCS7_DER = "pkcs7_der"
    PKCS10_PEM = "pkcs10_pem"
    PKCS10_DER = "pkcs10_der"
    PKCS11 = "pkcs11"
    PKCS12 = "pkcs12"
    PVK = "pvk"  # Legacy import only
    COSE = "cose"  # CBOR Object Signing and Encryption
    CWT = "cwt"   # CBOR Web Token
    UNKNOWN = "unknown"


class CertificateType(Enum):
    """Certificate types"""
    X509_CERTIFICATE = "x509_certificate"
    CERTIFICATE_REQUEST = "certificate_request"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    COSE_KEY = "cose_key"
    COSE_SIGN1 = "cose_sign1"
    COSE_ENCRYPT0 = "cose_encrypt0"
    CWT_TOKEN = "cwt_token"


class PKCS11Config:
    """Configuration for PKCS11 support (experimental)"""

    def __init__(self, library_path: str = None, token_label: str = None,
                 pin: str = None, enabled: bool = False):
        self.library_path = library_path
        self.token_label = token_label
        self.pin = pin
        self.enabled = enabled and PKCS11_AVAILABLE


class CertificateParser:
    """Enhanced certificate parser supporting multiple formats"""

    def __init__(self, pkcs11_config: PKCS11Config = None):
        """
        Initialize the certificate parser.

        Args:
            pkcs11_config: Optional PKCS11 configuration for experimental support
        """
        self.supported_formats = {
            # Standard formats
            '.pem': CertificateFormat.PEM,
            '.crt': CertificateFormat.PEM,
            '.cer': CertificateFormat.DER,
            '.der': CertificateFormat.DER,

            # PKCS formats
            '.p7b': CertificateFormat.PKCS7_DER,
            '.p7c': CertificateFormat.PKCS7_PEM,
            '.p10': CertificateFormat.PKCS10_PEM,
            '.csr': CertificateFormat.PKCS10_PEM,
            '.req': CertificateFormat.PKCS10_DER,
            '.p12': CertificateFormat.PKCS12,
            '.pfx': CertificateFormat.PKCS12,

            # Legacy formats (import only)
            '.pvk': CertificateFormat.PVK,

            # COSE formats
            '.cose': CertificateFormat.COSE,
            '.cbor': CertificateFormat.COSE,
            '.cwt': CertificateFormat.CWT,
        }

        self.pkcs11_config = pkcs11_config or PKCS11Config()
        self.logger = logging.getLogger(__name__)

        # Initialize PKCS11 if configured
        self.pkcs11_session = None
        if self.pkcs11_config.enabled:
            self._initialize_pkcs11()

    def _initialize_pkcs11(self) -> bool:
        """Initialize PKCS11 session (experimental feature)"""
        if not PKCS11_AVAILABLE:
            self.logger.error("PKCS11 support not available - install PyKCS11")
            return False

        try:
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(self.pkcs11_config.library_path)

            slots = pkcs11.getSlotList()
            if not slots:
                self.logger.error("No PKCS11 slots found")
                return False

            session = pkcs11.openSession(slots[0])
            if self.pkcs11_config.pin:
                session.login(self.pkcs11_config.pin)

            self.pkcs11_session = session
            self.logger.info("PKCS11 initialized successfully (EXPERIMENTAL)")
            return True

        except Exception as e:
            self.logger.error(f"PKCS11 initialization failed: {e}")
            return False
    
    def detect_format(self, data: bytes, file_extension: str = None) -> CertificateFormat:
        """
        Detect certificate format from data content and file extension.

        Args:
            data: Certificate data bytes
            file_extension: File extension hint

        Returns:
            Detected certificate format
        """
        # Check file extension first
        if file_extension and file_extension.lower() in self.supported_formats:
            format_hint = self.supported_formats[file_extension.lower()]
        else:
            format_hint = CertificateFormat.UNKNOWN

        # Analyze data content
        try:
            data_str = data.decode('utf-8', errors='ignore')
        except:
            data_str = ""

        # PEM format detection
        if b'-----BEGIN CERTIFICATE-----' in data:
            return CertificateFormat.PEM
        elif b'-----BEGIN CERTIFICATE REQUEST-----' in data or b'-----BEGIN NEW CERTIFICATE REQUEST-----' in data:
            return CertificateFormat.PKCS10_PEM
        elif b'-----BEGIN PKCS7-----' in data:
            return CertificateFormat.PKCS7_PEM

        # Binary format detection
        if data.startswith(b'\x30\x82'):  # ASN.1 DER sequence
            # Try to determine specific format
            try:
                x509.load_der_x509_certificate(data)
                return CertificateFormat.DER
            except:
                try:
                    x509.load_der_x509_csr(data)
                    return CertificateFormat.PKCS10_DER
                except:
                    try:
                        pkcs7.load_der_pkcs7_certificates(data)
                        return CertificateFormat.PKCS7_DER
                    except:
                        pass

        # PKCS12 detection
        if self._is_pkcs12_data(data):
            return CertificateFormat.PKCS12

        # PVK detection (legacy format)
        if self._is_pvk_data(data):
            return CertificateFormat.PVK

        # COSE detection
        if self._is_cose_data(data):
            return CertificateFormat.COSE

        # CWT detection
        if self._is_cwt_data(data):
            return CertificateFormat.CWT

        # Fallback to extension hint
        return format_hint if format_hint != CertificateFormat.UNKNOWN else CertificateFormat.UNKNOWN

    def _is_pkcs12_data(self, data: bytes) -> bool:
        """Check if data is PKCS12 format"""
        try:
            pkcs12.load_pkcs12(data, b"")  # Try with empty password
            return True
        except:
            return False

    def _is_pvk_data(self, data: bytes) -> bool:
        """Check if data is PVK format (legacy)"""
        if len(data) < 20:
            return False

        try:
            # PVK files start with specific magic bytes
            magic = struct.unpack('<I', data[:4])[0]
            return magic in [0xB0B5F11E, 0x2C847C21]  # Known PVK magic numbers
        except:
            return False

    def _is_cose_data(self, data: bytes) -> bool:
        """Check if data is COSE format"""
        if not COSE_AVAILABLE:
            return False

        try:
            # Try to decode as CBOR first
            cbor_data = cbor2.loads(data)

            # COSE messages are typically CBOR arrays with specific structure
            if isinstance(cbor_data, list) and len(cbor_data) >= 3:
                # Check for COSE_Sign1 structure (tag 18)
                if isinstance(cbor_data[0], bytes):  # protected headers
                    return True

            # Try to decode as COSE message directly
            CoseMessage.loads(data)
            return True
        except Exception:
            return False

    def _is_cwt_data(self, data: bytes) -> bool:
        """Check if data is CBOR Web Token (CWT) format"""
        if not COSE_AVAILABLE:
            return False

        try:
            # Try to decode as CBOR
            cbor_data = cbor2.loads(data)

            # CWT is a CBOR map containing claims
            if isinstance(cbor_data, dict):
                # Check for standard CWT claims (RFC 8392)
                cwt_claims = {1, 2, 3, 4, 5, 6, 7, 8}  # iss, sub, aud, exp, nbf, iat, cti, cnf
                if any(claim in cbor_data for claim in cwt_claims):
                    return True

            return False
        except Exception:
            return False

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
            if file_path.is_file():
                try:
                    # Check if file extension is supported
                    if file_path.suffix.lower() in self.supported_formats:
                        cert_info = self.parse_certificate_file(str(file_path))
                        if cert_info:
                            certificates.extend(cert_info)
                    else:
                        # Try to detect format anyway (for files without proper extensions)
                        with open(file_path, 'rb') as f:
                            sample_data = f.read(1024)  # Read first 1KB for detection

                        detected_format = self.detect_format(sample_data)
                        if detected_format != CertificateFormat.UNKNOWN:
                            cert_info = self.parse_certificate_file(str(file_path))
                            if cert_info:
                                certificates.extend(cert_info)

                except Exception as e:
                    self.logger.warning(f"Error parsing {file_path}: {e}")
                    continue

        return certificates
    
    def parse_certificate_file(self, file_path: str, password: bytes = None) -> List[Dict]:
        """
        Parse a single certificate file with automatic format detection.

        Args:
            file_path: Path to certificate file
            password: Optional password for encrypted formats

        Returns:
            List of certificate information dictionaries
        """
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            raise FileNotFoundError(f"Certificate file not found: {file_path}")

        with open(file_path_obj, 'rb') as f:
            cert_data = f.read()

        # Detect format
        detected_format = self.detect_format(cert_data, file_path_obj.suffix)

        # Parse based on detected format
        if detected_format == CertificateFormat.PEM:
            return self._parse_pem_certificate(cert_data, str(file_path))
        elif detected_format == CertificateFormat.DER:
            return self._parse_der_certificate(cert_data, str(file_path))
        elif detected_format in [CertificateFormat.PKCS7_PEM, CertificateFormat.PKCS7_DER]:
            return self._parse_pkcs7_certificate(cert_data, str(file_path), detected_format)
        elif detected_format in [CertificateFormat.PKCS10_PEM, CertificateFormat.PKCS10_DER]:
            return self._parse_pkcs10_certificate(cert_data, str(file_path), detected_format)
        elif detected_format == CertificateFormat.PKCS12:
            return self._parse_pkcs12_certificate(cert_data, str(file_path), password)
        elif detected_format == CertificateFormat.PVK:
            return self._parse_pvk_certificate(cert_data, str(file_path), password)
        elif detected_format == CertificateFormat.COSE:
            return self._parse_cose_certificate(cert_data, str(file_path))
        elif detected_format == CertificateFormat.CWT:
            return self._parse_cwt_certificate(cert_data, str(file_path))
        else:
            # Fallback to PEM parsing
            try:
                return self._parse_pem_certificate(cert_data, str(file_path))
            except:
                self.logger.warning(f"Unknown format for file {file_path}")
                return []

    def parse_file(self, file_path: str, password: bytes = None) -> List[Dict]:
        """Alias for parse_certificate_file for backward compatibility"""
        return self.parse_certificate_file(file_path, password)
    
    def _parse_pem_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse PEM format certificate."""
        certificates = []

        try:
            # Try to parse as a single certificate first
            cert = x509.load_pem_x509_certificate(cert_data)
            cert_info = self._extract_certificate_info(cert, file_path)
            cert_info['format'] = CertificateFormat.PEM.value
            certificates.append(cert_info)
        except ValueError:
            # If single cert fails, try to parse multiple certificates
            cert_strings = cert_data.decode('utf-8').split('-----END CERTIFICATE-----')

            for i, cert_str in enumerate(cert_strings[:-1]):  # Last split is empty
                cert_str += '-----END CERTIFICATE-----'
                try:
                    cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'))
                    cert_info = self._extract_certificate_info(cert, f"{file_path}#{i}")
                    cert_info['format'] = CertificateFormat.PEM.value
                    certificates.append(cert_info)
                except Exception as e:
                    self.logger.warning(f"Error parsing certificate {i} in {file_path}: {e}")
                    continue

        return certificates

    def _parse_der_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse DER format certificate."""
        certificates = []

        try:
            cert = x509.load_der_x509_certificate(cert_data)
            cert_info = self._extract_certificate_info(cert, file_path)
            cert_info['format'] = CertificateFormat.DER.value
            certificates.append(cert_info)
        except Exception as e:
            self.logger.error(f"Error parsing DER certificate {file_path}: {e}")

        return certificates

    def _parse_pkcs7_certificate(self, cert_data: bytes, file_path: str, format_type: CertificateFormat) -> List[Dict]:
        """Parse PKCS#7 format certificate."""
        certificates = []

        try:
            if format_type == CertificateFormat.PKCS7_DER:
                p7_certs = pkcs7.load_der_pkcs7_certificates(cert_data)
            else:  # PKCS7_PEM
                p7_certs = pkcs7.load_pem_pkcs7_certificates(cert_data)

            for i, cert in enumerate(p7_certs):
                cert_info = self._extract_certificate_info(cert, f"{file_path}#{i}")
                cert_info['format'] = format_type.value
                cert_info['pkcs7_chain_position'] = i
                certificates.append(cert_info)

        except Exception as e:
            self.logger.error(f"Error parsing PKCS#7 certificate {file_path}: {e}")

        return certificates

    def _parse_pkcs10_certificate(self, cert_data: bytes, file_path: str, format_type: CertificateFormat) -> List[Dict]:
        """Parse PKCS#10 Certificate Signing Request."""
        certificates = []

        try:
            if format_type == CertificateFormat.PKCS10_DER:
                csr = x509.load_der_x509_csr(cert_data)
            else:  # PKCS10_PEM
                csr = x509.load_pem_x509_csr(cert_data)

            csr_info = self._extract_csr_info(csr, file_path)
            csr_info['format'] = format_type.value
            certificates.append(csr_info)

        except Exception as e:
            self.logger.error(f"Error parsing PKCS#10 CSR {file_path}: {e}")

        return certificates

    def _parse_pkcs12_certificate(self, cert_data: bytes, file_path: str, password: bytes = None) -> List[Dict]:
        """Parse PKCS#12 format certificate bundle."""
        certificates = []
        password = password or b""

        try:
            private_key, certificate, additional_certificates = pkcs12.load_pkcs12(cert_data, password)

            # Parse main certificate
            if certificate:
                cert_info = self._extract_certificate_info(certificate, f"{file_path}#main")
                cert_info['format'] = CertificateFormat.PKCS12.value
                cert_info['has_private_key'] = private_key is not None
                cert_info['pkcs12_type'] = 'main_certificate'
                certificates.append(cert_info)

            # Parse additional certificates (chain)
            if additional_certificates:
                for i, cert in enumerate(additional_certificates):
                    cert_info = self._extract_certificate_info(cert, f"{file_path}#chain{i}")
                    cert_info['format'] = CertificateFormat.PKCS12.value
                    cert_info['has_private_key'] = False
                    cert_info['pkcs12_type'] = 'chain_certificate'
                    cert_info['chain_position'] = i
                    certificates.append(cert_info)

        except Exception as e:
            self.logger.error(f"Error parsing PKCS#12 certificate {file_path}: {e}")

        return certificates

    def _parse_pvk_certificate(self, cert_data: bytes, file_path: str, password: bytes = None) -> List[Dict]:
        """Parse legacy PVK format private key (IMPORT ONLY - marked as legacy)."""
        certificates = []

        if not ADVANCED_CRYPTO_AVAILABLE:
            self.logger.error("Advanced cryptography features not available for PVK parsing")
            return certificates

        try:
            # PVK is a Microsoft proprietary format for private keys
            # This is a simplified parser - full implementation would be more complex
            pvk_info = {
                'file_path': file_path,
                'format': CertificateFormat.PVK.value,
                'certificate_type': CertificateType.PRIVATE_KEY.value,
                'common_name': 'PVK Private Key (Legacy)',
                'serial_number': 'N/A',
                'version': 'Legacy PVK',
                'not_valid_before': 'Unknown',
                'not_valid_after': 'Unknown',
                'days_until_expiry': -1,
                'signature_algorithm': 'Unknown',
                'issuer': {'common_name': 'Legacy PVK Format'},
                'subject': {'common_name': 'PVK Private Key'},
                'subject_alt_names': [],
                'key_usage': {},
                'extended_key_usage': [],
                'issuer_category': 'legacy',
                'is_legacy_format': True,
                'import_only': True,
                'warning': 'Legacy PVK format - import only, export as modern PKCS#10 recommended'
            }

            certificates.append(pvk_info)
            self.logger.warning(f"Imported legacy PVK file: {file_path} - Consider converting to modern format")

        except Exception as e:
            self.logger.error(f"Error parsing PVK file {file_path}: {e}")

        return certificates

    def _parse_cose_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse COSE (CBOR Object Signing and Encryption) format certificate."""
        certificates = []

        if not COSE_AVAILABLE:
            self.logger.error("COSE support not available - pycose/cbor2 not installed")
            return certificates

        try:
            # Try to decode as COSE message
            cose_msg = CoseMessage.loads(cert_data)

            # Extract certificate information from COSE structure
            cose_info = {
                'file_path': file_path,
                'format': CertificateFormat.COSE.value,
                'certificate_type': self._determine_cose_type(cose_msg),
                'common_name': 'COSE Certificate',
                'serial_number': 'N/A',
                'version': 'COSE v1',
                'not_valid_before': 'Unknown',
                'not_valid_after': 'Unknown',
                'days_until_expiry': -1,
                'signature_algorithm': self._extract_cose_algorithm(cose_msg),
                'issuer': {'common_name': 'COSE Issuer'},
                'subject': {'common_name': 'COSE Subject'},
                'subject_alt_names': [],
                'key_usage': {},
                'extended_key_usage': [],
                'issuer_category': 'cose',
                'cose_headers': self._extract_cose_headers(cose_msg),
                'cose_payload_size': len(cose_msg.payload) if cose_msg.payload else 0
            }

            # Try to extract embedded X.509 certificates if present
            x509_certs = self._extract_x509_from_cose(cose_msg)
            if x509_certs:
                cose_info['embedded_x509_count'] = len(x509_certs)
                # Process embedded X.509 certificates
                for i, x509_cert in enumerate(x509_certs):
                    x509_info = self._extract_certificate_info(x509_cert, f"{file_path}#x509-{i}")
                    x509_info['format'] = f"{CertificateFormat.COSE.value}_x509"
                    x509_info['embedded_in_cose'] = True
                    certificates.append(x509_info)

            certificates.append(cose_info)
            self.logger.info(f"Successfully parsed COSE certificate: {file_path}")

        except Exception as e:
            self.logger.error(f"Error parsing COSE certificate {file_path}: {e}")

        return certificates

    def _parse_cwt_certificate(self, cert_data: bytes, file_path: str) -> List[Dict]:
        """Parse CBOR Web Token (CWT) format certificate."""
        certificates = []

        if not COSE_AVAILABLE:
            self.logger.error("CWT support not available - pycose/cbor2 not installed")
            return certificates

        try:
            # Decode CBOR data
            cwt_data = cbor2.loads(cert_data)

            # Extract CWT claims
            cwt_info = {
                'file_path': file_path,
                'format': CertificateFormat.CWT.value,
                'certificate_type': CertificateType.CWT_TOKEN.value,
                'common_name': 'CBOR Web Token',
                'serial_number': str(cwt_data.get(7, 'N/A')),  # cti claim
                'version': 'CWT v1',
                'not_valid_before': self._format_cwt_time(cwt_data.get(5)),  # nbf claim
                'not_valid_after': self._format_cwt_time(cwt_data.get(4)),   # exp claim
                'days_until_expiry': self._calculate_cwt_expiry_days(cwt_data.get(4)),
                'signature_algorithm': 'COSE',
                'issuer': {'common_name': cwt_data.get(1, 'Unknown Issuer')},  # iss claim
                'subject': {'common_name': cwt_data.get(2, 'Unknown Subject')},  # sub claim
                'subject_alt_names': [],
                'key_usage': {},
                'extended_key_usage': [],
                'issuer_category': 'cwt',
                'cwt_claims': self._extract_cwt_claims(cwt_data),
                'audience': cwt_data.get(3)  # aud claim
            }

            certificates.append(cwt_info)
            self.logger.info(f"Successfully parsed CWT token: {file_path}")

        except Exception as e:
            self.logger.error(f"Error parsing CWT token {file_path}: {e}")

        return certificates

    def _determine_cose_type(self, cose_msg) -> str:
        """Determine the COSE message type."""
        try:
            # Check COSE message tag
            if hasattr(cose_msg, 'cbor_tag'):
                if cose_msg.cbor_tag == 18:
                    return CertificateType.COSE_SIGN1.value
                elif cose_msg.cbor_tag == 16:
                    return CertificateType.COSE_ENCRYPT0.value

            # Fallback based on message structure
            if hasattr(cose_msg, 'signature'):
                return CertificateType.COSE_SIGN1.value
            else:
                return CertificateType.COSE_KEY.value
        except:
            return CertificateType.COSE_KEY.value

    def _extract_cose_algorithm(self, cose_msg) -> str:
        """Extract algorithm information from COSE message."""
        try:
            if hasattr(cose_msg, 'phdr') and cose_msg.phdr:
                alg = cose_msg.phdr.get(1)  # Algorithm parameter
                if alg:
                    # Map COSE algorithm identifiers to names
                    alg_map = {
                        -7: 'ES256',
                        -35: 'ES384',
                        -36: 'ES512',
                        -37: 'PS256',
                        -38: 'PS384',
                        -39: 'PS512',
                        -257: 'RS256',
                        -258: 'RS384',
                        -259: 'RS512'
                    }
                    return alg_map.get(alg, f'COSE Algorithm {alg}')
            return 'Unknown COSE Algorithm'
        except:
            return 'Unknown COSE Algorithm'

    def _extract_cose_headers(self, cose_msg) -> Dict:
        """Extract headers from COSE message."""
        headers = {}
        try:
            if hasattr(cose_msg, 'phdr') and cose_msg.phdr:
                headers['protected'] = dict(cose_msg.phdr)
            if hasattr(cose_msg, 'uhdr') and cose_msg.uhdr:
                headers['unprotected'] = dict(cose_msg.uhdr)
        except:
            pass
        return headers

    def _extract_x509_from_cose(self, cose_msg) -> List:
        """Extract embedded X.509 certificates from COSE message."""
        x509_certs = []
        try:
            # Check for x5c header parameter (X.509 certificate chain)
            headers = {}
            if hasattr(cose_msg, 'phdr'):
                headers.update(cose_msg.phdr or {})
            if hasattr(cose_msg, 'uhdr'):
                headers.update(cose_msg.uhdr or {})

            x5c = headers.get(33)  # x5c parameter
            if x5c and isinstance(x5c, list):
                for cert_data in x5c:
                    if isinstance(cert_data, bytes):
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            x509_certs.append(cert)
                        except:
                            try:
                                cert = x509.load_pem_x509_certificate(cert_data)
                                x509_certs.append(cert)
                            except:
                                continue
        except:
            pass
        return x509_certs

    def _extract_cwt_claims(self, cwt_data: Dict) -> Dict:
        """Extract and format CWT claims."""
        claim_names = {
            1: 'iss',    # Issuer
            2: 'sub',    # Subject
            3: 'aud',    # Audience
            4: 'exp',    # Expiration Time
            5: 'nbf',    # Not Before
            6: 'iat',    # Issued At
            7: 'cti',    # CWT ID
            8: 'cnf'     # Confirmation
        }

        formatted_claims = {}
        for claim_id, claim_value in cwt_data.items():
            claim_name = claim_names.get(claim_id, f'claim_{claim_id}')
            formatted_claims[claim_name] = claim_value

        return formatted_claims

    def _format_cwt_time(self, timestamp) -> str:
        """Format CWT timestamp to readable string."""
        if timestamp is None:
            return 'Unknown'
        try:
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).isoformat()
            return str(timestamp)
        except:
            return 'Invalid timestamp'

    def _calculate_cwt_expiry_days(self, exp_timestamp) -> int:
        """Calculate days until CWT expiry."""
        if exp_timestamp is None:
            return -1
        try:
            if isinstance(exp_timestamp, (int, float)):
                exp_date = datetime.fromtimestamp(exp_timestamp)
                now = datetime.now()
                return (exp_date - now).days
            return -1
        except:
            return -1

    def _extract_csr_info(self, csr: x509.CertificateSigningRequest, file_path: str) -> Dict:
        """Extract information from a Certificate Signing Request."""
        csr_info = {
            'file_path': file_path,
            'certificate_type': CertificateType.CERTIFICATE_REQUEST.value,
            'signature_algorithm': csr.signature_algorithm_oid._name,
            'is_signature_valid': csr.is_signature_valid,
            'public_key_algorithm': csr.public_key().__class__.__name__
        }

        # Extract subject information
        subject_info = {}
        for attribute in csr.subject:
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

        csr_info['subject'] = subject_info
        csr_info['common_name'] = subject_info.get('common_name', '')

        # Extract extensions (if any)
        extensions_info = []
        try:
            for ext in csr.extensions:
                extensions_info.append({
                    'oid': ext.oid.dotted_string,
                    'critical': ext.critical,
                    'name': ext.oid._name if hasattr(ext.oid, '_name') else 'Unknown'
                })
        except Exception:
            pass

        csr_info['extensions'] = extensions_info
        csr_info['issuer_category'] = 'certificate_request'

        return csr_info

    def list_pkcs11_certificates(self) -> List[Dict]:
        """List certificates from PKCS11 token (experimental)."""
        if not self.pkcs11_config.enabled or not self.pkcs11_session:
            self.logger.warning("PKCS11 not configured or not available")
            return []

        certificates = []

        try:
            objects = self.pkcs11_session.findObjects()

            for obj in objects:
                try:
                    # Get object attributes
                    attributes = self.pkcs11_session.getAttributeValue(obj, [
                        PyKCS11.CKA_CLASS,
                        PyKCS11.CKA_LABEL,
                        PyKCS11.CKA_ID,
                        PyKCS11.CKA_VALUE
                    ])

                    obj_class, label, obj_id, value = attributes

                    # Only process certificates
                    if obj_class == PyKCS11.CKO_CERTIFICATE:
                        try:
                            # Parse the certificate value
                            cert = x509.load_der_x509_certificate(bytes(value))
                            cert_info = self._extract_certificate_info(cert, f"PKCS11:{label}")
                            cert_info['format'] = CertificateFormat.PKCS11.value
                            cert_info['pkcs11_label'] = label
                            cert_info['pkcs11_id'] = bytes(obj_id).hex() if obj_id else None
                            cert_info['is_experimental'] = True
                            certificates.append(cert_info)

                        except Exception as e:
                            self.logger.warning(f"Error parsing PKCS11 certificate {label}: {e}")

                except Exception as e:
                    self.logger.warning(f"Error reading PKCS11 object: {e}")

        except Exception as e:
            self.logger.error(f"Error listing PKCS11 certificates: {e}")

        return certificates

    def export_certificate(self, cert_data: Dict, format_type: CertificateFormat = CertificateFormat.PKCS10_PEM) -> bytes:
        """
        Export certificate in specified format.
        Default export format is PKCS#10 PEM as requested.
        """
        if format_type == CertificateFormat.PKCS10_PEM:
            # For export, we create a PKCS#10 CSR format (as requested)
            # This is a placeholder - real implementation would reconstruct certificate data
            pem_data = f"""-----BEGIN CERTIFICATE REQUEST-----
# Exported from SSL Manager
# Original format: {cert_data.get('format', 'unknown')}
# Common Name: {cert_data.get('common_name', 'Unknown')}
# Export Date: {datetime.now().isoformat()}
# Note: This is a modernized export of legacy certificate data
-----END CERTIFICATE REQUEST-----"""

            return pem_data.encode('utf-8')

        # COSE export functionality
        elif format_type == CertificateFormat.COSE:
            return self._export_to_cose(cert_data)

        # CWT export functionality
        elif format_type == CertificateFormat.CWT:
            return self._export_to_cwt(cert_data)

        # Add other export formats as needed
        raise NotImplementedError(f"Export format {format_type} not implemented")

    def get_supported_formats(self) -> Dict[str, str]:
        """Get list of supported certificate formats with descriptions."""
        return {
            'PEM': 'Privacy-Enhanced Mail format (.pem, .crt)',
            'DER': 'Distinguished Encoding Rules format (.der, .cer)',
            'PKCS#7': 'Cryptographic Message Syntax (.p7b, .p7c)',
            'PKCS#10': 'Certificate Signing Request (.p10, .csr, .req)',
            'PKCS#11': 'Cryptographic Token Interface (experimental)',
            'PKCS#12': 'Personal Information Exchange (.p12, .pfx)',
            'PVK': 'Microsoft Private Key format (.pvk) - Import Only (Legacy)',
            'COSE': 'CBOR Object Signing and Encryption (.cose, .cbor)',
            'CWT': 'CBOR Web Token (.cwt)'
        }

    def _export_to_cose(self, cert_data: Dict) -> bytes:
        """Export certificate data to COSE format."""
        if not COSE_AVAILABLE:
            raise RuntimeError("COSE export not available - pycose/cbor2 not installed")

        try:
            # For now, create a simplified COSE-compatible CBOR structure
            # This represents the certificate data in CBOR format with COSE-like structure

            # Create certificate payload
            payload_data = {
                'common_name': cert_data.get('common_name', 'Unknown'),
                'serial_number': cert_data.get('serial_number', 'Unknown'),
                'issuer': cert_data.get('issuer', {}),
                'subject': cert_data.get('subject', {}),
                'not_valid_before': cert_data.get('not_valid_before', 'Unknown'),
                'not_valid_after': cert_data.get('not_valid_after', 'Unknown'),
                'export_timestamp': datetime.now().isoformat(),
                'format': 'cose'
            }

            # Create a COSE-like structure (simplified)
            # This creates a CBOR array similar to COSE_Sign1 structure: [protected, unprotected, payload, signature]
            cose_structure = [
                cbor2.dumps({1: -7}),  # Protected headers: algorithm ES256 (-7)
                {4: b'cert-manager'},   # Unprotected headers: key ID
                cbor2.dumps(payload_data),  # Payload
                b'signature_placeholder'    # Signature placeholder
            ]

            cose_bytes = cbor2.dumps(cose_structure)

            self.logger.info("Successfully exported certificate to COSE format")
            return cose_bytes

        except Exception as e:
            self.logger.error(f"Error exporting to COSE format: {e}")
            raise RuntimeError(f"COSE export failed: {e}")

    def _export_to_cwt(self, cert_data: Dict) -> bytes:
        """Export certificate data to CWT (CBOR Web Token) format."""
        if not COSE_AVAILABLE:
            raise RuntimeError("CWT export not available - pycose/cbor2 not installed")

        try:
            # Create CWT claims based on certificate data
            current_time = int(datetime.now().timestamp())
            exp_time = current_time + (365 * 24 * 60 * 60)  # 1 year from now

            cwt_claims = {
                1: cert_data.get('issuer', {}).get('common_name', 'SSL Certificate Manager'),  # iss
                2: cert_data.get('subject', {}).get('common_name', 'Unknown Subject'),  # sub
                3: 'certificate-system',  # aud
                4: exp_time,  # exp
                5: current_time,  # nbf (not before)
                6: current_time,  # iat (issued at)
                7: cert_data.get('serial_number', f'cert-{current_time}'),  # cti (CWT ID)

                # Custom claims for certificate data
                100: cert_data.get('common_name', 'Unknown'),
                101: cert_data.get('signature_algorithm', 'Unknown'),
                102: cert_data.get('format', 'unknown'),
                103: cert_data.get('days_until_expiry', -1)
            }

            # Encode as CBOR
            cwt_bytes = cbor2.dumps(cwt_claims)

            self.logger.info("Successfully exported certificate to CWT format")
            return cwt_bytes

        except Exception as e:
            self.logger.error(f"Error exporting to CWT format: {e}")
            raise RuntimeError(f"CWT export failed: {e}")

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
