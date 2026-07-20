"""
Private Certificate Authority Manager
Supports a complete CA hierarchy: Root → Intermediate → Issuing → End-entity.

Usage:
    mgr = PrivateCAManager(key_storage_dir='/secure/keys')
    root   = mgr.create_root_ca('My Root CA', organization='Acme', country='US')
    inter  = mgr.create_intermediate_ca('My Issuing CA', root['cert_pem'], root['key_pem'])
    cert   = mgr.issue_certificate('app.example.com', inter['cert_pem'], inter['key_pem'],
                                    cert_type=CertificateType.SERVER,
                                    san_dns=['app.example.com', 'www.example.com'])
"""

import ipaddress
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat,
)
from cryptography.x509 import (
    CertificateBuilder, CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.oid import ObjectIdentifier


PKINIT_SAN_OID = ObjectIdentifier('1.3.6.1.5.2.2')
PKINIT_CLIENT_EKU_OID = ObjectIdentifier('1.3.6.1.5.2.3.4')
PKINIT_KDC_EKU_OID = ObjectIdentifier('1.3.6.1.5.2.3.5')


class CertificateType:
    SERVER       = 'server'
    CLIENT       = 'client'
    CODE_SIGNING = 'code_signing'
    EMAIL        = 'email'
    OCSP         = 'ocsp'
    TIMESTAMPING = 'timestamping'
    PKINIT_CLIENT = 'pkinit_client'
    PKINIT_KDC    = 'pkinit_kdc'
    ROOT_CA      = 'root_ca'
    INTERMEDIATE_CA = 'intermediate_ca'
    ISSUING_CA   = 'issuing_ca'


class PrivateCAManager:
    """
    Manages private PKI: root / intermediate / issuing CAs and end-entity certs.
    Private keys are written to key_storage_dir (mode 0o700).
    """

    def __init__(self, key_storage_dir: str = './ca_keys'):
        self.logger = logging.getLogger(__name__)
        self.key_storage_dir = Path(key_storage_dir)
        self.key_storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ── Key generation ─────────────────────────────────────────────────────

    def generate_key(self, key_type: str = 'rsa', key_size_or_curve=4096):
        """Generate RSA or EC private key."""
        kt = key_type.lower()
        if kt == 'rsa':
            size = int(key_size_or_curve)
            if size not in (2048, 3072, 4096):
                raise ValueError(f"RSA key size must be 2048, 3072, or 4096 (got {size})")
            return rsa.generate_private_key(public_exponent=65537, key_size=size)
        elif kt == 'ec':
            curve_map = {
                'P-256': ec.SECP256R1(), 'P256': ec.SECP256R1(),
                'P-384': ec.SECP384R1(), 'P384': ec.SECP384R1(),
                'P-521': ec.SECP521R1(), 'P521': ec.SECP521R1(),
            }
            curve = curve_map.get(str(key_size_or_curve))
            if not curve:
                raise ValueError(f"EC curve must be P-256, P-384, or P-521 (got {key_size_or_curve})")
            return ec.generate_private_key(curve)
        raise ValueError(f"key_type must be 'rsa' or 'ec' (got {key_type})")

    def serialize_key(self, key, password: bytes = None) -> bytes:
        enc = BestAvailableEncryption(password) if password else NoEncryption()
        return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, enc)

    def load_key(self, pem: Union[str, bytes], password: bytes = None):
        if isinstance(pem, str):
            pem = pem.encode()
        return serialization.load_pem_private_key(pem, password=password)

    def load_cert(self, pem: Union[str, bytes]) -> x509.Certificate:
        if isinstance(pem, str):
            pem = pem.encode()
        return x509.load_pem_x509_certificate(pem)

    # ── DN helper ──────────────────────────────────────────────────────────

    def _name(self, cn, org=None, ou=None, country=None, state=None, locality=None, email=None):
        attrs = []
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
        if state:
            attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if org:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        if ou:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        if email:
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        return x509.Name(attrs)

    # ── CA creation ────────────────────────────────────────────────────────

    def create_root_ca(
        self,
        common_name: str,
        organization: str = None,
        organizational_unit: str = None,
        country: str = 'US',
        state: str = None,
        locality: str = None,
        validity_years: int = 20,
        key_type: str = 'rsa',
        key_size_or_curve=4096,
        path_length: int = None,
        key_password: bytes = None,
        crl_distribution_points: List[str] = None,
    ) -> Dict:
        """Create a self-signed Root CA. Returns cert_pem, key_pem, metadata."""
        key = self.generate_key(key_type, key_size_or_curve)
        subject = self._name(common_name, organization, organizational_unit, country, state, locality)
        serial = x509.random_serial_number()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_years * 365)

        builder = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        )
        builder = self._add_cdp(builder, crl_distribution_points)
        cert = builder.sign(key, hashes.SHA256())

        return {
            'cert_pem': cert.public_bytes(Encoding.PEM).decode(),
            'key_pem': self.serialize_key(key, key_password).decode(),
            'serial_number': str(serial),
            'common_name': common_name,
            'ca_type': CertificateType.ROOT_CA,
            'not_valid_before': now.isoformat(),
            'not_valid_after': expires.isoformat(),
            'key_type': key_type,
        }

    def create_intermediate_ca(
        self,
        common_name: str,
        issuer_cert_pem: Union[str, bytes],
        issuer_key_pem: Union[str, bytes],
        organization: str = None,
        organizational_unit: str = None,
        country: str = 'US',
        state: str = None,
        locality: str = None,
        validity_years: int = 10,
        key_type: str = 'rsa',
        key_size_or_curve=4096,
        path_length: int = 0,
        key_password: bytes = None,
        issuer_key_password: bytes = None,
        crl_distribution_points: List[str] = None,
        ocsp_url: str = None,
    ) -> Dict:
        """
        Create an Intermediate CA signed by a parent CA.
        path_length=0  → can only issue end-entity certs.
        path_length=1  → can sign one more level of sub-CAs (issuing CAs).
        """
        issuer_cert = self.load_cert(issuer_cert_pem)
        issuer_key  = self.load_key(issuer_key_pem, issuer_key_password)
        key     = self.generate_key(key_type, key_size_or_curve)
        subject = self._name(common_name, organization, organizational_unit, country, state, locality)
        serial  = x509.random_serial_number()
        now     = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_years * 365)

        builder = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
        )
        builder = self._add_cdp(builder, crl_distribution_points)
        builder = self._add_aia(builder, ocsp_url)
        cert = builder.sign(issuer_key, hashes.SHA256())

        return {
            'cert_pem': cert.public_bytes(Encoding.PEM).decode(),
            'key_pem': self.serialize_key(key, key_password).decode(),
            'serial_number': str(serial),
            'common_name': common_name,
            'ca_type': CertificateType.INTERMEDIATE_CA,
            'not_valid_before': now.isoformat(),
            'not_valid_after': expires.isoformat(),
            'key_type': key_type,
        }

    def create_issuing_ca(
        self,
        common_name: str,
        issuer_cert_pem: Union[str, bytes],
        issuer_key_pem: Union[str, bytes],
        organization: str = None,
        organizational_unit: str = None,
        country: str = 'US',
        state: str = None,
        locality: str = None,
        validity_years: int = 5,
        key_type: str = 'rsa',
        key_size_or_curve=4096,
        key_password: bytes = None,
        issuer_key_password: bytes = None,
        crl_distribution_points: List[str] = None,
        ocsp_url: str = None,
    ) -> Dict:
        """Create an Issuing CA (path_length=0) signed by an intermediate CA."""
        result = self.create_intermediate_ca(
            common_name=common_name,
            issuer_cert_pem=issuer_cert_pem,
            issuer_key_pem=issuer_key_pem,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state=state,
            locality=locality,
            validity_years=validity_years,
            key_type=key_type,
            key_size_or_curve=key_size_or_curve,
            path_length=0,
            key_password=key_password,
            issuer_key_password=issuer_key_password,
            crl_distribution_points=crl_distribution_points,
            ocsp_url=ocsp_url,
        )
        result['ca_type'] = CertificateType.ISSUING_CA
        return result

    # ── End-entity issuance ────────────────────────────────────────────────

    def issue_certificate(
        self,
        common_name: str,
        ca_cert_pem: Union[str, bytes],
        ca_key_pem: Union[str, bytes],
        cert_type: str = CertificateType.SERVER,
        san_dns: List[str] = None,
        san_ips: List[str] = None,
        san_emails: List[str] = None,
        san_uris: List[str] = None,
        organization: str = None,
        organizational_unit: str = None,
        country: str = None,
        state: str = None,
        locality: str = None,
        email: str = None,
        validity_days: int = 365,
        key_type: str = 'rsa',
        key_size_or_curve=2048,
        key_password: bytes = None,
        ca_key_password: bytes = None,
        crl_distribution_points: List[str] = None,
        ocsp_url: str = None,
        existing_csr_pem: Union[str, bytes] = None,
        pkinit_principal: str = None,
    ) -> Dict:
        """
        Issue an end-entity certificate from the given CA.

        cert_type: server | client | code_signing | email | ocsp | timestamping

        Pass existing_csr_pem to sign an external CSR instead of generating a new key.
        Returns cert_pem (and key_pem when a new key is generated).
        """
        ca_cert = self.load_cert(ca_cert_pem)
        ca_key  = self.load_key(ca_key_pem, ca_key_password)

        if existing_csr_pem:
            if isinstance(existing_csr_pem, str):
                existing_csr_pem = existing_csr_pem.encode()
            csr = x509.load_pem_x509_csr(existing_csr_pem)
            if not csr.is_signature_valid:
                raise ValueError("CSR signature is invalid")
            pub_key = csr.public_key()
            key_pem_out = None
        else:
            priv_key    = self.generate_key(key_type, key_size_or_curve)
            pub_key     = priv_key.public_key()
            key_pem_out = self.serialize_key(priv_key, key_password).decode()

        subject = self._name(common_name, organization, organizational_unit, country, state, locality, email)
        serial  = x509.random_serial_number()
        now     = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)

        builder = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(pub_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        )

        ku, eku = self._build_usages(cert_type)
        builder = builder.add_extension(ku, critical=True)
        if eku:
            builder = builder.add_extension(eku, critical=False)

        sans = self._build_san(
            common_name, cert_type, san_dns, san_ips, san_emails, san_uris,
            pkinit_principal=pkinit_principal,
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        builder = self._add_cdp(builder, crl_distribution_points)
        builder = self._add_aia(builder, ocsp_url)
        cert = builder.sign(ca_key, hashes.SHA256())

        result = {
            'cert_pem': cert.public_bytes(Encoding.PEM).decode(),
            'serial_number': str(serial),
            'common_name': common_name,
            'cert_type': cert_type,
            'not_valid_before': now.isoformat(),
            'not_valid_after': expires.isoformat(),
            'days_validity': validity_days,
            'san_dns': san_dns or [],
            'san_ips': san_ips or [],
            'san_emails': san_emails or [],
            'key_type': key_type,
            'issuing_ca_cn': self._cn(ca_cert),
            'pkinit_principal': pkinit_principal,
        }
        if key_pem_out:
            result['key_pem'] = key_pem_out
        return result

    def sign_csr(
        self,
        csr_pem: Union[str, bytes],
        ca_cert_pem: Union[str, bytes],
        ca_key_pem: Union[str, bytes],
        cert_type: str = CertificateType.SERVER,
        validity_days: int = 365,
        san_dns: List[str] = None,
        san_ips: List[str] = None,
        san_emails: List[str] = None,
        ca_key_password: bytes = None,
        crl_distribution_points: List[str] = None,
        ocsp_url: str = None,
        pkinit_principal: str = None,
    ) -> Dict:
        """Sign an external CSR. SANs are taken from the CSR if not overridden."""
        if isinstance(csr_pem, str):
            csr_pem = csr_pem.encode()
        csr = x509.load_pem_x509_csr(csr_pem)
        cn = self._csr_cn(csr)

        # Pull SANs from CSR if caller didn't supply them
        if san_dns is None and san_ips is None and san_emails is None:
            try:
                san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_dns    = list(san_ext.value.get_values_for_type(x509.DNSName))
                san_ips    = [str(n) for n in san_ext.value.get_values_for_type(x509.IPAddress)]
                san_emails = list(san_ext.value.get_values_for_type(x509.RFC822Name))
            except x509.ExtensionNotFound:
                pass

        return self.issue_certificate(
            common_name=cn,
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            cert_type=cert_type,
            san_dns=san_dns,
            san_ips=san_ips,
            san_emails=san_emails,
            validity_days=validity_days,
            ca_key_password=ca_key_password,
            crl_distribution_points=crl_distribution_points,
            ocsp_url=ocsp_url,
            existing_csr_pem=csr_pem,
            pkinit_principal=pkinit_principal,
        )

    def generate_csr(
        self,
        common_name: str,
        key_type: str = 'rsa',
        key_size_or_curve=2048,
        organization: str = None,
        organizational_unit: str = None,
        country: str = None,
        state: str = None,
        locality: str = None,
        san_dns: List[str] = None,
        san_ips: List[str] = None,
        san_emails: List[str] = None,
        key_password: bytes = None,
    ) -> Dict:
        """Generate a key + CSR (PKCS#10). Returns key_pem and csr_pem."""
        key     = self.generate_key(key_type, key_size_or_curve)
        subject = self._name(common_name, organization, organizational_unit, country, state, locality)
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        sans    = self._build_san(common_name, CertificateType.SERVER, san_dns, san_ips, san_emails, None)
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        csr = builder.sign(key, hashes.SHA256())
        return {
            'key_pem': self.serialize_key(key, key_password).decode(),
            'csr_pem': csr.public_bytes(Encoding.PEM).decode(),
            'common_name': common_name,
            'key_type': key_type,
        }

    # ── CRL management ─────────────────────────────────────────────────────

    def generate_crl(
        self,
        ca_cert_pem: Union[str, bytes],
        ca_key_pem: Union[str, bytes],
        revoked_serials: List[Dict] = None,
        validity_days: int = 7,
        ca_key_password: bytes = None,
    ) -> str:
        """
        Generate a CRL (Certificate Revocation List).

        revoked_serials: list of dicts with 'serial' (int/str), optional 'reason',
                         optional 'revocation_time' (datetime or ISO string).
        Returns PEM CRL string.
        """
        ca_cert = self.load_cert(ca_cert_pem)
        ca_key  = self.load_key(ca_key_pem, ca_key_password)
        now     = datetime.now(timezone.utc)

        builder = (
            CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=validity_days))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            .add_extension(x509.CRLNumber(secrets.randbelow(2**63)), critical=False)
        )

        reason_map = {
            'unspecified':           x509.ReasonFlags.unspecified,
            'key_compromise':        x509.ReasonFlags.key_compromise,
            'ca_compromise':         x509.ReasonFlags.ca_compromise,
            'affiliation_changed':   x509.ReasonFlags.affiliation_changed,
            'superseded':            x509.ReasonFlags.superseded,
            'cessation_of_operation':x509.ReasonFlags.cessation_of_operation,
            'certificate_hold':      x509.ReasonFlags.certificate_hold,
            'privilege_withdrawn':   x509.ReasonFlags.privilege_withdrawn,
        }

        for entry in (revoked_serials or []):
            serial   = int(entry['serial'])
            rev_time = entry.get('revocation_time', now)
            if isinstance(rev_time, str):
                rev_time = datetime.fromisoformat(rev_time)
            if rev_time.tzinfo is None:
                rev_time = rev_time.replace(tzinfo=timezone.utc)
            reason = reason_map.get(entry.get('reason', 'unspecified').lower(),
                                    x509.ReasonFlags.unspecified)
            revoked = (
                RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(rev_time)
                .add_extension(x509.CRLReason(reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(Encoding.PEM).decode()

    def revoke_certificate(
        self,
        cert_pem: Union[str, bytes],
        ca_cert_pem: Union[str, bytes],
        ca_key_pem: Union[str, bytes],
        reason: str = 'unspecified',
        existing_crl_pem: Union[str, bytes] = None,
        ca_key_password: bytes = None,
    ) -> Dict:
        """Revoke a certificate and return an updated CRL."""
        cert   = self.load_cert(cert_pem)
        serial = cert.serial_number

        revoked_serials = []
        if existing_crl_pem:
            if isinstance(existing_crl_pem, str):
                existing_crl_pem = existing_crl_pem.encode()
            crl = x509.load_pem_x509_crl(existing_crl_pem)
            for rev in crl:
                rd = (rev.revocation_date_utc
                      if hasattr(rev, 'revocation_date_utc')
                      else rev.revocation_date.replace(tzinfo=timezone.utc))
                revoked_serials.append({'serial': rev.serial_number, 'revocation_time': rd})

        revoked_serials.append({
            'serial': serial,
            'reason': reason,
            'revocation_time': datetime.now(timezone.utc),
        })

        crl_pem = self.generate_crl(ca_cert_pem, ca_key_pem, revoked_serials,
                                     ca_key_password=ca_key_password)
        return {
            'success': True,
            'crl_pem': crl_pem,
            'revoked_serial': str(serial),
            'revoked_cn': self._cn(cert),
            'reason': reason,
            'revocation_time': datetime.now(timezone.utc).isoformat(),
        }

    def build_chain_pem(self, *cert_pems: Union[str, bytes]) -> str:
        """Concatenate certs into a chain PEM (leaf first, root last)."""
        parts = []
        for pem in cert_pems:
            s = pem.decode() if isinstance(pem, bytes) else pem
            parts.append(s.strip())
        return '\n'.join(parts) + '\n'

    def get_certificate_info(self, cert_pem: Union[str, bytes]) -> Dict:
        """Return human-readable info dict for a PEM certificate."""
        cert = self.load_cert(cert_pem)
        nav = (cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc')
               else cert.not_valid_after.replace(tzinfo=timezone.utc))
        nbv = (cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc')
               else cert.not_valid_before.replace(tzinfo=timezone.utc))
        now = datetime.now(timezone.utc)
        return {
            'serial_number': str(cert.serial_number),
            'common_name': self._cn(cert),
            'issuer_cn': self._issuer_cn(cert),
            'not_valid_before': nbv.isoformat(),
            'not_valid_after': nav.isoformat(),
            'days_until_expiry': (nav - now).days,
            'is_ca': self._is_ca(cert),
            'signature_algorithm': cert.signature_algorithm_oid._name,
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _build_usages(self, cert_type: str) -> Tuple:
        """Return (KeyUsage, ExtendedKeyUsage | None) for a cert type."""
        ku_args = dict(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        )
        if cert_type == CertificateType.SERVER:
            ku_args.update(digital_signature=True, key_encipherment=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        elif cert_type == CertificateType.CLIENT:
            ku_args.update(digital_signature=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        elif cert_type == CertificateType.CODE_SIGNING:
            ku_args.update(digital_signature=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        elif cert_type == CertificateType.EMAIL:
            ku_args.update(digital_signature=True, content_commitment=True, key_encipherment=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION])
        elif cert_type == CertificateType.OCSP:
            ku_args.update(digital_signature=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING])
        elif cert_type == CertificateType.TIMESTAMPING:
            ku_args.update(digital_signature=True, content_commitment=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING])
        elif cert_type == CertificateType.PKINIT_CLIENT:
            ku_args.update(digital_signature=True)
            eku = x509.ExtendedKeyUsage([PKINIT_CLIENT_EKU_OID])
        elif cert_type == CertificateType.PKINIT_KDC:
            ku_args.update(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, key_agreement=True,
            )
            eku = x509.ExtendedKeyUsage([PKINIT_KDC_EKU_OID])
        else:
            # Default to server
            ku_args.update(digital_signature=True, key_encipherment=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        return x509.KeyUsage(**ku_args), eku

    def _build_san(self, cn, cert_type, san_dns, san_ips, san_emails, san_uris,
                   pkinit_principal=None):
        san = []
        # For server/client auto-include CN as DNS SAN when no explicit SANs given
        if cert_type in (CertificateType.SERVER, CertificateType.CLIENT) and san_dns is None:
            san.append(x509.DNSName(cn))
        for d in (san_dns or []):
            san.append(x509.DNSName(d))
        for ip in (san_ips or []):
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                self.logger.warning(f"Skipping invalid IP SAN: {ip}")
        for e in (san_emails or []):
            san.append(x509.RFC822Name(e))
        for u in (san_uris or []):
            san.append(x509.UniformResourceIdentifier(u))
        if cert_type in (CertificateType.PKINIT_CLIENT, CertificateType.PKINIT_KDC):
            if not pkinit_principal:
                raise ValueError('pkinit_principal is required for PKINIT certificate profiles')
            san.append(x509.OtherName(PKINIT_SAN_OID, self._encode_pkinit_principal(pkinit_principal)))
        return san

    @staticmethod
    def _der_length(length):
        if length < 128:
            return bytes([length])
        encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(encoded)]) + encoded

    @classmethod
    def _der(cls, tag, content):
        return bytes([tag]) + cls._der_length(len(content)) + content

    @classmethod
    def _encode_pkinit_principal(cls, principal):
        """Encode RFC 4556 KRB5PrincipalName for an OtherName SAN."""
        if '@' not in principal:
            raise ValueError('PKINIT principal must include a realm (name@REALM)')
        name, realm = principal.rsplit('@', 1)
        components = [item for item in name.split('/') if item]
        if not components or not realm:
            raise ValueError('PKINIT principal is invalid')
        name_type = 2 if len(components) > 1 else 1
        integer = cls._der(0x02, bytes([name_type]))
        names = b''.join(cls._der(0x1B, item.encode('utf-8')) for item in components)
        principal_name = cls._der(0x30, cls._der(0xA0, integer) + cls._der(0xA1, cls._der(0x30, names)))
        body = cls._der(0xA0, cls._der(0x1B, realm.encode('utf-8'))) + cls._der(0xA1, principal_name)
        return cls._der(0x30, body)

    def _add_cdp(self, builder, urls):
        if not urls:
            return builder
        return builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(u)],
                    relative_name=None, reasons=None, crl_issuer=None,
                ) for u in urls
            ]),
            critical=False,
        )

    def _add_aia(self, builder, ocsp_url):
        if not ocsp_url:
            return builder
        return builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )

    def _cn(self, cert):
        try:
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            return ''

    def _issuer_cn(self, cert):
        try:
            return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            return ''

    def _csr_cn(self, csr):
        try:
            return csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            return 'Unknown'

    def _is_ca(self, cert):
        try:
            return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            return False
