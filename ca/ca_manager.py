"""
Database-backed CA manager.
Wraps PrivateCAManager with SQLAlchemy persistence for the PrivateCA and
PrivatelyIssuedCertificate models.
"""
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from database.models import DatabaseManager, PrivateCA, PrivatelyIssuedCertificate
from ca.private_ca import PrivateCAManager, CertificateType


class CAManager:
    """
    High-level interface for private PKI operations.
    All crypto is delegated to PrivateCAManager; this class owns DB I/O.
    """

    def __init__(self, db_manager: DatabaseManager, key_storage_dir: str = None):
        self.db = db_manager
        key_dir = key_storage_dir or os.environ.get('SSLMGR_KEY_DIR', './ca_keys')
        self.pki = PrivateCAManager(key_dir)

    # ── Key file helpers ─────────────────────────────────────────────────────

    def _save_key(self, slug: str, key_pem: str) -> str:
        path = self.pki.key_storage_dir / f"{slug}.key.pem"
        path.write_text(key_pem)
        path.chmod(0o600)
        return str(path)

    def _load_ca_key(self, ca: PrivateCA) -> str:
        return Path(ca.key_file_path).read_text()

    @staticmethod
    def _slug(name: str) -> str:
        return name.lower().replace(' ', '_').replace('/', '_')

    # ── CA creation ──────────────────────────────────────────────────────────

    def create_root_ca(self, name: str, **kwargs) -> Dict:
        """Create a self-signed root CA and persist it."""
        common_name = kwargs.pop('common_name', name)
        result = self.pki.create_root_ca(common_name, **kwargs)
        key_path = self._save_key(self._slug(name), result['key_pem'])

        session = self.db.get_session()
        try:
            rec = PrivateCA(
                name=name,
                ca_type='root',
                common_name=result['common_name'],
                organization=kwargs.get('organization'),
                organizational_unit=kwargs.get('organizational_unit'),
                country=kwargs.get('country', 'US'),
                state=kwargs.get('state'),
                locality=kwargs.get('locality'),
                cert_pem=result['cert_pem'],
                key_file_path=key_path,
                not_valid_before=datetime.fromisoformat(result['not_valid_before']),
                not_valid_after=datetime.fromisoformat(result['not_valid_after']),
                key_type=result['key_type'],
                validity_years=kwargs.get('validity_years', 20),
                path_length=kwargs.get('path_length'),
                is_active=True,
            )
            session.add(rec)
            session.commit()
            session.refresh(rec)
            return {'success': True, 'ca_id': rec.id, 'name': rec.name,
                    'common_name': rec.common_name, 'cert_pem': rec.cert_pem}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    def create_intermediate_ca(self, name: str, parent_id: int, **kwargs) -> Dict:
        """Create an intermediate CA signed by an existing parent CA."""
        session = self.db.get_session()
        try:
            parent = session.query(PrivateCA).filter_by(id=parent_id).first()
            if not parent:
                return {'success': False, 'error': f'Parent CA {parent_id} not found'}

            common_name = kwargs.pop('common_name', name)
            parent_key = self._load_ca_key(parent)
            result = self.pki.create_intermediate_ca(
                common_name=common_name,
                issuer_cert_pem=parent.cert_pem,
                issuer_key_pem=parent_key,
                **kwargs,
            )
            key_path = self._save_key(self._slug(name), result['key_pem'])

            rec = PrivateCA(
                name=name,
                ca_type='intermediate',
                common_name=result['common_name'],
                parent_id=parent_id,
                organization=kwargs.get('organization'),
                organizational_unit=kwargs.get('organizational_unit'),
                country=kwargs.get('country', 'US'),
                state=kwargs.get('state'),
                locality=kwargs.get('locality'),
                cert_pem=result['cert_pem'],
                key_file_path=key_path,
                not_valid_before=datetime.fromisoformat(result['not_valid_before']),
                not_valid_after=datetime.fromisoformat(result['not_valid_after']),
                key_type=result['key_type'],
                validity_years=kwargs.get('validity_years', 10),
                path_length=kwargs.get('path_length', 0),
                is_active=True,
            )
            session.add(rec)
            session.commit()
            session.refresh(rec)
            return {'success': True, 'ca_id': rec.id, 'name': rec.name,
                    'common_name': rec.common_name, 'cert_pem': rec.cert_pem}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    def create_issuing_ca(self, name: str, parent_id: int, **kwargs) -> Dict:
        """Create an issuing CA (path_length=0) signed by an existing parent CA."""
        session = self.db.get_session()
        try:
            parent = session.query(PrivateCA).filter_by(id=parent_id).first()
            if not parent:
                return {'success': False, 'error': f'Parent CA {parent_id} not found'}

            common_name = kwargs.pop('common_name', name)
            parent_key = self._load_ca_key(parent)
            result = self.pki.create_issuing_ca(
                common_name=common_name,
                issuer_cert_pem=parent.cert_pem,
                issuer_key_pem=parent_key,
                **kwargs,
            )
            key_path = self._save_key(self._slug(name), result['key_pem'])

            rec = PrivateCA(
                name=name,
                ca_type='issuing',
                common_name=result['common_name'],
                parent_id=parent_id,
                organization=kwargs.get('organization'),
                organizational_unit=kwargs.get('organizational_unit'),
                country=kwargs.get('country', 'US'),
                state=kwargs.get('state'),
                locality=kwargs.get('locality'),
                cert_pem=result['cert_pem'],
                key_file_path=key_path,
                not_valid_before=datetime.fromisoformat(result['not_valid_before']),
                not_valid_after=datetime.fromisoformat(result['not_valid_after']),
                key_type=result['key_type'],
                validity_years=kwargs.get('validity_years', 5),
                path_length=0,
                is_active=True,
            )
            session.add(rec)
            session.commit()
            session.refresh(rec)
            return {'success': True, 'ca_id': rec.id, 'name': rec.name,
                    'common_name': rec.common_name, 'cert_pem': rec.cert_pem}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    # ── Certificate issuance ─────────────────────────────────────────────────

    def bootstrap_hierarchy(self, name_prefix: str, common_name_prefix: str = None,
                            **kwargs) -> Dict:
        """Create Root → Intermediate 1 → Intermediate 2 → Issuing CA."""
        cn = common_name_prefix or name_prefix
        root_years = kwargs.pop('root_validity_years', 20)
        intermediate_years = kwargs.pop('intermediate_validity_years', 10)
        issuing_years = kwargs.pop('issuing_validity_years', 5)
        definitions = []

        root = self.create_root_ca(
            f'{name_prefix}-root', common_name=f'{cn} Root CA',
            validity_years=root_years, path_length=3, **kwargs)
        if not root.get('success'):
            return root
        definitions.append((root['ca_id'], 'root', 3, root['cert_pem']))

        inter1 = self.create_intermediate_ca(
            f'{name_prefix}-intermediate-1', root['ca_id'],
            common_name=f'{cn} Intermediate CA 1', validity_years=intermediate_years,
            path_length=2, **kwargs)
        if not inter1.get('success'):
            return inter1
        definitions.append((inter1['ca_id'], 'intermediate', 2, inter1['cert_pem']))

        inter2 = self.create_intermediate_ca(
            f'{name_prefix}-intermediate-2', inter1['ca_id'],
            common_name=f'{cn} Intermediate CA 2', validity_years=intermediate_years,
            path_length=1, **kwargs)
        if not inter2.get('success'):
            return inter2
        definitions.append((inter2['ca_id'], 'intermediate', 1, inter2['cert_pem']))

        issuing = self.create_issuing_ca(
            f'{name_prefix}-issuing', inter2['ca_id'],
            common_name=f'{cn} Issuing CA', validity_years=issuing_years, **kwargs)
        if not issuing.get('success'):
            return issuing
        definitions.append((issuing['ca_id'], 'issuing', 0, issuing['cert_pem']))

        hierarchy = [
            {'id': ca_id, 'ca_type': ca_type, 'path_length': path_length}
            for ca_id, ca_type, path_length, _ in definitions
        ]
        chain_pem = self.pki.build_chain_pem(*(item[3] for item in reversed(definitions)))
        return {'success': True, 'hierarchy': hierarchy,
                'issuing_ca_id': issuing['ca_id'], 'chain_pem': chain_pem}

    def issue_certificate(self, ca_id: int, common_name: str,
                          cert_type: str = 'server', **kwargs) -> Dict:
        """Issue an end-entity certificate from the given CA."""
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id, is_active=True).first()
            if not ca:
                return {'success': False, 'error': f'CA {ca_id} not found or inactive'}

            ca_key = self._load_ca_key(ca)
            result = self.pki.issue_certificate(
                common_name=common_name,
                ca_cert_pem=ca.cert_pem,
                ca_key_pem=ca_key,
                cert_type=cert_type,
                **kwargs,
            )

            key_path = None
            if result.get('key_pem'):
                slug = common_name.replace('*', 'wildcard').replace('.', '_').replace(' ', '_')
                key_path = self._save_key(f"cert_{slug}", result['key_pem'])

            rec = PrivatelyIssuedCertificate(
                ca_id=ca_id,
                serial_number=result['serial_number'],
                common_name=common_name,
                cert_type=cert_type,
                cert_pem=result['cert_pem'],
                key_file_path=key_path,
                san_dns=result.get('san_dns'),
                san_ips=result.get('san_ips'),
                san_emails=result.get('san_emails'),
                not_valid_before=datetime.fromisoformat(result['not_valid_before']),
                not_valid_after=datetime.fromisoformat(result['not_valid_after']),
                days_validity=result.get('days_validity'),
            )
            session.add(rec)
            session.commit()
            session.refresh(rec)

            out = {
                'success': True,
                'cert_id': rec.id,
                'cert_pem': result['cert_pem'],
                'serial_number': result['serial_number'],
                'not_valid_after': result['not_valid_after'],
            }
            if result.get('key_pem'):
                out['key_pem'] = result['key_pem']
            return out
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    def sign_csr(self, ca_id: int, csr_pem: str, cert_type: str = 'server',
                 validity_days: int = 365, **kwargs) -> Dict:
        """Sign an external CSR with the given CA."""
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id, is_active=True).first()
            if not ca:
                return {'success': False, 'error': f'CA {ca_id} not found or inactive'}

            ca_key = self._load_ca_key(ca)
            result = self.pki.sign_csr(
                csr_pem=csr_pem,
                ca_cert_pem=ca.cert_pem,
                ca_key_pem=ca_key,
                cert_type=cert_type,
                validity_days=validity_days,
                **kwargs,
            )

            rec = PrivatelyIssuedCertificate(
                ca_id=ca_id,
                serial_number=result['serial_number'],
                common_name=result.get('common_name', ''),
                cert_type=cert_type,
                cert_pem=result['cert_pem'],
                san_dns=result.get('san_dns'),
                san_ips=result.get('san_ips'),
                san_emails=result.get('san_emails'),
                not_valid_before=datetime.fromisoformat(result['not_valid_before']),
                not_valid_after=datetime.fromisoformat(result['not_valid_after']),
                days_validity=result.get('days_validity'),
            )
            session.add(rec)
            session.commit()
            session.refresh(rec)

            return {'success': True, 'cert_id': rec.id, 'cert_pem': result['cert_pem'],
                    'serial_number': result['serial_number']}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    # ── Revocation ───────────────────────────────────────────────────────────

    def revoke_certificate(self, ca_id: int, cert_id: int,
                           reason: str = 'unspecified') -> Dict:
        """Revoke a certificate and regenerate the CA's CRL."""
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id).first()
            cert = session.query(PrivatelyIssuedCertificate).filter_by(
                id=cert_id, ca_id=ca_id
            ).first()

            if not ca or not cert:
                return {'success': False, 'error': 'CA or certificate not found'}
            if cert.is_revoked:
                return {'success': False, 'error': 'Certificate is already revoked'}

            ca_key = self._load_ca_key(ca)
            result = self.pki.revoke_certificate(
                cert_pem=cert.cert_pem,
                ca_cert_pem=ca.cert_pem,
                ca_key_pem=ca_key,
                reason=reason,
                existing_crl_pem=ca.crl_pem,
            )

            cert.is_revoked = True
            cert.revocation_reason = reason
            cert.revoked_at = datetime.now(timezone.utc)
            ca.crl_pem = result['crl_pem']
            ca.crl_last_generated = datetime.now(timezone.utc)

            session.commit()
            return {'success': True, 'crl_pem': result['crl_pem'],
                    'revoked_serial': result['revoked_serial']}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    def regenerate_crl(self, ca_id: int) -> Dict:
        """Rebuild the CRL for a CA from all revoked cert records."""
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id).first()
            if not ca:
                return {'success': False, 'error': 'CA not found'}

            ca_key = self._load_ca_key(ca)
            revoked = session.query(PrivatelyIssuedCertificate).filter_by(
                ca_id=ca_id, is_revoked=True
            ).all()

            revoked_serials = [
                {
                    'serial': c.serial_number,
                    'reason': c.revocation_reason or 'unspecified',
                    'revocation_time': c.revoked_at or datetime.now(timezone.utc),
                }
                for c in revoked
            ]

            crl_pem = self.pki.generate_crl(
                ca_cert_pem=ca.cert_pem,
                ca_key_pem=ca_key,
                revoked_serials=revoked_serials,
            )
            ca.crl_pem = crl_pem
            ca.crl_last_generated = datetime.now(timezone.utc)
            session.commit()
            return {'success': True, 'crl_pem': crl_pem}
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

    # ── Queries ──────────────────────────────────────────────────────────────

    def list_cas(self) -> List[Dict]:
        session = self.db.get_session()
        try:
            cas = session.query(PrivateCA).order_by(PrivateCA.id).all()
            return [self._ca_dict(c) for c in cas]
        finally:
            session.close()

    def get_ca(self, ca_id: int) -> Optional[Dict]:
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id).first()
            return self._ca_dict(ca) if ca else None
        finally:
            session.close()

    def list_issued_certs(self, ca_id: int) -> List[Dict]:
        session = self.db.get_session()
        try:
            certs = (session.query(PrivatelyIssuedCertificate)
                     .filter_by(ca_id=ca_id)
                     .order_by(PrivatelyIssuedCertificate.id)
                     .all())
            return [self._cert_dict(c) for c in certs]
        finally:
            session.close()

    def get_issued_cert(self, cert_id: int) -> Optional[Dict]:
        session = self.db.get_session()
        try:
            cert = session.query(PrivatelyIssuedCertificate).filter_by(id=cert_id).first()
            return self._cert_dict(cert) if cert else None
        finally:
            session.close()

    def get_crl(self, ca_id: int) -> Optional[str]:
        session = self.db.get_session()
        try:
            ca = session.query(PrivateCA).filter_by(id=ca_id).first()
            return ca.crl_pem if ca else None
        finally:
            session.close()

    # ── Serialisation helpers ────────────────────────────────────────────────

    def _ca_dict(self, ca: PrivateCA) -> Dict:
        return {
            'id': ca.id,
            'name': ca.name,
            'ca_type': ca.ca_type,
            'common_name': ca.common_name,
            'parent_id': ca.parent_id,
            'organization': ca.organization,
            'country': ca.country,
            'not_valid_before': ca.not_valid_before.isoformat() if ca.not_valid_before else None,
            'not_valid_after': ca.not_valid_after.isoformat() if ca.not_valid_after else None,
            'key_type': ca.key_type,
            'is_active': ca.is_active,
            'ocsp_url': ca.ocsp_url,
            'crl_distribution_url': ca.crl_distribution_url,
            'crl_last_generated': ca.crl_last_generated.isoformat() if ca.crl_last_generated else None,
            'cert_pem': ca.cert_pem,
        }

    def _cert_dict(self, cert: PrivatelyIssuedCertificate) -> Dict:
        return {
            'id': cert.id,
            'ca_id': cert.ca_id,
            'serial_number': cert.serial_number,
            'common_name': cert.common_name,
            'cert_type': cert.cert_type,
            'not_valid_before': cert.not_valid_before.isoformat() if cert.not_valid_before else None,
            'not_valid_after': cert.not_valid_after.isoformat() if cert.not_valid_after else None,
            'days_validity': cert.days_validity,
            'is_revoked': cert.is_revoked,
            'revocation_reason': cert.revocation_reason,
            'revoked_at': cert.revoked_at.isoformat() if cert.revoked_at else None,
            'san_dns': cert.san_dns,
            'san_ips': cert.san_ips,
            'san_emails': cert.san_emails,
            'cert_pem': cert.cert_pem,
        }
