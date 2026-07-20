"""CSR-based host enrollment and certificate lifecycle service."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from database.models import EnrollmentToken, ManagedAgent, PrivateCA


class EnrollmentService:
    def __init__(self, db_manager, ca_manager, renewal_threshold_days=30):
        self.db = db_manager
        self.ca_manager = ca_manager
        self.renewal_threshold_days = int(renewal_threshold_days)

    @staticmethod
    def _token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _fingerprint(cert_pem):
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        return cert.fingerprint(hashes.SHA256()).hex()

    def create_token(self, ca_id, name, cert_type='server', ttl_hours=1,
                     max_uses=1, pkinit_principal=None):
        ca = self.ca_manager.get_ca(ca_id)
        if not ca or ca['ca_type'] != 'issuing' or not ca['is_active']:
            return self._error('authorization', 'An active issuing CA is required')
        plaintext = secrets.token_urlsafe(32)
        session = self.db.get_session()
        try:
            record = EnrollmentToken(
                token_hash=self._token_hash(plaintext), name=name, ca_id=ca_id,
                cert_type=cert_type, pkinit_principal=pkinit_principal,
                expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
                max_uses=max_uses, uses=0,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return {'success': True, 'token_id': record.id, 'token': plaintext,
                    'expires_at': record.expires_at.isoformat()}
        finally:
            session.close()

    def enroll(self, token, csr_pem, validity_days=90):
        session = self.db.get_session()
        try:
            record = session.query(EnrollmentToken).filter_by(
                token_hash=self._token_hash(token)).first()
            if not record or record.is_revoked or record.uses >= record.max_uses:
                return self._error('authentication', 'Enrollment token is invalid or already used')
            if record.expires_at < datetime.utcnow():
                return self._error('authentication', 'Enrollment token has expired')
            issued = self.ca_manager.sign_csr(
                record.ca_id, csr_pem, cert_type=record.cert_type,
                validity_days=validity_days,
                pkinit_principal=record.pkinit_principal,
            )
            if not issued.get('success'):
                return self._error('validation', issued.get('error', 'Certificate issuance failed'))
            fingerprint = self._fingerprint(issued['cert_pem'])
            agent = ManagedAgent(
                name=record.name, ca_id=record.ca_id,
                certificate_id=issued['cert_id'], cert_type=record.cert_type,
                pkinit_principal=record.pkinit_principal,
                certificate_fingerprint=fingerprint,
                last_seen_at=datetime.utcnow(),
            )
            record.uses += 1
            session.add(agent)
            session.commit()
            session.refresh(agent)
            return self._certificate_response(agent, issued)
        except Exception as exc:
            session.rollback()
            return self._error('validation', str(exc))
        finally:
            session.close()

    def renew(self, agent_id, certificate_fingerprint, csr_pem, validity_days=90,
              force=False):
        session = self.db.get_session()
        try:
            agent = session.query(ManagedAgent).filter_by(uuid=agent_id).first()
            auth_error = self._authenticate(agent, certificate_fingerprint)
            if auth_error:
                return auth_error
            if agent.is_revoked:
                return self._error('authorization', 'Agent is revoked')
            current = self.ca_manager.get_issued_cert(agent.certificate_id)
            if not force and current and current.get('not_valid_after'):
                expires = datetime.fromisoformat(current['not_valid_after'])
                if expires.tzinfo is not None:
                    expires = expires.replace(tzinfo=None)
                if expires - datetime.utcnow() > timedelta(days=self.renewal_threshold_days):
                    return self._error('authorization', 'Certificate is not within the renewal window')
            issued = self.ca_manager.sign_csr(
                agent.ca_id, csr_pem, cert_type=agent.cert_type,
                validity_days=validity_days,
                pkinit_principal=agent.pkinit_principal,
            )
            if not issued.get('success'):
                return self._error('validation', issued.get('error', 'Certificate issuance failed'))
            agent.certificate_id = issued['cert_id']
            agent.certificate_fingerprint = self._fingerprint(issued['cert_pem'])
            agent.last_seen_at = datetime.utcnow()
            session.commit()
            return self._certificate_response(agent, issued)
        except Exception as exc:
            session.rollback()
            return self._error('validation', str(exc))
        finally:
            session.close()

    def revoke(self, agent_id, reason='unspecified', certificate_fingerprint=None):
        session = self.db.get_session()
        try:
            agent = session.query(ManagedAgent).filter_by(uuid=agent_id).first()
            auth_error = self._authenticate(agent, certificate_fingerprint)
            if auth_error:
                return auth_error
            result = self.ca_manager.revoke_certificate(agent.ca_id, agent.certificate_id, reason)
            if result.get('success'):
                agent.is_revoked = True
                agent.last_seen_at = datetime.utcnow()
                session.commit()
            return result
        finally:
            session.close()

    def _authenticate(self, agent, fingerprint):
        if not agent or not fingerprint or not hmac.compare_digest(
                agent.certificate_fingerprint, fingerprint.lower()):
            return self._error('authentication', 'Agent certificate authentication failed')
        return None

    def _certificate_response(self, agent, issued):
        return {
            'success': True, 'agent_id': agent.uuid,
            'certificate_id': issued['cert_id'], 'cert_pem': issued['cert_pem'],
            'chain_pem': self._chain_pem(agent.ca_id),
            'certificate_fingerprint': agent.certificate_fingerprint,
        }

    def _chain_pem(self, ca_id):
        session = self.db.get_session()
        try:
            chain = []
            current = session.query(PrivateCA).filter_by(id=ca_id).first()
            while current:
                chain.append(current.cert_pem.strip())
                current = current.parent
            return '\n'.join(chain) + '\n'
        finally:
            session.close()

    @staticmethod
    def _error(kind, message):
        return {'success': False, 'error': message, 'error_kind': kind,
                'retryable': False}
