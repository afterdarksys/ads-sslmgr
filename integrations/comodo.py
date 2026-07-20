"""
Sectigo (formerly Comodo CA) Certificate Manager (SCM) API integration.
Supports: enroll, renew, collect, revoke, list — for both SSL and client certs.

Auth: Sectigo SCM uses HTTP Basic-style headers:
    login       — customer login (email)
    password    — customer password or API password
    customerUri — your SCM organisation URI (e.g. 'mycompany')

Set these in config.certificate_authorities.sectigo (or comodo) section.
"""

import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import requests

from database.models import Certificate, RenewalAttempt, DatabaseManager
from providers.certificates import atomic_write_certificate, parse_pem_bundle

log = logging.getLogger(__name__)

_BASE_URL       = 'https://cert-manager.com/api'
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_RETRIES    = 4
_POLL_INTERVAL  = 15   # seconds
_POLL_TIMEOUT   = 600  # seconds

# Sectigo cert type IDs (serverType parameter)
SERVER_TYPES = {
    'server':        -1,   # auto-detect
    'apache':         2,
    'iis':            1,
    'nginx':         14,
    'other':         -1,
}

# Term values in days → Sectigo 'term' field (days)
TERMS = {1: 365, 2: 730, 3: 1095}


class ComodoIntegration:
    """Sectigo SCM API integration (replaces legacy Comodo integration)."""

    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config     = config
        self.db_manager = db_manager

        # Support both 'sectigo' and legacy 'comodo' config keys
        ca_cfg = (config.get('certificate_authorities', {}).get('sectigo')
                  or config.get('certificate_authorities', {}).get('comodo', {}))

        self.enabled      = ca_cfg.get('enabled', False)
        self.login        = ca_cfg.get('login', '')
        self.password     = ca_cfg.get('password', '')
        self.customer_uri = ca_cfg.get('customer_uri', '')
        self.org_id       = ca_cfg.get('org_id', '')
        self.base_url     = ca_cfg.get('base_url', _BASE_URL)
        self.cert_dir     = Path(config.get('directories', {}).get('certificates', './certificates'))
        self.cert_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────────────────

    def enroll_certificate(
        self,
        common_name: str,
        san_domains: List[str] = None,
        cert_type_id: int = 224,   # 224 = OV SSL; 283 = DV SSL — confirm with your account
        validity_days: int = 365,
        server_type: str = 'other',
        org_id: int = None,
        extra_fields: Dict = None,
    ) -> Dict:
        """
        Enroll a new SSL certificate.
        Returns ssl_id immediately; call poll_for_certificate(ssl_id) to get the PEM.
        """
        if not self._check_ready():
            return self._disabled_error()

        csr_result  = self._generate_csr(common_name, san_domains or [])
        san_str     = ','.join(san_domains) if san_domains else ''
        oid         = org_id or (int(self.org_id) if self.org_id else None)
        svr_type    = SERVER_TYPES.get(server_type, -1)
        term        = min(validity_days, 825)   # CA/B Forum max

        payload = {
            'orgId':      oid,
            'csr':        csr_result['csr_pem'],
            'subjAltNames': san_str,
            'certType':   cert_type_id,
            'numberServers': 1,
            'serverType': svr_type,
            'term':       term,
            'comments':   f'Enrolled via SSL Manager — {datetime.utcnow().isoformat()}',
        }
        if extra_fields:
            payload.update(extra_fields)

        resp = self._request('POST', '/ssl/v1/enroll', json=payload)
        if not resp['success']:
            return resp

        ssl_id = resp['data'].get('sslId') or resp['data'].get('id')
        return {
            'success':  True,
            'ssl_id':   ssl_id,
            'csr_pem':  csr_result['csr_pem'],
            'key_pem':  csr_result['key_pem'],
            'message':  f'Enrollment submitted, ssl_id={ssl_id}',
        }

    def poll_for_certificate(self, ssl_id: int, timeout: int = _POLL_TIMEOUT) -> Dict:
        """
        Poll until the certificate is issued, then collect and return it.
        Sectigo status codes: 0=requested, 1=approved, 2=issued, -1=revoked, etc.
        """
        if not self._check_ready():
            return self._disabled_error()

        deadline = time.time() + timeout
        while time.time() < deadline:
            detail = self._request('GET', f'/ssl/v1/{ssl_id}')
            if not detail['success']:
                return detail

            data   = detail['data']
            status = data.get('status', 0)

            if status == 2:   # issued
                return self.collect_certificate(ssl_id)
            if status < 0:    # revoked / rejected
                return {'success': False, 'error': f'ssl_id={ssl_id} has status {status} (rejected/revoked)'}

            log.debug(f'Sectigo ssl_id={ssl_id} status={status}, sleeping {_POLL_INTERVAL}s')
            time.sleep(_POLL_INTERVAL)

        return {'success': False, 'error': f'Timed out waiting for ssl_id={ssl_id} after {timeout}s'}

    def collect_certificate(self, ssl_id: int, format_type: str = 'x509CO') -> Dict:
        """
        Collect (download) an issued certificate.
        format_type: x509   = leaf only
                     x509CO = leaf + intermediates (default)
                     x509IOR = reverse chain
                     base64  = PKCS#7 base64
        """
        resp = self._request('GET', f'/ssl/v1/collect/{ssl_id}/{format_type}')
        if not resp['success']:
            return resp

        pem_data = resp['data']
        if isinstance(pem_data, dict):
            pem_data = pem_data.get('certificate', '')

        cert_file = self.cert_dir / f'sectigo_{ssl_id}.pem'
        try:
            from datetime import timezone
            cert_pem, chain_pem, c = parse_pem_bundle(pem_data)
            expiry = (c.not_valid_after_utc if hasattr(c, 'not_valid_after_utc')
                      else c.not_valid_after.replace(tzinfo=timezone.utc))
            atomic_write_certificate(cert_file, cert_pem)
        except Exception as exc:
            return {'success': False, 'error': str(exc), 'error_kind': 'validation',
                    'retryable': False, 'provider': 'sectigo'}

        return {
            'success':     True,
            'ssl_id':      ssl_id,
            'cert_pem':    cert_pem,
            'chain_pem':   chain_pem,
            'cert_path':   str(cert_file),
            'expiry_date': expiry,
            'message':     f'Certificate ssl_id={ssl_id} collected successfully',
        }

    def renew_certificate(self, cert: Certificate, domains: List[str] = None) -> Dict:
        """Renew by re-enrolling; Sectigo SCM does not have a true duplicate endpoint."""
        if not self._check_ready():
            return self._disabled_error()

        session = self.db_manager.get_session()
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='sectigo',
            renewal_method='api',
            status='pending',
        )
        session.add(attempt)
        session.commit()

        try:
            result = self._do_renewal(cert, domains)
            attempt.status               = 'success' if result['success'] else 'failed'
            attempt.error_message        = result.get('error') if not result['success'] else None
            attempt.new_expiry_date      = result.get('expiry_date')
            attempt.new_certificate_path = result.get('cert_path', '')
            session.commit()
            return result
        except Exception as exc:
            attempt.status        = 'failed'
            attempt.error_message = str(exc)
            session.commit()
            return {'success': False, 'error': str(exc)}
        finally:
            session.close()

    def revoke_certificate_api(self, ssl_id: int, reason: str = 'Superseded') -> Dict:
        payload = {'sslId': ssl_id, 'reason': reason}
        return self._request('POST', '/ssl/v1/revoke', json=payload)

    def list_certificates(self, size: int = 100, position: int = 0, status: int = None) -> Dict:
        params = {'size': size, 'position': position}
        if status is not None:
            params['status'] = status
        return self._request('GET', '/ssl/v1', params=params)

    def get_certificate_details(self, ssl_id: int) -> Dict:
        return self._request('GET', f'/ssl/v1/{ssl_id}')

    def get_account_info(self) -> Dict:
        return self._request('GET', '/account/v1/info')

    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        if cert.issuer_category not in ('sectigo', 'comodo'):
            return {'eligible': False, 'reason': 'Not a Sectigo/Comodo certificate'}
        if not self.login or not self.password or not self.customer_uri:
            return {'eligible': False, 'reason': 'Sectigo credentials not fully configured'}
        if cert.days_until_expiry > 90:
            return {'eligible': False,
                    'reason': f'Expires in {cert.days_until_expiry}d (renew within 90 days)'}
        return {'eligible': True, 'days_until_expiry': cert.days_until_expiry,
                'serial_number': cert.serial_number}

    def test_configuration(self) -> Dict:
        tests  = {
            'login_configured':        bool(self.login),
            'password_configured':     bool(self.password),
            'customer_uri_configured': bool(self.customer_uri),
            'api_accessible':          False,
            'account_valid':           False,
        }
        errors = []
        for field, name in [
            (self.login,        'login'),
            (self.password,     'password'),
            (self.customer_uri, 'customer_uri'),
        ]:
            if not field:
                errors.append(f'{name} not configured')

        if not errors:
            r = self.get_account_info()
            if r['success']:
                tests['api_accessible'] = True
                tests['account_valid']  = True
            else:
                tests['api_accessible'] = True
                errors.append(f"Account validation failed: {r.get('error')}")

        return {'enabled': self.enabled, 'tests': tests, 'errors': errors,
                'all_tests_passed': not errors}

    # ── Internal helpers ────────────────────────────────────────────────────

    def _do_renewal(self, cert: Certificate, domains: List[str]) -> Dict:
        if not domains:
            domains = self._cert_domains(cert)

        enroll = self.enroll_certificate(
            common_name=cert.common_name,
            san_domains=domains,
        )
        if not enroll['success']:
            return enroll

        result          = self.poll_for_certificate(enroll['ssl_id'])
        result['key_pem'] = enroll.get('key_pem')
        return result

    def _generate_csr(self, common_name: str, san_domains: List[str]) -> Dict:
        import sys, pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
        from ca.private_ca import PrivateCAManager
        mgr = PrivateCAManager(self.cert_dir / 'keys')
        return mgr.generate_csr(
            common_name=common_name,
            key_type='rsa',
            key_size_or_curve=2048,
            san_dns=san_domains or [],
        )

    def _request(self, method: str, path: str, **kwargs) -> Dict:
        """HTTP request with Sectigo header auth and exponential-backoff retry."""
        url     = self.base_url.rstrip('/') + path
        headers = {
            'Content-Type': 'application/json',
            'login':        self.login,
            'password':     self.password,
            'customerUri':  self.customer_uri,
        }

        for attempt in range(_MAX_RETRIES):
            try:
                resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
                if resp.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES - 1:
                    wait = 2 ** attempt
                    log.warning(f'Sectigo {method} {path} → {resp.status_code}, retry in {wait}s')
                    time.sleep(wait)
                    continue
                if resp.status_code == 400:
                    # Sectigo returns 400 with a JSON error body
                    try:
                        err = resp.json()
                    except ValueError:
                        err = resp.text
                    return {'success': False, 'error': str(err), 'status_code': 400}
                if resp.status_code >= 400:
                    if resp.status_code in (401, 403):
                        return {'success': False,
                                'error': 'Sectigo rejected the configured API credentials',
                                'error_kind': 'authentication', 'retryable': False,
                                'status_code': resp.status_code}
                    return {'success': False,
                            'error':   f'Sectigo API returned HTTP {resp.status_code}',
                            'error_kind': 'remote_service',
                            'retryable': resp.status_code >= 500,
                            'status_code': resp.status_code}
                try:
                    data = resp.json()
                except ValueError:
                    data = resp.text
                return {'success': True, 'data': data, 'status_code': resp.status_code}
            except requests.RequestException as exc:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                return {'success': False, 'error': str(exc)}

        return {'success': False, 'error': 'Max retries exceeded'}

    def _check_ready(self) -> bool:
        return self.enabled and bool(self.login) and bool(self.password) and bool(self.customer_uri)

    def _disabled_error(self) -> Dict:
        if not self.enabled:
            return {'success': False, 'error': 'Sectigo integration is disabled'}
        return {'success': False, 'error': 'Sectigo credentials (login/password/customer_uri) not fully configured'}

    def _cert_domains(self, cert: Certificate) -> List[str]:
        domains = []
        if cert.common_name:
            domains.append(cert.common_name)
        for san in (cert.subject_alt_names or []):
            if san.startswith('DNS:'):
                d = san[4:]
                if d not in domains:
                    domains.append(d)
        return domains
