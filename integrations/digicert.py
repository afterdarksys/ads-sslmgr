"""
DigiCert API v2 integration
Supports: order new certificates, renew (duplicate order), poll for issuance,
download, revoke, list orders, and configuration testing.
"""

import time
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

from database.models import Certificate, RenewalAttempt, DatabaseManager
from providers.certificates import atomic_write_certificate, parse_pem_bundle

log = logging.getLogger(__name__)

# DigiCert product type mapping (cert_type → product slug)
PRODUCT_TYPES = {
    'server':       'ssl_plus',           # DV/OV single-domain
    'wildcard':     'ssl_wildcard_plus',  # OV wildcard
    'multi_domain': 'ssl_multi_domain',   # SAN/UCC
    'ev':           'ssl_ev_plus',        # EV single-domain
    'ev_multi':     'ssl_ev_multi_domain',
    'client':       'client_premium',
    'code_signing': 'code_signing',
    'email':        'client_email_security_plus',
}

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_RETRIES    = 4
_POLL_INTERVAL  = 10   # seconds between issuance polls
_POLL_TIMEOUT   = 300  # seconds before giving up on issuance


class DigiCertIntegration:
    """DigiCert Services API v2 integration."""

    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config      = config
        self.db_manager  = db_manager
        dc               = config.get('certificate_authorities', {}).get('digicert', {})
        self.enabled     = dc.get('enabled', False)
        self.api_key     = dc.get('api_key', '')
        self.org_id      = dc.get('organization_id', '')
        self.base_url    = dc.get('base_url', 'https://www.digicert.com/services/v2')
        self.cert_dir    = Path(config.get('directories', {}).get('certificates', './certificates'))
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self._headers    = {
            'X-DC-DEVKEY':  self.api_key,
            'Content-Type': 'application/json',
        }

    # ── Public API ──────────────────────────────────────────────────────────

    def order_certificate(
        self,
        common_name: str,
        san_domains: List[str] = None,
        product_type: str = 'server',
        validity_years: int = 1,
        organization_id: str = None,
        extra_fields: Dict = None,
    ) -> Dict:
        """
        Place a new DigiCert certificate order.
        Returns order_id immediately; call poll_for_certificate() to wait for issuance.
        """
        if not self._check_ready():
            return self._disabled_error()

        csr_result = self._generate_csr(common_name, san_domains or [])
        product    = PRODUCT_TYPES.get(product_type, 'ssl_plus')
        org        = organization_id or self.org_id

        payload = {
            'certificate': {
                'common_name': common_name,
                'dns_names':   san_domains or [],
                'csr':         csr_result['csr_pem'],
                'signature_hash': 'sha256',
            },
            'organization': {'id': int(org)} if org else {},
            'validity_years': validity_years,
            'payment_method': 'balance',
        }
        if extra_fields:
            payload.update(extra_fields)

        resp = self._request('POST', f'/order/certificate/{product}', json=payload)
        if not resp['success']:
            return resp

        order_id = resp['data'].get('id')
        return {
            'success':    True,
            'order_id':   order_id,
            'csr_pem':    csr_result['csr_pem'],
            'key_pem':    csr_result['key_pem'],
            'message':    f'Order {order_id} placed, awaiting issuance',
        }

    def poll_for_certificate(self, order_id: str, timeout: int = _POLL_TIMEOUT) -> Dict:
        """
        Poll an order until the certificate is issued, then download it.
        Returns cert_pem, chain_pem, and expiry_date on success.
        """
        if not self._check_ready():
            return self._disabled_error()

        deadline = time.time() + timeout
        while time.time() < deadline:
            order = self._request('GET', f'/order/certificate/{order_id}')
            if not order['success']:
                return order

            data   = order['data']
            status = data.get('status', '')

            if status == 'issued':
                cert_id = data.get('certificate', {}).get('id')
                if not cert_id:
                    return {'success': False, 'error': 'Order issued but no certificate id returned'}
                return self._download_certificate(cert_id)

            if status in ('rejected', 'canceled', 'expired'):
                return {'success': False, 'error': f'Order {order_id} reached terminal status: {status}'}

            log.debug(f'DigiCert order {order_id} status={status}, sleeping {_POLL_INTERVAL}s')
            time.sleep(_POLL_INTERVAL)

        return {'success': False, 'error': f'Timed out waiting for order {order_id} after {timeout}s'}

    def renew_certificate(self, cert: Certificate, domains: List[str] = None) -> Dict:
        """
        Renew by duplicating the original DigiCert order, then polling for issuance.
        Falls back to ordering a new ssl_plus cert if the original order cannot be found.
        """
        if not self._check_ready():
            return self._disabled_error()

        session = self.db_manager.get_session()
        attempt = RenewalAttempt(
            certificate_id=cert.id,
            ca_provider='digicert',
            renewal_method='api',
            status='pending',
        )
        session.add(attempt)
        session.commit()

        try:
            result = self._do_renewal(cert, domains)
            attempt.status           = 'success' if result['success'] else 'failed'
            attempt.error_message    = result.get('error') if not result['success'] else None
            attempt.new_expiry_date  = result.get('expiry_date')
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

    def list_orders(self, limit: int = 100, status: str = None) -> Dict:
        params = {'limit': limit}
        if status:
            params['filters[status]'] = status
        return self._request('GET', '/order/certificate', params=params)

    def get_order(self, order_id: str) -> Dict:
        return self._request('GET', f'/order/certificate/{order_id}')

    def get_certificate(self, cert_id: str) -> Dict:
        return self._request('GET', f'/certificate/{cert_id}')

    def revoke_certificate_api(self, cert_id: str, reason: str = 'superseded') -> Dict:
        return self._request('PUT', f'/certificate/{cert_id}/revoke', json={'comments': reason})

    def get_account_balance(self) -> Dict:
        return self._request('GET', '/account/balance')

    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        if cert.issuer_category != 'digicert':
            return {'eligible': False, 'reason': 'Not a DigiCert certificate'}
        if not self.api_key or not self.org_id:
            return {'eligible': False, 'reason': 'DigiCert API credentials not configured'}
        if cert.days_until_expiry > 90:
            return {'eligible': False,
                    'reason': f'Expires in {cert.days_until_expiry}d (renew within 90 days)'}
        return {'eligible': True, 'days_until_expiry': cert.days_until_expiry,
                'serial_number': cert.serial_number}

    def test_configuration(self) -> Dict:
        tests  = {'api_key_configured': bool(self.api_key),
                  'org_id_configured':  bool(self.org_id),
                  'api_accessible':     False,
                  'account_valid':      False}
        errors = []
        if not self.api_key:
            errors.append('api_key not configured')
        if not self.org_id:
            errors.append('organization_id not configured')
        if self.api_key:
            r = self._request('GET', '/user/me')
            if r['success']:
                tests['api_accessible'] = True
                tests['account_valid']  = True
            else:
                tests['api_accessible'] = True
                errors.append(f"Auth failed: {r.get('error')}")
        return {'enabled': self.enabled, 'tests': tests, 'errors': errors,
                'all_tests_passed': not errors}

    # ── Internal helpers ────────────────────────────────────────────────────

    def _do_renewal(self, cert: Certificate, domains: List[str]) -> Dict:
        """Find existing order and duplicate it, or fall back to a fresh order."""
        if not domains:
            domains = self._cert_domains(cert)

        order_resp = self._request('GET', '/order/certificate',
                                   params={'filters[serial_number]': cert.serial_number})
        if order_resp['success']:
            orders = order_resp['data'].get('orders', [])
            if orders:
                order_id = orders[0]['id']
                dup = self._duplicate_order(order_id, cert, domains)
                if dup['success']:
                    return self.poll_for_certificate(dup['order_id'])

        # Fall back to fresh order
        log.info(f'DigiCert: no existing order found for {cert.common_name}, placing new order')
        new_order = self.order_certificate(
            common_name=cert.common_name,
            san_domains=domains,
        )
        if not new_order['success']:
            return new_order
        result = self.poll_for_certificate(new_order['order_id'])
        result['key_pem'] = new_order.get('key_pem')
        return result

    def _duplicate_order(self, order_id: str, cert: Certificate, domains: List[str]) -> Dict:
        """Duplicate (renew) an existing DigiCert order."""
        csr_result = self._generate_csr(cert.common_name, domains)
        details    = self._request('GET', f'/order/certificate/{order_id}')
        if not details['success']:
            return details

        orig = details['data']
        payload = {
            'certificate': {
                'common_name': cert.common_name,
                'dns_names':   domains,
                'csr':         csr_result['csr_pem'],
                'signature_hash': 'sha256',
            },
            'organization':   orig.get('organization', {'id': int(self.org_id)} if self.org_id else {}),
            'validity_years': orig.get('validity_years', 1),
            'payment_method': 'balance',
        }
        resp = self._request('POST', f'/order/certificate/{order_id}/duplicate', json=payload)
        if resp['success']:
            resp['key_pem'] = csr_result['key_pem']
        return resp

    def _download_certificate(self, cert_id: str) -> Dict:
        """Download a certificate in pem_all format (cert + chain)."""
        resp = self._request('GET', f'/certificate/{cert_id}/download/format/pem_all')
        if not resp['success']:
            return resp

        pem_data = resp['data']
        if isinstance(pem_data, dict):
            pem_data = pem_data.get('certificate', '')

        cert_filename = self.cert_dir / f'digicert_{cert_id}.pem'
        try:
            cert_pem, chain_pem, c = parse_pem_bundle(pem_data)
            expiry = (c.not_valid_after_utc if hasattr(c, 'not_valid_after_utc')
                      else c.not_valid_after.replace(tzinfo=timezone.utc))
            atomic_write_certificate(cert_filename, cert_pem)
        except Exception as exc:
            return {'success': False, 'error': str(exc), 'error_kind': 'validation',
                    'retryable': False, 'provider': 'digicert'}

        return {
            'success':     True,
            'cert_id':     cert_id,
            'cert_pem':    cert_pem,
            'chain_pem':   chain_pem,
            'cert_path':   str(cert_filename),
            'expiry_date': expiry,
            'message':     f'Certificate {cert_id} downloaded successfully',
        }

    def _generate_csr(self, common_name: str, san_domains: List[str]) -> Dict:
        """Generate a real private key + CSR using the private CA module."""
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
        """HTTP request with exponential-backoff retry on transient errors."""
        url = self.base_url.rstrip('/') + path
        for attempt in range(_MAX_RETRIES):
            try:
                resp = requests.request(method, url, headers=self._headers,
                                        timeout=30, **kwargs)
                if resp.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES - 1:
                    wait = 2 ** attempt
                    log.warning(f'DigiCert {method} {path} → {resp.status_code}, retry in {wait}s')
                    time.sleep(wait)
                    continue
                if resp.status_code >= 400:
                    if resp.status_code in (401, 403):
                        return {'success': False,
                                'error': 'DigiCert rejected the configured API credentials',
                                'error_kind': 'authentication', 'retryable': False,
                                'status_code': resp.status_code}
                    return {'success': False,
                            'error':   f'DigiCert API returned HTTP {resp.status_code}',
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
        return self.enabled and bool(self.api_key)

    def _disabled_error(self) -> Dict:
        if not self.enabled:
            return {'success': False, 'error': 'DigiCert integration is disabled'}
        return {'success': False, 'error': 'DigiCert api_key not configured'}

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
