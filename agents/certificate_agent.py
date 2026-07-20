#!/usr/bin/env python3
"""Small Linux/BSD host agent for CSR enrollment and certificate renewal."""

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from providers.certificates import atomic_write_certificate


class CertificateAgent:
    def __init__(self, config, session=None):
        self.config = config or {}
        self.server_url = self.config.get('server_url', '').rstrip('/')
        self.state_dir = Path(self.config.get('state_dir', '/var/lib/sslmgr-agent'))
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cert_path = self.state_dir / self.config.get('certificate_file', 'tls.crt')
        self.key_path = self.state_dir / self.config.get('key_file', 'tls.key')
        self.chain_path = self.state_dir / self.config.get('chain_file', 'ca-chain.crt')
        self.state_path = self.state_dir / 'agent.json'
        self.common_name = self.config.get('common_name') or os.uname().nodename
        self.san_dns = self.config.get('san_dns') or [self.common_name]
        self.renewal_days = int(self.config.get('renewal_days', 30))
        self.timeout = float(self.config.get('timeout', 30))
        self.verify = self.config.get('verify_tls', True)
        self.session = session or requests.Session()

    def enroll(self, token):
        key_pem, csr_pem = self._new_key_and_csr()
        response = self.session.post(
            self.server_url + '/api/pki/enroll',
            json={'token': token, 'csr_pem': csr_pem},
            timeout=self.timeout, verify=self.verify,
        )
        result = response.json()
        if response.status_code >= 400 or not result.get('success'):
            return result
        self._install(result, key_pem)
        return result

    def renew_if_needed(self, force=False):
        if not self.cert_path.exists() or not self.state_path.exists():
            return {'success': False, 'error': 'Agent is not enrolled'}
        if not force and self._days_remaining() > self.renewal_days:
            return {'success': True, 'renewed': False, 'reason': 'not_due'}
        state = json.loads(self.state_path.read_text())
        key_pem, csr_pem = self._new_key_and_csr()
        response = self.session.post(
            self.server_url + '/api/pki/agents/{}/renew'.format(state['agent_id']),
            json={'csr_pem': csr_pem, 'force': force},
            cert=(str(self.cert_path), str(self.key_path)),
            timeout=self.timeout, verify=self.verify,
        )
        result = response.json()
        if response.status_code >= 400 or not result.get('success'):
            return result
        self._install(result, key_pem)
        result['renewed'] = True
        return result

    def _new_key_and_csr(self):
        if self.config.get('key_type', 'rsa').lower() == 'ec':
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=int(self.config.get('key_size', 2048)))
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)])
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in self.san_dns]),
            critical=False,
        )
        csr = builder.sign(key, hashes.SHA256())
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode()

    def _install(self, result, key_pem):
        # The key never leaves this process. Each file is fsync'd then renamed.
        atomic_write_certificate(self.key_path, key_pem)
        atomic_write_certificate(self.cert_path, result['cert_pem'])
        atomic_write_certificate(self.chain_path, result['chain_pem'])
        os.chmod(self.cert_path, 0o644)
        os.chmod(self.chain_path, 0o644)
        state = json.dumps({
            'agent_id': result['agent_id'],
            'certificate_fingerprint': result['certificate_fingerprint'],
            'updated_at': datetime.now(timezone.utc).isoformat(),
        })
        atomic_write_certificate(self.state_path, state)
        hook = self.config.get('post_install_hook')
        if hook:
            if not isinstance(hook, list):
                raise ValueError('post_install_hook must be an argument list')
            subprocess.run(hook, check=True, timeout=60)

    def _days_remaining(self):
        cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        expires = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        return (expires - datetime.now(timezone.utc)).total_seconds() / 86400


def main(argv=None):
    parser = argparse.ArgumentParser(description='SSL Manager certificate renewal agent')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    enroll = commands.add_parser('enroll')
    enroll.add_argument('--token', required=True)
    renew = commands.add_parser('renew')
    renew.add_argument('--force', action='store_true')
    args = parser.parse_args(argv)
    config = json.loads(Path(args.config).read_text())
    agent = CertificateAgent(config)
    result = agent.enroll(args.token) if args.command == 'enroll' else agent.renew_if_needed(args.force)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
