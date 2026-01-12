"""
Desktop Certificate Scanner
Discovers all SSL/TLS certificates on desktop systems (Windows, macOS, Linux)
Supports client certificates, server certificates, CA certificates, and smart cards
"""

import os
import sys
import platform
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime
from enum import Enum


class CertificateStoreType(Enum):
    """Types of certificate stores"""
    SYSTEM_ROOT = "system_root"
    SYSTEM_INTERMEDIATE = "system_intermediate"
    USER_PERSONAL = "user_personal"
    USER_ROOT = "user_root"
    APPLICATION = "application"
    SMART_CARD = "smart_card"
    TPM = "tpm"
    BROWSER = "browser"
    VPN = "vpn"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"


class DesktopCertificateScanner:
    """Universal certificate scanner for desktop systems"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system().lower()
        self.discovered_certs: List[Dict] = []
        self.visited_paths: Set[str] = set()

    def scan_all(self, include_applications: bool = True,
                 include_smart_cards: bool = True) -> Dict:
        """
        Scan all certificate stores on the system

        Returns:
            Dictionary with scan results and statistics
        """
        results = {
            'platform': self.platform,
            'scan_time': datetime.now().isoformat(),
            'certificates': [],
            'statistics': {},
            'errors': []
        }

        try:
            if self.platform == 'windows':
                results['certificates'].extend(self._scan_windows_stores())
                if include_applications:
                    results['certificates'].extend(self._scan_windows_applications())
                if include_smart_cards:
                    results['certificates'].extend(self._scan_windows_smart_cards())

            elif self.platform == 'darwin':
                results['certificates'].extend(self._scan_macos_keychains())
                if include_applications:
                    results['certificates'].extend(self._scan_macos_applications())
                if include_smart_cards:
                    results['certificates'].extend(self._scan_macos_smart_cards())

            elif self.platform == 'linux':
                results['certificates'].extend(self._scan_linux_stores())
                if include_applications:
                    results['certificates'].extend(self._scan_linux_applications())
                if include_smart_cards:
                    results['certificates'].extend(self._scan_linux_smart_cards())

            # Add statistics
            results['statistics'] = self._calculate_statistics(results['certificates'])

        except Exception as e:
            self.logger.error(f"Error during certificate scan: {e}")
            results['errors'].append(str(e))

        return results

    # ============================================================================
    # WINDOWS SCANNING
    # ============================================================================

    def _scan_windows_stores(self) -> List[Dict]:
        """Scan Windows certificate stores"""
        certificates = []

        stores = [
            ('CurrentUser', 'My', CertificateStoreType.USER_PERSONAL),
            ('CurrentUser', 'Root', CertificateStoreType.USER_ROOT),
            ('CurrentUser', 'CA', CertificateStoreType.SYSTEM_INTERMEDIATE),
            ('CurrentUser', 'Trust', CertificateStoreType.SYSTEM_ROOT),
            ('CurrentUser', 'Disallowed', CertificateStoreType.SYSTEM_ROOT),
            ('LocalMachine', 'My', CertificateStoreType.SYSTEM_ROOT),
            ('LocalMachine', 'Root', CertificateStoreType.SYSTEM_ROOT),
            ('LocalMachine', 'CA', CertificateStoreType.SYSTEM_INTERMEDIATE),
            ('LocalMachine', 'AuthRoot', CertificateStoreType.SYSTEM_ROOT),
            ('LocalMachine', 'TrustedPeople', CertificateStoreType.SYSTEM_ROOT),
        ]

        for location, store_name, store_type in stores:
            try:
                certs = self._read_windows_store(location, store_name, store_type)
                certificates.extend(certs)
            except Exception as e:
                self.logger.warning(f"Error reading Windows store {location}\\{store_name}: {e}")

        return certificates

    def _read_windows_store(self, location: str, store_name: str,
                           store_type: CertificateStoreType) -> List[Dict]:
        """Read certificates from a specific Windows store using PowerShell"""
        certificates = []

        powershell_script = f"""
        $certs = Get-ChildItem -Path Cert:\\{location}\\{store_name}
        foreach ($cert in $certs) {{
            $output = @{{
                'Thumbprint' = $cert.Thumbprint
                'Subject' = $cert.Subject
                'Issuer' = $cert.Issuer
                'NotBefore' = $cert.NotBefore.ToString('o')
                'NotAfter' = $cert.NotAfter.ToString('o')
                'SerialNumber' = $cert.SerialNumber
                'FriendlyName' = $cert.FriendlyName
                'HasPrivateKey' = $cert.HasPrivateKey
                'EnhancedKeyUsageList' = @($cert.EnhancedKeyUsageList | ForEach-Object {{ $_.FriendlyName }})
                'DnsNameList' = @($cert.DnsNameList)
            }}
            $output | ConvertTo-Json -Compress
        }}
        """

        try:
            result = subprocess.run(
                ['powershell', '-Command', powershell_script],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            cert_data = json.loads(line)
                            cert_info = {
                                'source': f'Windows:{location}\\{store_name}',
                                'store_type': store_type.value,
                                'platform': 'windows',
                                'thumbprint': cert_data.get('Thumbprint'),
                                'subject': cert_data.get('Subject'),
                                'issuer': cert_data.get('Issuer'),
                                'common_name': self._extract_cn(cert_data.get('Subject', '')),
                                'not_valid_before': cert_data.get('NotBefore'),
                                'not_valid_after': cert_data.get('NotAfter'),
                                'serial_number': cert_data.get('SerialNumber'),
                                'friendly_name': cert_data.get('FriendlyName'),
                                'has_private_key': cert_data.get('HasPrivateKey', False),
                                'enhanced_key_usage': cert_data.get('EnhancedKeyUsageList', []),
                                'dns_names': cert_data.get('DnsNameList', []),
                                'certificate_type': self._determine_cert_type_from_usage(
                                    cert_data.get('EnhancedKeyUsageList', [])
                                ),
                                'scan_time': datetime.now().isoformat()
                            }

                            # Calculate days until expiry
                            try:
                                not_after = datetime.fromisoformat(cert_data.get('NotAfter').replace('Z', '+00:00'))
                                cert_info['days_until_expiry'] = (not_after - datetime.now()).days
                                cert_info['is_expired'] = cert_info['days_until_expiry'] < 0
                            except:
                                cert_info['days_until_expiry'] = None
                                cert_info['is_expired'] = None

                            certificates.append(cert_info)

                        except json.JSONDecodeError as e:
                            self.logger.warning(f"Error parsing certificate JSON: {e}")

        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout reading Windows store {location}\\{store_name}")
        except Exception as e:
            self.logger.error(f"Error executing PowerShell: {e}")

        return certificates

    def _scan_windows_applications(self) -> List[Dict]:
        """Scan application-specific certificate stores on Windows"""
        certificates = []

        # Chrome/Edge certificate database (uses Windows store)
        # Firefox NSS database
        firefox_paths = [
            Path(os.environ.get('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles',
        ]

        for profile_dir in firefox_paths:
            if profile_dir.exists():
                for profile in profile_dir.iterdir():
                    if profile.is_dir():
                        cert8_db = profile / 'cert8.db'
                        cert9_db = profile / 'cert9.db'
                        if cert8_db.exists() or cert9_db.exists():
                            certs = self._scan_firefox_nss(profile)
                            certificates.extend(certs)

        # VPN clients
        certificates.extend(self._scan_windows_vpn())

        # Docker Desktop
        certificates.extend(self._scan_windows_docker())

        return certificates

    def _scan_windows_smart_cards(self) -> List[Dict]:
        """Scan smart cards and TPM-backed certificates on Windows"""
        certificates = []

        # Smart card certificates appear in Windows store with special provider
        # TPM-backed certificates are also in Windows store

        powershell_script = """
        Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {
            $_.PrivateKey.CspKeyContainerInfo.HardwareDevice -or
            $_.PrivateKey.Key.UniqueName -like '*TPM*'
        } | ForEach-Object {
            @{
                'Thumbprint' = $_.Thumbprint
                'Subject' = $_.Subject
                'Issuer' = $_.Issuer
                'NotAfter' = $_.NotAfter.ToString('o')
                'Provider' = $_.PrivateKey.CspKeyContainerInfo.ProviderName
                'IsHardware' = $_.PrivateKey.CspKeyContainerInfo.HardwareDevice
            } | ConvertTo-Json -Compress
        }
        """

        try:
            result = subprocess.run(
                ['powershell', '-Command', powershell_script],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            cert_data = json.loads(line)
                            cert_info = {
                                'source': 'Windows:SmartCard/TPM',
                                'store_type': CertificateStoreType.SMART_CARD.value,
                                'platform': 'windows',
                                'thumbprint': cert_data.get('Thumbprint'),
                                'subject': cert_data.get('Subject'),
                                'issuer': cert_data.get('Issuer'),
                                'common_name': self._extract_cn(cert_data.get('Subject', '')),
                                'not_valid_after': cert_data.get('NotAfter'),
                                'provider': cert_data.get('Provider'),
                                'is_hardware': cert_data.get('IsHardware', False),
                                'certificate_type': 'smart_card',
                                'scan_time': datetime.now().isoformat()
                            }
                            certificates.append(cert_info)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            self.logger.warning(f"Error scanning smart cards: {e}")

        return certificates

    # ============================================================================
    # macOS SCANNING
    # ============================================================================

    def _scan_macos_keychains(self) -> List[Dict]:
        """Scan macOS keychains"""
        certificates = []

        keychains = [
            ('login.keychain-db', CertificateStoreType.USER_PERSONAL),
            ('System.keychain', CertificateStoreType.SYSTEM_ROOT),
            ('SystemRootCertificates.keychain', CertificateStoreType.SYSTEM_ROOT),
        ]

        for keychain, store_type in keychains:
            try:
                certs = self._read_macos_keychain(keychain, store_type)
                certificates.extend(certs)
            except Exception as e:
                self.logger.warning(f"Error reading macOS keychain {keychain}: {e}")

        return certificates

    def _read_macos_keychain(self, keychain: str,
                            store_type: CertificateStoreType) -> List[Dict]:
        """Read certificates from macOS keychain"""
        certificates = []

        try:
            # Use security command to list certificates
            result = subprocess.run(
                ['security', 'find-certificate', '-a', '-p', keychain],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse PEM certificates from output
                pem_certs = self._split_pem_certificates(result.stdout)

                for pem_cert in pem_certs:
                    cert_info = self._parse_macos_certificate(pem_cert, keychain, store_type)
                    if cert_info:
                        certificates.append(cert_info)

        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout reading macOS keychain {keychain}")
        except Exception as e:
            self.logger.error(f"Error reading macOS keychain: {e}")

        return certificates

    def _parse_macos_certificate(self, pem_cert: str, keychain: str,
                                store_type: CertificateStoreType) -> Optional[Dict]:
        """Parse a PEM certificate from macOS keychain"""
        try:
            # Import certificate parser from parent module
            from certificate_parser import CertificateParser

            parser = CertificateParser()
            certs = parser._parse_pem_certificate(pem_cert.encode(), f"macOS:{keychain}")

            if certs:
                cert_info = certs[0]
                cert_info['source'] = f'macOS:{keychain}'
                cert_info['store_type'] = store_type.value
                cert_info['platform'] = 'darwin'
                cert_info['scan_time'] = datetime.now().isoformat()
                return cert_info

        except Exception as e:
            self.logger.warning(f"Error parsing macOS certificate: {e}")

        return None

    def _scan_macos_applications(self) -> List[Dict]:
        """Scan application-specific certificates on macOS"""
        certificates = []

        # Firefox profiles
        firefox_path = Path.home() / 'Library' / 'Application Support' / 'Firefox' / 'Profiles'
        if firefox_path.exists():
            for profile in firefox_path.iterdir():
                if profile.is_dir():
                    certs = self._scan_firefox_nss(profile)
                    certificates.extend(certs)

        # Docker for Mac
        docker_path = Path.home() / '.docker'
        if docker_path.exists():
            certs = self._scan_docker_certs(docker_path)
            certificates.extend(certs)

        # Kubernetes
        k8s_path = Path.home() / '.kube'
        if k8s_path.exists():
            certs = self._scan_kubernetes_certs(k8s_path)
            certificates.extend(certs)

        return certificates

    def _scan_macos_smart_cards(self) -> List[Dict]:
        """Scan smart card certificates on macOS"""
        certificates = []

        try:
            # Check for smart card identities
            result = subprocess.run(
                ['security', 'list-smartcards'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout:
                # Smart cards detected, get certificates
                result = subprocess.run(
                    ['security', 'find-certificate', '-a', '-p', '-Z'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                # Parse smart card certificates
                # (implementation would parse output and identify smart card certs)

        except Exception as e:
            self.logger.warning(f"Error scanning macOS smart cards: {e}")

        return certificates

    # ============================================================================
    # LINUX SCANNING
    # ============================================================================

    def _scan_linux_stores(self) -> List[Dict]:
        """Scan Linux certificate stores"""
        certificates = []

        # System certificate directories
        cert_paths = [
            ('/etc/ssl/certs', CertificateStoreType.SYSTEM_ROOT),
            ('/etc/pki/tls/certs', CertificateStoreType.SYSTEM_ROOT),
            ('/usr/local/share/ca-certificates', CertificateStoreType.SYSTEM_ROOT),
            ('/etc/ca-certificates', CertificateStoreType.SYSTEM_ROOT),
        ]

        for cert_path, store_type in cert_paths:
            path = Path(cert_path)
            if path.exists():
                certs = self._scan_linux_directory(path, store_type)
                certificates.extend(certs)

        # User NSS database (used by Firefox, Chrome)
        nss_path = Path.home() / '.pki' / 'nssdb'
        if nss_path.exists():
            certs = self._scan_linux_nss(nss_path)
            certificates.extend(certs)

        return certificates

    def _scan_linux_directory(self, path: Path,
                             store_type: CertificateStoreType) -> List[Dict]:
        """Scan a Linux directory for certificates"""
        certificates = []

        if str(path) in self.visited_paths:
            return certificates

        self.visited_paths.add(str(path))

        try:
            for file_path in path.rglob('*.pem'):
                if file_path.is_file() and file_path.stat().st_size > 0:
                    certs = self._parse_linux_certificate_file(file_path, store_type)
                    certificates.extend(certs)

            for file_path in path.rglob('*.crt'):
                if file_path.is_file() and file_path.stat().st_size > 0:
                    certs = self._parse_linux_certificate_file(file_path, store_type)
                    certificates.extend(certs)

        except PermissionError:
            self.logger.warning(f"Permission denied accessing {path}")
        except Exception as e:
            self.logger.warning(f"Error scanning {path}: {e}")

        return certificates

    def _parse_linux_certificate_file(self, file_path: Path,
                                     store_type: CertificateStoreType) -> List[Dict]:
        """Parse a certificate file on Linux"""
        certificates = []

        try:
            from certificate_parser import CertificateParser

            parser = CertificateParser()
            certs = parser.parse_certificate_file(str(file_path))

            for cert in certs:
                cert['source'] = f'Linux:{file_path}'
                cert['store_type'] = store_type.value
                cert['platform'] = 'linux'
                cert['scan_time'] = datetime.now().isoformat()
                certificates.append(cert)

        except Exception as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")

        return certificates

    def _scan_linux_applications(self) -> List[Dict]:
        """Scan application-specific certificates on Linux"""
        certificates = []

        # Docker certificates
        docker_paths = [
            Path.home() / '.docker',
            Path('/etc/docker'),
        ]

        for docker_path in docker_paths:
            if docker_path.exists():
                certs = self._scan_docker_certs(docker_path)
                certificates.extend(certs)

        # Kubernetes
        k8s_path = Path.home() / '.kube'
        if k8s_path.exists():
            certs = self._scan_kubernetes_certs(k8s_path)
            certificates.extend(certs)

        # Snap packages
        snap_path = Path('/snap')
        if snap_path.exists():
            for snap_dir in snap_path.iterdir():
                if snap_dir.is_dir():
                    cert_dir = snap_dir / 'current' / 'etc' / 'ssl' / 'certs'
                    if cert_dir.exists():
                        certs = self._scan_linux_directory(cert_dir, CertificateStoreType.APPLICATION)
                        certificates.extend(certs)

        return certificates

    def _scan_linux_smart_cards(self) -> List[Dict]:
        """Scan smart card certificates on Linux"""
        certificates = []

        try:
            # Check for PKCS#11 modules
            result = subprocess.run(
                ['p11tool', '--list-tokens'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout:
                # Parse tokens and extract certificates
                # (implementation would use p11tool or OpenSC)
                pass

        except FileNotFoundError:
            # p11tool not installed
            pass
        except Exception as e:
            self.logger.warning(f"Error scanning smart cards: {e}")

        return certificates

    def _scan_linux_nss(self, nss_path: Path) -> List[Dict]:
        """Scan NSS database on Linux"""
        certificates = []

        try:
            result = subprocess.run(
                ['certutil', '-L', '-d', f'sql:{nss_path}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse certutil output
                # (implementation would parse certificate list)
                pass

        except FileNotFoundError:
            # certutil not installed
            pass
        except Exception as e:
            self.logger.warning(f"Error scanning NSS database: {e}")

        return certificates

    # ============================================================================
    # APPLICATION-SPECIFIC SCANNERS
    # ============================================================================

    def _scan_firefox_nss(self, profile_dir: Path) -> List[Dict]:
        """Scan Firefox NSS certificate database"""
        certificates = []

        # Firefox uses NSS database (cert8.db or cert9.db)
        cert_db = profile_dir / 'cert9.db'
        if not cert_db.exists():
            cert_db = profile_dir / 'cert8.db'

        if cert_db.exists():
            try:
                # Would use certutil or python-nss to read database
                self.logger.info(f"Found Firefox NSS database: {cert_db}")
                # Implementation would extract certificates from NSS DB
            except Exception as e:
                self.logger.warning(f"Error reading Firefox NSS database: {e}")

        return certificates

    def _scan_docker_certs(self, docker_path: Path) -> List[Dict]:
        """Scan Docker certificates"""
        certificates = []

        cert_dirs = [
            docker_path / 'certs.d',
            docker_path / 'tls',
        ]

        for cert_dir in cert_dirs:
            if cert_dir.exists():
                try:
                    from certificate_parser import CertificateParser
                    parser = CertificateParser()

                    for cert_file in cert_dir.rglob('*'):
                        if cert_file.is_file() and cert_file.suffix in ['.pem', '.crt', '.cert']:
                            certs = parser.parse_certificate_file(str(cert_file))
                            for cert in certs:
                                cert['source'] = f'Docker:{cert_file}'
                                cert['store_type'] = CertificateStoreType.DOCKER.value
                                cert['application'] = 'docker'
                                certificates.append(cert)
                except Exception as e:
                    self.logger.warning(f"Error scanning Docker certificates: {e}")

        return certificates

    def _scan_kubernetes_certs(self, k8s_path: Path) -> List[Dict]:
        """Scan Kubernetes certificates from kubeconfig"""
        certificates = []

        kubeconfig = k8s_path / 'config'
        if kubeconfig.exists():
            try:
                with open(kubeconfig, 'r') as f:
                    import yaml
                    config = yaml.safe_load(f)

                    # Extract certificates from kubeconfig
                    # (implementation would parse embedded certificates)

            except Exception as e:
                self.logger.warning(f"Error reading kubeconfig: {e}")

        return certificates

    def _scan_windows_vpn(self) -> List[Dict]:
        """Scan VPN client certificates on Windows"""
        certificates = []
        # Implementation would scan common VPN client certificate locations
        return certificates

    def _scan_windows_docker(self) -> List[Dict]:
        """Scan Docker Desktop certificates on Windows"""
        certificates = []
        docker_path = Path(os.environ.get('USERPROFILE', '')) / '.docker'
        if docker_path.exists():
            certificates.extend(self._scan_docker_certs(docker_path))
        return certificates

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def _extract_cn(self, subject: str) -> str:
        """Extract CN from subject string"""
        for part in subject.split(','):
            part = part.strip()
            if part.startswith('CN='):
                return part[3:]
        return subject

    def _determine_cert_type_from_usage(self, usage_list: List[str]) -> str:
        """Determine certificate type from enhanced key usage"""
        usage_str = ' '.join(usage_list).lower()

        if 'server authentication' in usage_str:
            return 'server'
        elif 'client authentication' in usage_str:
            return 'client'
        elif 'code signing' in usage_str:
            return 'code_signing'
        elif 'secure email' in usage_str or 'email protection' in usage_str:
            return 'email'
        else:
            return 'unknown'

    def _split_pem_certificates(self, pem_data: str) -> List[str]:
        """Split multiple PEM certificates"""
        certs = []
        current_cert = []
        in_cert = False

        for line in pem_data.split('\n'):
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current_cert = [line]
            elif '-----END CERTIFICATE-----' in line:
                current_cert.append(line)
                certs.append('\n'.join(current_cert))
                current_cert = []
                in_cert = False
            elif in_cert:
                current_cert.append(line)

        return certs

    def _calculate_statistics(self, certificates: List[Dict]) -> Dict:
        """Calculate statistics about discovered certificates"""
        stats = {
            'total_certificates': len(certificates),
            'by_store_type': {},
            'by_certificate_type': {},
            'with_private_key': 0,
            'expired': 0,
            'expiring_30_days': 0,
            'expiring_90_days': 0,
            'smart_card': 0,
            'tpm_backed': 0,
        }

        for cert in certificates:
            # Count by store type
            store_type = cert.get('store_type', 'unknown')
            stats['by_store_type'][store_type] = stats['by_store_type'].get(store_type, 0) + 1

            # Count by certificate type
            cert_type = cert.get('certificate_type', 'unknown')
            stats['by_certificate_type'][cert_type] = stats['by_certificate_type'].get(cert_type, 0) + 1

            # Count private keys
            if cert.get('has_private_key'):
                stats['with_private_key'] += 1

            # Count expired/expiring
            days_until_expiry = cert.get('days_until_expiry')
            if days_until_expiry is not None:
                if days_until_expiry < 0:
                    stats['expired'] += 1
                elif days_until_expiry <= 30:
                    stats['expiring_30_days'] += 1
                elif days_until_expiry <= 90:
                    stats['expiring_90_days'] += 1

            # Count smart card/TPM
            if cert.get('is_hardware') or store_type == CertificateStoreType.SMART_CARD.value:
                stats['smart_card'] += 1
            if 'tpm' in cert.get('provider', '').lower():
                stats['tpm_backed'] += 1

        return stats


def main():
    """CLI interface for desktop scanner"""
    import argparse

    parser = argparse.ArgumentParser(description='Desktop Certificate Scanner')
    parser.add_argument('--no-applications', action='store_true',
                       help='Skip application-specific certificates')
    parser.add_argument('--no-smart-cards', action='store_true',
                       help='Skip smart card certificates')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    scanner = DesktopCertificateScanner()

    print("Scanning desktop for certificates...")
    results = scanner.scan_all(
        include_applications=not args.no_applications,
        include_smart_cards=not args.no_smart_cards
    )

    print(f"\nScan Results:")
    print(f"Platform: {results['platform']}")
    print(f"Total certificates found: {results['statistics']['total_certificates']}")
    print(f"With private keys: {results['statistics']['with_private_key']}")
    print(f"Expired: {results['statistics']['expired']}")
    print(f"Expiring in 30 days: {results['statistics']['expiring_30_days']}")
    print(f"Smart card/TPM: {results['statistics']['smart_card']}")

    print("\nBy Store Type:")
    for store_type, count in results['statistics']['by_store_type'].items():
        print(f"  {store_type}: {count}")

    print("\nBy Certificate Type:")
    for cert_type, count in results['statistics']['by_certificate_type'].items():
        print(f"  {cert_type}: {count}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == '__main__':
    main()
