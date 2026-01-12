#!/usr/bin/env python3
"""
Prometheus node_exporter textfile collector for SSL certificate metrics.

This script exports SSL certificate expiry information in a format that
node_exporter's textfile collector can scrape. Run this script periodically
(e.g., via cron) to update the metrics.

Usage:
    python prometheus_exporter.py [--config CONFIG_PATH]

Example cron entry (run every 5 minutes):
    */5 * * * * /usr/bin/python3 /path/to/prometheus_exporter.py
"""

import os
import sys
import json
import argparse
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import Certificate, DatabaseManager


class PrometheusExporter:
    """Export SSL certificate metrics for Prometheus node_exporter."""

    def __init__(self, config: dict):
        self.config = config
        self.prom_config = config.get('prometheus', {})
        self.db_manager = DatabaseManager(config)

        # Configuration
        self.enabled = self.prom_config.get('enabled', False)
        self.textfile_path = self.prom_config.get('textfile_path', '/var/lib/node_exporter/textfile_collector')
        self.metrics_file = self.prom_config.get('metrics_file', 'ssl_certificates.prom')
        self.include_metadata = self.prom_config.get('include_metadata', True)

    def generate_metrics(self) -> str:
        """Generate Prometheus metrics from certificate database."""

        lines = [
            '# HELP ssl_certificate_expiry_seconds Unix timestamp when the certificate expires',
            '# TYPE ssl_certificate_expiry_seconds gauge',
        ]

        # Get all certificates from database
        session = self.db_manager.get_session()
        try:
            certificates = session.query(Certificate).all()

            for cert in certificates:
                # Calculate expiry timestamp
                expiry_timestamp = int(cert.not_valid_after.timestamp())

                # Build labels
                labels = {
                    'cn': self._escape_label(cert.common_name or 'unknown'),
                    'serial': self._escape_label(cert.serial_number),
                    'issuer': self._escape_label(cert.issuer_category or 'unknown'),
                    'file_path': self._escape_label(cert.file_path)
                }

                # Add optional metadata
                if self.include_metadata:
                    if cert.subject_alt_names:
                        # Take first SAN for label
                        sans = cert.subject_alt_names.split(',')
                        if sans:
                            labels['san'] = self._escape_label(sans[0].strip())

                    labels['format'] = self._escape_label(cert.certificate_format or 'unknown')

                # Format metric line
                label_str = ','.join([f'{k}="{v}"' for k, v in labels.items()])
                lines.append(f'ssl_certificate_expiry_seconds{{{label_str}}} {expiry_timestamp}')

            # Add summary metrics
            lines.extend([
                '',
                '# HELP ssl_certificates_total Total number of certificates being monitored',
                '# TYPE ssl_certificates_total gauge',
                f'ssl_certificates_total {len(certificates)}'
            ])

            # Count certificates by status
            now = datetime.utcnow()
            expired = sum(1 for c in certificates if c.not_valid_after < now)
            expiring_soon = sum(1 for c in certificates if now <= c.not_valid_after < now + timedelta(days=30))

            lines.extend([
                '',
                '# HELP ssl_certificates_expired Number of expired certificates',
                '# TYPE ssl_certificates_expired gauge',
                f'ssl_certificates_expired {expired}',
                '',
                '# HELP ssl_certificates_expiring_soon Number of certificates expiring in 30 days',
                '# TYPE ssl_certificates_expiring_soon gauge',
                f'ssl_certificates_expiring_soon {expiring_soon}'
            ])

            # Add days until expiry metric (easier for graphing)
            lines.extend([
                '',
                '# HELP ssl_certificate_days_until_expiry Days until certificate expires',
                '# TYPE ssl_certificate_days_until_expiry gauge'
            ])

            for cert in certificates:
                days_until_expiry = (cert.not_valid_after - now).total_seconds() / 86400

                labels = {
                    'cn': self._escape_label(cert.common_name or 'unknown'),
                    'serial': self._escape_label(cert.serial_number),
                    'file_path': self._escape_label(cert.file_path)
                }

                label_str = ','.join([f'{k}="{v}"' for k, v in labels.items()])
                lines.append(f'ssl_certificate_days_until_expiry{{{label_str}}} {days_until_expiry:.2f}')

        finally:
            session.close()

        return '\n'.join(lines) + '\n'

    def _escape_label(self, value: str) -> str:
        """Escape label values for Prometheus format."""
        if not value:
            return ''
        # Escape backslashes, quotes, and newlines
        return value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

    def export_metrics(self) -> bool:
        """Export metrics to textfile for node_exporter."""
        if not self.enabled:
            print("Prometheus export is disabled in configuration")
            return False

        try:
            # Ensure output directory exists
            os.makedirs(self.textfile_path, exist_ok=True)

            # Generate metrics
            metrics_content = self.generate_metrics()

            # Write to temporary file first (atomic write)
            output_path = os.path.join(self.textfile_path, self.metrics_file)
            temp_path = output_path + '.tmp'

            with open(temp_path, 'w') as f:
                f.write(metrics_content)

            # Atomic rename
            os.replace(temp_path, output_path)

            print(f"Metrics exported successfully to {output_path}")
            return True

        except Exception as e:
            print(f"Error exporting metrics: {e}")
            return False

    def print_metrics(self):
        """Print metrics to stdout (for testing)."""
        print(self.generate_metrics())


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Export SSL certificate metrics for Prometheus')
    parser.add_argument('--config', default='config/config.json', help='Path to configuration file')
    parser.add_argument('--print', action='store_true', help='Print metrics to stdout instead of writing to file')
    parser.add_argument('--test', action='store_true', help='Test mode - print metrics and exit')
    args = parser.parse_args()

    # Load configuration
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

    # Create exporter
    exporter = PrometheusExporter(config)

    # Print or export
    if args.print or args.test:
        exporter.print_metrics()
    else:
        success = exporter.export_metrics()
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
