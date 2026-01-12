#!/usr/bin/env python3
"""
Integrated monitoring script for SSL certificate management.

This script performs:
1. Certificate expiration checks
2. SNMP trap generation with escalating frequency
3. Prometheus metrics export

Designed to be run periodically via cron or systemd timer.

Usage:
    python run_monitoring.py [--config CONFIG_PATH] [--snmp] [--prometheus]

Example cron entry (run every hour):
    0 * * * * /usr/bin/python3 /path/to/run_monitoring.py

Example systemd timer (ssl-monitoring.timer):
    [Unit]
    Description=SSL Certificate Monitoring Timer

    [Timer]
    OnCalendar=hourly
    Persistent=true

    [Install]
    WantedBy=timers.target
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta
from typing import List, Dict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import Certificate, DatabaseManager
from notifications.snmp_notifier import SNMPNotifier
from scripts.prometheus_exporter import PrometheusExporter


class CertificateMonitor:
    """Monitor certificates and trigger appropriate notifications."""

    def __init__(self, config: dict):
        self.config = config
        self.db_manager = DatabaseManager(config)
        self.snmp_notifier = SNMPNotifier(config, self.db_manager)
        self.prom_exporter = PrometheusExporter(config)

    def check_certificates(self) -> Dict:
        """Check all certificates and send notifications as needed."""
        results = {
            'checked': 0,
            'expiring': 0,
            'expired': 0,
            'traps_sent': 0,
            'trap_skipped': 0,
            'errors': []
        }

        session = self.db_manager.get_session()
        try:
            certificates = session.query(Certificate).all()
            results['checked'] = len(certificates)

            now = datetime.utcnow()

            for cert in certificates:
                try:
                    # Check if certificate is expired
                    if cert.not_valid_after < now:
                        results['expired'] += 1
                        continue

                    # Check if certificate is expiring soon
                    time_until_expiry = cert.not_valid_after - now
                    days_until_expiry = time_until_expiry.total_seconds() / 86400

                    # Send SNMP trap if enabled and conditions are met
                    if self.snmp_notifier.enabled:
                        trap_sent = self.snmp_notifier.send_expiration_trap(cert)
                        if trap_sent:
                            results['traps_sent'] += 1
                            results['expiring'] += 1
                        else:
                            # Trap not sent (could be due to frequency throttling)
                            results['trap_skipped'] += 1

                except Exception as e:
                    error_msg = f"Error processing certificate {cert.id}: {str(e)}"
                    results['errors'].append(error_msg)
                    print(error_msg)

        finally:
            session.close()

        return results

    def run_snmp_monitoring(self) -> Dict:
        """Run SNMP monitoring check."""
        if not self.snmp_notifier.enabled:
            return {
                'success': False,
                'message': 'SNMP monitoring is disabled'
            }

        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running SNMP monitoring check...")
        results = self.check_certificates()

        print(f"  Checked: {results['checked']} certificates")
        print(f"  Expiring: {results['expiring']} certificates")
        print(f"  Expired: {results['expired']} certificates")
        print(f"  SNMP traps sent: {results['traps_sent']}")
        print(f"  SNMP traps skipped: {results['trap_skipped']} (frequency throttling)")

        if results['errors']:
            print(f"  Errors: {len(results['errors'])}")
            for error in results['errors'][:5]:  # Show first 5 errors
                print(f"    - {error}")

        return {
            'success': True,
            'results': results
        }

    def run_prometheus_export(self) -> Dict:
        """Run Prometheus metrics export."""
        if not self.prom_exporter.enabled:
            return {
                'success': False,
                'message': 'Prometheus export is disabled'
            }

        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Exporting Prometheus metrics...")
        success = self.prom_exporter.export_metrics()

        return {
            'success': success,
            'message': 'Metrics exported successfully' if success else 'Export failed'
        }

    def run_all(self) -> Dict:
        """Run all monitoring tasks."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'snmp': None,
            'prometheus': None
        }

        print(f"\n{'='*60}")
        print(f"SSL Certificate Monitoring - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        # Run SNMP monitoring
        if self.snmp_notifier.enabled:
            results['snmp'] = self.run_snmp_monitoring()
        else:
            print("SNMP monitoring: disabled")

        print()

        # Run Prometheus export
        if self.prom_exporter.enabled:
            results['prometheus'] = self.run_prometheus_export()
        else:
            print("Prometheus export: disabled")

        print(f"\n{'='*60}\n")

        return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run SSL certificate monitoring tasks')
    parser.add_argument('--config', default='config/config.json', help='Path to configuration file')
    parser.add_argument('--snmp', action='store_true', help='Only run SNMP monitoring')
    parser.add_argument('--prometheus', action='store_true', help='Only run Prometheus export')
    parser.add_argument('--test', action='store_true', help='Test mode - check config and exit')
    args = parser.parse_args()

    # Load configuration
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

    # Create monitor
    monitor = CertificateMonitor(config)

    # Test mode
    if args.test:
        print("Configuration loaded successfully")
        print(f"SNMP enabled: {monitor.snmp_notifier.enabled}")
        print(f"Prometheus enabled: {monitor.prom_exporter.enabled}")
        if monitor.snmp_notifier.enabled:
            print(f"  SNMP host: {monitor.snmp_notifier.host}:{monitor.snmp_notifier.port}")
            print(f"  Trap frequency: {monitor.snmp_notifier.trap_frequency_hours} hours")
        if monitor.prom_exporter.enabled:
            print(f"  Prometheus path: {monitor.prom_exporter.textfile_path}")
            print(f"  Metrics file: {monitor.prom_exporter.metrics_file}")
        sys.exit(0)

    # Run selected tasks
    try:
        if args.snmp:
            result = monitor.run_snmp_monitoring()
        elif args.prometheus:
            result = monitor.run_prometheus_export()
        else:
            result = monitor.run_all()

        # Exit with appropriate code
        if result.get('success', True):
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
