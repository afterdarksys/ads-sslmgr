#!/usr/bin/env python3
"""
Script to send certificate expiration notifications
Called by cron jobs for automated notifications
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.models import DatabaseManager, get_database_url
from notifications.email_notifier import EmailNotifier
from notifications.snmp_notifier import SNMPNotifier


def load_config(config_path: str = None) -> dict:
    """Load configuration from file."""
    if not config_path:
        config_path = project_root / "config" / "config.json"
    
    config_file = Path(config_path)
    if not config_file.exists():
        print(f"Configuration file not found: {config_file}")
        sys.exit(1)
    
    with open(config_file) as f:
        return json.load(f)


def send_notifications(days_before: int, config: dict, dry_run: bool = False) -> dict:
    """Send notifications for certificates expiring in specified days."""
    
    print(f"Processing notifications for certificates expiring in {days_before} days...")
    
    # Initialize components
    db_manager = DatabaseManager(get_database_url(config))
    email_notifier = EmailNotifier(config, db_manager)
    snmp_notifier = SNMPNotifier(config, db_manager)
    
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'days_before': days_before,
        'dry_run': dry_run,
        'email': {'sent': 0, 'failed': 0, 'errors': []},
        'snmp': {'sent': 0, 'failed': 0, 'errors': []}
    }
    
    try:
        if not dry_run:
            # Send email notifications
            email_results = email_notifier.send_expiration_notifications(days_before)
            results['email'] = email_results
            
            print(f"Email notifications: {email_results['sent']} sent, {email_results['failed']} failed")
            
            # Send SNMP notifications if enabled
            if config.get('snmp', {}).get('enabled', False):
                # Get certificates that would trigger SNMP notifications
                session = db_manager.get_session()
                try:
                    from datetime import timedelta
                    from database.models import Certificate
                    
                    target_date = datetime.utcnow() + timedelta(days=days_before)
                    start_date = target_date - timedelta(days=1)
                    
                    expiring_certs = session.query(Certificate).filter(
                        Certificate.not_valid_after >= start_date,
                        Certificate.not_valid_after <= target_date,
                        Certificate.is_active == True,
                        Certificate.is_expired == False
                    ).all()
                    
                    snmp_sent = 0
                    snmp_failed = 0
                    snmp_errors = []
                    
                    for cert in expiring_certs:
                        try:
                            success = snmp_notifier.send_expiration_trap(cert, days_before)
                            if success:
                                snmp_sent += 1
                            else:
                                snmp_failed += 1
                        except Exception as e:
                            snmp_failed += 1
                            snmp_errors.append(f"SNMP error for cert {cert.id}: {str(e)}")
                    
                    results['snmp'] = {
                        'sent': snmp_sent,
                        'failed': snmp_failed,
                        'errors': snmp_errors
                    }
                    
                    print(f"SNMP notifications: {snmp_sent} sent, {snmp_failed} failed")
                    
                finally:
                    session.close()
        else:
            print("DRY RUN - No notifications will be sent")
            
            # Just count what would be sent
            session = db_manager.get_session()
            try:
                from datetime import timedelta
                from database.models import Certificate
                
                target_date = datetime.utcnow() + timedelta(days=days_before)
                start_date = target_date - timedelta(days=1)
                
                expiring_certs = session.query(Certificate).filter(
                    Certificate.not_valid_after >= start_date,
                    Certificate.not_valid_after <= target_date,
                    Certificate.is_active == True,
                    Certificate.is_expired == False
                ).all()
                
                print(f"Would send notifications for {len(expiring_certs)} certificates")
                
                for cert in expiring_certs:
                    print(f"  - {cert.common_name} (expires: {cert.not_valid_after})")
                
                results['certificates_found'] = len(expiring_certs)
                
            finally:
                session.close()
        
        return results
        
    except Exception as e:
        error_msg = f"Error in notification process: {str(e)}"
        print(error_msg)
        results['error'] = error_msg
        
        # Send system error SNMP trap if configured
        if config.get('snmp', {}).get('enabled', False):
            try:
                snmp_notifier.send_system_error_trap(error_msg, "notification_system")
            except:
                pass  # Don't fail if SNMP error notification fails
        
        return results


def main():
    """Main entry point for the notification script."""
    parser = argparse.ArgumentParser(description='Send SSL certificate expiration notifications')
    parser.add_argument('--days', type=int, required=True, 
                       help='Days before expiration to send notifications for')
    parser.add_argument('--config', default=None,
                       help='Path to configuration file')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be sent without actually sending')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Send notifications
    results = send_notifications(args.days, config, args.dry_run)
    
    # Output results
    if args.verbose:
        print(json.dumps(results, indent=2))
    
    # Exit with appropriate code
    if 'error' in results:
        sys.exit(1)
    else:
        total_failed = results.get('email', {}).get('failed', 0) + results.get('snmp', {}).get('failed', 0)
        if total_failed > 0:
            print(f"Completed with {total_failed} failures")
            sys.exit(2)  # Partial failure
        else:
            print("Notifications sent successfully")
            sys.exit(0)


if __name__ == "__main__":
    main()
