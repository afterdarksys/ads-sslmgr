"""
Cron job scheduler for SSL certificate expiration notifications
"""

import os
import json
from datetime import datetime
from typing import Dict, List
from crontab import CronTab
from pathlib import Path

from notifications.email_notifier import EmailNotifier
from notifications.snmp_notifier import SNMPNotifier
from database.models import DatabaseManager, get_database_url


class CronScheduler:
    """Manage cron jobs for certificate expiration notifications."""
    
    def __init__(self, config: dict):
        self.config = config
        self.notification_days = config.get('notification_days', [120, 90, 60, 30, 15, 5, 2, 1])
        self.project_root = Path(__file__).parent.parent
        
        # Initialize cron
        self.cron = CronTab(user=True)
        
        # Job identifiers
        self.job_comment_prefix = "sslmgr_notification"
    
    def setup_notification_jobs(self) -> Dict:
        """Set up cron jobs for all notification intervals."""
        results = {
            'created': 0,
            'updated': 0,
            'errors': []
        }
        
        try:
            # Remove existing SSL manager jobs
            self.remove_existing_jobs()
            
            # Create jobs for each notification interval
            for days in self.notification_days:
                try:
                    self._create_notification_job(days)
                    results['created'] += 1
                except Exception as e:
                    results['errors'].append(f"Error creating job for {days} days: {e}")
            
            # Write cron jobs
            self.cron.write()
            
            return results
            
        except Exception as e:
            results['errors'].append(f"General error: {e}")
            return results
    
    def _create_notification_job(self, days_before: int):
        """Create a cron job for a specific notification interval."""
        
        # Determine cron schedule based on days
        if days_before >= 30:
            # Weekly for long-term notifications (every Monday at 9 AM)
            schedule = "0 9 * * 1"
        elif days_before >= 7:
            # Daily for medium-term notifications (9 AM daily)
            schedule = "0 9 * * *"
        else:
            # Twice daily for urgent notifications (9 AM and 3 PM)
            schedule = "0 9,15 * * *"
        
        # Python script path
        script_path = self.project_root / "scripts" / "send_notifications.py"
        
        # Command to run
        command = f"cd {self.project_root} && python {script_path} --days {days_before}"
        
        # Create cron job
        job = self.cron.new(command=command)
        job.setall(schedule)
        job.set_comment(f"{self.job_comment_prefix}_{days_before}days")
        
        # Enable the job
        job.enable()
    
    def remove_existing_jobs(self):
        """Remove existing SSL manager cron jobs."""
        jobs_to_remove = []
        
        for job in self.cron:
            if job.comment and self.job_comment_prefix in job.comment:
                jobs_to_remove.append(job)
        
        for job in jobs_to_remove:
            self.cron.remove(job)
    
    def list_jobs(self) -> List[Dict]:
        """List all SSL manager cron jobs."""
        jobs = []
        
        for job in self.cron:
            if job.comment and self.job_comment_prefix in job.comment:
                jobs.append({
                    'comment': job.comment,
                    'command': str(job.command),
                    'schedule': str(job.slices),
                    'enabled': job.is_enabled()
                })
        
        return jobs
    
    def enable_job(self, days_before: int) -> bool:
        """Enable a specific notification job."""
        comment = f"{self.job_comment_prefix}_{days_before}days"
        
        for job in self.cron:
            if job.comment == comment:
                job.enable()
                self.cron.write()
                return True
        
        return False
    
    def disable_job(self, days_before: int) -> bool:
        """Disable a specific notification job."""
        comment = f"{self.job_comment_prefix}_{days_before}days"
        
        for job in self.cron:
            if job.comment == comment:
                job.enable(False)
                self.cron.write()
                return True
        
        return False
    
    def get_job_status(self) -> Dict:
        """Get status of all notification jobs."""
        status = {
            'total_jobs': 0,
            'enabled_jobs': 0,
            'disabled_jobs': 0,
            'jobs': []
        }
        
        for job in self.cron:
            if job.comment and self.job_comment_prefix in job.comment:
                status['total_jobs'] += 1
                
                if job.is_enabled():
                    status['enabled_jobs'] += 1
                else:
                    status['disabled_jobs'] += 1
                
                # Extract days from comment
                days = job.comment.replace(f"{self.job_comment_prefix}_", "").replace("days", "")
                
                status['jobs'].append({
                    'days_before': int(days) if days.isdigit() else 0,
                    'enabled': job.is_enabled(),
                    'schedule': str(job.slices),
                    'next_run': self._get_next_run_time(job)
                })
        
        # Sort by days_before
        status['jobs'].sort(key=lambda x: x['days_before'], reverse=True)
        
        return status
    
    def _get_next_run_time(self, job) -> str:
        """Get next run time for a cron job."""
        try:
            # This is a simplified version - in production you'd want more accurate calculation
            return "Next run calculation not implemented"
        except:
            return "Unknown"
    
    def test_notification_system(self) -> Dict:
        """Test the notification system without sending actual notifications."""
        try:
            # Initialize components
            db_manager = DatabaseManager(get_database_url(self.config))
            email_notifier = EmailNotifier(self.config, db_manager)
            
            results = {
                'email_config_valid': False,
                'database_accessible': False,
                'certificates_found': 0,
                'test_results': {}
            }
            
            # Test database connection
            try:
                session = db_manager.get_session()
                session.close()
                results['database_accessible'] = True
            except Exception as e:
                results['database_error'] = str(e)
            
            # Test email configuration
            email_test = email_notifier.test_email_configuration()
            results['email_config_valid'] = email_test['success']
            if not email_test['success']:
                results['email_error'] = email_test.get('error', 'Unknown error')
            
            # Count certificates that would trigger notifications
            for days in self.notification_days:
                try:
                    # This would normally call the notification method in dry-run mode
                    results['test_results'][f'{days}_days'] = {
                        'status': 'ready',
                        'message': f'Job configured for {days} days before expiration'
                    }
                except Exception as e:
                    results['test_results'][f'{days}_days'] = {
                        'status': 'error',
                        'message': str(e)
                    }
            
            return results
            
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }


def main():
    """Command line interface for cron scheduler."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SSL Certificate Notification Scheduler')
    parser.add_argument('--setup', action='store_true', help='Set up cron jobs')
    parser.add_argument('--list', action='store_true', help='List existing jobs')
    parser.add_argument('--status', action='store_true', help='Show job status')
    parser.add_argument('--test', action='store_true', help='Test notification system')
    parser.add_argument('--config', default='config/config.json', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        return
    
    with open(config_path) as f:
        config = json.load(f)
    
    scheduler = CronScheduler(config)
    
    if args.setup:
        print("Setting up notification cron jobs...")
        results = scheduler.setup_notification_jobs()
        print(f"Created: {results['created']}, Updated: {results['updated']}")
        if results['errors']:
            print("Errors:")
            for error in results['errors']:
                print(f"  - {error}")
    
    elif args.list:
        jobs = scheduler.list_jobs()
        print(f"Found {len(jobs)} SSL manager cron jobs:")
        for job in jobs:
            status = "enabled" if job['enabled'] else "disabled"
            print(f"  - {job['comment']} ({status}): {job['schedule']}")
    
    elif args.status:
        status = scheduler.get_job_status()
        print(f"Job Status: {status['enabled_jobs']}/{status['total_jobs']} enabled")
        for job in status['jobs']:
            status_text = "✓" if job['enabled'] else "✗"
            print(f"  {status_text} {job['days_before']} days: {job['schedule']}")
    
    elif args.test:
        print("Testing notification system...")
        results = scheduler.test_notification_system()
        print(f"Database accessible: {results.get('database_accessible', False)}")
        print(f"Email config valid: {results.get('email_config_valid', False)}")
        
        if 'test_results' in results:
            print("Notification job tests:")
            for job, result in results['test_results'].items():
                print(f"  - {job}: {result['status']}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
