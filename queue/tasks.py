"""
Celery Tasks for Async Certificate Operations
Handles certificate renewal, validation, and monitoring as background jobs
Uses Message Queue for distributed processing - no more constant scanning!
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from celery import Celery, Task, group, chain, chord
from celery.schedules import crontab
from kombu import Queue

# Initialize Celery app
app = Celery('sslmgr')

# Load configuration from config file or environment
app.config_from_object('queue.celeryconfig')

# Define queues with priority levels
app.conf.task_queues = (
    Queue('critical', routing_key='critical', priority=10),
    Queue('high', routing_key='high', priority=7),
    Queue('normal', routing_key='normal', priority=5),
    Queue('low', routing_key='low', priority=3),
)

# Task routing based on urgency
app.conf.task_routes = {
    'queue.tasks.renew_certificate_urgent': {'queue': 'critical'},
    'queue.tasks.renew_certificate_high': {'queue': 'high'},
    'queue.tasks.renew_certificate': {'queue': 'normal'},
    'queue.tasks.validate_certificate': {'queue': 'normal'},
    'queue.tasks.scan_desktop': {'queue': 'low'},
}

logger = logging.getLogger(__name__)


# ============================================================================
# BASE TASK CLASSES
# ============================================================================

class SSLManagerTask(Task):
    """Base task with common functionality"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Task {task_id} failed: {exc}")

        # Log to database
        try:
            from database.models import DatabaseManager, get_database_url
            from queue.job_tracker import JobTracker

            config = self.app.conf.get('config', {})
            db_manager = DatabaseManager(get_database_url(config))
            tracker = JobTracker(db_manager)

            tracker.mark_failed(task_id, str(exc))
        except Exception as e:
            logger.error(f"Failed to log task failure: {e}")

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info(f"Task {task_id} completed successfully")

        # Log to database
        try:
            from database.models import DatabaseManager, get_database_url
            from queue.job_tracker import JobTracker

            config = self.app.conf.get('config', {})
            db_manager = DatabaseManager(get_database_url(config))
            tracker = JobTracker(db_manager)

            tracker.mark_completed(task_id, retval)
        except Exception as e:
            logger.error(f"Failed to log task success: {e}")


# ============================================================================
# CERTIFICATE RENEWAL TASKS
# ============================================================================

@app.task(base=SSLManagerTask, bind=True, max_retries=3, default_retry_delay=300)
def renew_certificate(self, cert_id: int, force_ca: str = None,
                     renewal_options: Dict = None) -> Dict:
    """
    Renew a certificate (normal priority)

    Args:
        cert_id: Certificate ID to renew
        force_ca: Force specific CA
        renewal_options: Additional renewal options

    Returns:
        Renewal result
    """
    try:
        from core.certificate_manager import CertificateManager
        from core.renewal_router import RenewalRouter
        from database.models import DatabaseManager, get_database_url

        config = self.app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)
        renewal_router = RenewalRouter(config, db_manager)

        # Get certificate
        cert = cert_manager.get_certificate_by_id(cert_id)
        if not cert:
            raise ValueError(f"Certificate {cert_id} not found")

        logger.info(f"Renewing certificate {cert_id}: {cert.get('common_name')}")

        # Pre-renewal validation
        from validators.certificate_validator import CertificateValidator
        from integrations.dnsscience_integration import DNSScienceClient

        validator = CertificateValidator(config)
        dnsscience = DNSScienceClient(config)

        # Check DNS readiness
        domain = cert.get('common_name', '').replace('*.', '')
        dns_check = dnsscience.pre_renewal_validation(domain)

        if not dns_check['ready_for_renewal']:
            logger.warning(f"DNS not ready for renewal: {dns_check['blockers']}")
            # Still attempt renewal but log warning
            pass

        # Perform renewal
        result = renewal_router.route_renewal(
            cert,
            force_ca=force_ca,
            renewal_options=renewal_options or {}
        )

        if result['success']:
            logger.info(f"Certificate {cert_id} renewed successfully")

            # Post-renewal validation
            validation_task = validate_certificate.delay(cert_id)
            result['validation_task_id'] = validation_task.id

        else:
            logger.error(f"Certificate {cert_id} renewal failed: {result.get('error')}")

            # Retry if transient error
            if result.get('retryable'):
                raise self.retry(countdown=300)  # Retry in 5 minutes

        return result

    except Exception as e:
        logger.error(f"Error renewing certificate {cert_id}: {e}")

        # Retry on error
        try:
            raise self.retry(countdown=300)
        except self.MaxRetriesExceededError:
            return {
                'success': False,
                'error': f'Max retries exceeded: {str(e)}',
                'cert_id': cert_id
            }


@app.task(base=SSLManagerTask, bind=True, max_retries=5, default_retry_delay=180)
def renew_certificate_urgent(self, cert_id: int, force_ca: str = None,
                            renewal_options: Dict = None) -> Dict:
    """
    Renew certificate urgently (high priority, shorter retry delay)
    Used for certificates expiring in < 7 days
    """
    logger.warning(f"URGENT renewal for certificate {cert_id}")
    return renew_certificate(self, cert_id, force_ca, renewal_options)


@app.task(base=SSLManagerTask, bind=True, max_retries=3, default_retry_delay=600)
def renew_certificate_high(self, cert_id: int, force_ca: str = None,
                          renewal_options: Dict = None) -> Dict:
    """
    Renew certificate with high priority
    Used for certificates expiring in < 15 days
    """
    logger.info(f"High priority renewal for certificate {cert_id}")
    return renew_certificate(self, cert_id, force_ca, renewal_options)


@app.task(base=SSLManagerTask)
def batch_renew_certificates(cert_ids: List[int], force_ca: str = None) -> Dict:
    """
    Batch renew multiple certificates
    Creates individual tasks for each certificate
    """
    logger.info(f"Batch renewal for {len(cert_ids)} certificates")

    # Group tasks based on urgency
    from core.certificate_manager import CertificateManager
    from database.models import DatabaseManager, get_database_url

    config = app.conf.get('config', {})
    db_manager = DatabaseManager(get_database_url(config))
    cert_manager = CertificateManager(config)

    urgent_tasks = []
    high_tasks = []
    normal_tasks = []

    for cert_id in cert_ids:
        try:
            cert = cert_manager.get_certificate_by_id(cert_id)
            days_until_expiry = cert.get('days_until_expiry', 999)

            if days_until_expiry < 7:
                task = renew_certificate_urgent.signature((cert_id,), {'force_ca': force_ca})
                urgent_tasks.append(task)
            elif days_until_expiry < 15:
                task = renew_certificate_high.signature((cert_id,), {'force_ca': force_ca})
                high_tasks.append(task)
            else:
                task = renew_certificate.signature((cert_id,), {'force_ca': force_ca})
                normal_tasks.append(task)

        except Exception as e:
            logger.error(f"Error queueing certificate {cert_id}: {e}")

    # Execute tasks in priority order
    results = {
        'total': len(cert_ids),
        'queued': {
            'urgent': len(urgent_tasks),
            'high': len(high_tasks),
            'normal': len(normal_tasks)
        },
        'task_ids': []
    }

    # Submit tasks
    for task in urgent_tasks + high_tasks + normal_tasks:
        result = task.apply_async()
        results['task_ids'].append(result.id)

    return results


# ============================================================================
# VALIDATION TASKS
# ============================================================================

@app.task(base=SSLManagerTask)
def validate_certificate(cert_id: int, full_validation: bool = True) -> Dict:
    """
    Validate a certificate

    Args:
        cert_id: Certificate ID to validate
        full_validation: Perform full validation including chain, revocation, etc.

    Returns:
        Validation report
    """
    try:
        from core.certificate_manager import CertificateManager
        from validators.certificate_validator import CertificateValidator
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)
        validator = CertificateValidator(config)

        # Get certificate
        cert = cert_manager.get_certificate_by_id(cert_id)
        if not cert:
            raise ValueError(f"Certificate {cert_id} not found")

        logger.info(f"Validating certificate {cert_id}: {cert.get('common_name')}")

        # Perform validation
        report = validator.validate_certificate(
            cert,
            check_chain=full_validation,
            check_revocation=full_validation,
            check_transparency=full_validation,
            check_policy=full_validation
        )

        # Store validation report in database
        # (Implementation would save report to validation_reports table)

        return report

    except Exception as e:
        logger.error(f"Error validating certificate {cert_id}: {e}")
        return {
            'success': False,
            'error': str(e),
            'cert_id': cert_id
        }


@app.task(base=SSLManagerTask)
def batch_validate_certificates(cert_ids: List[int]) -> Dict:
    """Batch validate multiple certificates"""
    logger.info(f"Batch validation for {len(cert_ids)} certificates")

    # Create validation tasks
    job = group(validate_certificate.s(cert_id) for cert_id in cert_ids)
    result = job.apply_async()

    return {
        'total': len(cert_ids),
        'group_id': result.id
    }


# ============================================================================
# THREAT INTELLIGENCE TASKS
# ============================================================================

@app.task(base=SSLManagerTask)
def check_certificate_threats(cert_id: int) -> Dict:
    """Check certificate for security threats"""
    try:
        from core.certificate_manager import CertificateManager
        from integrations.darkapi_integration import DarkAPIClient
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)
        darkapi = DarkAPIClient(config)

        cert = cert_manager.get_certificate_by_id(cert_id)
        if not cert:
            raise ValueError(f"Certificate {cert_id} not found")

        logger.info(f"Checking threats for certificate {cert_id}: {cert.get('common_name')}")

        # Check for threats
        report = darkapi.check_certificate_threats(cert)

        # Store threat report
        # (Implementation would save to threat_reports table)

        # If threats found, create alert
        if report['threat_score'] > 50:
            logger.warning(f"High threat score ({report['threat_score']}) for certificate {cert_id}")
            # Send alert (implementation would use notification system)

        return report

    except Exception as e:
        logger.error(f"Error checking threats for certificate {cert_id}: {e}")
        return {
            'success': False,
            'error': str(e),
            'cert_id': cert_id
        }


# ============================================================================
# DNS VALIDATION TASKS
# ============================================================================

@app.task(base=SSLManagerTask)
def validate_dns_for_certificate(cert_id: int) -> Dict:
    """Validate DNS for certificate domain"""
    try:
        from core.certificate_manager import CertificateManager
        from integrations.dnsscience_integration import DNSScienceClient
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)
        dnsscience = DNSScienceClient(config)

        cert = cert_manager.get_certificate_by_id(cert_id)
        if not cert:
            raise ValueError(f"Certificate {cert_id} not found")

        domain = cert.get('common_name', '').replace('*.', '')
        logger.info(f"Validating DNS for certificate {cert_id}: {domain}")

        # Validate DNS
        report = dnsscience.validate_dns_for_certificate(domain, cert)

        # Store DNS validation report
        # (Implementation would save to dns_validation_reports table)

        return report

    except Exception as e:
        logger.error(f"Error validating DNS for certificate {cert_id}: {e}")
        return {
            'success': False,
            'error': str(e),
            'cert_id': cert_id
        }


# ============================================================================
# DESKTOP SCANNING TASKS
# ============================================================================

@app.task(base=SSLManagerTask)
def scan_desktop(save_to_database: bool = True) -> Dict:
    """Scan desktop for certificates"""
    try:
        from agents.desktop_scanner import DesktopCertificateScanner
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        logger.info("Starting desktop certificate scan")

        scanner = DesktopCertificateScanner(config)
        results = scanner.scan_all()

        if save_to_database:
            # Save discovered certificates to database
            # (Implementation would bulk insert/update certificates)
            pass

        logger.info(f"Desktop scan completed: {results['statistics']['total_certificates']} certificates found")

        return results

    except Exception as e:
        logger.error(f"Error scanning desktop: {e}")
        return {
            'success': False,
            'error': str(e)
        }


# ============================================================================
# MONITORING AND SCHEDULING TASKS
# ============================================================================

@app.task(base=SSLManagerTask)
def monitor_expiry_and_queue_renewals() -> Dict:
    """
    Monitor certificate expiry and queue renewal jobs
    This replaces constant scanning - runs periodically via Celery Beat
    """
    try:
        from core.certificate_manager import CertificateManager
        from validators.certificate_validator import CertificateValidator
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)
        validator = CertificateValidator(config)

        logger.info("Starting expiry monitoring and renewal queue")

        # Get all active certificates
        certificates = cert_manager.get_all_active_certificates()

        # Monitor expiry
        summary = validator.monitor_expiry_batch(certificates)

        # Queue renewals based on urgency
        renewal_stats = {
            'urgent_queued': 0,
            'high_queued': 0,
            'medium_queued': 0,
            'alerts_sent': 0
        }

        # CRITICAL: < 7 days - queue urgent renewal
        for item in summary['critical']:
            cert = item['cert']
            cert_id = cert.get('id')

            logger.warning(f"Queueing URGENT renewal for certificate {cert_id} (expires in {cert.get('days_until_expiry')} days)")

            renew_certificate_urgent.apply_async(
                args=[cert_id],
                priority=10
            )
            renewal_stats['urgent_queued'] += 1

        # HIGH: < 15 days - queue high priority renewal
        for item in summary['high']:
            cert = item['cert']
            cert_id = cert.get('id')

            logger.info(f"Queueing high priority renewal for certificate {cert_id} (expires in {cert.get('days_until_expiry')} days)")

            renew_certificate_high.apply_async(
                args=[cert_id],
                priority=7
            )
            renewal_stats['high_queued'] += 1

        # MEDIUM: < 30 days - queue normal renewal
        for item in summary['medium']:
            cert = item['cert']
            cert_id = cert.get('id')

            logger.info(f"Queueing normal renewal for certificate {cert_id} (expires in {cert.get('days_until_expiry')} days)")

            renew_certificate.apply_async(
                args=[cert_id],
                priority=5
            )
            renewal_stats['medium_queued'] += 1

        # Send alerts for expired certificates
        for item in summary['expired']:
            cert = item['cert']
            logger.error(f"Certificate {cert.get('id')} is EXPIRED: {cert.get('common_name')}")
            # Send critical alert (implementation would use notification system)
            renewal_stats['alerts_sent'] += 1

        logger.info(f"Expiry monitoring completed: {renewal_stats}")

        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'total_certificates': summary['total_certificates'],
            'expired': len(summary['expired']),
            'critical': len(summary['critical']),
            'high': len(summary['high']),
            'medium': len(summary['medium']),
            'renewal_stats': renewal_stats
        }

    except Exception as e:
        logger.error(f"Error in expiry monitoring: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@app.task(base=SSLManagerTask)
def daily_threat_intelligence_scan() -> Dict:
    """
    Daily threat intelligence scan for all active certificates
    """
    try:
        from core.certificate_manager import CertificateManager
        from database.models import DatabaseManager, get_database_url

        config = app.conf.get('config', {})
        db_manager = DatabaseManager(get_database_url(config))

        cert_manager = CertificateManager(config)

        logger.info("Starting daily threat intelligence scan")

        # Get all active certificates
        certificates = cert_manager.get_all_active_certificates()

        # Queue threat checks
        job = group(check_certificate_threats.s(cert.get('id')) for cert in certificates)
        result = job.apply_async()

        return {
            'success': True,
            'total_certificates': len(certificates),
            'group_id': result.id
        }

    except Exception as e:
        logger.error(f"Error in threat intelligence scan: {e}")
        return {
            'success': False,
            'error': str(e)
        }


# ============================================================================
# PERIODIC TASKS (Celery Beat Schedule)
# ============================================================================

@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks"""

    # Monitor expiry and queue renewals - every 4 hours
    sender.add_periodic_task(
        crontab(minute=0, hour='*/4'),
        monitor_expiry_and_queue_renewals.s(),
        name='monitor_expiry_4h'
    )

    # Daily threat intelligence scan - 2am
    sender.add_periodic_task(
        crontab(hour=2, minute=0),
        daily_threat_intelligence_scan.s(),
        name='daily_threat_scan'
    )

    # Weekly desktop scan - Sunday 3am
    sender.add_periodic_task(
        crontab(hour=3, minute=0, day_of_week=0),
        scan_desktop.s(save_to_database=True),
        name='weekly_desktop_scan'
    )


if __name__ == '__main__':
    app.start()
