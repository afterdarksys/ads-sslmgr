#!/usr/bin/env python3
"""
SSL Certificate Manager - Python CLI Interface
Command-line interface for managing SSL certificates
"""

import sys
import json
import click
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.models import DatabaseManager, get_database_url
from core.certificate_manager import CertificateManager
from core.certificate_parser import CertificateParser
from core.renewal_router import RenewalRouter
from notifications.cron_scheduler import CronScheduler
from notifications.email_notifier import EmailNotifier
from notifications.snmp_notifier import SNMPNotifier


def load_config(config_path: str = None) -> dict:
    """Load configuration from file."""
    if not config_path:
        config_path = project_root / "config" / "config.json"
    
    config_file = Path(config_path)
    if not config_file.exists():
        click.echo(f"Configuration file not found: {config_file}")
        click.echo("Please copy config/config.example.json to config/config.json and configure it.")
        sys.exit(1)
    
    with open(config_file) as f:
        return json.load(f)


@click.group()
@click.option('--config', '-c', default=None, help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config, verbose):
    """SSL Certificate Manager - Comprehensive certificate management system."""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['verbose'] = verbose


@cli.group()
@click.pass_context
def scan(ctx):
    """Certificate scanning operations."""
    pass


@scan.command('directory')
@click.argument('directory_path', type=click.Path(exists=True))
@click.option('--update-ownership', is_flag=True, help='Update existing ownership information')
@click.pass_context
def scan_directory(ctx, directory_path, update_ownership):
    """Scan a directory for SSL certificates."""
    config = ctx.obj['config']
    verbose = ctx.obj['verbose']
    
    cert_manager = CertificateManager(config)
    
    click.echo(f"Scanning directory: {directory_path}")
    
    try:
        results = cert_manager.scan_directory(directory_path, update_ownership)
        
        click.echo(f"✓ Scan completed successfully")
        click.echo(f"  Job ID: {results['job_id']}")
        click.echo(f"  Certificates found: {results['certificates_found']}")
        click.echo(f"  Certificates added: {results['certificates_added']}")
        click.echo(f"  Certificates updated: {results['certificates_updated']}")
        
        if results['errors']:
            click.echo(f"  Errors: {len(results['errors'])}")
            if verbose:
                for error in results['errors']:
                    click.echo(f"    - {error}")
        
    except Exception as e:
        click.echo(f"✗ Scan failed: {e}")
        sys.exit(1)


@scan.command('file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']), 
              help='Output format')
@click.pass_context
def scan_file(ctx, file_path, output_format):
    """Parse a single certificate file."""
    verbose = ctx.obj['verbose']
    
    parser = CertificateParser()
    
    try:
        certificates = parser.parse_certificate_file(file_path)
        
        if output_format == 'json':
            click.echo(parser.to_json(certificates))
        else:
            for i, cert in enumerate(certificates):
                if i > 0:
                    click.echo("-" * 50)
                
                click.echo(f"Certificate #{i+1}:")
                click.echo(f"  Common Name: {cert['common_name']}")
                click.echo(f"  Issuer: {cert['issuer'].get('common_name', 'Unknown')}")
                click.echo(f"  Expires: {cert['not_valid_after']}")
                click.echo(f"  Days until expiry: {cert['days_until_expiry']}")
                click.echo(f"  Serial Number: {cert['serial_number']}")
                
                if cert['subject_alt_names']:
                    click.echo(f"  SANs: {', '.join(cert['subject_alt_names'])}")
                
                if verbose:
                    click.echo(f"  Certificate Type: {cert['certificate_type']}")
                    click.echo(f"  Issuer Category: {cert['issuer_category']}")
        
    except Exception as e:
        click.echo(f"✗ Failed to parse certificate: {e}")
        sys.exit(1)


@cli.group()
@click.pass_context
def list(ctx):
    """List certificates and information."""
    pass


@list.command('certificates')
@click.option('--expiring', type=int, help='Show certificates expiring within N days')
@click.option('--issuer', help='Filter by issuer category')
@click.option('--expired', is_flag=True, help='Show only expired certificates')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']),
              help='Output format')
@click.option('--limit', default=50, help='Maximum number of results')
@click.pass_context
def list_certificates(ctx, expiring, issuer, expired, output_format, limit):
    """List certificates in the database."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    
    # Build filters
    filters = {}
    if issuer:
        filters['issuer_category'] = issuer
    if expired:
        filters['is_expired'] = True
    if expiring:
        filters['days_until_expiry_max'] = expiring
    
    try:
        certificates = cert_manager.search_certificates(filters=filters)
        
        if limit:
            certificates = certificates[:limit]
        
        if output_format == 'json':
            cert_data = []
            for cert in certificates:
                cert_data.append({
                    'id': cert.id,
                    'common_name': cert.common_name,
                    'issuer_category': cert.issuer_category,
                    'days_until_expiry': cert.days_until_expiry,
                    'is_expired': cert.is_expired,
                    'file_path': cert.file_path
                })
            click.echo(json.dumps(cert_data, indent=2))
        else:
            if not certificates:
                click.echo("No certificates found matching criteria.")
                return
            
            click.echo(f"Found {len(certificates)} certificates:")
            click.echo()
            
            # Table header
            click.echo(f"{'ID':<5} {'Common Name':<30} {'Issuer':<15} {'Days':<6} {'Status':<8} {'File Path':<40}")
            click.echo("-" * 104)
            
            for cert in certificates:
                status = "EXPIRED" if cert.is_expired else "VALID"
                if cert.days_until_expiry <= 30 and not cert.is_expired:
                    status = "EXPIRING"
                
                click.echo(f"{cert.id:<5} {cert.common_name[:29]:<30} {cert.issuer_category[:14]:<15} "
                          f"{cert.days_until_expiry:<6} {status:<8} {cert.file_path[:39]:<40}")
        
    except Exception as e:
        click.echo(f"✗ Failed to list certificates: {e}")
        sys.exit(1)


@list.command('statistics')
@click.pass_context
def list_statistics(ctx):
    """Show certificate statistics."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    
    try:
        stats = cert_manager.get_certificate_statistics()
        
        click.echo("Certificate Statistics:")
        click.echo(f"  Total certificates: {stats['total_certificates']}")
        click.echo(f"  Expired certificates: {stats['expired_certificates']}")
        click.echo(f"  Expiring in 30 days: {stats['expiring_30_days']}")
        click.echo(f"  Expiring in 60 days: {stats['expiring_60_days']}")
        click.echo(f"  Expiring in 90 days: {stats['expiring_90_days']}")
        
        click.echo("\nBy Issuer:")
        for issuer, count in stats['by_issuer'].items():
            click.echo(f"  {issuer}: {count}")
        
        click.echo(f"\nLast updated: {stats['last_updated']}")
        
    except Exception as e:
        click.echo(f"✗ Failed to get statistics: {e}")
        sys.exit(1)


@cli.group()
@click.pass_context
def renew(ctx):
    """Certificate renewal operations."""
    pass


@renew.command('certificate')
@click.argument('cert_id', type=int)
@click.option('--ca', help='Force specific CA (letsencrypt, digicert, comodo, aws, cloudflare)')
@click.option('--domains', help='Comma-separated list of domains to include')
@click.option('--dry-run', is_flag=True, help='Show what would be done without executing')
@click.pass_context
def renew_certificate(ctx, cert_id, ca, domains, dry_run):
    """Renew a specific certificate."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    renewal_router = RenewalRouter(config, cert_manager.db_manager)
    
    try:
        # Get certificate
        cert = cert_manager.get_certificate_by_id(cert_id)
        if not cert:
            click.echo(f"✗ Certificate with ID {cert_id} not found")
            sys.exit(1)
        
        click.echo(f"Certificate: {cert.common_name}")
        click.echo(f"Current expiry: {cert.not_valid_after}")
        click.echo(f"Days until expiry: {cert.days_until_expiry}")
        
        if dry_run:
            click.echo("\n[DRY RUN] Would perform renewal with:")
            click.echo(f"  Target CA: {ca or 'auto-detect'}")
            if domains:
                click.echo(f"  Domains: {domains}")
            return
        
        # Prepare renewal options
        renewal_options = {}
        if domains:
            renewal_options['domains'] = [d.strip() for d in domains.split(',')]
        
        # Perform renewal
        click.echo("\nStarting renewal...")
        result = renewal_router.route_renewal(cert, force_ca=ca, renewal_options=renewal_options)
        
        if result['success']:
            click.echo(f"✓ Certificate renewed successfully")
            click.echo(f"  CA used: {result.get('routed_to', 'unknown')}")
            click.echo(f"  Method: {result.get('detection_method', 'unknown')}")
            if 'message' in result:
                click.echo(f"  Details: {result['message']}")
        else:
            click.echo(f"✗ Renewal failed: {result['error']}")
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"✗ Renewal failed: {e}")
        sys.exit(1)


@renew.command('batch')
@click.option('--expiring', type=int, default=30, help='Renew certificates expiring within N days')
@click.option('--ca', help='Force specific CA for all renewals')
@click.option('--dry-run', is_flag=True, help='Show what would be done without executing')
@click.pass_context
def renew_batch(ctx, expiring, ca, dry_run):
    """Batch renew multiple certificates."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    renewal_router = RenewalRouter(config, cert_manager.db_manager)
    
    try:
        # Get expiring certificates
        certificates = cert_manager.get_expiring_certificates(expiring)
        
        if not certificates:
            click.echo(f"No certificates expiring within {expiring} days")
            return
        
        click.echo(f"Found {len(certificates)} certificates expiring within {expiring} days")
        
        if dry_run:
            click.echo("\n[DRY RUN] Would renew:")
            for cert in certificates:
                click.echo(f"  - {cert.common_name} (expires in {cert.days_until_expiry} days)")
            return
        
        # Perform batch renewal
        click.echo("\nStarting batch renewal...")
        renewal_options = {}
        
        results = renewal_router.batch_renewal(certificates, renewal_options)
        
        click.echo(f"\nBatch renewal completed:")
        click.echo(f"  Total processed: {results['total_certificates']}")
        click.echo(f"  Successful: {results['successful_renewals']}")
        click.echo(f"  Failed: {results['failed_renewals']}")
        
        if results['errors']:
            click.echo(f"  Errors: {len(results['errors'])}")
            for error in results['errors']:
                click.echo(f"    - {error}")
        
        # Show detailed results
        if ctx.obj['verbose']:
            click.echo("\nDetailed results:")
            for result in results['results']:
                status = "✓" if result['success'] else "✗"
                click.echo(f"  {status} {result['common_name']} ({result['ca_used']}): {result['message']}")
        
    except Exception as e:
        click.echo(f"✗ Batch renewal failed: {e}")
        sys.exit(1)


@cli.group()
@click.pass_context
def notify(ctx):
    """Notification management."""
    pass


@notify.command('setup')
@click.pass_context
def notify_setup(ctx):
    """Set up notification cron jobs."""
    config = ctx.obj['config']
    
    scheduler = CronScheduler(config)
    
    try:
        results = scheduler.setup_notification_jobs()
        
        click.echo("Notification setup completed:")
        click.echo(f"  Jobs created: {results['created']}")
        click.echo(f"  Jobs updated: {results['updated']}")
        
        if results['errors']:
            click.echo(f"  Errors: {len(results['errors'])}")
            for error in results['errors']:
                click.echo(f"    - {error}")
        
    except Exception as e:
        click.echo(f"✗ Notification setup failed: {e}")
        sys.exit(1)


@notify.command('test')
@click.option('--email', is_flag=True, help='Test email notifications')
@click.option('--snmp', is_flag=True, help='Test SNMP notifications')
@click.pass_context
def notify_test(ctx, email, snmp):
    """Test notification systems."""
    config = ctx.obj['config']
    
    db_manager = DatabaseManager(get_database_url(config))
    
    if email or not snmp:
        click.echo("Testing email configuration...")
        email_notifier = EmailNotifier(config, db_manager)
        result = email_notifier.test_email_configuration()
        
        if result['success']:
            click.echo("✓ Email test successful")
        else:
            click.echo(f"✗ Email test failed: {result.get('error', 'Unknown error')}")
    
    if snmp or not email:
        click.echo("Testing SNMP configuration...")
        snmp_notifier = SNMPNotifier(config, db_manager)
        result = snmp_notifier.test_snmp_configuration()
        
        if result['success']:
            click.echo("✓ SNMP test successful")
            click.echo(f"  {result['message']}")
        else:
            click.echo(f"✗ SNMP test failed: {result['message']}")


@cli.group()
@click.pass_context
def config(ctx):
    """Configuration management."""
    pass


@config.command('test')
@click.pass_context
def config_test(ctx):
    """Test all integrations and configurations."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    renewal_router = RenewalRouter(config, cert_manager.db_manager)
    
    try:
        results = renewal_router.test_all_integrations()
        
        click.echo("Integration Test Results:")
        click.echo(f"  Total integrations: {results['summary']['total']}")
        click.echo(f"  Enabled: {results['summary']['enabled']}")
        click.echo(f"  Working: {results['summary']['working']}")
        click.echo(f"  Failed: {results['summary']['failed']}")
        
        click.echo("\nDetailed Results:")
        for ca_name, test_result in results['integrations'].items():
            status = "✓" if test_result.get('all_tests_passed', False) else "✗"
            enabled = "enabled" if test_result.get('enabled', False) else "disabled"
            
            click.echo(f"  {status} {ca_name.title()} ({enabled})")
            
            if test_result.get('errors'):
                for error in test_result['errors']:
                    click.echo(f"      - {error}")
        
    except Exception as e:
        click.echo(f"✗ Configuration test failed: {e}")
        sys.exit(1)


@cli.command('export')
@click.option('--format', 'output_format', default='json', type=click.Choice(['json', 'csv']),
              help='Export format')
@click.option('--output', '-o', help='Output file path')
@click.option('--issuer', help='Filter by issuer category')
@click.option('--expiring', type=int, help='Include only certificates expiring within N days')
@click.pass_context
def export(ctx, output_format, output, issuer, expiring):
    """Export certificate data."""
    config = ctx.obj['config']
    
    cert_manager = CertificateManager(config)
    
    # Build filters
    filters = {}
    if issuer:
        filters['issuer_category'] = issuer
    if expiring:
        filters['days_until_expiry_max'] = expiring
    
    try:
        if output_format == 'json':
            data = cert_manager.export_certificates_json(filters)
        else:
            # CSV export would be implemented here
            click.echo("CSV export not yet implemented")
            return
        
        if output:
            with open(output, 'w') as f:
                f.write(data)
            click.echo(f"✓ Data exported to {output}")
        else:
            click.echo(data)
        
    except Exception as e:
        click.echo(f"✗ Export failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
