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


def _make_provider_registry(config):
    from providers.config import ProviderConfig
    from providers.dns import BunnyDNSProvider, CloudflareDNSProvider
    from providers.registry import ProviderRegistry

    db = DatabaseManager(get_database_url(config))
    router = RenewalRouter(config, db)
    registry = router.provider_registry
    resolved = ProviderConfig(config)
    for name, provider_type in (('cloudflare', CloudflareDNSProvider), ('bunny', BunnyDNSProvider)):
        keys = ('enabled', 'api_token', 'api_key', 'zone_id', 'zone_name', 'ttl', 'timeout', 'base_url')
        values = {key: resolved.dns(name, key) for key in keys if resolved.dns(name, key) is not None}
        registry.register_dns(name, provider_type(values))
    return registry, router.plugin_failures


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
@click.option('--ca', help='Force specific CA (letsencrypt, digicert, sectigo, aws, cloudflare)')
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


@cli.group()
def providers():
    """Certificate authority and DNS provider plugins."""
    pass


@providers.command('list')
@click.option('--format', 'output_format', default='table',
              type=click.Choice(['table', 'json']))
@click.pass_context
def providers_list(ctx, output_format):
    """List built-in and installed provider plugins."""
    registry, failures = _make_provider_registry(ctx.obj['config'])
    result = {
        'certificate_authorities': registry.list_ca(),
        'dns_providers': registry.list_dns(),
        'plugin_failures': failures,
    }
    if output_format == 'json':
        click.echo(json.dumps(result, indent=2))
        return
    click.echo('Certificate authorities: ' + ', '.join(result['certificate_authorities']))
    click.echo('DNS providers: ' + ', '.join(result['dns_providers']))
    for failure in failures:
        click.echo('Plugin failed: {provider}: {error}'.format(**failure), err=True)


@providers.command('health')
@click.argument('name')
@click.option('--kind', type=click.Choice(['ca', 'dns']), default='ca')
@click.pass_context
def providers_health(ctx, name, kind):
    """Run an explicit provider configuration/reachability check."""
    registry, _ = _make_provider_registry(ctx.obj['config'])
    try:
        provider = registry.get_ca(name) if kind == 'ca' else registry.get_dns(name)
    except KeyError as exc:
        raise click.ClickException(str(exc))
    check = getattr(provider, 'health', None) or getattr(provider, 'test_configuration', None)
    if not check:
        raise click.ClickException('Provider has no health check')
    click.echo(json.dumps(check(), indent=2, default=str))


@cli.group()
@click.pass_context
def ca(ctx):
    """Private Certificate Authority management."""
    pass


def _make_ca_manager(ctx) -> 'CAManager':
    from database.models import DatabaseManager, get_database_url
    from ca.ca_manager import CAManager
    config = ctx.obj['config']
    db_manager = DatabaseManager(get_database_url(config))
    db_manager.create_tables()
    key_dir = config.get('private_ca', {}).get('key_storage_dir')
    return CAManager(db_manager, key_dir)


@ca.command('bootstrap')
@click.argument('name_prefix')
@click.option('--common-name-prefix')
@click.option('--org')
@click.option('--country', default='US')
@click.option('--key-type', default='rsa', type=click.Choice(['rsa', 'ec']))
@click.option('--key-size', default=4096, type=int)
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']))
@click.pass_context
def ca_bootstrap(ctx, name_prefix, common_name_prefix, org, country,
                 key_type, key_size, output_format):
    """Create Root → Intermediate 1 → Intermediate 2 → Issuing CA."""
    result = _make_ca_manager(ctx).bootstrap_hierarchy(
        name_prefix, common_name_prefix, organization=org, country=country,
        key_type=key_type, key_size_or_curve=key_size,
    )
    if not result.get('success'):
        raise click.ClickException(result.get('error', 'Hierarchy bootstrap failed'))
    if output_format == 'json':
        click.echo(json.dumps(result, indent=2))
    else:
        for item in result['hierarchy']:
            click.echo('{ca_type}: ID={id} path_length={path_length}'.format(**item))
        click.echo('Issuing CA ID: {}'.format(result['issuing_ca_id']))


@ca.command('create-token')
@click.argument('ca_id', type=int)
@click.argument('name')
@click.option('--type', 'cert_type', default='server',
              type=click.Choice(['server', 'client', 'pkinit_client', 'pkinit_kdc']))
@click.option('--pkinit-principal')
@click.option('--ttl-hours', default=1, type=int)
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']))
@click.pass_context
def ca_create_token(ctx, ca_id, name, cert_type, pkinit_principal,
                    ttl_hours, output_format):
    """Create a short-lived one-time host enrollment token."""
    from pki.enrollment import EnrollmentService
    manager = _make_ca_manager(ctx)
    service = EnrollmentService(manager.db, manager)
    result = service.create_token(
        ca_id, name, cert_type=cert_type, ttl_hours=ttl_hours,
        pkinit_principal=pkinit_principal,
    )
    if not result.get('success'):
        raise click.ClickException(result.get('error', 'Token creation failed'))
    if output_format == 'json':
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo('Enrollment token (shown once): {}'.format(result['token']))
        click.echo('Expires: {}'.format(result['expires_at']))


@ca.command('list')
@click.option('--format', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
@click.pass_context
def ca_list(ctx, output_format):
    """List all private Certificate Authorities."""
    try:
        mgr = _make_ca_manager(ctx)
        cas = mgr.list_cas()

        if output_format == 'json':
            click.echo(json.dumps(cas, indent=2))
            return

        if not cas:
            click.echo("No private CAs found.")
            return

        click.echo(f"{'ID':<5} {'Name':<30} {'Type':<14} {'Common Name':<35} {'Valid Until':<12} {'Active':<6}")
        click.echo("-" * 102)
        for c in cas:
            exp = (c['not_valid_after'] or '')[:10]
            click.echo(f"{c['id']:<5} {c['name'][:29]:<30} {c['ca_type']:<14} "
                       f"{c['common_name'][:34]:<35} {exp:<12} {str(c['is_active']):<6}")
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('create-root')
@click.argument('name')
@click.option('--common-name', '-cn', help='Certificate Common Name (defaults to NAME)')
@click.option('--org', '-o', help='Organization')
@click.option('--country', '-c', default='US', help='Country code (2 letters)')
@click.option('--state', '-st', help='State/Province')
@click.option('--locality', '-l', help='Locality/City')
@click.option('--validity-years', default=20, type=int, help='Validity in years')
@click.option('--key-type', default='rsa', type=click.Choice(['rsa', 'ec']), help='Key type')
@click.option('--key-size', default=4096, type=int, help='RSA key size or EC curve (256/384/521)')
@click.pass_context
def ca_create_root(ctx, name, common_name, org, country, state, locality,
                   validity_years, key_type, key_size):
    """Create a self-signed Root CA."""
    try:
        mgr = _make_ca_manager(ctx)
        click.echo(f"Creating root CA '{name}'...")
        result = mgr.create_root_ca(
            name=name,
            common_name=common_name or name,
            organization=org,
            country=country,
            state=state,
            locality=locality,
            validity_years=validity_years,
            key_type=key_type,
            key_size_or_curve=key_size,
        )
        if result['success']:
            click.echo(f"Root CA created: ID={result['ca_id']}  CN={result['common_name']}")
        else:
            click.echo(f"Failed: {result['error']}")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('create-intermediate')
@click.argument('name')
@click.argument('parent_id', type=int)
@click.option('--common-name', '-cn', help='Certificate Common Name (defaults to NAME)')
@click.option('--org', '-o', help='Organization')
@click.option('--country', '-c', default='US', help='Country code')
@click.option('--validity-years', default=10, type=int, help='Validity in years')
@click.option('--key-type', default='rsa', type=click.Choice(['rsa', 'ec']))
@click.option('--key-size', default=4096, type=int)
@click.option('--ocsp-url', help='OCSP responder URL')
@click.pass_context
def ca_create_intermediate(ctx, name, parent_id, common_name, org, country,
                           validity_years, key_type, key_size, ocsp_url):
    """Create an Intermediate CA signed by PARENT_ID."""
    try:
        mgr = _make_ca_manager(ctx)
        click.echo(f"Creating intermediate CA '{name}' under CA {parent_id}...")
        result = mgr.create_intermediate_ca(
            name=name,
            parent_id=parent_id,
            common_name=common_name or name,
            organization=org,
            country=country,
            validity_years=validity_years,
            key_type=key_type,
            key_size_or_curve=key_size,
            ocsp_url=ocsp_url,
        )
        if result['success']:
            click.echo(f"Intermediate CA created: ID={result['ca_id']}  CN={result['common_name']}")
        else:
            click.echo(f"Failed: {result['error']}")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('create-issuing')
@click.argument('name')
@click.argument('parent_id', type=int)
@click.option('--common-name', '-cn', help='Certificate Common Name (defaults to NAME)')
@click.option('--org', '-o', help='Organization')
@click.option('--country', '-c', default='US', help='Country code')
@click.option('--validity-years', default=5, type=int, help='Validity in years')
@click.option('--key-type', default='rsa', type=click.Choice(['rsa', 'ec']))
@click.option('--key-size', default=4096, type=int)
@click.option('--ocsp-url', help='OCSP responder URL')
@click.pass_context
def ca_create_issuing(ctx, name, parent_id, common_name, org, country,
                      validity_years, key_type, key_size, ocsp_url):
    """Create an Issuing CA (path_length=0) signed by PARENT_ID."""
    try:
        mgr = _make_ca_manager(ctx)
        click.echo(f"Creating issuing CA '{name}' under CA {parent_id}...")
        result = mgr.create_issuing_ca(
            name=name,
            parent_id=parent_id,
            common_name=common_name or name,
            organization=org,
            country=country,
            validity_years=validity_years,
            key_type=key_type,
            key_size_or_curve=key_size,
            ocsp_url=ocsp_url,
        )
        if result['success']:
            click.echo(f"Issuing CA created: ID={result['ca_id']}  CN={result['common_name']}")
        else:
            click.echo(f"Failed: {result['error']}")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('issue')
@click.argument('ca_id', type=int)
@click.argument('common_name')
@click.option('--type', 'cert_type', default='server',
              type=click.Choice(['server', 'client', 'code_signing', 'email', 'ocsp', 'timestamping',
                                 'pkinit_client', 'pkinit_kdc']),
              help='Certificate type')
@click.option('--pkinit-principal', help='Kerberos principal, including @REALM')
@click.option('--san', 'san_dns', multiple=True, help='DNS SAN entries (repeatable)')
@click.option('--ip', 'san_ips', multiple=True, help='IP SAN entries (repeatable)')
@click.option('--days', default=365, type=int, help='Validity in days')
@click.option('--key-type', default='rsa', type=click.Choice(['rsa', 'ec']))
@click.option('--key-size', default=2048, type=int)
@click.option('--out-cert', '-o', help='Write cert PEM to this file')
@click.option('--out-key', '-k', help='Write key PEM to this file')
@click.pass_context
def ca_issue(ctx, ca_id, common_name, cert_type, pkinit_principal, san_dns, san_ips, days,
             key_type, key_size, out_cert, out_key):
    """Issue a certificate from CA_ID for COMMON_NAME."""
    try:
        mgr = _make_ca_manager(ctx)
        click.echo(f"Issuing {cert_type} certificate '{common_name}' from CA {ca_id}...")
        result = mgr.issue_certificate(
            ca_id=ca_id,
            common_name=common_name,
            cert_type=cert_type,
            san_dns=list(san_dns) if san_dns else None,
            san_ips=list(san_ips) if san_ips else None,
            validity_days=days,
            key_type=key_type,
            key_size_or_curve=key_size,
            pkinit_principal=pkinit_principal,
        )
        if result['success']:
            click.echo(f"Certificate issued: ID={result['cert_id']}  "
                       f"serial={result['serial_number']}")
            if out_cert:
                Path(out_cert).write_text(result['cert_pem'])
                click.echo(f"Cert written to {out_cert}")
            if out_key and result.get('key_pem'):
                Path(out_key).write_text(result['key_pem'])
                Path(out_key).chmod(0o600)
                click.echo(f"Key written to {out_key}")
            elif not out_cert and not out_key:
                click.echo("\nCertificate PEM:")
                click.echo(result['cert_pem'])
        else:
            click.echo(f"Failed: {result['error']}")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('revoke')
@click.argument('ca_id', type=int)
@click.argument('cert_id', type=int)
@click.option('--reason', default='unspecified',
              type=click.Choice(['unspecified', 'key_compromise', 'ca_compromise',
                                 'affiliation_changed', 'superseded',
                                 'cessation_of_operation', 'certificate_hold']),
              help='Revocation reason')
@click.pass_context
def ca_revoke(ctx, ca_id, cert_id, reason):
    """Revoke certificate CERT_ID issued by CA_ID."""
    try:
        mgr = _make_ca_manager(ctx)
        result = mgr.revoke_certificate(ca_id, cert_id, reason)
        if result['success']:
            click.echo(f"Certificate {cert_id} revoked (reason: {reason})")
            click.echo(f"Serial: {result['revoked_serial']}")
        else:
            click.echo(f"Failed: {result['error']}")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('crl')
@click.argument('ca_id', type=int)
@click.option('--out', '-o', help='Write CRL PEM to this file')
@click.option('--regenerate', is_flag=True, help='Regenerate CRL before fetching')
@click.pass_context
def ca_crl(ctx, ca_id, out, regenerate):
    """Fetch (or regenerate) the CRL for CA_ID."""
    try:
        mgr = _make_ca_manager(ctx)
        if regenerate:
            result = mgr.regenerate_crl(ca_id)
            if not result['success']:
                click.echo(f"Failed to regenerate CRL: {result['error']}")
                sys.exit(1)
            click.echo("CRL regenerated.")
            crl_pem = result['crl_pem']
        else:
            crl_pem = mgr.get_crl(ca_id)
            if not crl_pem:
                click.echo(f"No CRL found for CA {ca_id}. Use --regenerate to create one.")
                sys.exit(1)

        if out:
            Path(out).write_text(crl_pem)
            click.echo(f"CRL written to {out}")
        else:
            click.echo(crl_pem)
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@ca.command('list-certs')
@click.argument('ca_id', type=int)
@click.option('--format', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
@click.pass_context
def ca_list_certs(ctx, ca_id, output_format):
    """List certificates issued by CA_ID."""
    try:
        mgr = _make_ca_manager(ctx)
        certs = mgr.list_issued_certs(ca_id)

        if output_format == 'json':
            click.echo(json.dumps(certs, indent=2))
            return

        if not certs:
            click.echo(f"No certificates issued by CA {ca_id}.")
            return

        click.echo(f"{'ID':<6} {'Common Name':<35} {'Type':<14} {'Valid Until':<12} {'Revoked':<8}")
        click.echo("-" * 75)
        for c in certs:
            exp = (c['not_valid_after'] or '')[:10]
            rev = 'YES' if c['is_revoked'] else 'no'
            click.echo(f"{c['id']:<6} {c['common_name'][:34]:<35} {c['cert_type']:<14} "
                       f"{exp:<12} {rev:<8}")
    except Exception as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
