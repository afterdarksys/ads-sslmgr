"""
Intelligent certificate renewal routing system
Routes renewal requests to appropriate Certificate Authorities based on issuer detection
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime

from database.models import Certificate, DatabaseManager
from integrations.letsencrypt import LetsEncryptIntegration
from integrations.digicert import DigiCertIntegration
from integrations.comodo import ComodoIntegration
from integrations.aws_certificates import AWSCertificateIntegration
from integrations.cloudflare_certificates import CloudflareIntegration


class RenewalRouter:
    """Intelligent routing system for certificate renewals."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        
        # Initialize CA integrations
        self.integrations = {
            'letsencrypt': LetsEncryptIntegration(config, db_manager),
            'digicert': DigiCertIntegration(config, db_manager),
            'comodo': ComodoIntegration(config, db_manager),
            'aws': AWSCertificateIntegration(config, db_manager),
            'cloudflare': CloudflareIntegration(config, db_manager)
        }
        
        # Issuer mapping patterns
        self.issuer_patterns = {
            'letsencrypt': [
                'let\'s encrypt',
                'letsencrypt',
                'r3',  # Let's Encrypt intermediate
                'e1',  # Let's Encrypt ECDSA intermediate
            ],
            'digicert': [
                'digicert',
                'rapidssl',
                'geotrust',
                'thawte',
                'symantec'
            ],
            'comodo': [
                'comodo',
                'sectigo',
                'addtrust',
                'usertrust',
                'comodoca'
            ],
            'aws': [
                'amazon',
                'aws',
                'amazon root ca'
            ],
            'cloudflare': [
                'cloudflare',
                'cloudflare inc'
            ]
        }
    
    def route_renewal(self, cert: Certificate, force_ca: str = None, 
                     renewal_options: Dict = None) -> Dict:
        """
        Route certificate renewal to appropriate CA.
        
        Args:
            cert: Certificate to renew
            force_ca: Force specific CA (override detection)
            renewal_options: Additional options for renewal
            
        Returns:
            Dictionary with renewal results
        """
        renewal_options = renewal_options or {}
        
        try:
            # Determine target CA
            if force_ca:
                target_ca = force_ca.lower()
                if target_ca not in self.integrations:
                    return {
                        'success': False,
                        'error': f'Unsupported CA: {force_ca}'
                    }
            else:
                target_ca = self._detect_issuer_ca(cert)
                if not target_ca:
                    return {
                        'success': False,
                        'error': 'Could not determine certificate authority for renewal'
                    }
            
            # Check if CA integration is enabled
            integration = self.integrations[target_ca]
            if not integration.enabled:
                return {
                    'success': False,
                    'error': f'{target_ca.title()} integration is disabled'
                }
            
            # Check renewal eligibility
            eligibility = integration.check_renewal_eligibility(cert)
            if not eligibility['eligible']:
                return {
                    'success': False,
                    'error': f'Certificate not eligible for renewal: {eligibility["reason"]}'
                }
            
            # Perform renewal
            print(f"Routing renewal to {target_ca.title()} for certificate: {cert.common_name}")
            
            renewal_result = integration.renew_certificate(cert, **renewal_options)
            
            # Add routing information to result
            renewal_result['routed_to'] = target_ca
            renewal_result['detection_method'] = 'forced' if force_ca else 'automatic'
            
            return renewal_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Renewal routing failed: {str(e)}'
            }
    
    def _detect_issuer_ca(self, cert: Certificate) -> Optional[str]:
        """Detect the appropriate CA for certificate renewal based on issuer."""
        
        # First check the stored issuer category
        if cert.issuer_category and cert.issuer_category in self.integrations:
            return cert.issuer_category
        
        # Fallback to pattern matching on issuer information
        issuer_text = ""
        if cert.issuer_info:
            issuer_text = " ".join([
                cert.issuer_info.get('common_name', ''),
                cert.issuer_info.get('organization', ''),
                cert.issuer_info.get('organizational_unit', '')
            ]).lower()
        
        # Check patterns for each CA
        for ca, patterns in self.issuer_patterns.items():
            for pattern in patterns:
                if pattern in issuer_text:
                    return ca
        
        return None
    
    def batch_renewal(self, certificates: List[Certificate], 
                     renewal_options: Dict = None) -> Dict:
        """
        Perform batch renewal of multiple certificates.
        
        Args:
            certificates: List of certificates to renew
            renewal_options: Options to apply to all renewals
            
        Returns:
            Dictionary with batch renewal results
        """
        results = {
            'total_certificates': len(certificates),
            'successful_renewals': 0,
            'failed_renewals': 0,
            'skipped_renewals': 0,
            'results': [],
            'errors': []
        }
        
        for cert in certificates:
            try:
                renewal_result = self.route_renewal(cert, renewal_options=renewal_options)
                
                result_entry = {
                    'certificate_id': cert.id,
                    'common_name': cert.common_name,
                    'success': renewal_result['success'],
                    'ca_used': renewal_result.get('routed_to', 'unknown'),
                    'message': renewal_result.get('error') or renewal_result.get('message', 'Success')
                }
                
                if renewal_result['success']:
                    results['successful_renewals'] += 1
                else:
                    results['failed_renewals'] += 1
                
                results['results'].append(result_entry)
                
            except Exception as e:
                results['failed_renewals'] += 1
                results['errors'].append(f"Error processing cert {cert.id}: {str(e)}")
                
                results['results'].append({
                    'certificate_id': cert.id,
                    'common_name': cert.common_name,
                    'success': False,
                    'ca_used': 'error',
                    'message': str(e)
                })
        
        return results
    
    def get_renewal_recommendations(self, days_threshold: int = 30) -> Dict:
        """
        Get renewal recommendations for certificates expiring soon.
        
        Args:
            days_threshold: Days before expiration to consider
            
        Returns:
            Dictionary with renewal recommendations
        """
        session = self.db_manager.get_session()
        
        try:
            from datetime import timedelta
            
            threshold_date = datetime.utcnow() + timedelta(days=days_threshold)
            
            expiring_certs = session.query(Certificate).filter(
                Certificate.not_valid_after <= threshold_date,
                Certificate.is_active == True,
                Certificate.is_expired == False
            ).all()
            
            recommendations = {
                'total_expiring': len(expiring_certs),
                'by_ca': {},
                'recommendations': [],
                'summary': {}
            }
            
            ca_counts = {}
            
            for cert in expiring_certs:
                # Detect target CA
                target_ca = self._detect_issuer_ca(cert)
                if not target_ca:
                    target_ca = 'unknown'
                
                # Count by CA
                ca_counts[target_ca] = ca_counts.get(target_ca, 0) + 1
                
                # Check eligibility
                if target_ca in self.integrations:
                    integration = self.integrations[target_ca]
                    eligibility = integration.check_renewal_eligibility(cert)
                else:
                    eligibility = {'eligible': False, 'reason': 'Unknown CA'}
                
                recommendation = {
                    'certificate_id': cert.id,
                    'common_name': cert.common_name,
                    'days_until_expiry': cert.days_until_expiry,
                    'target_ca': target_ca,
                    'eligible': eligibility['eligible'],
                    'reason': eligibility.get('reason', 'Eligible for renewal'),
                    'priority': self._calculate_priority(cert.days_until_expiry)
                }
                
                recommendations['recommendations'].append(recommendation)
            
            recommendations['by_ca'] = ca_counts
            
            # Generate summary
            eligible_count = sum(1 for r in recommendations['recommendations'] if r['eligible'])
            high_priority = sum(1 for r in recommendations['recommendations'] 
                              if r['priority'] == 'high')
            
            recommendations['summary'] = {
                'eligible_for_renewal': eligible_count,
                'high_priority': high_priority,
                'auto_renewable': sum(ca_counts.get(ca, 0) for ca in ['letsencrypt', 'aws']),
                'manual_attention_needed': eligible_count - sum(ca_counts.get(ca, 0) for ca in ['letsencrypt', 'aws'])
            }
            
            return recommendations
            
        finally:
            session.close()
    
    def _calculate_priority(self, days_until_expiry: int) -> str:
        """Calculate renewal priority based on days until expiry."""
        if days_until_expiry <= 7:
            return 'critical'
        elif days_until_expiry <= 15:
            return 'high'
        elif days_until_expiry <= 30:
            return 'medium'
        else:
            return 'low'
    
    def test_all_integrations(self) -> Dict:
        """Test all CA integrations."""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'integrations': {},
            'summary': {
                'total': len(self.integrations),
                'enabled': 0,
                'working': 0,
                'failed': 0
            }
        }
        
        for ca_name, integration in self.integrations.items():
            test_result = integration.test_configuration()
            results['integrations'][ca_name] = test_result
            
            if integration.enabled:
                results['summary']['enabled'] += 1
                
                if test_result.get('all_tests_passed', False):
                    results['summary']['working'] += 1
                else:
                    results['summary']['failed'] += 1
        
        return results
    
    def get_ca_statistics(self) -> Dict:
        """Get statistics about certificates by CA."""
        session = self.db_manager.get_session()
        
        try:
            stats = {
                'by_issuer_category': {},
                'total_certificates': 0,
                'renewal_eligible': {},
                'integration_status': {}
            }
            
            # Get all active certificates
            certificates = session.query(Certificate).filter(
                Certificate.is_active == True
            ).all()
            
            stats['total_certificates'] = len(certificates)
            
            # Count by issuer category
            for cert in certificates:
                category = cert.issuer_category or 'unknown'
                stats['by_issuer_category'][category] = stats['by_issuer_category'].get(category, 0) + 1
            
            # Check renewal eligibility for each CA
            for ca_name, integration in self.integrations.items():
                eligible_count = 0
                ca_certs = [c for c in certificates if c.issuer_category == ca_name]
                
                for cert in ca_certs:
                    eligibility = integration.check_renewal_eligibility(cert)
                    if eligibility['eligible']:
                        eligible_count += 1
                
                stats['renewal_eligible'][ca_name] = {
                    'total': len(ca_certs),
                    'eligible': eligible_count
                }
                
                stats['integration_status'][ca_name] = {
                    'enabled': integration.enabled,
                    'configured': integration.test_configuration().get('all_tests_passed', False)
                }
            
            return stats
            
        finally:
            session.close()
    
    def suggest_ca_for_domain(self, domain: str) -> Dict:
        """Suggest appropriate CA for a new domain."""
        suggestions = []
        
        # Check each CA's capabilities and cost
        ca_info = {
            'letsencrypt': {
                'cost': 'free',
                'automation': 'excellent',
                'validity': '90 days',
                'wildcard': True,
                'reputation': 'high'
            },
            'digicert': {
                'cost': 'paid',
                'automation': 'good',
                'validity': '1-2 years',
                'wildcard': True,
                'reputation': 'premium'
            },
            'comodo': {
                'cost': 'paid',
                'automation': 'good',
                'validity': '1-2 years',
                'wildcard': True,
                'reputation': 'high'
            },
            'aws': {
                'cost': 'free (AWS services)',
                'automation': 'excellent',
                'validity': 'auto-renew',
                'wildcard': True,
                'reputation': 'high'
            },
            'cloudflare': {
                'cost': 'free/paid',
                'automation': 'excellent',
                'validity': '90 days - 1 year',
                'wildcard': True,
                'reputation': 'high'
            }
        }
        
        # Rank CAs based on domain characteristics
        for ca_name, integration in self.integrations.items():
            if integration.enabled:
                info = ca_info.get(ca_name, {})
                score = 0
                
                # Scoring logic
                if info.get('cost') == 'free':
                    score += 3
                if info.get('automation') == 'excellent':
                    score += 2
                if integration.test_configuration().get('all_tests_passed', False):
                    score += 2
                
                suggestions.append({
                    'ca': ca_name,
                    'score': score,
                    'info': info,
                    'enabled': integration.enabled,
                    'configured': integration.test_configuration().get('all_tests_passed', False)
                })
        
        # Sort by score
        suggestions.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'domain': domain,
            'suggestions': suggestions,
            'recommended': suggestions[0] if suggestions else None
        }
