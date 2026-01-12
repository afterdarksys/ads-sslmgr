"""
After Dark Systems Ticketing API Client
Lightweight ticketing for small/medium businesses
API: support.afterdarksys.com
"""

import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional
from integrations.ticketing import TicketingInterface


class AfterDarkTicketingClient(TicketingInterface):
    """Client for After Dark Systems ticketing API"""

    def __init__(self, config: Dict):
        super().__init__(config)

        # After Dark Systems configuration
        ads_config = config.get('ticketing', {}).get('afterdark', {})
        self.enabled = ads_config.get('enabled', False)
        self.api_url = ads_config.get('api_url', 'https://support.afterdarksys.com/api/v1')
        self.api_key = ads_config.get('api_key')
        self.organization_id = ads_config.get('organization_id')

        # Ticket configuration
        self.default_queue = ads_config.get('default_queue', 'SSL Certificates')
        self.default_tags = ads_config.get('default_tags', ['ssl', 'certificate'])

        # Priority mapping
        self.priority_mapping = {
            'critical': 4,  # Urgent
            'high': 3,      # High
            'medium': 2,    # Normal
            'low': 1        # Low
        }

        # Assignee configuration
        self.default_assignee = ads_config.get('default_assignee')
        self.assignee_by_priority = ads_config.get('assignee_by_priority', {})

        # API headers
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'SSL-Manager/1.0'
        }

    def create_expiry_ticket(self, cert_data: Dict, days_until_expiry: int,
                            priority: str = 'high') -> Optional[Dict]:
        """Create ticket for expiring certificate"""
        if not self.enabled or not self.api_key:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            expiry_date = cert_data.get('not_valid_after')

            # Determine urgency
            if days_until_expiry < 7:
                priority = 'critical'
                urgency_label = 'URGENT'
            elif days_until_expiry < 15:
                priority = 'high'
                urgency_label = 'High Priority'
            elif days_until_expiry < 30:
                priority = 'medium'
                urgency_label = 'Action Needed'
            else:
                priority = 'low'
                urgency_label = 'Plan Renewal'

            # Build ticket payload
            payload = {
                'organization_id': self.organization_id,
                'queue': self.default_queue,
                'subject': f'[{urgency_label}] SSL Certificate Expiring: {common_name}',
                'description': self._build_expiry_description(cert_data, days_until_expiry, urgency_label),
                'priority': self.priority_mapping.get(priority, 2),
                'tags': self.default_tags + ['expiring', f'expires-{days_until_expiry}d'],
                'metadata': {
                    'certificate_id': cert_id,
                    'certificate_domain': common_name,
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': expiry_date,
                    'ticket_type': 'certificate_expiry'
                }
            }

            # Add assignee
            assignee = self.assignee_by_priority.get(priority) or self.default_assignee
            if assignee:
                payload['assignee_email'] = assignee

            # Create ticket via API
            response = requests.post(
                f'{self.api_url}/tickets',
                json=payload,
                headers=self.headers,
                timeout=30
            )

            if response.status_code in [200, 201]:
                ticket_data = response.json()

                self.logger.info(f"Created After Dark Systems ticket {ticket_data['id']} for certificate {cert_id}")

                return {
                    'success': True,
                    'ticket_id': ticket_data['id'],
                    'ticket_number': ticket_data['ticket_number'],
                    'ticket_url': ticket_data['url']
                }
            else:
                self.logger.error(f"Failed to create ticket: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }

        except requests.RequestException as e:
            self.logger.error(f"Request error creating ticket: {e}")
            return {
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            self.logger.error(f"Error creating expiry ticket: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_renewal_failure_ticket(self, cert_data: Dict, error_message: str) -> Optional[Dict]:
        """Create ticket for failed renewal"""
        if not self.enabled or not self.api_key:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')

            payload = {
                'organization_id': self.organization_id,
                'queue': self.default_queue,
                'subject': f'[URGENT] Certificate Renewal Failed: {common_name}',
                'description': self._build_renewal_failure_description(cert_data, error_message),
                'priority': self.priority_mapping.get('critical', 4),
                'tags': self.default_tags + ['renewal-failure', 'urgent'],
                'metadata': {
                    'certificate_id': cert_id,
                    'certificate_domain': common_name,
                    'error_message': error_message,
                    'ticket_type': 'renewal_failure'
                }
            }

            assignee = self.assignee_by_priority.get('critical') or self.default_assignee
            if assignee:
                payload['assignee_email'] = assignee

            response = requests.post(
                f'{self.api_url}/tickets',
                json=payload,
                headers=self.headers,
                timeout=30
            )

            if response.status_code in [200, 201]:
                ticket_data = response.json()
                return {
                    'success': True,
                    'ticket_id': ticket_data['id'],
                    'ticket_number': ticket_data['ticket_number'],
                    'ticket_url': ticket_data['url']
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"Error creating renewal failure ticket: {e}")
            return None

    def create_threat_detection_ticket(self, cert_data: Dict, threat_report: Dict) -> Optional[Dict]:
        """Create ticket for security threat"""
        if not self.enabled or not self.api_key:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            threat_score = threat_report.get('threat_score', 0)
            threats = threat_report.get('threats_found', [])

            payload = {
                'organization_id': self.organization_id,
                'queue': self.default_queue,
                'subject': f'[SECURITY] Threat Detected on Certificate: {common_name}',
                'description': self._build_threat_description(cert_data, threat_report),
                'priority': self.priority_mapping.get('critical', 4),
                'tags': self.default_tags + ['security-threat', 'threat-intelligence'],
                'metadata': {
                    'certificate_id': cert_id,
                    'certificate_domain': common_name,
                    'threat_score': threat_score,
                    'threats_count': len(threats),
                    'ticket_type': 'security_threat'
                }
            }

            assignee = self.assignee_by_priority.get('critical') or self.default_assignee
            if assignee:
                payload['assignee_email'] = assignee

            response = requests.post(
                f'{self.api_url}/tickets',
                json=payload,
                headers=self.headers,
                timeout=30
            )

            if response.status_code in [200, 201]:
                ticket_data = response.json()
                return {
                    'success': True,
                    'ticket_id': ticket_data['id'],
                    'ticket_number': ticket_data['ticket_number'],
                    'ticket_url': ticket_data['url']
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"Error creating threat detection ticket: {e}")
            return None

    def create_validation_failure_ticket(self, cert_data: Dict, validation_report: Dict) -> Optional[Dict]:
        """Create ticket for validation failure"""
        if not self.enabled or not self.api_key:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            findings = validation_report.get('findings', [])

            # Only create ticket for critical/high findings
            critical_findings = [f for f in findings if f['severity'] in ['critical', 'high']]
            if not critical_findings:
                return None

            payload = {
                'organization_id': self.organization_id,
                'queue': self.default_queue,
                'subject': f'Certificate Validation Failed: {common_name}',
                'description': self._build_validation_failure_description(cert_data, validation_report),
                'priority': self.priority_mapping.get('high', 3),
                'tags': self.default_tags + ['validation-failure'],
                'metadata': {
                    'certificate_id': cert_id,
                    'certificate_domain': common_name,
                    'risk_score': validation_report.get('risk_score', 0),
                    'findings_count': len(critical_findings),
                    'ticket_type': 'validation_failure'
                }
            }

            assignee = self.assignee_by_priority.get('high') or self.default_assignee
            if assignee:
                payload['assignee_email'] = assignee

            response = requests.post(
                f'{self.api_url}/tickets',
                json=payload,
                headers=self.headers,
                timeout=30
            )

            if response.status_code in [200, 201]:
                ticket_data = response.json()
                return {
                    'success': True,
                    'ticket_id': ticket_data['id'],
                    'ticket_number': ticket_data['ticket_number'],
                    'ticket_url': ticket_data['url']
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"Error creating validation failure ticket: {e}")
            return None

    def update_ticket(self, ticket_id: str, comment: str = None, status: str = None) -> bool:
        """Update existing ticket"""
        if not self.enabled or not self.api_key:
            return False

        try:
            payload = {}

            if comment:
                # Add comment to ticket
                comment_response = requests.post(
                    f'{self.api_url}/tickets/{ticket_id}/comments',
                    json={'comment': comment},
                    headers=self.headers,
                    timeout=30
                )

                if comment_response.status_code not in [200, 201]:
                    self.logger.error(f"Failed to add comment: {comment_response.status_code}")
                    return False

            if status:
                payload['status'] = status

            if payload:
                response = requests.patch(
                    f'{self.api_url}/tickets/{ticket_id}',
                    json=payload,
                    headers=self.headers,
                    timeout=30
                )

                return response.status_code in [200, 204]

            return True

        except Exception as e:
            self.logger.error(f"Error updating ticket: {e}")
            return False

    def close_ticket(self, ticket_id: str, comment: str = None) -> bool:
        """Close ticket"""
        return self.update_ticket(
            ticket_id,
            comment=comment or "Certificate issue resolved via SSL Management System",
            status='closed'
        )

    def search_tickets_for_certificate(self, cert_id: int) -> List[Dict]:
        """Search for tickets related to certificate"""
        if not self.enabled or not self.api_key:
            return []

        try:
            response = requests.get(
                f'{self.api_url}/tickets',
                params={
                    'organization_id': self.organization_id,
                    'metadata.certificate_id': cert_id
                },
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                tickets = response.json().get('tickets', [])
                return [
                    {
                        'ticket_id': ticket['id'],
                        'ticket_number': ticket['ticket_number'],
                        'subject': ticket['subject'],
                        'status': ticket['status'],
                        'priority': ticket['priority'],
                        'created_at': ticket['created_at'],
                        'url': ticket['url']
                    }
                    for ticket in tickets
                ]

            return []

        except Exception as e:
            self.logger.error(f"Error searching tickets: {e}")
            return []

    def test_connection(self) -> Dict:
        """Test connection to After Dark Systems API"""
        if not self.enabled:
            return {
                'success': False,
                'message': 'After Dark Systems ticketing not enabled'
            }

        if not self.api_key:
            return {
                'success': False,
                'message': 'API key not configured'
            }

        try:
            response = requests.get(
                f'{self.api_url}/health',
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'After Dark Systems API connection successful',
                    'api_url': self.api_url,
                    'organization_id': self.organization_id
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e)
            }

    # Helper methods for building ticket descriptions

    def _build_expiry_description(self, cert_data: Dict, days_until_expiry: int, urgency_label: str) -> str:
        """Build description for expiry ticket"""
        common_name = cert_data.get('common_name', 'Unknown')
        cert_id = cert_data.get('id')
        expiry_date = cert_data.get('not_valid_after')

        return f"""
SSL Certificate Expiration Notice

Certificate Details:
- Common Name: {common_name}
- Certificate ID: {cert_id}
- Expiration Date: {expiry_date}
- Days Until Expiry: {days_until_expiry}
- Serial Number: {cert_data.get('serial_number', 'Unknown')}
- Issuer: {cert_data.get('issuer_category', 'Unknown')}

Action Required:
The SSL certificate for {common_name} will expire in {days_until_expiry} days.

Recommended Actions:
1. Review certificate usage and affected systems
2. Initiate renewal process via SSL Management System
3. Validate DNS configuration before renewal
4. Test renewed certificate before deployment
5. Update certificate on all affected systems

Priority Explanation:
This ticket is marked as {urgency_label} because the certificate expires in {days_until_expiry} days.
"""

    def _build_renewal_failure_description(self, cert_data: Dict, error_message: str) -> str:
        """Build description for renewal failure ticket"""
        common_name = cert_data.get('common_name', 'Unknown')
        cert_id = cert_data.get('id')

        return f"""
SSL Certificate Renewal Failure

Certificate Details:
- Common Name: {common_name}
- Certificate ID: {cert_id}
- Serial Number: {cert_data.get('serial_number', 'Unknown')}
- Current Expiry: {cert_data.get('not_valid_after', 'Unknown')}
- Days Until Expiry: {cert_data.get('days_until_expiry', 'Unknown')}

Failure Details:
- Attempted At: {datetime.now().isoformat()}
- Error Message: {error_message}
- CA Provider: {cert_data.get('issuer_category', 'Unknown')}

Immediate Actions Required:
1. Investigate root cause of renewal failure
2. Check DNS configuration and CAA records
3. Verify CA account credentials and rate limits
4. Review certificate requirements and validation method
5. Attempt manual renewal if automated renewal fails
6. If renewal continues to fail, plan for service interruption
"""

    def _build_threat_description(self, cert_data: Dict, threat_report: Dict) -> str:
        """Build description for threat detection ticket"""
        common_name = cert_data.get('common_name', 'Unknown')
        cert_id = cert_data.get('id')
        threat_score = threat_report.get('threat_score', 0)
        threats = threat_report.get('threats_found', [])

        threats_text = "\n".join([
            f"- {threat['type']} ({threat['severity']}): {threat['description']}"
            for threat in threats
        ])

        return f"""
Security Threat Detection Alert

Certificate Details:
- Common Name: {common_name}
- Certificate ID: {cert_id}
- Threat Score: {threat_score}/100

Threats Detected:
{threats_text}

Recommended Actions:
1. Review threat intelligence findings immediately
2. Verify certificate legitimacy and ownership
3. Check for unauthorized certificate issuance
4. Investigate potential phishing or typosquatting
5. Consider certificate revocation if compromised
6. Update security monitoring rules
"""

    def _build_validation_failure_description(self, cert_data: Dict, validation_report: Dict) -> str:
        """Build description for validation failure ticket"""
        common_name = cert_data.get('common_name', 'Unknown')
        cert_id = cert_data.get('id')
        findings = validation_report.get('findings', [])

        critical_findings = [f for f in findings if f['severity'] in ['critical', 'high']]

        findings_text = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']}: {f['description']}"
            for f in critical_findings
        ])

        recommendations = "\n".join([
            f"- {rec}" for rec in validation_report.get('recommendations', [])
        ])

        return f"""
Certificate Validation Failure

Certificate Details:
- Common Name: {common_name}
- Certificate ID: {cert_id}
- Risk Score: {validation_report.get('risk_score', 0)}/100

Validation Findings:
{findings_text}

Recommendations:
{recommendations}
"""


def main():
    """CLI interface for After Dark Systems ticketing"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='After Dark Systems Ticketing Client')
    parser.add_argument('--test', action='store_true', help='Test API connection')
    parser.add_argument('--config', help='Config file path', default='config/config.json')

    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = json.load(f)

    client = AfterDarkTicketingClient(config)

    if args.test:
        result = client.test_connection()
        if result['success']:
            print(f"✓ After Dark Systems API connection successful")
            print(f"  API URL: {result['api_url']}")
            print(f"  Organization ID: {result['organization_id']}")
        else:
            print(f"✗ Connection failed: {result.get('error')}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
