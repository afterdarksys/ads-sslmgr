"""
JIRA Integration
Automatically creates and manages JIRA tickets for certificate operations:
- Expiring certificates
- Failed renewals
- Security threats
- Validation failures
- Certificate discoveries

Uses official Python JIRA library (jira)
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from jira import JIRA
from jira.exceptions import JIRAError


class JIRAIntegration:
    """JIRA integration for certificate management"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # JIRA configuration
        jira_config = self.config.get('jira', {})
        self.enabled = jira_config.get('enabled', False)
        self.server_url = jira_config.get('server_url')
        self.username = jira_config.get('username')
        self.api_token = jira_config.get('api_token')  # For JIRA Cloud
        self.password = jira_config.get('password')    # For JIRA Server

        # Project configuration
        self.project_key = jira_config.get('project_key', 'CERT')
        self.default_issue_type = jira_config.get('default_issue_type', 'Task')

        # Priority mapping
        self.priority_mapping = {
            'critical': jira_config.get('critical_priority', 'Highest'),
            'high': jira_config.get('high_priority', 'High'),
            'medium': jira_config.get('medium_priority', 'Medium'),
            'low': jira_config.get('low_priority', 'Low')
        }

        # Labels and components
        self.default_labels = jira_config.get('default_labels', ['certificate', 'ssl'])
        self.default_component = jira_config.get('default_component')

        # Assignee configuration
        self.default_assignee = jira_config.get('default_assignee')
        self.assignee_by_priority = jira_config.get('assignee_by_priority', {})

        # Custom fields
        self.custom_fields = jira_config.get('custom_fields', {})

        # Initialize JIRA client
        self.jira_client = None
        if self.enabled:
            self._initialize_client()

    def _initialize_client(self) -> bool:
        """Initialize JIRA client"""
        try:
            if not self.server_url:
                self.logger.error("JIRA server URL not configured")
                return False

            # JIRA Cloud uses API token, Server uses password
            if self.api_token:
                auth = (self.username, self.api_token)
            elif self.password:
                auth = (self.username, self.password)
            else:
                self.logger.error("JIRA credentials not configured")
                return False

            self.jira_client = JIRA(
                server=self.server_url,
                basic_auth=auth
            )

            self.logger.info(f"JIRA client initialized for {self.server_url}")
            return True

        except JIRAError as e:
            self.logger.error(f"Failed to initialize JIRA client: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error initializing JIRA: {e}")
            return False

    def create_expiry_ticket(self, cert_data: Dict, days_until_expiry: int,
                            priority: str = 'high') -> Optional[Dict]:
        """
        Create JIRA ticket for expiring certificate

        Args:
            cert_data: Certificate data dictionary
            days_until_expiry: Days until certificate expires
            priority: Ticket priority (critical, high, medium, low)

        Returns:
            Created issue data or None
        """
        if not self.enabled or not self.jira_client:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            expiry_date = cert_data.get('not_valid_after')

            # Determine priority based on days until expiry
            if days_until_expiry < 7:
                priority = 'critical'
                urgency = 'URGENT'
            elif days_until_expiry < 15:
                priority = 'high'
                urgency = 'High Priority'
            elif days_until_expiry < 30:
                priority = 'medium'
                urgency = 'Action Needed'
            else:
                priority = 'low'
                urgency = 'Plan Renewal'

            # Build issue summary and description
            summary = f"[{urgency}] SSL Certificate Expiring: {common_name}"

            description = f"""
*SSL Certificate Expiration Notice*

h3. Certificate Details
* *Common Name:* {common_name}
* *Certificate ID:* {cert_id}
* *Expiration Date:* {expiry_date}
* *Days Until Expiry:* {days_until_expiry}
* *Serial Number:* {cert_data.get('serial_number', 'Unknown')}
* *Issuer:* {cert_data.get('issuer_category', 'Unknown')}

h3. Action Required
The SSL certificate for {common_name} will expire in {days_until_expiry} days.

h4. Recommended Actions:
# Review certificate usage and affected systems
# Initiate renewal process via SSL Management System
# Validate DNS configuration before renewal
# Test renewed certificate before deployment
# Update certificate on all affected systems

h3. Links
* Certificate Management System: [View Certificate|{self._get_cert_url(cert_id)}]

h3. Priority Explanation
This ticket is marked as *{priority.upper()}* because the certificate expires in {days_until_expiry} days.
"""

            # Build issue fields
            issue_fields = {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description,
                'issuetype': {'name': self.default_issue_type},
                'priority': {'name': self.priority_mapping.get(priority, 'Medium')},
                'labels': self.default_labels + ['expiring', f'expires-{days_until_expiry}d']
            }

            # Add component if configured
            if self.default_component:
                issue_fields['components'] = [{'name': self.default_component}]

            # Add assignee
            assignee = self.assignee_by_priority.get(priority) or self.default_assignee
            if assignee:
                issue_fields['assignee'] = {'name': assignee}

            # Add custom fields
            if 'certificate_id' in self.custom_fields:
                issue_fields[self.custom_fields['certificate_id']] = str(cert_id)
            if 'days_until_expiry' in self.custom_fields:
                issue_fields[self.custom_fields['days_until_expiry']] = days_until_expiry
            if 'certificate_domain' in self.custom_fields:
                issue_fields[self.custom_fields['certificate_domain']] = common_name

            # Create issue
            issue = self.jira_client.create_issue(fields=issue_fields)

            self.logger.info(f"Created JIRA ticket {issue.key} for certificate {cert_id}")

            return {
                'success': True,
                'issue_key': issue.key,
                'issue_url': f"{self.server_url}/browse/{issue.key}",
                'issue_id': issue.id
            }

        except JIRAError as e:
            self.logger.error(f"JIRA error creating expiry ticket: {e}")
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
        """Create JIRA ticket for failed certificate renewal"""
        if not self.enabled or not self.jira_client:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')

            summary = f"[URGENT] Certificate Renewal Failed: {common_name}"

            description = f"""
*SSL Certificate Renewal Failure*

h3. Certificate Details
* *Common Name:* {common_name}
* *Certificate ID:* {cert_id}
* *Serial Number:* {cert_data.get('serial_number', 'Unknown')}
* *Current Expiry:* {cert_data.get('not_valid_after', 'Unknown')}
* *Days Until Expiry:* {cert_data.get('days_until_expiry', 'Unknown')}

h3. Failure Details
* *Attempted At:* {datetime.now().isoformat()}
* *Error Message:* {{{{color:red}}}}{error_message}{{{{color}}}}
* *CA Provider:* {cert_data.get('issuer_category', 'Unknown')}

h3. Immediate Actions Required
# Investigate root cause of renewal failure
# Check DNS configuration and CAA records
# Verify CA account credentials and rate limits
# Review certificate requirements and validation method
# Attempt manual renewal if automated renewal fails
# If renewal continues to fail, plan for service interruption

h3. Links
* Certificate Management System: [View Certificate|{self._get_cert_url(cert_id)}]
* [Retry Renewal|{self._get_cert_url(cert_id)}/renew]
"""

            issue_fields = {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': {'name': self.priority_mapping.get('critical', 'Highest')},
                'labels': self.default_labels + ['renewal-failure', 'urgent']
            }

            # Add component and assignee
            if self.default_component:
                issue_fields['components'] = [{'name': self.default_component}]

            assignee = self.assignee_by_priority.get('critical') or self.default_assignee
            if assignee:
                issue_fields['assignee'] = {'name': assignee}

            issue = self.jira_client.create_issue(fields=issue_fields)

            self.logger.error(f"Created JIRA ticket {issue.key} for renewal failure (cert {cert_id})")

            return {
                'success': True,
                'issue_key': issue.key,
                'issue_url': f"{self.server_url}/browse/{issue.key}",
                'issue_id': issue.id
            }

        except Exception as e:
            self.logger.error(f"Error creating renewal failure ticket: {e}")
            return None

    def create_threat_detection_ticket(self, cert_data: Dict, threat_report: Dict) -> Optional[Dict]:
        """Create JIRA ticket for detected security threat"""
        if not self.enabled or not self.jira_client:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            threat_score = threat_report.get('threat_score', 0)
            threats = threat_report.get('threats_found', [])

            summary = f"[SECURITY] Threat Detected on Certificate: {common_name}"

            # Build threats list
            threats_text = "\n".join([
                f"* *{threat['type']}* ({threat['severity']}): {threat['description']}"
                for threat in threats
            ])

            description = f"""
*Security Threat Detection Alert*

h3. Certificate Details
* *Common Name:* {common_name}
* *Certificate ID:* {cert_id}
* *Threat Score:* {{{{color:red}}}}{threat_score}/100{{{{color}}}}

h3. Threats Detected
{threats_text}

h3. Recommended Actions
# Review threat intelligence findings immediately
# Verify certificate legitimacy and ownership
# Check for unauthorized certificate issuance
# Investigate potential phishing or typosquatting
# Consider certificate revocation if compromised
# Update security monitoring rules

h3. Links
* Certificate Management System: [View Certificate|{self._get_cert_url(cert_id)}]
* [View Threat Report|{self._get_cert_url(cert_id)}/threats]
"""

            issue_fields = {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': {'name': self.priority_mapping.get('critical', 'Highest')},
                'labels': self.default_labels + ['security-threat', 'threat-intelligence']
            }

            if self.default_component:
                issue_fields['components'] = [{'name': self.default_component}]

            assignee = self.assignee_by_priority.get('critical') or self.default_assignee
            if assignee:
                issue_fields['assignee'] = {'name': assignee}

            issue = self.jira_client.create_issue(fields=issue_fields)

            self.logger.warning(f"Created JIRA ticket {issue.key} for security threat (cert {cert_id})")

            return {
                'success': True,
                'issue_key': issue.key,
                'issue_url': f"{self.server_url}/browse/{issue.key}",
                'issue_id': issue.id
            }

        except Exception as e:
            self.logger.error(f"Error creating threat detection ticket: {e}")
            return None

    def create_validation_failure_ticket(self, cert_data: Dict, validation_report: Dict) -> Optional[Dict]:
        """Create JIRA ticket for certificate validation failures"""
        if not self.enabled or not self.jira_client:
            return None

        try:
            common_name = cert_data.get('common_name', 'Unknown')
            cert_id = cert_data.get('id')
            findings = validation_report.get('findings', [])

            # Filter critical/high findings
            critical_findings = [f for f in findings if f['severity'] in ['critical', 'high']]

            if not critical_findings:
                return None  # Don't create ticket for minor issues

            summary = f"Certificate Validation Failed: {common_name}"

            findings_text = "\n".join([
                f"* *[{f['severity'].upper()}]* {f['title']}: {f['description']}"
                for f in critical_findings
            ])

            description = f"""
*Certificate Validation Failure*

h3. Certificate Details
* *Common Name:* {common_name}
* *Certificate ID:* {cert_id}
* *Risk Score:* {validation_report.get('risk_score', 0)}/100

h3. Validation Findings
{findings_text}

h3. Recommendations
{chr(10).join(['* ' + rec for rec in validation_report.get('recommendations', [])])}

h3. Links
* Certificate Management System: [View Certificate|{self._get_cert_url(cert_id)}]
"""

            issue_fields = {
                'project': {'key': self.project_key},
                'summary': summary,
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': {'name': self.priority_mapping.get('high', 'High')},
                'labels': self.default_labels + ['validation-failure']
            }

            if self.default_component:
                issue_fields['components'] = [{'name': self.default_component}]

            assignee = self.assignee_by_priority.get('high') or self.default_assignee
            if assignee:
                issue_fields['assignee'] = {'name': assignee}

            issue = self.jira_client.create_issue(fields=issue_fields)

            self.logger.warning(f"Created JIRA ticket {issue.key} for validation failure (cert {cert_id})")

            return {
                'success': True,
                'issue_key': issue.key,
                'issue_url': f"{self.server_url}/browse/{issue.key}",
                'issue_id': issue.id
            }

        except Exception as e:
            self.logger.error(f"Error creating validation failure ticket: {e}")
            return None

    def update_ticket(self, issue_key: str, comment: str = None,
                     status: str = None) -> bool:
        """Update existing JIRA ticket"""
        if not self.enabled or not self.jira_client:
            return False

        try:
            issue = self.jira_client.issue(issue_key)

            # Add comment
            if comment:
                self.jira_client.add_comment(issue, comment)

            # Update status
            if status:
                transitions = self.jira_client.transitions(issue)
                transition_id = None

                for transition in transitions:
                    if transition['name'].lower() == status.lower():
                        transition_id = transition['id']
                        break

                if transition_id:
                    self.jira_client.transition_issue(issue, transition_id)

            return True

        except JIRAError as e:
            self.logger.error(f"JIRA error updating ticket: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error updating ticket: {e}")
            return False

    def close_ticket(self, issue_key: str, comment: str = None) -> bool:
        """Close JIRA ticket"""
        return self.update_ticket(
            issue_key,
            comment=comment or "Certificate issue resolved via SSL Management System",
            status='Done'
        )

    def search_tickets_for_certificate(self, cert_id: int) -> List[Dict]:
        """Search for JIRA tickets related to certificate"""
        if not self.enabled or not self.jira_client:
            return []

        try:
            # Search using custom field or labels
            if 'certificate_id' in self.custom_fields:
                jql = f'project = {self.project_key} AND {self.custom_fields["certificate_id"]} = {cert_id}'
            else:
                jql = f'project = {self.project_key} AND labels = "cert-{cert_id}"'

            issues = self.jira_client.search_issues(jql, maxResults=50)

            return [
                {
                    'key': issue.key,
                    'summary': issue.fields.summary,
                    'status': issue.fields.status.name,
                    'priority': issue.fields.priority.name if issue.fields.priority else None,
                    'created': issue.fields.created,
                    'url': f"{self.server_url}/browse/{issue.key}"
                }
                for issue in issues
            ]

        except Exception as e:
            self.logger.error(f"Error searching tickets: {e}")
            return []

    def _get_cert_url(self, cert_id: int) -> str:
        """Get URL for certificate in web UI"""
        base_url = self.config.get('web_ui_url', 'http://localhost:5000')
        return f"{base_url}/certificates/{cert_id}"

    def test_connection(self) -> Dict:
        """Test JIRA connection"""
        if not self.enabled:
            return {
                'success': False,
                'message': 'JIRA integration not enabled'
            }

        try:
            if not self.jira_client:
                if not self._initialize_client():
                    return {
                        'success': False,
                        'message': 'Failed to initialize JIRA client'
                    }

            # Test connection by getting server info
            server_info = self.jira_client.server_info()

            return {
                'success': True,
                'message': 'JIRA connection successful',
                'server_version': server_info.get('version'),
                'server_url': self.server_url,
                'project_key': self.project_key
            }

        except JIRAError as e:
            return {
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


def main():
    """CLI interface for JIRA integration"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='JIRA Integration for SSL Manager')
    parser.add_argument('--test', action='store_true', help='Test JIRA connection')
    parser.add_argument('--config', help='Config file path', default='config/config.json')

    args = parser.parse_args()

    # Load config
    with open(args.config, 'r') as f:
        config = json.load(f)

    jira = JIRAIntegration(config)

    if args.test:
        result = jira.test_connection()
        if result['success']:
            print(f"✓ JIRA connection successful")
            print(f"  Server: {result['server_url']}")
            print(f"  Version: {result.get('server_version')}")
            print(f"  Project: {result['project_key']}")
        else:
            print(f"✗ JIRA connection failed: {result.get('error')}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
