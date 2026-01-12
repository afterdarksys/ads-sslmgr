"""
Unified Ticketing System
Supports multiple ticketing backends:
- JIRA (for enterprises)
- After Dark Systems Ticketing API (for small/medium businesses)
- ServiceNow (optional)
- Zendesk (optional)

Configuration determines which system to use
"""

from enum import Enum
from typing import Dict, Optional
import logging


class TicketingSystem(Enum):
    """Supported ticketing systems"""
    JIRA = "jira"
    AFTERDARK = "afterdark"
    SERVICENOW = "servicenow"
    ZENDESK = "zendesk"
    NONE = "none"


class TicketingInterface:
    """Abstract interface for ticketing systems"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = False

    def create_expiry_ticket(self, cert_data: Dict, days_until_expiry: int,
                            priority: str = 'high') -> Optional[Dict]:
        """Create ticket for expiring certificate"""
        raise NotImplementedError

    def create_renewal_failure_ticket(self, cert_data: Dict,
                                     error_message: str) -> Optional[Dict]:
        """Create ticket for failed renewal"""
        raise NotImplementedError

    def create_threat_detection_ticket(self, cert_data: Dict,
                                      threat_report: Dict) -> Optional[Dict]:
        """Create ticket for security threat"""
        raise NotImplementedError

    def create_validation_failure_ticket(self, cert_data: Dict,
                                        validation_report: Dict) -> Optional[Dict]:
        """Create ticket for validation failure"""
        raise NotImplementedError

    def update_ticket(self, ticket_id: str, comment: str = None,
                     status: str = None) -> bool:
        """Update existing ticket"""
        raise NotImplementedError

    def close_ticket(self, ticket_id: str, comment: str = None) -> bool:
        """Close ticket"""
        raise NotImplementedError

    def search_tickets_for_certificate(self, cert_id: int) -> list:
        """Search for tickets related to certificate"""
        raise NotImplementedError

    def test_connection(self) -> Dict:
        """Test connection to ticketing system"""
        raise NotImplementedError


def get_ticketing_client(config: Dict) -> TicketingInterface:
    """
    Factory function to get appropriate ticketing client

    Configuration example:
    {
        "ticketing": {
            "system": "jira",  // or "afterdark"
            "jira": {...},
            "afterdark": {...}
        }
    }
    """
    ticketing_config = config.get('ticketing', {})
    system = ticketing_config.get('system', 'none').lower()

    if system == TicketingSystem.JIRA.value:
        from integrations.ticketing.jira_client import JIRATicketingClient
        return JIRATicketingClient(config)

    elif system == TicketingSystem.AFTERDARK.value:
        from integrations.ticketing.afterdark_client import AfterDarkTicketingClient
        return AfterDarkTicketingClient(config)

    elif system == TicketingSystem.SERVICENOW.value:
        from integrations.ticketing.servicenow_client import ServiceNowTicketingClient
        return ServiceNowTicketingClient(config)

    elif system == TicketingSystem.ZENDESK.value:
        from integrations.ticketing.zendesk_client import ZendeskTicketingClient
        return ZendeskTicketingClient(config)

    else:
        # No ticketing system configured
        from integrations.ticketing.null_client import NullTicketingClient
        return NullTicketingClient(config)
