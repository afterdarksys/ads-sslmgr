"""
SNMP notification system for SSL certificate monitoring
"""

from datetime import datetime
from typing import Dict, List, Optional
from pysnmp.hlapi import *
from pysnmp.proto.rfc1902 import OctetString, Integer32

from database.models import Certificate, CertificateOwnership, NotificationLog, DatabaseManager


class SNMPNotifier:
    """Handle SNMP notifications for certificate expiration and events."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.snmp_config = config.get('snmp', {})
        
        # SNMP configuration
        self.enabled = self.snmp_config.get('enabled', False)
        self.community = self.snmp_config.get('community', 'public')
        self.host = self.snmp_config.get('host', 'localhost')
        self.port = self.snmp_config.get('port', 162)  # SNMP trap port
        self.oid_base = self.snmp_config.get('oid_base', '1.3.6.1.4.1.12345')
        
        # Define OIDs for different notification types
        self.oids = {
            'certificate_expiring': f"{self.oid_base}.1.1",
            'certificate_expired': f"{self.oid_base}.1.2", 
            'renewal_success': f"{self.oid_base}.2.1",
            'renewal_failure': f"{self.oid_base}.2.2",
            'scan_completed': f"{self.oid_base}.3.1",
            'system_error': f"{self.oid_base}.4.1"
        }
    
    def send_expiration_trap(self, cert: Certificate, days_before: int) -> bool:
        """Send SNMP trap for certificate expiration warning."""
        if not self.enabled:
            return False
        
        try:
            # Prepare trap data
            trap_oid = self.oids['certificate_expiring']
            
            var_binds = [
                ObjectType(ObjectIdentity(f"{trap_oid}.1"), OctetString(cert.common_name or 'Unknown')),
                ObjectType(ObjectIdentity(f"{trap_oid}.2"), OctetString(cert.file_path)),
                ObjectType(ObjectIdentity(f"{trap_oid}.3"), Integer32(days_before)),
                ObjectType(ObjectIdentity(f"{trap_oid}.4"), OctetString(cert.not_valid_after.isoformat())),
                ObjectType(ObjectIdentity(f"{trap_oid}.5"), OctetString(cert.serial_number)),
                ObjectType(ObjectIdentity(f"{trap_oid}.6"), OctetString(cert.issuer_category or 'unknown'))
            ]
            
            # Send trap
            success = self._send_trap(trap_oid, var_binds)
            
            # Log the notification
            session = self.db_manager.get_session()
            try:
                self._log_notification(
                    session, cert.id, 'snmp', days_before,
                    f"{self.host}:{self.port}",
                    f"Certificate expiring in {days_before} days",
                    f"SNMP trap sent to {self.host}:{self.port}",
                    'sent' if success else 'failed'
                )
                session.commit()
            finally:
                session.close()
            
            return success
            
        except Exception as e:
            print(f"Error sending SNMP expiration trap: {e}")
            return False
    
    def send_renewal_trap(self, cert: Certificate, success: bool, message: str = "") -> bool:
        """Send SNMP trap for certificate renewal result."""
        if not self.enabled:
            return False
        
        try:
            trap_oid = self.oids['renewal_success'] if success else self.oids['renewal_failure']
            
            var_binds = [
                ObjectType(ObjectIdentity(f"{trap_oid}.1"), OctetString(cert.common_name or 'Unknown')),
                ObjectType(ObjectIdentity(f"{trap_oid}.2"), OctetString(cert.file_path)),
                ObjectType(ObjectIdentity(f"{trap_oid}.3"), OctetString(message)),
                ObjectType(ObjectIdentity(f"{trap_oid}.4"), OctetString(cert.serial_number)),
                ObjectType(ObjectIdentity(f"{trap_oid}.5"), OctetString(datetime.utcnow().isoformat()))
            ]
            
            result = self._send_trap(trap_oid, var_binds)
            
            # Log the notification
            session = self.db_manager.get_session()
            try:
                status_text = 'successful' if success else 'failed'
                self._log_notification(
                    session, cert.id, 'snmp', 0,
                    f"{self.host}:{self.port}",
                    f"Certificate renewal {status_text}",
                    message,
                    'sent' if result else 'failed'
                )
                session.commit()
            finally:
                session.close()
            
            return result
            
        except Exception as e:
            print(f"Error sending SNMP renewal trap: {e}")
            return False
    
    def send_scan_completed_trap(self, scan_results: Dict) -> bool:
        """Send SNMP trap when certificate scan is completed."""
        if not self.enabled:
            return False
        
        try:
            trap_oid = self.oids['scan_completed']
            
            var_binds = [
                ObjectType(ObjectIdentity(f"{trap_oid}.1"), Integer32(scan_results.get('certificates_found', 0))),
                ObjectType(ObjectIdentity(f"{trap_oid}.2"), Integer32(scan_results.get('certificates_added', 0))),
                ObjectType(ObjectIdentity(f"{trap_oid}.3"), Integer32(scan_results.get('certificates_updated', 0))),
                ObjectType(ObjectIdentity(f"{trap_oid}.4"), OctetString(scan_results.get('scan_path', 'unknown'))),
                ObjectType(ObjectIdentity(f"{trap_oid}.5"), OctetString(datetime.utcnow().isoformat()))
            ]
            
            return self._send_trap(trap_oid, var_binds)
            
        except Exception as e:
            print(f"Error sending SNMP scan completed trap: {e}")
            return False
    
    def send_system_error_trap(self, error_message: str, component: str = "system") -> bool:
        """Send SNMP trap for system errors."""
        if not self.enabled:
            return False
        
        try:
            trap_oid = self.oids['system_error']
            
            var_binds = [
                ObjectType(ObjectIdentity(f"{trap_oid}.1"), OctetString(component)),
                ObjectType(ObjectIdentity(f"{trap_oid}.2"), OctetString(error_message)),
                ObjectType(ObjectIdentity(f"{trap_oid}.3"), OctetString(datetime.utcnow().isoformat()))
            ]
            
            return self._send_trap(trap_oid, var_binds)
            
        except Exception as e:
            print(f"Error sending SNMP system error trap: {e}")
            return False
    
    def _send_trap(self, trap_oid: str, var_binds: List) -> bool:
        """Send SNMP trap with the specified OID and variable bindings."""
        try:
            # Create SNMP engine
            for (errorIndication, errorStatus, errorIndex, varBinds) in sendNotification(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((self.host, self.port)),
                ContextData(),
                'trap',
                NotificationType(ObjectIdentity(trap_oid)).addVarBinds(*var_binds)
            ):
                if errorIndication:
                    print(f"SNMP Error: {errorIndication}")
                    return False
                elif errorStatus:
                    error_location = varBinds[int(errorIndex) - 1][0] if errorIndex else "?"
                    print(f"SNMP Error: {errorStatus.prettyPrint()} at {error_location}")
                    return False
                else:
                    return True
            
            return False
            
        except Exception as e:
            print(f"SNMP Transport Error: {e}")
            return False
    
    def _log_notification(self, session, cert_id: int, notification_type: str,
                         days_before: int, recipient: str, subject: str,
                         message: str, status: str):
        """Log SNMP notification to database."""
        log_entry = NotificationLog(
            certificate_id=cert_id,
            notification_type=notification_type,
            days_before_expiry=days_before,
            recipient=recipient,
            subject=subject,
            message=message,
            status=status,
            error_message=message if status == 'failed' else None
        )
        session.add(log_entry)
    
    def test_snmp_configuration(self) -> Dict:
        """Test SNMP configuration by sending a test trap."""
        if not self.enabled:
            return {
                'success': False,
                'message': 'SNMP notifications are disabled'
            }
        
        try:
            # Send test trap
            test_oid = f"{self.oid_base}.999.1"  # Test OID
            var_binds = [
                ObjectType(ObjectIdentity(f"{test_oid}.1"), OctetString("SSL Manager Test")),
                ObjectType(ObjectIdentity(f"{test_oid}.2"), OctetString(datetime.utcnow().isoformat()))
            ]
            
            success = self._send_trap(test_oid, var_binds)
            
            return {
                'success': success,
                'message': f'Test trap {"sent successfully" if success else "failed"} to {self.host}:{self.port}',
                'host': self.host,
                'port': self.port,
                'community': self.community
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'SNMP test failed: {str(e)}'
            }
    
    def get_mib_information(self) -> Dict:
        """Get MIB information for the SSL Manager SNMP implementation."""
        return {
            'enterprise_oid': self.oid_base,
            'traps': {
                'certificate_expiring': {
                    'oid': self.oids['certificate_expiring'],
                    'description': 'Sent when a certificate is approaching expiration',
                    'variables': [
                        f"{self.oids['certificate_expiring']}.1 - Common Name (OctetString)",
                        f"{self.oids['certificate_expiring']}.2 - File Path (OctetString)",
                        f"{self.oids['certificate_expiring']}.3 - Days Before Expiry (Integer32)",
                        f"{self.oids['certificate_expiring']}.4 - Expiry Date (OctetString)",
                        f"{self.oids['certificate_expiring']}.5 - Serial Number (OctetString)",
                        f"{self.oids['certificate_expiring']}.6 - Issuer Category (OctetString)"
                    ]
                },
                'certificate_expired': {
                    'oid': self.oids['certificate_expired'],
                    'description': 'Sent when a certificate has expired',
                    'variables': [
                        f"{self.oids['certificate_expired']}.1 - Common Name (OctetString)",
                        f"{self.oids['certificate_expired']}.2 - File Path (OctetString)",
                        f"{self.oids['certificate_expired']}.3 - Days Since Expiry (Integer32)",
                        f"{self.oids['certificate_expired']}.4 - Expiry Date (OctetString)"
                    ]
                },
                'renewal_success': {
                    'oid': self.oids['renewal_success'],
                    'description': 'Sent when certificate renewal succeeds',
                    'variables': [
                        f"{self.oids['renewal_success']}.1 - Common Name (OctetString)",
                        f"{self.oids['renewal_success']}.2 - File Path (OctetString)",
                        f"{self.oids['renewal_success']}.3 - Success Message (OctetString)",
                        f"{self.oids['renewal_success']}.4 - Serial Number (OctetString)",
                        f"{self.oids['renewal_success']}.5 - Timestamp (OctetString)"
                    ]
                },
                'renewal_failure': {
                    'oid': self.oids['renewal_failure'],
                    'description': 'Sent when certificate renewal fails',
                    'variables': [
                        f"{self.oids['renewal_failure']}.1 - Common Name (OctetString)",
                        f"{self.oids['renewal_failure']}.2 - File Path (OctetString)",
                        f"{self.oids['renewal_failure']}.3 - Error Message (OctetString)",
                        f"{self.oids['renewal_failure']}.4 - Serial Number (OctetString)",
                        f"{self.oids['renewal_failure']}.5 - Timestamp (OctetString)"
                    ]
                },
                'scan_completed': {
                    'oid': self.oids['scan_completed'],
                    'description': 'Sent when certificate directory scan completes',
                    'variables': [
                        f"{self.oids['scan_completed']}.1 - Certificates Found (Integer32)",
                        f"{self.oids['scan_completed']}.2 - Certificates Added (Integer32)",
                        f"{self.oids['scan_completed']}.3 - Certificates Updated (Integer32)",
                        f"{self.oids['scan_completed']}.4 - Scan Path (OctetString)",
                        f"{self.oids['scan_completed']}.5 - Timestamp (OctetString)"
                    ]
                },
                'system_error': {
                    'oid': self.oids['system_error'],
                    'description': 'Sent when system errors occur',
                    'variables': [
                        f"{self.oids['system_error']}.1 - Component (OctetString)",
                        f"{self.oids['system_error']}.2 - Error Message (OctetString)",
                        f"{self.oids['system_error']}.3 - Timestamp (OctetString)"
                    ]
                }
            }
        }
