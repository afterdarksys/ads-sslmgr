# SSL Certificate Monitoring Setup

This guide covers setting up monitoring integrations for the SSL Certificate Management System, including SNMP traps with escalating frequency and Prometheus metrics export.

## Table of Contents

- [SNMP Trap Monitoring](#snmp-trap-monitoring)
- [Prometheus Metrics Export](#prometheus-metrics-export)
- [Automated Monitoring](#automated-monitoring)
- [Troubleshooting](#troubleshooting)

---

## SNMP Trap Monitoring

The SNMP integration sends traps when certificates are expiring, with an escalating frequency that becomes more annoying as expiration approaches.

### Features

- **Escalating Trap Frequency**: Configurable trap intervals that increase as expiration nears
- **Smart Throttling**: Prevents duplicate traps within the configured frequency window
- **Multiple Trap Types**:
  - Certificate expiring warnings
  - Certificate expired alerts
  - Renewal success notifications
  - Renewal failure alerts
  - System errors
  - Scan completion events

### Configuration

Edit `config/config.json` and configure the SNMP section:

```json
{
  "snmp": {
    "enabled": true,
    "community": "public",
    "host": "your-snmp-manager.example.com",
    "port": 162,
    "oid_base": "1.3.6.1.4.1.12345",
    "trap_frequency_hours": [1, 3, 6, 12, 24, 36, 48, 72],
    "trap_frequency_enabled": true
  }
}
```

#### Configuration Options

- **enabled**: Enable/disable SNMP trap sending
- **community**: SNMP community string (default: "public")
- **host**: SNMP trap receiver hostname or IP
- **port**: SNMP trap port (default: 162)
- **oid_base**: Base OID for SSL Manager traps (default: "1.3.6.1.4.1.12345")
- **trap_frequency_hours**: Array of hours before expiration for trap frequencies
- **trap_frequency_enabled**: Enable escalating trap frequency feature

#### Trap Frequency Behavior

The `trap_frequency_hours` array defines when traps are sent. For example:

```json
"trap_frequency_hours": [1, 3, 6, 12, 24, 36, 48, 72]
```

This means:
- When cert expires in **72 hours or less**: Send trap every **72 hours**
- When cert expires in **48 hours or less**: Send trap every **48 hours** (more frequent!)
- When cert expires in **24 hours or less**: Send trap every **24 hours** (even more frequent!)
- When cert expires in **12 hours or less**: Send trap every **12 hours**
- When cert expires in **6 hours or less**: Send trap every **6 hours**
- When cert expires in **3 hours or less**: Send trap every **3 hours**
- When cert expires in **1 hour or less**: Send trap every **1 hour** (very annoying!)

### SNMP Trap OIDs

The system uses the following OID structure (assuming base OID `1.3.6.1.4.1.12345`):

| Trap Type | OID | Description |
|-----------|-----|-------------|
| certificate_expiring | `.1.1` | Certificate approaching expiration |
| certificate_expired | `.1.2` | Certificate has expired |
| renewal_success | `.2.1` | Certificate renewal succeeded |
| renewal_failure | `.2.2` | Certificate renewal failed |
| scan_completed | `.3.1` | Certificate scan completed |
| system_error | `.4.1` | System error occurred |

#### Certificate Expiring Trap Variables

- `.1` - Common Name (OctetString)
- `.2` - File Path (OctetString)
- `.3` - Days Before Expiry (Integer32)
- `.4` - Expiry Date ISO format (OctetString)
- `.5` - Serial Number (OctetString)
- `.6` - Issuer Category (OctetString)

### Testing SNMP Configuration

Test your SNMP configuration:

```bash
python scripts/run_monitoring.py --config config/config.json --test
```

Or test sending a trap manually in Python:

```python
from database.models import DatabaseManager
from notifications.snmp_notifier import SNMPNotifier
import json

# Load config
with open('config/config.json') as f:
    config = json.load(f)

# Create notifier
db_manager = DatabaseManager(config)
notifier = SNMPNotifier(config, db_manager)

# Test trap
result = notifier.test_snmp_configuration()
print(result)
```

### Receiving SNMP Traps

To receive and view traps, you can use **snmptrapd**:

```bash
# Install snmptrapd (Ubuntu/Debian)
sudo apt-get install snmptrapd

# Create basic config
sudo tee /etc/snmp/snmptrapd.conf << EOF
authCommunity log,execute,net public
disableAuthorization yes
EOF

# Run in foreground (for testing)
sudo snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf

# Or enable as service
sudo systemctl enable snmptrapd
sudo systemctl start snmptrapd
```

---

## Prometheus Metrics Export

Export certificate expiry data to Prometheus via node_exporter's textfile collector.

### Features

- **Textfile Collector Format**: Compatible with node_exporter
- **Multiple Metrics**:
  - Certificate expiry timestamps
  - Days until expiration
  - Total certificate counts
  - Expired certificate counts
  - Certificates expiring soon
- **Rich Labels**: CN, serial, issuer, file path, SANs, format
- **Atomic Writes**: Safe for concurrent access

### Configuration

Edit `config/config.json` and configure the Prometheus section:

```json
{
  "prometheus": {
    "enabled": true,
    "textfile_path": "/var/lib/node_exporter/textfile_collector",
    "metrics_file": "ssl_certificates.prom",
    "include_metadata": true
  }
}
```

#### Configuration Options

- **enabled**: Enable/disable Prometheus metrics export
- **textfile_path**: Directory where node_exporter reads textfiles
- **metrics_file**: Name of the metrics file to create
- **include_metadata**: Include additional metadata labels (SANs, format)

### Setup node_exporter

1. **Install node_exporter**:

```bash
# Download latest release
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvfz node_exporter-*.tar.gz
sudo cp node_exporter-*/node_exporter /usr/local/bin/

# Create textfile collector directory
sudo mkdir -p /var/lib/node_exporter/textfile_collector
sudo chown -R node_exporter:node_exporter /var/lib/node_exporter
```

2. **Create systemd service** (`/etc/systemd/system/node_exporter.service`):

```ini
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
  --collector.textfile.directory=/var/lib/node_exporter/textfile_collector

[Install]
WantedBy=multi-user.target
```

3. **Enable and start**:

```bash
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
```

### Exported Metrics

#### `ssl_certificate_expiry_seconds`

Certificate expiry as Unix timestamp.

**Labels**: `cn`, `serial`, `issuer`, `file_path`, `san`, `format`

```
ssl_certificate_expiry_seconds{cn="example.com",serial="ABC123",issuer="letsencrypt",file_path="/path/to/cert.pem"} 1735689600
```

#### `ssl_certificate_days_until_expiry`

Days until certificate expires (negative if expired).

**Labels**: `cn`, `serial`, `file_path`

```
ssl_certificate_days_until_expiry{cn="example.com",serial="ABC123",file_path="/path/to/cert.pem"} 45.23
```

#### `ssl_certificates_total`

Total number of certificates being monitored.

```
ssl_certificates_total 150
```

#### `ssl_certificates_expired`

Number of expired certificates.

```
ssl_certificates_expired 3
```

#### `ssl_certificates_expiring_soon`

Number of certificates expiring within 30 days.

```
ssl_certificates_expiring_soon 12
```

### Manual Export

Export metrics manually:

```bash
# Export to configured path
python scripts/prometheus_exporter.py

# Export with custom config
python scripts/prometheus_exporter.py --config /path/to/config.json

# Print to stdout (for testing)
python scripts/prometheus_exporter.py --print
```

### Prometheus Configuration

Add node_exporter to your Prometheus configuration (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
```

### Example Queries

**Certificates expiring in 7 days**:
```promql
ssl_certificate_days_until_expiry < 7
```

**Alert on expiring certificates**:
```yaml
- alert: CertificateExpiringSoon
  expr: ssl_certificate_days_until_expiry < 30
  labels:
    severity: warning
  annotations:
    summary: "Certificate {{ $labels.cn }} expires in {{ $value }} days"
```

**Graph certificates by expiry time**:
```promql
ssl_certificate_days_until_expiry
```

---

## Automated Monitoring

Run monitoring tasks automatically using cron or systemd timers.

### Option 1: Cron (Simple)

Add to crontab (`crontab -e`):

```bash
# Run monitoring every hour
0 * * * * /usr/bin/python3 /path/to/ads-sslmgr/scripts/run_monitoring.py >> /var/log/ssl-monitoring.log 2>&1

# Or run SNMP and Prometheus separately
0 * * * * /usr/bin/python3 /path/to/ads-sslmgr/scripts/run_monitoring.py --snmp
5 * * * * /usr/bin/python3 /path/to/ads-sslmgr/scripts/prometheus_exporter.py
```

### Option 2: Systemd Timer (Recommended)

1. **Create service file** (`/etc/systemd/system/ssl-monitoring.service`):

```ini
[Unit]
Description=SSL Certificate Monitoring
After=network.target

[Service]
Type=oneshot
User=sslmanager
Group=sslmanager
WorkingDirectory=/opt/ads-sslmgr
ExecStart=/usr/bin/python3 /opt/ads-sslmgr/scripts/run_monitoring.py
StandardOutput=journal
StandardError=journal
```

2. **Create timer file** (`/etc/systemd/system/ssl-monitoring.timer`):

```ini
[Unit]
Description=SSL Certificate Monitoring Timer
Requires=ssl-monitoring.service

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

3. **Enable and start timer**:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ssl-monitoring.timer
sudo systemctl start ssl-monitoring.timer

# Check timer status
sudo systemctl status ssl-monitoring.timer
sudo systemctl list-timers
```

### Monitoring Script Options

```bash
# Run all monitoring (SNMP + Prometheus)
python scripts/run_monitoring.py

# Only run SNMP monitoring
python scripts/run_monitoring.py --snmp

# Only run Prometheus export
python scripts/run_monitoring.py --prometheus

# Test configuration
python scripts/run_monitoring.py --test

# Use custom config
python scripts/run_monitoring.py --config /path/to/config.json
```

---

## Troubleshooting

### SNMP Traps Not Sending

1. **Check SNMP is enabled**:
   ```bash
   python scripts/run_monitoring.py --test
   ```

2. **Verify network connectivity**:
   ```bash
   ping your-snmp-manager.example.com
   nc -zv your-snmp-manager.example.com 162
   ```

3. **Check firewall rules**:
   ```bash
   sudo iptables -L -n | grep 162
   ```

4. **Test with snmptrap manually**:
   ```bash
   snmptrap -v2c -c public your-snmp-manager.example.com '' 1.3.6.1.4.1.12345.999.1 1.3.6.1.4.1.12345.999.1.1 s "test"
   ```

### Prometheus Metrics Not Updating

1. **Check Prometheus is enabled**:
   ```bash
   python scripts/prometheus_exporter.py --test
   ```

2. **Verify textfile directory permissions**:
   ```bash
   ls -la /var/lib/node_exporter/textfile_collector/
   ```

3. **Check metrics file exists**:
   ```bash
   cat /var/lib/node_exporter/textfile_collector/ssl_certificates.prom
   ```

4. **Verify node_exporter is running**:
   ```bash
   systemctl status node_exporter
   curl http://localhost:9100/metrics | grep ssl_certificate
   ```

### Trap Frequency Not Working

1. **Check database for notification logs**:
   ```python
   from database.models import DatabaseManager, NotificationLog
   import json

   with open('config/config.json') as f:
       config = json.load(f)

   db = DatabaseManager(config)
   session = db.get_session()

   logs = session.query(NotificationLog).filter(
       NotificationLog.notification_type == 'snmp'
   ).order_by(NotificationLog.sent_at.desc()).limit(10).all()

   for log in logs:
       print(f"{log.sent_at} - Cert {log.certificate_id} - {log.status}")
   ```

2. **Verify trap_frequency_enabled is true** in config

3. **Check that certificates are within frequency thresholds**

### Getting Help

- Check logs: `tail -f logs/ssl_manager.log`
- Run in test mode: `python scripts/run_monitoring.py --test`
- View systemd journal: `journalctl -u ssl-monitoring.service -f`
- Enable debug output in scripts (add `print()` statements)

---

## Example Dashboard

### Grafana Dashboard Query Examples

**Panel 1: Days to Expiration (Graph)**
```promql
ssl_certificate_days_until_expiry > 0
```

**Panel 2: Expired Certificates (Single Stat)**
```promql
ssl_certificates_expired
```

**Panel 3: Expiring Soon (Single Stat)**
```promql
ssl_certificates_expiring_soon
```

**Panel 4: Certificate List (Table)**
```promql
sort_desc(ssl_certificate_days_until_expiry)
```

---

## Best Practices

1. **Start with conservative trap frequencies** (longer intervals) and adjust based on your needs
2. **Monitor trap receiver capacity** - too many traps can overwhelm receivers
3. **Use appropriate OID base** - coordinate with your network team
4. **Set up log rotation** for monitoring script output
5. **Test monitoring after configuration changes**
6. **Set up Prometheus alerts** for critical expiration thresholds
7. **Use systemd timers over cron** for better logging and reliability
8. **Keep metrics files small** by limiting metadata when not needed

---

## Additional Resources

- [Prometheus Node Exporter](https://github.com/prometheus/node_exporter)
- [SNMP Trap Documentation](http://www.net-snmp.org/docs/man/snmptrap.html)
- [Prometheus Query Documentation](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Grafana Dashboard Examples](https://grafana.com/grafana/dashboards/)
