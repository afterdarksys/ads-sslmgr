# Monitoring Quick Start Guide

Get up and running with SNMP and Prometheus monitoring in 5 minutes!

## Quick Setup

### 1. Run Interactive Setup

```bash
./scripts/setup_monitoring.sh
```

This will guide you through configuring both SNMP and Prometheus.

### 2. Or Configure Manually

Edit `config/config.json`:

```json
{
  "snmp": {
    "enabled": true,
    "host": "your-snmp-manager.example.com",
    "trap_frequency_hours": [1, 3, 6, 12, 24, 36, 48, 72]
  },
  "prometheus": {
    "enabled": true,
    "textfile_path": "/var/lib/node_exporter/textfile_collector"
  }
}
```

### 3. Test Configuration

```bash
python scripts/run_monitoring.py --test
```

### 4. Run Monitoring

```bash
# Run everything (SNMP + Prometheus)
python scripts/run_monitoring.py

# Or run separately
python scripts/run_monitoring.py --snmp
python scripts/prometheus_exporter.py
```

## How the Trap Frequency Works

The escalating frequency makes traps more "annoying" as expiration approaches:

| Time Until Expiry | Trap Frequency |
|-------------------|----------------|
| 72+ hours (3 days) | Every 72 hours |
| 48-72 hours (2-3 days) | Every 48 hours |
| 24-48 hours (1-2 days) | Every 24 hours |
| 12-24 hours | Every 12 hours |
| 6-12 hours | Every 6 hours |
| 3-6 hours | Every 3 hours |
| 1-3 hours | Every hour |
| < 1 hour | **Every hour!** |

Configure this in `trap_frequency_hours` array - smaller numbers = more frequent traps!

## Automate with Cron

```bash
# Edit crontab
crontab -e

# Add this line to run every hour
0 * * * * /usr/bin/python3 /path/to/ads-sslmgr/scripts/run_monitoring.py
```

## Automate with Systemd

```bash
# Copy example files
sudo cp examples/systemd/ssl-monitoring.* /etc/systemd/system/

# Update paths in ssl-monitoring.service
sudo nano /etc/systemd/system/ssl-monitoring.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ssl-monitoring.timer
sudo systemctl start ssl-monitoring.timer

# Check status
systemctl status ssl-monitoring.timer
```

## Prometheus Metrics

Once exported, query in Prometheus:

```promql
# Days until expiration
ssl_certificate_days_until_expiry

# Certificates expiring in 7 days
ssl_certificate_days_until_expiry < 7

# Total expired certificates
ssl_certificates_expired
```

## Grafana Dashboard Example

Import this JSON snippet for a quick dashboard:

```json
{
  "panels": [
    {
      "title": "Days to Expiration",
      "targets": [{"expr": "ssl_certificate_days_until_expiry"}],
      "type": "graph"
    },
    {
      "title": "Expired Certificates",
      "targets": [{"expr": "ssl_certificates_expired"}],
      "type": "singlestat"
    }
  ]
}
```

## SNMP Trap Receiver Setup

Quick snmptrapd setup for testing:

```bash
# Install (Ubuntu/Debian)
sudo apt-get install snmptrapd

# Run in foreground to see traps
sudo snmptrapd -f -Lo
```

## Import MIB into Monitoring System

```bash
# Copy MIB file to SNMP MIBs directory
sudo cp examples/snmp/SSL-MANAGER-MIB.txt /usr/share/snmp/mibs/

# Test loading
snmptranslate -m SSL-MANAGER-MIB -IR certificateExpiring
```

## Troubleshooting

**SNMP traps not sending?**
- Check `enabled: true` in config
- Verify network connectivity: `nc -zv hostname 162`
- Check firewall rules

**Prometheus metrics not updating?**
- Verify textfile path exists and is writable
- Check node_exporter is running: `systemctl status node_exporter`
- View metrics: `curl localhost:9100/metrics | grep ssl_`

**Traps sending too frequently?**
- Increase numbers in `trap_frequency_hours` array
- Set `trap_frequency_enabled: false` to disable throttling

**Need more help?**
- Full documentation: [docs/MONITORING_SETUP.md](docs/MONITORING_SETUP.md)
- View logs: `journalctl -u ssl-monitoring.service -f`
- Test mode: `python scripts/run_monitoring.py --test`

## Files Reference

| File | Purpose |
|------|---------|
| `scripts/run_monitoring.py` | Main monitoring script (SNMP + Prometheus) |
| `scripts/prometheus_exporter.py` | Standalone Prometheus exporter |
| `scripts/setup_monitoring.sh` | Interactive setup wizard |
| `notifications/snmp_notifier.py` | SNMP trap implementation |
| `examples/systemd/*` | Systemd unit files |
| `examples/cron/*` | Cron job examples |
| `examples/snmp/SSL-MANAGER-MIB.txt` | SNMP MIB definition |
| `docs/MONITORING_SETUP.md` | Complete documentation |

---

**You're all set!** Run `./scripts/run_monitoring.py` to start monitoring.
