#!/bin/bash
#
# SSL Certificate Monitoring Setup Script
# Helps configure SNMP and Prometheus monitoring
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_DIR}/config/config.json"

echo "==========================================="
echo "SSL Certificate Monitoring Setup"
echo "==========================================="
echo ""

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found at $CONFIG_FILE"
    echo "Please copy config/config.example.json to config/config.json first"
    exit 1
fi

echo "Configuration file found: $CONFIG_FILE"
echo ""

# Function to ask yes/no question
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"

    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$prompt" answer
    answer="${answer:-$default}"

    case "$answer" in
        [Yy]* ) return 0;;
        * ) return 1;;
    esac
}

# SNMP Configuration
echo "--- SNMP Configuration ---"
if ask_yes_no "Do you want to configure SNMP trap monitoring?"; then
    read -p "SNMP Manager hostname/IP [localhost]: " snmp_host
    snmp_host="${snmp_host:-localhost}"

    read -p "SNMP Trap port [162]: " snmp_port
    snmp_port="${snmp_port:-162}"

    read -p "SNMP Community string [public]: " snmp_community
    snmp_community="${snmp_community:-public}"

    read -p "Base OID [1.3.6.1.4.1.12345]: " snmp_oid
    snmp_oid="${snmp_oid:-1.3.6.1.4.1.12345}"

    echo ""
    echo "SNMP Configuration:"
    echo "  Host: $snmp_host"
    echo "  Port: $snmp_port"
    echo "  Community: $snmp_community"
    echo "  Base OID: $snmp_oid"
    echo ""

    if ask_yes_no "Apply this SNMP configuration?" "y"; then
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)
config['snmp']['enabled'] = True
config['snmp']['host'] = '$snmp_host'
config['snmp']['port'] = $snmp_port
config['snmp']['community'] = '$snmp_community'
config['snmp']['oid_base'] = '$snmp_oid'
with open('$CONFIG_FILE', 'w') as f:
    json.dump(config, f, indent=4)
print('SNMP configuration updated!')
"
    fi
fi

echo ""

# Prometheus Configuration
echo "--- Prometheus Configuration ---"
if ask_yes_no "Do you want to configure Prometheus metrics export?"; then
    read -p "Node exporter textfile path [/var/lib/node_exporter/textfile_collector]: " prom_path
    prom_path="${prom_path:-/var/lib/node_exporter/textfile_collector}"

    read -p "Metrics filename [ssl_certificates.prom]: " prom_file
    prom_file="${prom_file:-ssl_certificates.prom}"

    echo ""
    echo "Prometheus Configuration:"
    echo "  Textfile path: $prom_path"
    echo "  Metrics file: $prom_file"
    echo ""

    if ask_yes_no "Apply this Prometheus configuration?" "y"; then
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)
config['prometheus']['enabled'] = True
config['prometheus']['textfile_path'] = '$prom_path'
config['prometheus']['metrics_file'] = '$prom_file'
with open('$CONFIG_FILE', 'w') as f:
    json.dump(config, f, indent=4)
print('Prometheus configuration updated!')
"

        # Create directory if needed
        if [ ! -d "$prom_path" ]; then
            echo ""
            if ask_yes_no "Directory $prom_path doesn't exist. Create it?"; then
                sudo mkdir -p "$prom_path"
                echo "Directory created. You may need to adjust permissions."
            fi
        fi
    fi
fi

echo ""
echo "--- Test Configuration ---"
if ask_yes_no "Do you want to test the monitoring configuration?"; then
    echo ""
    python3 "${PROJECT_DIR}/scripts/run_monitoring.py" --test
fi

echo ""
echo "--- Automated Scheduling ---"
echo "You can schedule monitoring to run automatically using:"
echo "  1. Systemd Timer (recommended for modern Linux)"
echo "  2. Cron (traditional, works everywhere)"
echo ""

if ask_yes_no "Do you want to install systemd timer?" "n"; then
    echo ""
    echo "Installing systemd units..."

    # Check if we need sudo
    if [ "$EUID" -ne 0 ]; then
        echo "Note: This requires sudo privileges"
        SUDO="sudo"
    else
        SUDO=""
    fi

    # Copy service and timer files
    $SUDO cp "${PROJECT_DIR}/examples/systemd/ssl-monitoring.service" /etc/systemd/system/
    $SUDO cp "${PROJECT_DIR}/examples/systemd/ssl-monitoring.timer" /etc/systemd/system/

    # Update paths in service file
    $SUDO sed -i "s|/opt/ads-sslmgr|$PROJECT_DIR|g" /etc/systemd/system/ssl-monitoring.service

    # Reload and enable
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable ssl-monitoring.timer
    $SUDO systemctl start ssl-monitoring.timer

    echo ""
    echo "Systemd timer installed and started!"
    echo "Check status with: systemctl status ssl-monitoring.timer"
    echo "View logs with: journalctl -u ssl-monitoring.service -f"

elif ask_yes_no "Do you want to install cron job?" "n"; then
    echo ""
    echo "Example cron configuration:"
    cat "${PROJECT_DIR}/examples/cron/ssl-monitoring.cron"
    echo ""
    echo "To install, run:"
    echo "  crontab -e"
    echo "Then add the appropriate lines from above."
fi

echo ""
echo "==========================================="
echo "Setup Complete!"
echo "==========================================="
echo ""
echo "Configuration updated in: $CONFIG_FILE"
echo ""
echo "Next steps:"
echo "  1. Review your configuration: cat $CONFIG_FILE"
echo "  2. Test SNMP: python3 scripts/run_monitoring.py --snmp"
echo "  3. Test Prometheus: python3 scripts/prometheus_exporter.py --print"
echo "  4. Read full documentation: docs/MONITORING_SETUP.md"
echo ""
echo "Happy monitoring!"
