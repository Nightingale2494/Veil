#!/bin/bash
# deploy.sh - Idempotent deployment script for Veil messaging backend as a systemd service.
set -e

echo "=========================================="
echo "    Veil Production Deployment Script     "
echo "=========================================="

# 1. Ensure unprivileged system user and group 'veil' exist
echo "[1/6] Provisioning unprivileged system user and group..."
if ! getent group veil >/dev/null 2>&1; then
    sudo groupadd -r veil
    echo "Group 'veil' created."
else
    echo "Group 'veil' already exists."
fi

if ! getent passwd veil >/dev/null 2>&1; then
    sudo useradd -r -g veil -d /var/lib/veil -s /usr/sbin/nologin -c "Veil Secure Messaging System User" veil
    echo "User 'veil' created."
else
    echo "User 'veil' already exists."
fi

# 2. Compile Veil backend in release mode on the VM
echo "[2/6] Building release binary using Cargo..."
cargo build --release --manifest-path backend/Cargo.toml

# 3. Provision installation directories and set permissions
echo "[3/6] Configuring directories and permissions..."
sudo mkdir -p /opt/veil
sudo mkdir -p /var/lib/veil/uploads
sudo mkdir -p /etc/veil

# Copy compiled release binary to stable location
echo "Installing release binary..."
sudo cp backend/target/release/veil_backend /opt/veil/veil_backend
sudo chmod 755 /opt/veil/veil_backend
sudo chown veil:veil /opt/veil/veil_backend

# Setup environment configuration file safely
if [ ! -f /etc/veil/veil.env ]; then
    echo "Provisioning new configuration file /etc/veil/veil.env from template..."
    sudo cp .env.example /etc/veil/veil.env
    # Change permissions so only veil user/group can read it
    sudo chmod 600 /etc/veil/veil.env
    sudo chown veil:veil /etc/veil/veil.env
    echo "Environment file created. Please update database credentials in /etc/veil/veil.env."
else
    echo "Existing configuration /etc/veil/veil.env found. Keeping it intact for idempotency."
fi

# Ensure correct folder ownership for storage directory
sudo chown -R veil:veil /var/lib/veil

# 4. Generate systemd service configuration file
echo "[4/6] Creating systemd service file..."
sudo cp veil.service /etc/systemd/system/veil.service
sudo chmod 644 /etc/systemd/system/veil.service

# 5. Reload systemd daemon and configure automatic boot start
echo "[5/6] Registering service with systemd..."
sudo systemctl daemon-reload
sudo systemctl enable veil

# 6. Start/Restart the service to load the new binary
echo "[6/6] Launching Veil service..."
sudo systemctl restart veil

echo "=========================================="
echo "    Deployment Completed Successfully!    "
echo "=========================================="
echo "Verify status:    sudo systemctl status veil"
echo "Restart service:  sudo systemctl restart veil"
echo "Follow logs:      sudo journalctl -u veil -f"
