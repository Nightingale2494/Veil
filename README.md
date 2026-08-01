# Veil E2E Secure Messaging Backend - Production Deployment

This directory contains configuration files and scripts to deploy the Veil messaging backend as a production-grade systemd service on a Linux (Ubuntu) environment.

---

## Prerequisites

Before running the deployment script, ensure the following dependencies are installed on the target host:
1. **Rust and Cargo**: Required to compile the release binary.
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. **PostgreSQL Database**: Accessible from the host system.
3. **systemd**: Installed and active as the default init manager.

---

## Deployment Steps

1. **Clone the Repository**:
   Clone your repository onto the target VM and navigate to the project root folder.
2. **Execute Deployment Script**:
   The `deploy.sh` script compiles the backend in release mode, configures directories, sets permissions securely, registers the systemd unit file, and starts the service:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```
3. **Configure Environment Secrets**:
   Open `/etc/veil/veil.env` to configure your database connection string and server binding parameters:
   ```bash
   sudo nano /etc/veil/veil.env
   ```
   For example:
   ```ini
   DATABASE_URL=postgres://username:password@localhost:5432/veil
   SERVER_ADDRESS=0.0.0.0:8080
   ```
4. **Restart Service to Apply Changes**:
   ```bash
   sudo systemctl restart veil
   ```

---

## Service Management

Use the following commands to manage the Veil backend service:

* **Check Service Status**:
  ```bash
  sudo systemctl status veil
  ```
* **Restart the Service**:
  ```bash
  sudo systemctl restart veil
  ```
* **Enable Auto-start on Boot**:
  ```bash
  sudo systemctl enable veil
  ```
* **Follow Real-time Service Logs**:
  ```bash
  sudo journalctl -u veil -f
  ```
* **Stop the Service**:
  ```bash
  sudo systemctl stop veil
  ```

---

## Security Best Practices

1. **Unprivileged System User**: The service executes under the `veil` system user, preventing system-level access in case of a service vulnerability.
2. **Secure Environment Variables**: The environment configuration is stored in `/etc/veil/veil.env` with `600` permissions, making it readable only by the `veil` service user.
3. **Auto-Restart**: If the Veil process panics or terminates, systemd automatically restarts the service within 5 seconds.
