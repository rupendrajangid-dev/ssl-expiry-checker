# Production Deployment Guide - SSL Expiry Monitor

This guide covers step-by-step production setup, service hardening, reverse proxy mapping, container orchestration, and security best practices for hosting the SSL Certificate Expiry Monitor.

All application logic is contained inside [ssl_monitor.py](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py), while configurations are mapped dynamically to [config.json](file:///e:/Tagid/ssl-expiry-checker/config.json) and [domains.json](file:///e:/Tagid/ssl-expiry-checker/domains.json).

---

## 📋 Prerequisites & System Requirements
* **Operating System**: Linux (Ubuntu 20.04+ / Debian 11+ recommended), macOS, or Windows Server.
* **Runtime**: Python 3.8 or higher.
* **Relay Access**: An active SMTP mail transfer relay (e.g., Google Workspace/Gmail, Amazon SES, SendGrid, Mailgun, or standard postfix servers).
* **Network Ports**:
  * Outbound access to port `443` (to perform SSL socket checks on target domains).
  * Outbound access to port `465` or `587` (SMTP mail servers).
  * Inbound access to port `80` (HTTP) and `443` (HTTPS) on proxy layer.

---

## 🔒 Step 1: Secure Environment Isolation (Linux)

For security, do **not** run the dashboard daemon or cron checkers under the root user account. Always create a dedicated system account with restricted privileges.

1. **Create a System User and Group**:
   ```bash
   sudo groupadd --system sslmonitor
   sudo useradd -s /sbin/nologin --system -g sslmonitor sslmonitor
   ```

2. **Configure Project Directories**:
   Move the project files to a clean deployment directory, e.g., `/var/www/ssl-expiry-checker`, and establish ownership constraints:
   ```bash
   sudo mkdir -p /var/www/ssl-expiry-checker
   sudo cp -r . /var/www/ssl-expiry-checker/
   sudo chown -R sslmonitor:sslmonitor /var/www/ssl-expiry-checker
   ```

3. **Secure Environment Credentials**:
   Restrict read access to the environment credentials database file containing SMTP login keys:
   ```bash
   sudo chmod 600 /var/www/ssl-expiry-checker/.env
   ```

---

## 🛠️ Step 2: Virtual Environment Configuration

Always perform execution wrapping within a Python virtual environment to isolate standard library packages.

```bash
cd /var/www/ssl-expiry-checker

# Initialize virtualenv
sudo -u sslmonitor python3 -m venv venv

# Activate and update packages
sudo -u sslmonitor ./venv/bin/pip install --upgrade pip
sudo -u sslmonitor ./venv/bin/pip install -r requirements.txt
```

---

## ⚙️ Step 3: Hosting Options (Production)

Select one of the following methods to host the Web Admin UI dashboard server.

### Option A: Systemd Service Daemon (System-level Auto-boot)
To ensure the Python HTTP web server runs continuously and recovers automatically from hardware reboots, configure it as a Systemd service.

1. **Create Service Unit Config**:
   ```bash
   sudo nano /etc/systemd/system/ssl-monitor.service
   ```
2. **Add Service Details**:
   ```ini
   [Unit]
   Description=SSL Expiry Checker Web Admin Dashboard Service
   After=network.target

   [Service]
   Type=simple
   User=sslmonitor
   Group=sslmonitor
   WorkingDirectory=/var/www/ssl-expiry-checker
   ExecStart=/var/www/ssl-expiry-checker/venv/bin/python ssl_monitor.py --web --port 8000
   Restart=always
   RestartSec=10
   StandardOutput=journal
   StandardError=journal
   EnvironmentFile=/var/www/ssl-expiry-checker/.env
   Environment=PATH=/var/www/ssl-expiry-checker/venv/bin:/usr/bin:/usr/local/bin

   [Install]
   WantedBy=multi-user.target
   ```
3. **Register and Boot Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable ssl-monitor.service
   sudo systemctl start ssl-monitor.service
   ```
4. **Monitor Execution Health**:
   ```bash
   sudo systemctl status ssl-monitor.service
   ```

---

### Option B: Docker Compose Orchestration (Containerized Stack)
A containerized execution stack isolates configuration files, databases, and logs inside portable volumes.

1. **Create Container Specification (`docker-compose.yml`)**:
   Create a `docker-compose.yml` file in the root directory:
   ```yaml
   version: '3.8'

   services:
     ssl-monitor:
       build: .
       container_name: ssl_monitor_dashboard
       ports:
         - "127.0.0.1:8000:8000"
       volumes:
         - ./domains.json:/app/domains.json
         - ./config.json:/app/config.json
         - ./last_results.json:/app/last_results.json
         - ./logs:/app/logs
       env_file:
         - .env
       restart: always
       command: python ssl_monitor.py --web --port 8000
   ```
2. **Verify target Dockerfile**:
   Ensure your `Dockerfile` maps execution dependencies:
   ```dockerfile
   FROM python:3.10-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   EXPOSE 8000
   CMD ["python", "ssl_monitor.py", "--web", "--port", "8000"]
   ```
3. **Run the container stack**:
   ```bash
   docker compose up -d --build
   ```

---

## 🔀 Step 4: Reverse Proxy & Let's Encrypt Setup (Nginx)

Do not expose Python's raw HTTP socket directly to the public internet. Secure it behind an Nginx reverse proxy layer.

### 1. Configure Nginx Server Block
Create a virtual host configuration file:
```bash
sudo nano /etc/nginx/sites-available/ssl-monitor.yourdomain.com
```
Add Nginx server definitions:
```nginx
server {
    listen 80;
    server_name ssl-monitor.yourdomain.com;

    # Limit payload bounds
    client_max_body_size 2M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Performance Tuning: Disable Nginx buffer storage to allow
        # immediate real-time rendering of checking log output stream
        proxy_buffering off;
        proxy_read_timeout 90;
        
        # Bypass caching mechanisms for API endpoints
        proxy_cache_bypass $http_upgrade;
        proxy_no_cache $http_upgrade;
    }
}
```

### 2. Enable Configuration
```bash
sudo ln -s /etc/nginx/sites-available/ssl-monitor.yourdomain.com /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 3. Enroll SSL Certificate via Let's Encrypt
```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d ssl-monitor.yourdomain.com
```

---

## 🛡️ Step 5: Service Hardening & Security Best Practices

### 1. Firewall Isolation
Keep port `8000` completely blocked from inbound external requests at the network level (using UFW or security groups). All inbound traffic must pass through Nginx over secure port `443` (HTTPS) to validate requests before hitting the Python backend.
```bash
# Block port 8000 globally
sudo ufw deny 8000/tcp
# Allow secure web ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### 2. Rate Limiting (Brute Force Protection)
Add a rate-limiting layer in Nginx to protect the dashboard login endpoint (`/api/login`) from automated attacks:
```nginx
# Add inside http block in /etc/nginx/nginx.conf
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

# Add inside server block in /etc/nginx/sites-available/...
location = /api/login {
    limit_req zone=login_limit burst=3 nodelay;
    proxy_pass http://127.0.0.1:8000;
    # ... standard headers config ...
}
```

### 3. App-Specific Credentials for SMTP
If using external SMTP relays (like Google Workspace, Gmail, or SendGrid), never use account master passwords. Generate a dedicated **App Password** with restricted scopes (Mail-only) and assign it to `SMTP_PASSWORD` in your `.env`.

---

## 💾 Step 6: Database Backups & Maintenance

All configurations and registered domains are stored cleanly in plain-text JSON files. Automate daily backups to prevent accidental data loss.

1. **Backup Script (`backup_registry.sh`)**:
   ```bash
   #!/bin/bash
   BACKUP_DIR="/var/backups/sslmonitor"
   TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
   mkdir -p "$BACKUP_DIR"

   # Create gzip compressed archive of the database files
   tar -czf "$BACKUP_DIR/ssl_backup_$TIMESTAMP.tar.gz" -C /var/www/ssl-expiry-checker config.json domains.json last_results.json
   
   # Retain backups for only 30 days
   find "$BACKUP_DIR" -type f -name "*.tar.gz" -mtime +30 -delete
   ```
2. **Schedule Daily Backup Cron**:
   ```bash
   # Add to crontab
   0 2 * * * /bin/bash /var/www/ssl-expiry-checker/backup_registry.sh
   ```
