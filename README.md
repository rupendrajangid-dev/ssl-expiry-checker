# SSL Certificate Expiry Monitor & Admin Dashboard

An enterprise-grade, concurrent SSL verification system and glassmorphic Web Admin Dashboard built in Python. Designed for system administrators, devops teams, and service providers to monitor dozens of domain targets, prevent certificate outages, and route scoped alerts to specific organization contacts.

---

## 🚀 Key Features

* **Parallel Handshake Checker Engine**: Resolves SSL peer certificates concurrently utilizing native `ThreadPoolExecutor` workers. 
* **Zero External API Dependencies**: Performs direct low-level secure socket connections for maximum performance, privacy, and reliability.
* **Premium Glassmorphic Admin Dashboard**: A responsive dark-themed SPA UI with interactive graphs, statistics, real-time logging streams, and forms.
* **Organization-Scoped Recipient Lists**: 
  * Group domains by individual customer or internal organizations.
  * Define unique recipient email lists for each organization.
  * **Report Isolation**: Automated scans auto-split reports so each recipient list **only** receives alerts for their designated organization's domains.
* **Background Cron Scheduler**: A native background daemon thread running Daily, Weekly, or Monthly checks at precise times.
* **Indian Standard Time (IST) Support**: 
  * Displays dashboard clocks, last-checked logs, and certificate expiries in Indian Standard Time (IST) (`Asia/Kolkata` timezone with `en-IN` formatting).
  * Scheduler executes checks aligned with IST regardless of the VPS/host server operating system timezone.
* **SMTP Alerting & Fail-Safes**: Delivers beautiful responsive HTML emails color-coded by severity, with automated connection retry parameters.

---

## 📁 Directory Structure

```text
ssl-expiry-checker/
├── config.json               # Alert thresholds, timeouts, retries, and scheduler configurations
├── domains.json              # Domains registry, organization assignments, and scoped recipient lists
├── .env                      # Local environment configurations (SMTP settings, admin passwords)
├── .env.example              # Template containing default environment variables
├── last_results.json         # Cached outputs of the last check execution
├── requirements.txt          # Minimal Python dependencies (python-dotenv)
├── ssl_monitor.py            # Monolithic self-contained monitor script (backend & frontend)
└── docs/
    ├── scheduler_and_settings.md # Reference manual for the Cron scheduler and configurations
    └── deployment_guide.md       # Detailed guide for production deployment, hardening, and backups
```

---

## ⚙️ Schema Specifications

### 1. Domains & Recipients Registry ([domains.json](file:///e:/Tagid/ssl-expiry-checker/domains.json))
This registry maps domains globally, assigns them to organizations, and binds specific recipient email addresses to those organizations:
```json
{
  "domains": [
    "demo-admin.tagid.co.in",
    "iesglabs.com"
  ],
  "organizations": {
    "Tagid": [
      "demo-admin.tagid.co.in"
    ],
    "IESG Labs": [
      "iesglabs.com"
    ]
  },
  "org_recipients": {
    "Tagid": [
      "rupendra.j@smart-iam.com",
      "rupendra.iam@gmail.com"
    ],
    "IESG Labs": [
      "devops@tagid.co.in"
    ]
  }
}
```

### 2. Runtime Configurations ([config.json](file:///e:/Tagid/ssl-expiry-checker/config.json))
Defines alert days, network settings, and background daemon scheduler behaviors:
```json
{
  "warning_days": 30,
  "high_priority_days": 14,
  "critical_days": 7,
  "timeout": 10,
  "max_retries": 3,
  "retry_delay": 5,
  "max_workers": 20,
  "send_daily_summary": true,
  "cron_enabled": true,
  "cron_schedule": "daily",
  "cron_time": "09:00",
  "cron_weekly_day": "Monday",
  "cron_monthly_day": 1
}
```

---

## 🚀 Getting Started

### 1. Setup & Installation
1. Clone the project to your host server or workspace.
2. Install virtual environment and runtime requirements:
   ```bash
   python -m venv venv
   
   # Windows:
   .\venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   
   pip install -r requirements.txt
   ```
3. Initialize the environment configuration file:
   ```bash
   cp .env.example .env
   ```
4. Update the `.env` settings with your SMTP mail server credentials and customize the dashboard access password:
   ```ini
   SMTP_HOST=smtp.yourserver.com
   SMTP_PORT=465
   SMTP_USERNAME=alerts@yourserver.com
   SMTP_PASSWORD=yoursecurepassword
   SMTP_SENDER_EMAIL=alerts@yourserver.com
   SMTP_SENDER_NAME="SSL Expiry Monitor"
   SMTP_RECEIVER_EMAILS=fallback-admin@yourserver.com
   DASHBOARD_PASSWORD=admin123
   ```

---

## 🛠️ Usage & Operational Modes

### 1. Command Line Interface (CLI Mode)
Execute direct manual scans or manage registry domains:

* **Trigger Parallel SSL Check**:
  ```bash
  python ssl_monitor.py
  ```
* **List Registered Targets**:
  ```bash
  python ssl_monitor.py --list
  ```
* **Add a Target Domain**:
  ```bash
  python ssl_monitor.py --add example.com myapi.org
  ```
* **Remove a Target Domain**:
  ```bash
  python ssl_monitor.py --remove myapi.org
  ```

### 2. Web Admin UI Server (Dashboard Mode)
Host the built-in HTTP server web interface:
```bash
python ssl_monitor.py --web --port 8000
```
Open your browser and navigate to `http://localhost:8000`. Login using the value configured for `DASHBOARD_PASSWORD` in your `.env` (defaults to `admin123`).

---

## 🌐 REST API References

All endpoints require session validation cookies generated upon login.

| Endpoint | Method | Description | Parameters / Payload |
| :--- | :--- | :--- | :--- |
| `/api/login` | `POST` | Validates dashboard password credentials. | `{ "password": "..." }` |
| `/api/domains` | `GET` | Returns list of domains, organizations mapping, and scoped recipients. | None |
| `/api/domains` | `POST` | Adds a domain to the registry under a specified organization. | `{ "domain": "...", "org_name": "..." }` |
| `/api/domains` | `DELETE`| Removes a domain from the registry globally. | Query string: `?domain=...` |
| `/api/orgs` | `POST` | Creates a new organization in the registry. | `{ "org_name": "..." }` |
| `/api/orgs` | `DELETE`| Deletes an organization and all its domains. | Query string: `?org_name=...` |
| `/api/recipients` | `POST` | Binds a new recipient email address to an organization. | `{ "org_name": "...", "email": "..." }` |
| `/api/recipients` | `DELETE`| Removes a recipient email from an organization. | Query string: `?org_name=...&email=...` |
| `/api/config` | `GET` | Fetches active alert thresholds, workers, and cron parameters. | None |
| `/api/config` | `POST` | Saves updated threshold constraints and scheduler timings. | Full JSON configurations payload |
| `/api/check` | `POST` | Triggers check pipeline asynchronously via parallel execution locks. | Query string: `?org_name=...` (Optional filter) |
| `/api/logs` | `GET` | Streams the terminal execution log content to the browser console. | None |

---

## 🐳 VPS & Linux Daemon Deployments

> [!TIP]
> For step-by-step security hardening, database backups, and reverse proxy setup instructions, please consult the complete **[Production Deployment Guide](file:///e:/Tagid/ssl-expiry-checker/docs/deployment_guide.md)**.

### 1. Host continuously using Systemd
To ensure the Web Admin UI daemon runs 24/7 and restarts automatically:
1. Create a service template:
   ```bash
   sudo nano /etc/systemd/system/ssl-monitor.service
   ```
2. Insert configuration:
   ```ini
   [Unit]
   Description=SSL Expiry Checker Web Admin Dashboard Service
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/var/www/ssl-expiry-checker
   ExecStart=/var/www/ssl-expiry-checker/venv/bin/python ssl_monitor.py --web --port 8000
   Restart=always
   RestartSec=5
   Environment=PATH=/var/www/ssl-expiry-checker/venv/bin:/usr/bin:/usr/local/bin
   EnvironmentFile=/var/www/ssl-expiry-checker/.env

   [Install]
   WantedBy=multi-user.target
   ```
3. Load and start the background service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable ssl-monitor.service
   sudo systemctl start ssl-monitor.service
   ```

### 2. Nginx Reverse Proxy Setup
Map a custom subdomain (e.g. `ssl-monitor.yourdomain.com`) to the dashboard:
1. Configure Nginx Server Block:
   ```nginx
   server {
       listen 80;
       server_name ssl-monitor.yourdomain.com;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           
           # Bypass caching for logging streams
           proxy_cache_bypass $http_upgrade;
           proxy_no_cache $http_upgrade;
       }
   }
   ```
2. Enable configurations and secure using Let's Encrypt Certbot:
   ```bash
   sudo ln -s /etc/nginx/sites-available/ssl-monitor.yourdomain.com /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   sudo certbot --nginx -d ssl-monitor.yourdomain.com
   ```

### 3. Docker Container Deployment
Run as a background container mapping state configurations:
```bash
# Build the application image
docker build -t ssl-expiry-monitor .

# Run continuous Web UI Dashboard container
docker run -d --name ssl-dashboard \
  -p 8000:8000 \
  --env-file .env \
  -v "$(pwd)/domains.json:/app/domains.json" \
  -v "$(pwd)/config.json:/app/config.json" \
  -v "$(pwd)/logs:/app/logs" \
  --restart unless-stopped \
  ssl-expiry-monitor \
  python ssl_monitor.py --web --port 8000
```

---

## 🛡️ Troubleshooting

### 1. Gmail or Secure SMTP Auth Failures
Modern email providers block basic authentication. If using Gmail/Google Workspace:
* Enforce **2-Step Verification** on the sender account.
* Navigate to **Google Account Settings -> Security -> App Passwords**.
* Generate a dedicated 16-character **App Password** for "Mail" and insert it in `SMTP_PASSWORD` under `.env`.

### 2. Server Timeout Warnings
If certain targets fail with `"Connection timed out"`:
* Verify outbound port `443` is open on your VPS firewall (e.g. UFW or security groups).
* Verify that you have not typed port prefixes or subpaths in the domains list (registry values should look like `google.com` or `api.site.in`, not `https://google.com/api`).
* Increase `Socket Timeout (Seconds)` (`timeout` in `config.json`) via the Settings panel to allow slow servers more time to respond.
