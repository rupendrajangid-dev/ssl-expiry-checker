# Walkthrough - SSL Expiry Monitor Upgrades (Per-Org Recipient Lists & Cron Scheduler)

We have successfully engineered, integrated, and verified a set of production-grade upgrades to the single-file **SSL Certificate Expiry Monitor & Admin Dashboard** (`ssl_monitor.py`). 

These upgrades introduce **Per-Organization Email Recipient Lists** and a fully custom **Background Cron Scheduler** with a premium admin Settings panel.

---

## 🚀 Newly Implemented Capabilities

### 1. Per-Organization Email Recipient Lists
- **Registry Schema & Data Persistence**:
  - Extended `domains.json` with an `org_recipients` dictionary mapping organization names to email lists.
  - Implemented self-healing migration logic in `migrate_and_load_registry`.
- **REST API Endpoints (`/api/recipients`)**:
  - `POST /api/recipients`: Validates parameters and appends a new recipient email address to a selected organization.
  - `DELETE /api/recipients`: Safely removes a recipient email from a specific organization.
- **Scoped Email Alert Routing**:
  - Refactored `send_email_alert` to retrieve and merge scoped email recipients dynamically from the registry database.
  - **Global Scan Splitting**: When scanning all domains globally (e.g. CLI run, Cron, or All Organizations trigger), `send_email_alert` automatically groups results by organization and sends separate email reports to only that organization's recipients. This prevents mixing domain alerts between organizations.

### 2. Custom Background Cron Scheduler
- **Scheduler Logic (`background_scheduler`)**:
  - A dedicated background daemon thread runs continuously, checking the scheduling configuration every 30 seconds.
  - Supports **Daily**, **Weekly**, and **Monthly** intervals at a precise scheduled execution time (`HH:MM`).
  - Implements concurrency locks (`acquire_lock`) and prevents duplicate run triggers on the same calendar day.
- **REST API Endpoints (`/api/config`)**:
  - `GET /api/config`: Retrieves the current threshold configurations, max workers, and cron schedule settings.
  - `POST /api/config`: Receives configuration payload, performs threshold validations (Critical < High < Warning), and persists them to `config.json`.
- **Frontend UI Settings Tab**:
  - Added a dedicated "Scheduler & Settings" tab to the admin dashboard.
  - Added a premium form layout containing toggle switches, dropdown selectors, number inputs, and interactive styling.
  - Features real-time validation constraints and digital UTC clock reference display.

---

## 🧪 Verification and Testing Results

We executed extensive functional validation tests to guarantee correctness across all upgraded subsystems:

### 1. Automated Scoped Email Routing Verification Suite
We ran `verify_recipient_scoping_behavior.py` that mocks SMTP delivery and validates the scoped email dispatch:
- **Global Check Test**: Splits results and generates custom emails only to respective recipients.
- **Scoped Check Test**: Generates and sends exactly one email only to that organization's recipients.

### 2. Automated Scheduler & Config Verification Suite
We ran `verify_scheduler_and_config.py` validating the scheduler trigger logic:
- **Test 1**: Verifies default scheduler settings are populated in `load_config()`.
- **Test 2**: Confirms daily scheduler triggers `run_monitor()` on time match and prevents multiple runs in a single day.
- **Test 3**: Confirms weekly schedule triggers only when the weekday matches, and skips when there is a mismatch.

```text
PASSED: background_scheduler triggers run_monitor correctly on matched time and only once per day.
PASSED: background_scheduler triggers correctly when weekly day matches.
PASSED: background_scheduler respects weekly day filter mismatch.
PASSED: load_config includes correct scheduler defaults.

Ran 4 tests in 0.007s
OK
```

---

## 📋 Running the Server
The updated Web UI is fully active and ready to run.
1. **Launch Command**:
   ```powershell
   python ssl_monitor.py --web --port 8000
   ```
2. **Access URL**: Open your browser and navigate to `http://localhost:8000`.
