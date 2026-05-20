# SSL Expiry Monitor - Scheduler & Settings Guide

This document provides a detailed breakdown of the **Scheduler & Settings** management configuration in the SSL Expiry Monitor. All configuration options are persisted dynamically in the [config.json](file:///e:/Tagid/ssl-expiry-checker/config.json) database and managed by the REST API within [ssl_monitor.py](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py).

---

## 📅 Background Cron Scheduler Settings

The background scheduler is a multi-threaded daemon loop implemented in the [background_scheduler](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py#L1034-L1087) function. It runs automatically in a separate background thread when the dashboard server is started.

### 1. Scheduler Enable/Disable (`cron_enabled`)
* **Type**: Boolean (`true` / `false`)
* **UI Label**: "Enable Background Cron Scheduler"
* **Description**: Toggles the automated check scheduler thread on or off.
* **Under the Hood**:
  * **When `true`**: The background scheduler thread actively checks the time every 30 seconds and compares it with your schedule settings.
  * **When `false`**: The scheduler thread goes idle, and no automated SSL checks are executed. SSL scans will only run when manually triggered via the Admin UI, curl script calls, or direct CLI execution.

### 2. Schedule Frequency (`cron_schedule`)
* **Type**: String (`"daily"` / `"weekly"` / `"monthly"`)
* **UI Label**: "Schedule Frequency"
* **Description**: Controls the calendar interval patterns for automated execution triggers.
* **Behaviors**:
  * **Daily**: Runs every single day of the week at the selected time.
  * **Weekly**: Restricts check triggers to a specific day of the week (e.g. every Sunday) at the designated time.
  * **Monthly**: Restricts triggers to a specific day of the month (e.g. the 1st of every month) at the designated time.

### 3. Execution Time (`cron_time`)
* **Type**: String (Format: `HH:MM`, 24-hour time, e.g. `"09:00"`, `"23:30"`)
* **UI Label**: "Scheduled Execution Time"
* **Description**: Specifies the exact clock time when the checker starts validation.
* **Timezone Behavior**: Trigger times are evaluated against **Indian Standard Time (IST)** (`Asia/Kolkata` timezone). Even if the monitor runs on a server set to UTC (e.g. AWS/VPS), the scheduler translates your setting to run at the precise local Indian clock time you requested.

### 4. Scheduled Weekly Day (`cron_weekly_day`)
* **Type**: String (`"Monday"`, `"Tuesday"`, etc.)
* **UI Label**: "Day of Week"
* **Description**: Visible and active only when the schedule frequency is set to **Weekly**.
* **Behavior**: The scheduler verifies the day name on the system clock. If it matches this value (e.g. `"Sunday"`), it runs the monitor. Otherwise, it skips.

### 5. Scheduled Monthly Day (`cron_monthly_day`)
* **Type**: Integer (Range: `1` to `31`)
* **UI Label**: "Day of Month"
* **Description**: Visible and active only when the schedule frequency is set to **Monthly**.
* **Behavior**: Runs the monitor on the matching calendar day number (e.g. `1` for the first day of the month).
* *Note: If a month is shorter than the configured day (e.g., setting day 31 for February), the scheduler skips execution. It is recommended to use days `1` through `28` for guaranteed monthly runs.*

---

## 🔔 Alert Threshold Settings

Alert thresholds classify certificate health states and control when email warnings are dispatched. These values are used inside [check_domain](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py#L665-L748) and [send_email_alert](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py#L749-L885).

### 1. Warning Threshold (`warning_days`)
* **Type**: Integer (Default: `30` days)
* **UI Label**: "Warning Status Threshold (Days)"
* **Description**: The window when a certificate first flags warning signs.
* **Result**: When days remaining fall below this value, the domain gets a yellow status badge on the dashboard indicating it is expiring soon.

### 2. High Priority Threshold (`high_priority_days`)
* **Type**: Integer (Default: `14` days)
* **UI Label**: "High Status Threshold (Days)"
* **Description**: A secondary escalation priority level.
* **Result**: When days remaining fall below this value, the status turns orange to warn admins that renewal is becoming urgent.

### 3. Critical Threshold (`critical_days`)
* **Type**: Integer (Default: `7` days)
* **UI Label**: "Critical Status Threshold (Days)"
* **Description**: The highest severity alert category.
* **Result**: When days remaining fall below this value, a critical red alarm status is shown, indicating immediate attention is required.
* **Validation Constraint**: The dashboard enforces a logical restriction that `Critical <= High Priority <= Warning` and all values must be greater than zero.

### 4. Send Daily Summary (`send_daily_summary`)
* **Type**: Boolean (`true` / `false`)
* **UI Label**: "Always Send Summary Emails (Daily Summary)"
* **Description**: Determines whether email notifications are sent when all certificates are healthy.
* **Behaviors**:
  * **Enabled (`true`)**: The scheduler will send a daily health status report email containing all checked domains, even if 100% of domains are fully secure and healthy.
  * **Disabled (`false`)**: Email alerts are silent if everything is healthy. An email report will **only** be triggered if at least one domain fails, has expired, or falls below the configured warning thresholds.

---

## ⚙️ Performance & Connection Tuning

These settings adjust execution performance and network socket behavior. They prevent script execution timeouts and control resource utilization on the host system.

### 1. Parallel workers (`max_workers`)
* **Type**: Integer (Default: `20` concurrent threads)
* **UI Label**: "Parallel Network Workers"
* **Description**: Dictates the concurrency level for parallel domain scans.
* **Under the Hood**: Controls the size of the `ThreadPoolExecutor` pool. Higher values check hundreds of domains in parallel, saving time. Lower values reduce outbound port usage and lower the network load.

### 2. Connection Timeout (`timeout`)
* **Type**: Integer (Default: `10` seconds)
* **UI Label**: "Socket Timeout (Seconds)"
* **Description**: The maximum time allowed for a secure SSL socket handshake connection.
* **Result**: If a domain server does not reply or perform a handshake within this duration, the check fails with a `"Connection timed out"` remark.

### 3. Max Connection Retries (`max_retries`)
* **Type**: Integer (Default: `3` retries)
* **UI Label**: "Max Retries per Domain"
* **Description**: How many times the system will retry establishing a socket connection if a check fails.
* **Result**: Prevents false alert notifications triggered by temporary network drops. The system must fail all retry attempts consecutively to flag a domain check as `Failed`.

### 4. Connection Retry Delay (`retry_delay`)
* **Type**: Integer (Default: `5` seconds)
* **UI Label**: "Retry Delay (Seconds)"
* **Description**: The sleep delay between consecutive domain connection retries.
* **Result**: If attempt 1 fails, the thread waits for this duration before firing attempt 2, allowing transient routing issues to clear.

---

## 💾 Storage & REST Endpoints
* **Database File**: [config.json](file:///e:/Tagid/ssl-expiry-checker/config.json)
* **Endpoint to Read Config**: `GET /api/config`
* **Endpoint to Write Config**: `POST /api/config` (Authentications apply, payload validated before write).
