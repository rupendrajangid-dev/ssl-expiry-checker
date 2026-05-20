#!/usr/bin/env python3
"""
SSL Certificate Expiry Monitor & Admin Dashboard
A production-grade, single-file monitoring script that runs secure HTTPS SSL certificate
checks in parallel, classifies warning/critical/expired metrics, sends professional
HTML reports via SMTP, and records execution activities to rotating logs.
Features a built-in zero-dependency responsive glassmorphic Web UI Admin Dashboard.

Author: Senior Python Backend & DevOps Engineer
Date: May 2026
"""

import os
import sys
import ssl
import json
import time
import socket
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta
import concurrent.futures
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Any, Tuple, Optional
import http.server
import urllib.parse
import threading

# Load env variables if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

# Constants
DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_DOMAINS_PATH = "domains.json"
DEFAULT_RESULTS_PATH = "last_results.json"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "ssl_monitor.log")
LOCK_FILE = "ssl_monitor.lock"

# Timezone
IST = timezone(timedelta(hours=5, minutes=30))

# Setup graceful shutdown flag
SHUTTING_DOWN = False

# Global Session Authentication cache for Web Admin UI
ACTIVE_SESSIONS: Dict[str, float] = {}  # token -> login_timestamp
SESSION_LOCK = threading.Lock()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin123")


def parse_cookies(cookie_header: str) -> Dict[str, str]:
    """
    Parses a standard Cookie HTTP header string into a key-value dictionary.
    """
    cookies = {}
    if not cookie_header:
        return cookies
    try:
        # Split individual cookies on semicolon
        parts = cookie_header.split(";")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
    except Exception as e:
        logger.error(f"Error parsing cookies: {e}")
    return cookies


def is_session_valid(token: str) -> bool:
    """
    Verifies if the provided session token is active and has not expired (24 hours).
    """
    if not token:
        return False
    
    current_time = time.time()
    max_age_seconds = 86400  # 24 hours
    
    with SESSION_LOCK:
        if token in ACTIVE_SESSIONS:
            login_time = ACTIVE_SESSIONS[token]
            if current_time - login_time < max_age_seconds:
                return True
            else:
                # Session expired, purge it
                del ACTIVE_SESSIONS[token]
                logger.info("Session expired and purged from memory cache.")
    return False



def setup_logging() -> logging.Logger:
    """
    Initializes rotating file and console logging configurations.
    """
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("SSL_Monitor")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if script is re-imported
    if logger.handlers:
        return logger

    # Log formatters
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_formatter = logging.Formatter(
        "[%(levelname)s] %(message)s"
    )

    # Rotating File Handler (10MB max size, 5 backups)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    # Console Handler for clean interactive/docker logs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()


# ==========================================
# Cross-Platform PID Lock Mechanism
# ==========================================

def is_pid_running(pid: int) -> bool:
    """
    Checks if a given process ID is currently running on Windows or POSIX.
    """
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h_process:
            kernel32.CloseHandle(h_process)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def acquire_lock() -> bool:
    """
    Acquires an exclusive execution lock using a local lock file containing the PID.
    Detects and clears stale lock files automatically.
    """
    try:
        # Open with exclusive creation flag
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return True
    except FileExistsError:
        # Lock file exists, read the PID and check if it is active
        try:
            with open(LOCK_FILE, "r") as f:
                content = f.read().strip()
                if not content:
                    # Empty lock file, assume stale
                    os.remove(LOCK_FILE)
                    return acquire_lock()
                pid = int(content)
            
            if not is_pid_running(pid):
                logger.info(f"Detected stale lock file with inactive PID {pid}. Cleaning up lock.")
                try:
                    os.remove(LOCK_FILE)
                except OSError:
                    pass
                return acquire_lock()
        except Exception as e:
            # If we can't read or handle the lock file, assume it's corrupt/stale
            logger.warning(f"Error checking existing lock file: {e}. Re-creating lock.")
            try:
                os.remove(LOCK_FILE)
            except OSError:
                pass
            return acquire_lock()
        return False


def release_lock() -> None:
    """
    Releases the exclusive execution lock file.
    """
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except Exception as e:
        logger.warning(f"Failed to release lock file: {e}")


# ==========================================
# Core CRUD Operations
# ==========================================

def migrate_and_load_registry(path: str = DEFAULT_DOMAINS_PATH) -> Tuple[List[str], Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Ensures domains.json has both a flat list of 'domains', an 'orgs' mapping, and 'org_recipients'.
    Migrates legacy structures automatically, ensuring robust self-healing and synchronization.
    Returns: (domains_list, orgs_dict, org_recipients_dict)
    """
    default_org = "Tagid"
    if not os.path.exists(path):
        empty_data = {
            "domains": [],
            "orgs": {default_org: []},
            "org_recipients": {}
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(empty_data, f, indent=2)
            return [], {default_org: []}, {}
        except Exception as e:
            logger.error(f"Failed to create domains registry: {e}")
            return [], {default_org: []}, {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read domains file: {e}")
        return [], {default_org: []}, {}

    if not isinstance(data, dict):
        data = {}

    domains = data.get("domains", [])
    if not isinstance(domains, list):
        domains = []

    orgs = data.get("orgs", {})
    if not isinstance(orgs, dict):
        orgs = {}

    # Migrate legacy flat domains list to Tagid organization if 'orgs' is completely empty
    if not orgs:
        orgs = {default_org: list(domains)}
        data["orgs"] = orgs
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save migrated domains: {e}")

    # Sanitize and synchronize organizations mappings
    all_org_domains = set()
    for org_name, org_domains in list(orgs.items()):
        if not isinstance(org_domains, list):
            orgs[org_name] = []
            org_domains = []
        sanitized_org_domains = []
        for d in org_domains:
            if isinstance(d, str):
                clean = d.strip().lower()
                if clean:
                    if clean.startswith("https://"):
                        clean = clean[8:]
                    elif clean.startswith("http://"):
                        clean = clean[7:]
                    clean = clean.split("/")[0].split(":")[0]
                    if clean not in sanitized_org_domains:
                        sanitized_org_domains.append(clean)
                        all_org_domains.add(clean)
        orgs[org_name] = sanitized_org_domains

    # Sanitize global domains list
    sanitized_global = []
    for d in domains:
        if isinstance(d, str):
            clean = d.strip().lower()
            if clean:
                if clean.startswith("https://"):
                    clean = clean[8:]
                elif clean.startswith("http://"):
                    clean = clean[7:]
                clean = clean.split("/")[0].split(":")[0]
                if clean not in sanitized_global:
                    sanitized_global.append(clean)
    
    # Resolve orphans: global domains that are not associated with any organization
    orphan_domains = []
    for gd in sanitized_global:
        if gd not in all_org_domains:
            orphan_domains.append(gd)

    if orphan_domains:
        if default_org not in orgs:
            orgs[default_org] = []
        for od in orphan_domains:
            if od not in orgs[default_org]:
                orgs[default_org].append(od)
            all_org_domains.add(od)

    # Final synchronized domains sorted globally
    final_domains = sorted(list(all_org_domains))

    # Load org_recipients (self-healing: default to empty dict if missing)
    org_recipients = data.get("org_recipients", {})
    if not isinstance(org_recipients, dict):
        org_recipients = {}

    # Write back alignment updates if there is a mismatch
    if final_domains != data.get("domains") or orgs != data.get("orgs"):
        data["domains"] = final_domains
        data["orgs"] = orgs
        data["org_recipients"] = org_recipients
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save synchronized domains registry: {e}")

    return final_domains, orgs, org_recipients


def add_domain_programmatic(domain: str, org_name: str = "Tagid", path: str = DEFAULT_DOMAINS_PATH) -> Tuple[bool, str]:
    """
    CRUD - Create: Programmatic helper to sanitize and add a domain under a target organization.
    """
    if not isinstance(domain, str):
        return False, "Domain must be a string."
    clean = domain.strip().lower()
    if not clean:
        return False, "Domain cannot be empty."
    if clean.startswith("https://"):
        clean = clean[8:]
    elif clean.startswith("http://"):
        clean = clean[7:]
    
    clean = clean.split("/")[0].split(":")[0]
    if not clean:
        return False, "Invalid domain format."

    if not isinstance(org_name, str) or not org_name.strip():
        org_name = "Tagid"
    org_name = org_name.strip()

    domains, orgs, _ = migrate_and_load_registry(path)

    # Check for domain registration globally
    for o_name, o_domains in orgs.items():
        if clean in o_domains:
            return False, f"Domain '{clean}' is already registered under organization '{o_name}'."

    if org_name not in orgs:
        orgs[org_name] = []

    orgs[org_name].append(clean)
    if clean not in domains:
        domains.append(clean)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domains": sorted(domains), "orgs": orgs}, f, indent=2)
        return True, f"Successfully registered target '{clean}' under organization '{org_name}'."
    except Exception as e:
        return False, f"Failed to save changes to domains registry: {e}"


def remove_domain_programmatic(domain: str, path: str = DEFAULT_DOMAINS_PATH) -> Tuple[bool, str]:
    """
    CRUD - Delete: Programmatic helper to remove a domain globally from all organizations and history.
    """
    if not isinstance(domain, str):
        return False, "Domain must be a string."
    clean = domain.strip().lower()
    if not clean:
        return False, "Domain cannot be empty."
    if clean.startswith("https://"):
        clean = clean[8:]
    elif clean.startswith("http://"):
        clean = clean[7:]
    clean = clean.split("/")[0].split(":")[0]

    domains, orgs, _ = migrate_and_load_registry(path)

    if clean not in domains:
        return False, f"Domain '{clean}' is not registered."

    domains.remove(clean)
    for o_name in orgs:
        if clean in orgs[o_name]:
            orgs[o_name].remove(clean)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domains": sorted(domains), "orgs": orgs}, f, indent=2)
        
        try:
            if os.path.exists(DEFAULT_RESULTS_PATH):
                with open(DEFAULT_RESULTS_PATH, "r", encoding="utf-8") as rf:
                    res_data = json.load(rf)
                if clean in res_data:
                    del res_data[clean]
                    with open(DEFAULT_RESULTS_PATH, "w", encoding="utf-8") as wf:
                        json.dump(res_data, wf, indent=2)
        except Exception as err:
            logger.warning(f"Failed to clean deleted domain '{clean}' from last results: {err}")

        return True, f"Successfully deleted target '{clean}'."
    except Exception as e:
        return False, f"Failed to save changes to domains registry: {e}"


def add_organization_programmatic(org_name: str, path: str = DEFAULT_DOMAINS_PATH) -> Tuple[bool, str]:
    """
    CRUD - Create Org: Programmatic helper to add a new organization.
    """
    if not isinstance(org_name, str):
        return False, "Organization name must be a string."
    org_clean = org_name.strip()
    if not org_clean:
        return False, "Organization name cannot be empty."
    if org_clean.lower() == "all":
        return False, "Organization name 'All' is reserved and cannot be created."

    domains, orgs, _ = migrate_and_load_registry(path)

    for existing_org in orgs:
        if existing_org.lower() == org_clean.lower():
            return False, f"Organization '{existing_org}' already exists."

    orgs[org_clean] = []

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domains": sorted(domains), "orgs": orgs}, f, indent=2)
        return True, f"Successfully created organization '{org_clean}'."
    except Exception as e:
        return False, f"Failed to save organization to registry: {e}"


def remove_organization_programmatic(org_name: str, path: str = DEFAULT_DOMAINS_PATH) -> Tuple[bool, str]:
    """
    CRUD - Delete Org: Programmatic helper to delete an organization and all its domains.
    """
    if not isinstance(org_name, str):
        return False, "Organization name must be a string."
    org_clean = org_name.strip()
    if not org_clean:
        return False, "Organization name cannot be empty."
    if org_clean == "Tagid":
        return False, "The default organization 'Tagid' cannot be deleted."

    domains, orgs, _ = migrate_and_load_registry(path)

    found_org = None
    for existing_org in orgs:
        if existing_org.lower() == org_clean.lower():
            found_org = existing_org
            break

    if not found_org:
        return False, f"Organization '{org_clean}' not found."

    org_domains = orgs[found_org]
    del orgs[found_org]

    # Find domains still present in other organizations
    other_org_domains = set()
    for o_name, o_domains in orgs.items():
        for d in o_domains:
            other_org_domains.add(d)

    # Remove domains uniquely owned by deleted organization globally
    deleted_domains = []
    for d in org_domains:
        if d not in other_org_domains:
            if d in domains:
                domains.remove(d)
            deleted_domains.append(d)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domains": sorted(domains), "orgs": orgs}, f, indent=2)
        
        if deleted_domains and os.path.exists(DEFAULT_RESULTS_PATH):
            try:
                with open(DEFAULT_RESULTS_PATH, "r", encoding="utf-8") as rf:
                    res_data = json.load(rf)
                
                updated_results = False
                for d in deleted_domains:
                    if d in res_data:
                        del res_data[d]
                        updated_results = True
                
                if updated_results:
                    with open(DEFAULT_RESULTS_PATH, "w", encoding="utf-8") as wf:
                        json.dump(res_data, wf, indent=2)
            except Exception as err:
                logger.warning(f"Failed to clean deleted organization domains from last results: {err}")

        return True, f"Successfully deleted organization '{found_org}' and its associated domains."
    except Exception as e:
        return False, f"Failed to save changes to domains registry: {e}"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Loads runtime configurations from JSON. Returns validated defaults on failure.
    """
    default_config = {
        "warning_days": 30,
        "high_priority_days": 14,
        "critical_days": 7,
        "timeout": 10,
        "max_retries": 3,
        "retry_delay": 5,
        "max_workers": 20,
        "send_daily_summary": True,
        "cron_enabled": False,
        "cron_schedule": "daily",
        "cron_time": "09:00",
        "cron_weekly_day": "Monday",
        "cron_monthly_day": 1
    }

    if not os.path.exists(path):
        logger.warning(f"Config file not found at {path}. Using default configuration parameters.")
        return default_config

    try:
        with open(path, "r", encoding="utf-8") as f:
            user_config = json.load(f)
        
        # Verify and merge default structure
        merged = {**default_config, **user_config}
        
        # Simple logical boundaries validation
        if not (0 < merged["critical_days"] <= merged["high_priority_days"] <= merged["warning_days"]):
            raise ValueError("Configuration logic mismatch: critical_days <= high_priority_days <= warning_days constraint violated.")
        
        return merged
    except Exception as e:
        logger.error(f"Failed to parse config file: {e}. Falling back to default configuration.")
        return default_config


def load_domains(path: str = DEFAULT_DOMAINS_PATH) -> List[str]:
    """
    Reads the list of domains to monitor. Sanitizes input domains.
    Maintains backward compatibility by utilizing migrate_and_load_registry.
    """
    domains, _, _ = migrate_and_load_registry(path)
    return domains


def save_last_results(results: List[Dict[str, Any]], path: str = DEFAULT_RESULTS_PATH) -> None:
    """
    Saves the last SSL check results to a local JSON file.
    Merges with existing results to ensure all histories are preserved.
    """
    try:
        data = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        
        for r in results:
            domain = r["domain"]
            data[domain] = {
                "status": r["status"],
                "expiry_date": r["expiry_date"],
                "days_remaining": r["days_remaining"],
                "severity": r["severity"],
                "remarks": r["remarks"],
                "checked_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
            }
            
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save last check results: {e}")


def load_last_results(path: str = DEFAULT_RESULTS_PATH) -> Dict[str, Any]:
    """
    Loads the last check results from JSON. Returns a dictionary mapping domains to their check metrics.
    """
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load last check results: {e}")
        return {}


def parse_expiry_date(date_str: str) -> datetime:
    """
    Robust parsing for ssl peer cert 'notAfter' strings. Normalizes spaces and timezones.
    """
    normalized = " ".join(date_str.split())
    # Format typically: 'May 20 17:00:00 2026 GMT'
    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        # Fallback if timezone code causes unexpected strptime failures
        parts = normalized.split()
        if len(parts) >= 4:
            rebuilt = " ".join(parts[:4])  # 'May 20 17:00:00 2026'
            try:
                return datetime.strptime(rebuilt, "%b %d %H:%M:%S %Y")
            except ValueError:
                pass
        raise


def get_ssl_expiry_days(domain: str, timeout: int) -> Tuple[datetime, int]:
    """
    Performs direct socket connection and secure SSL handshake to parse certificate expiry.
    """
    # Create secure SSL context resolving host and checking certificate trust chains
    context = ssl.create_default_context()
    
    # Establish connection under custom socket rules
    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
            cert = ssl_sock.getpeercert()
            if not cert:
                raise ValueError("No peer certificate returned from host.")
            
            not_after_str = cert.get("notAfter")
            if not not_after_str:
                raise ValueError("Certificate is missing the 'notAfter' expiry field.")
            
            expiry_date = parse_expiry_date(not_after_str)
            
            # Compute difference relative to timezone-naive UTC
            now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
            remaining_days = (expiry_date - now_utc).days
            
            return expiry_date, remaining_days


def check_domain(domain: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestrates target checks including custom retries, metrics extraction, and severity tagging.
    """
    global SHUTTING_DOWN
    if SHUTTING_DOWN:
        return {
            "domain": domain,
            "status": "Failed",
            "expiry_date": "N/A",
            "days_remaining": -1,
            "severity": "Failed",
            "remarks": "Monitoring job interrupted/shutdown."
        }

    timeout = config["timeout"]
    max_retries = config["max_retries"]
    retry_delay = config["retry_delay"]
    
    last_error = ""
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Checking SSL for '{domain}' (Attempt {attempt}/{max_retries})...")
            expiry_date, days_remaining = get_ssl_expiry_days(domain, timeout)
            
            # Determine Severity
            if days_remaining <= 0:
                severity = "Expired"
                status = "Expired"
                remarks = "Certificate has expired!"
            elif days_remaining < config["critical_days"]:
                severity = "Critical"
                status = "Warning"
                remarks = f"Expires in less than {config['critical_days']} days."
            elif days_remaining < config["high_priority_days"]:
                severity = "High"
                status = "Warning"
                remarks = f"Expires in less than {config['high_priority_days']} days."
            elif days_remaining <= config["warning_days"]:
                severity = "Warning"
                status = "Warning"
                remarks = f"Expires in less than {config['warning_days']} days."
            else:
                severity = "Healthy"
                status = "Healthy"
                remarks = "Certificate is valid and secure."

            logger.info(f"Success: '{domain}' is {severity} ({days_remaining} days remaining).")
            return {
                "domain": domain,
                "status": status,
                "expiry_date": expiry_date.replace(tzinfo=timezone.utc).astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
                "days_remaining": days_remaining,
                "severity": severity,
                "remarks": remarks
            }

        except socket.timeout:
            last_error = "Connection timed out."
            logger.warning(f"Attempt {attempt} failed for '{domain}': Connection timed out.")
        except ssl.SSLError as ssl_err:
            last_error = f"SSL Handshake failed: {ssl_err.reason if hasattr(ssl_err, 'reason') else ssl_err}"
            logger.warning(f"Attempt {attempt} failed for '{domain}': {last_error}")
        except socket.gaierror:
            last_error = "DNS resolution failed/Unreachable domain."
            logger.warning(f"Attempt {attempt} failed for '{domain}': Host address could not be resolved.")
        except Exception as e:
            last_error = str(e)
            logger.warning(f"Attempt {attempt} failed for '{domain}': {last_error}")

        if attempt < max_retries and not SHUTTING_DOWN:
            time.sleep(retry_delay)

    logger.error(f"Failure: '{domain}' failed all {max_retries} attempts. Last Error: {last_error}")
    return {
        "domain": domain,
        "status": "Failed",
        "expiry_date": "N/A",
        "days_remaining": -1,
        "severity": "Failed",
        "remarks": f"All connection attempts failed: {last_error}"
    }


def send_email_alert(results: List[Dict[str, Any]], config: Dict[str, Any], org_name: Optional[str] = None) -> bool:
    """
    Builds the styled HTML report and sends it over SMTP to custom recipient lists.
    Supports per-organization recipient routing when org_name is provided.
    Guarantees zero duplicate emails via strict case-insensitive recipient deduplication.
    """
    # Load orgs mapping first to check if we need to split global reports
    _, orgs, org_recipients = migrate_and_load_registry()

    if not org_name or org_name == "all":
        # Global scan: split results by organization to send scoped reports to respective recipients only.
        # This ensures each organization's recipients only receive alerts for their own domains.
        logger.info("Global email dispatch: splitting report by organization to ensure recipient scoping.")
        success = True
        for org_key, org_domains in orgs.items():
            # Filter results for this organization
            org_results = [r for r in results if r["domain"] in org_domains]
            if org_results:
                # Recursively call send_email_alert for this specific organization
                ret = send_email_alert(org_results, config, org_name=org_key)
                if not ret:
                    success = False
        return success

    # Environment credentials fetch
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port_raw = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USERNAME")
    smtp_pass = os.environ.get("SMTP_PASSWORD")
    if smtp_pass and smtp_pass.startswith("enc:"):
        decryption_key = os.environ.get("SMTP_DECRYPTION_KEY")
        if not decryption_key:
            logger.error("SMTP_PASSWORD is encrypted but SMTP_DECRYPTION_KEY environment variable is not set. Email notification skipped.")
            return False
        try:
            from cryptography.fernet import Fernet
            f = Fernet(decryption_key.encode())
            smtp_pass = f.decrypt(smtp_pass[4:].encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt SMTP_PASSWORD: {e}. Email notification skipped.")
            return False

    sender = os.environ.get("SMTP_SENDER_EMAIL")
    sender_name = os.environ.get("SMTP_SENDER_NAME")
    receivers_raw = os.environ.get("SMTP_RECEIVER_EMAILS", "")

    # Simple validations for required SMTP settings
    if not all([smtp_host, smtp_port_raw, smtp_user, smtp_pass, sender]):
        logger.error("Missing SMTP configurations in environment variables. Email notification skipped.")
        return False

    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        logger.error(f"Invalid SMTP_PORT: {smtp_port_raw}. Port must be an integer.")
        return False

    # Build the recipient list based on org_name scoping
    seen = set()
    receivers = []

    def _add_emails(email_list):
        """Helper to deduplicate and add emails."""
        for email in email_list:
            clean_email = email.strip()
            if not clean_email:
                continue
            normalized = clean_email.lower()
            if normalized not in seen:
                seen.add(normalized)
                receivers.append(clean_email)

    # Org-scoped: use only this org's recipients, fall back to .env if empty
    org_emails = org_recipients.get(org_name, [])
    if org_emails:
        _add_emails(org_emails)
        logger.info(f"Using {len(receivers)} org-specific recipient(s) for '{org_name}'.")
    else:
        # Fallback to .env recipients
        _add_emails(receivers_raw.split(","))
        logger.info(f"No org-specific recipients for '{org_name}'. Falling back to .env recipients ({len(receivers)}).")

    if not receivers:
        logger.error("No valid receiver email addresses resolved. Email notification skipped.")
        return False

    # Counters logic
    total = len(results)
    healthy = sum(1 for r in results if r["severity"] == "Healthy")
    warning = sum(1 for r in results if r["severity"] == "Warning")
    high = sum(1 for r in results if r["severity"] == "High")
    critical = sum(1 for r in results if r["severity"] == "Critical")
    expired = sum(1 for r in results if r["severity"] == "Expired")
    failed = sum(1 for r in results if r["severity"] == "Failed")

    any_expired = expired > 0
    any_failed = failed > 0
    any_expiring_soon = (warning + high + critical) > 0

    # Determine notification trigger criteria
    should_send = any_expired or any_failed or any_expiring_soon or config.get("send_daily_summary", True)
    if not should_send:
        logger.info(f"Alert criteria not met for '{org_name}' (all domains healthy and send_daily_summary disabled). Email not sent.")
        return True

    # Subject line logic with organization name
    org_label = f" - {org_name}" if org_name else ""
    if any_expired:
        subject = f"[SSL Monitor{org_label}] SSL Certificate Expired! (Expired: {expired})"
    elif critical > 0 or high > 0:
        alert_count = critical + high
        subject = f"[SSL Monitor{org_label}] Critical Alert: {alert_count} Domains Expiring Soon"
    elif any_failed:
        subject = f"[SSL Monitor{org_label}] Warning: {failed} Domains SSL Check Failed"
    else:
        subject = f"[SSL Monitor{org_label}] Daily SSL Health Report"

    # HTML Styling and badge generation
    severity_colors = {
        "Healthy": {"bg": "#e6f4ea", "text": "#137333", "label": "Healthy"},
        "Warning": {"bg": "#fef7e0", "text": "#b06000", "label": "Warning"},
        "High": {"bg": "#ffe8d6", "text": "#d97706", "label": "High Warning"},
        "Critical": {"bg": "#fce8e6", "text": "#c5221f", "label": "Critical"},
        "Expired": {"bg": "#c5221f", "text": "#ffffff", "label": "EXPIRED"},
        "Failed": {"bg": "#f1f3f4", "text": "#5f6368", "label": "Failed"}
    }

    # Generate HTML Table lines
    table_rows_html = ""
    for r in results:
        sev = r["severity"]
        color = severity_colors.get(sev, {"bg": "#ffffff", "text": "#000000", "label": sev})
        
        days_disp = r["days_remaining"] if r["days_remaining"] >= 0 else "N/A"
        
        table_rows_html += f"""
        <tr>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; font-weight: bold; color: #374151;">{r['domain']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; color: #555555;">{r['status']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; color: #555555; font-family: monospace;">{r['expiry_date']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; font-weight: bold; color: #222222;">{days_disp}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; text-align: center;">
                <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; background-color: {color['bg']}; color: {color['text']}; text-transform: uppercase;">
                    {color['label']}
                </span>
            </td>
            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #6b7280; font-style: italic;">{r['remarks']}</td>
        </tr>
        """

    # Premium CSS/HTML Structure
    email_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{subject}</title>
    </head>
    <body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f3f4f6; padding: 20px 0;">
            <tr>
                <td align="center">
                    <table width="90%" max-width="800px" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); max-width: 800px;">
                        
                        <!-- Premium Header Section -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #1f2937 0%, #111827 100%); padding: 30px 40px; text-align: left; border-bottom: 3px solid #ef4444;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">SSL Certificate Expiry Monitor{org_label}</h1>
                                <p style="margin: 8px 0 0 0; color: #9ca3af; font-size: 14px;">Automated production environment health checker</p>
                            </td>
                        </tr>

                        <!-- Content Core -->
                        <tr>
                            <td style="padding: 30px 40px;">
                                <p style="margin-top: 0; font-size: 16px; line-height: 1.6; color: #374151;">
                                    Hello Admin,
                                </p>
                                <p style="font-size: 15px; line-height: 1.6; color: #4b5563; margin-bottom: 25px;">
                                    The automated SSL validation pipeline has completed scanning your environment targets. Here is the compiled health status summary:
                                </p>

                                <!-- Grid Summary Cards -->
                                <table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin-bottom: 30px;">
                                    <tr>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #f3f4f6; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #9ca3af;">
                                                <div style="font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase;">Total</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #111827; margin-top: 4px;">{total}</div>
                                            </div>
                                        </td>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #e6f4ea; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #137333;">
                                                <div style="font-size: 12px; font-weight: 600; color: #137333; text-transform: uppercase;">Healthy</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #137333; margin-top: 4px;">{healthy}</div>
                                            </div>
                                        </td>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #fef7e0; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #b06000;">
                                                <div style="font-size: 12px; font-weight: 600; color: #b06000; text-transform: uppercase;">Warning</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #b06000; margin-top: 4px;">{warning + high}</div>
                                            </div>
                                        </td>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #fce8e6; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #c5221f;">
                                                <div style="font-size: 12px; font-weight: 600; color: #c5221f; text-transform: uppercase;">Critical</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #c5221f; margin-top: 4px;">{critical}</div>
                                            </div>
                                        </td>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #c5221f; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #7f1d1d;">
                                                <div style="font-size: 12px; font-weight: 600; color: #ffffff; text-transform: uppercase;">Expired</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #ffffff; margin-top: 4px;">{expired}</div>
                                            </div>
                                        </td>
                                        <td style="padding: 5px; width: 16%;">
                                            <div style="background-color: #f1f3f4; border-radius: 8px; padding: 12px; text-align: center; border-left: 4px solid #5f6368;">
                                                <div style="font-size: 12px; font-weight: 600; color: #5f6368; text-transform: uppercase;">Failed</div>
                                                <div style="font-size: 22px; font-weight: 700; color: #5f6368; margin-top: 4px;">{failed}</div>
                                            </div>
                                        </td>
                                    </tr>
                                </table>

                                <!-- Detailed Domains Report Table -->
                                <h3 style="font-size: 16px; font-weight: 600; margin: 0 0 12px 0; color: #111827;">Detailed Status Breakdown</h3>
                                <div style="overflow-x: auto; border: 1px solid #e5e7eb; border-radius: 8px;">
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0" style="border-collapse: collapse; min-width: 600px;">
                                        <thead>
                                            <tr style="background-color: #f9fafb;">
                                                <th align="left" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; width: 22%;">Domain</th>
                                                <th align="left" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; width: 12%;">Status</th>
                                                <th align="left" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; width: 25%;">Expiry Date</th>
                                                <th align="left" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; width: 13%;">Remaining</th>
                                                <th align="center" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; text-align: center; width: 13%;">Severity</th>
                                                <th align="left" style="padding: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #4b5563; border-bottom: 2px solid #e5e7eb; width: 15%;">Remarks</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {table_rows_html}
                                        </tbody>
                                    </table>
                                </div>
                            </td>
                        </tr>

                        <!-- Premium Footer block -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 24px 40px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                                    This is an automated system email generated by SSL Monitor script. Please do not reply.
                                </p>
                                <p style="margin: 4px 0 0 0; font-size: 12px; color: #9ca3af;">
                                    Report executed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                                </p>
                            </td>
                        </tr>

                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """

    # SMTP dispatcher
    try:
        logger.info(f"Connecting to SMTP server {smtp_host}:{smtp_port}...")
        # Check standard SSL port 465, else default to TLS 587 (or general connection with starttls)
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()

        server.login(smtp_user, smtp_pass)
        
        # Dispatch unique emails individually to ensure complete security and clean individualized headers
        for receiver in receivers:
            logger.info(f"Sending SMTP email to recipient: {receiver}...")
            msg = MIMEText(email_html, "html", "utf-8")
            msg["Subject"] = subject
            if sender_name:
                from email.utils import formataddr
                msg["From"] = formataddr((sender_name, sender))
            else:
                msg["From"] = sender
            msg["To"] = receiver
            server.sendmail(sender, [receiver], msg.as_string())
            
        server.quit()
        logger.info("Email notification alert dispatched successfully!")
        return True
    except Exception as e:
        logger.error(f"SMTP delivery failed: {e}")
        return False


def background_scheduler() -> None:
    """
    Background daemon thread that periodically checks config.json for Cron settings
    and triggers run_monitor if the schedule criteria match the current system time.
    """
    logger.info("Background Scheduler: Service thread started.")
    last_run_date: Optional[str] = None
    
    while True:
        try:
            # Load current configuration
            config = load_config()
            cron_enabled = config.get("cron_enabled", False)
            
            if not cron_enabled:
                time.sleep(30)
                continue
                
            schedule_type = config.get("cron_schedule", "daily").lower().strip()
            scheduled_time_str = config.get("cron_time", "09:00").strip() # Format: "HH:MM"
            
            now = datetime.now(IST)
            current_time_str = now.strftime("%H:%M")
            
            if current_time_str == scheduled_time_str:
                today_str = now.strftime("%Y-%m-%d")
                
                # Ensure we only run once per day/scheduled event
                if last_run_date != today_str:
                    trigger_check = False
                    
                    if schedule_type == "daily":
                        trigger_check = True
                    elif schedule_type == "weekly":
                        weekly_day = config.get("cron_weekly_day", "Monday").strip().capitalize()
                        if now.strftime("%A") == weekly_day:
                            trigger_check = True
                    elif schedule_type == "monthly":
                        monthly_day = int(config.get("cron_monthly_day", 1))
                        if now.day == monthly_day:
                            trigger_check = True
                            
                    if trigger_check:
                        logger.info(f"Background Scheduler: Triggering automated scan on '{schedule_type}' schedule at {scheduled_time_str}.")
                        # Run the monitor checking flow.
                        run_monitor(should_exit=False, org_name=None)
                        last_run_date = today_str
                        
        except Exception as e:
            logger.error(f"Background Scheduler encountered an error: {e}")
            
        time.sleep(30)


def run_monitor(should_exit: bool = True, org_name: Optional[str] = None) -> bool:
    """
    Core SSL monitoring execution flow. Runs thread pool, logs, and SMTP notifications.
    Returns True if all checks are healthy, False if any critical/expired/failed checks exist.
    """
    global SHUTTING_DOWN
    
    if not acquire_lock():
        logger.warning("Another instance of SSL Expiry Monitor is already running. Skipping execution.")
        if should_exit:
            sys.exit(0)
        return False

    try:
        start_time = time.time()
        org_suffix = f" [Org: {org_name}]" if org_name and org_name != "all" else " [All Organizations]"
        logger.info(f"=== SSL Expiry Monitor execution started{org_suffix} ===")

        # Configuration loading
        config = load_config()
        if org_name and org_name != "all":
            _, orgs, _ = migrate_and_load_registry()
            domains = orgs.get(org_name, [])
            logger.info(f"Target organization filter applied: '{org_name}'. Loaded {len(domains)} domain(s).")
        else:
            domains = load_domains()
            logger.info(f"Loaded all {len(domains)} domain(s) globally.")

        if not domains:
            logger.error("No valid domains to check in domains.json. Exiting program.")
            logger.info("=== SSL Expiry Monitor completed (no execution targets) ===")
            if should_exit:
                sys.exit(0)
            return True

        logger.info(f"Queueing {len(domains)} domains across parallel threads (max_workers={config['max_workers']}).")

        results: List[Dict[str, Any]] = []

        # Parallel Execution Pool
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=config["max_workers"]) as executor:
                # Map domains to checks
                future_to_domain = {executor.submit(check_domain, domain, config): domain for domain in domains}
                
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        res = future.result()
                        results.append(res)
                    except Exception as exc:
                        logger.error(f"Thread execution error for domain '{domain}': {exc}")
                        results.append({
                            "domain": domain,
                            "status": "Failed",
                            "expiry_date": "N/A",
                            "days_remaining": -1,
                            "severity": "Failed",
                            "remarks": f"System execution runtime failure: {exc}"
                        })

        except KeyboardInterrupt:
            logger.warning("Keyboard interrupt received! Initiating shutdown cleanups...")
            SHUTTING_DOWN = True
            logger.info("Execution cancelled by user. Terminating threads gracefully.")
        except Exception as err:
            logger.error(f"System execution failure in thread pool scheduling: {err}")

        # Process and sort results by severity or domain name
        results.sort(key=lambda x: (x["severity"] == "Healthy", x["severity"] == "Failed", x["days_remaining"], x["domain"]))

        # Save last check results to persistent storage
        save_last_results(results)

        # Print summary metrics to console beautifully
        total = len(results)
        healthy = sum(1 for r in results if r["severity"] == "Healthy")
        warning = sum(1 for r in results if r["severity"] == "Warning")
        high = sum(1 for r in results if r["severity"] == "High")
        critical = sum(1 for r in results if r["severity"] == "Critical")
        expired = sum(1 for r in results if r["severity"] == "Expired")
        failed = sum(1 for r in results if r["severity"] == "Failed")

        elapsed_time = time.time() - start_time
        logger.info("--- Execution Summary ---")
        logger.info(f"Total domains checked: {total}")
        logger.info(f"Healthy certificates : {healthy}")
        logger.info(f"Warning certificates : {warning}")
        logger.info(f"High risk warnings    : {high}")
        logger.info(f"Critical certificates: {critical}")
        logger.info(f"Expired certificates : {expired}")
        logger.info(f"Check Failures       : {failed}")
        logger.info(f"Total time elapsed   : {elapsed_time:.2f} seconds")
        logger.info("-------------------------")

        # SMTP execution block
        email_sent = send_email_alert(results, config, org_name)

        logger.info("=== SSL Expiry Monitor execution completed ===")
        
        has_issues = expired > 0 or critical > 0 or failed > 0
        if should_exit:
            sys.exit(1 if has_issues else 0)
        return not has_issues
    finally:
        release_lock()


# ==========================================
# CLI Domain CRUD Operations
# ==========================================

def add_domains_cli(domains_to_add: List[str], path: str = DEFAULT_DOMAINS_PATH) -> None:
    """
    CLI Wrapper: Adds new domains.
    """
    for dom in domains_to_add:
        success, msg = add_domain_programmatic(dom, path)
        if success:
            print(f"[+] {msg}")
        else:
            print(f"[-] {msg}")


def remove_domains_cli(domains_to_remove: List[str], path: str = DEFAULT_DOMAINS_PATH) -> None:
    """
    CLI Wrapper: Removes domains.
    """
    for dom in domains_to_remove:
        success, msg = remove_domain_programmatic(dom, path)
        if success:
            print(f"[x] {msg}")
        else:
            print(f"[-] {msg}")


def list_domains_cli(path: str = DEFAULT_DOMAINS_PATH) -> None:
    """
    CRUD - Read: Outputs configured domains with clean index values.
    """
    if not os.path.exists(path):
        print(f"[-] Error: Domains database file not found at {path}.")
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        existing = data.get("domains", [])
    except Exception as e:
        print(f"[!] Error reading database file: {e}")
        return

    if not existing:
        print("[-] No domains registered for monitoring.")
        return

    print("=== Configured SSL Domains Registry ===")
    for index, domain in enumerate(existing, 1):
        print(f"  {index}. {domain}")
    print(f"=======================================")


# ==========================================
# Built-in Web Server Dashboard & REST APIs
# ==========================================

class WebAdminHandler(http.server.BaseHTTPRequestHandler):
    """
    Native HTTP Request Handler for the zero-dependency Web Dashboard and API endpoints.
    """
    def log_message(self, format, *args):
        # Route standard HTTP server logs to rotating logger files
        logger.info(f"WebUI: {format % args}")

    def is_authenticated(self) -> Tuple[bool, str]:
        """
        Parses incoming Request headers and checks if SessionToken is valid.
        """
        cookie_header = self.headers.get("Cookie", "")
        cookies = parse_cookies(cookie_header)
        token = cookies.get("SessionToken", "")
        if is_session_valid(token):
            return True, token
        return False, ""

    def send_unauthorized_response(self, error_message: str):
        self.send_response(401)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": False, "error": error_message}).encode("utf-8"))


    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        authenticated, _ = self.is_authenticated()
        
        # 1. Main Dashboard Index HTML Page or Login Page
        if parsed_path.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            # Set caching rules to prevent stale rendering
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            if authenticated:
                self.wfile.write(HTML_UI_CONTENT.encode("utf-8"))
            else:
                self.wfile.write(LOGIN_UI_CONTENT.encode("utf-8"))
            
        # 2. REST API: Load Monitored Domain Targets
        elif parsed_path.path == "/api/domains":
            if not authenticated:
                self.send_unauthorized_response("Unauthorized: Active session required.")
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            domains, orgs, org_recipients = migrate_and_load_registry()
            last_results = load_last_results()
            self.wfile.write(json.dumps({
                "domains": domains,
                "orgs": orgs,
                "org_recipients": org_recipients,
                "last_results": last_results
            }).encode("utf-8"))
            
        # REST API: Load Current Configuration Settings
        elif parsed_path.path == "/api/config":
            if not authenticated:
                self.send_unauthorized_response("Unauthorized: Active session required.")
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            config = load_config()
            self.wfile.write(json.dumps(config).encode("utf-8"))
            
        # 3. REST API: Read Rotating Log Details
        elif parsed_path.path == "/api/logs":
            if not authenticated:
                self.send_unauthorized_response("Unauthorized: Active session required.")
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            
            recent_logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        recent_logs = f.readlines()[-100:]  # Fetch last 100 lines
                except Exception as e:
                    recent_logs = [f"[Error reading log file: {e}]"]
            else:
                recent_logs = ["Log file does not exist yet. Run a validation check to start logging!"]
                
            self.wfile.write(json.dumps({"logs": recent_logs}).encode("utf-8"))
            
        # 4. Routing fallbacks
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        # 0. Auth endpoint: Login (Bypass Authentication Check)
        if parsed_path.path == "/api/login":
            try:
                payload = json.loads(post_data)
                password = payload.get("password", "")
                if password == DASHBOARD_PASSWORD:
                    # Generate secure random session token
                    token = os.urandom(24).hex()
                    with SESSION_LOCK:
                        ACTIVE_SESSIONS[token] = time.time()
                    
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.send_header("Set-Cookie", f"SessionToken={token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "message": "Login successful"}).encode("utf-8"))
                    logger.info("Admin login successful. Session token generated.")
                else:
                    self.send_error_response("Incorrect password.")
                    logger.warning("Failed login attempt: Incorrect password submitted.")
            except Exception as e:
                self.send_error_response(f"Payload parse failure: {e}")
            return

        # Enforce Authentication check for all other POST routes
        authenticated, token = self.is_authenticated()
        if not authenticated:
            self.send_unauthorized_response("Unauthorized: Active session required.")
            return

        # 0b. Auth endpoint: Logout
        if parsed_path.path == "/api/logout":
            if token:
                with SESSION_LOCK:
                    if token in ACTIVE_SESSIONS:
                        del ACTIVE_SESSIONS[token]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Set-Cookie", "SessionToken=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Successfully logged out."}).encode("utf-8"))
            logger.info("Admin logout successful. Session token cleared.")
            return

        # 1. REST API: Add Domain Target (Create)
        elif parsed_path.path == "/api/domains":
            try:
                payload = json.loads(post_data)
                domain = payload.get("domain", "")
                org_name = payload.get("org_name", "Tagid")
                if not domain:
                    self.send_error_response("Domain value cannot be empty.")
                    return
                
                success, msg = add_domain_programmatic(domain, org_name)
                if success:
                    self.send_success_response(msg)
                else:
                    self.send_error_response(msg)
            except Exception as e:
                self.send_error_response(f"Payload parse failure: {e}")
                
        # 1b. REST API: Add New Organization (Create Org)
        elif parsed_path.path == "/api/orgs":
            try:
                payload = json.loads(post_data)
                org_name = payload.get("org_name", "")
                if not org_name:
                    self.send_error_response("Organization name cannot be empty.")
                    return
                
                success, msg = add_organization_programmatic(org_name)
                if success:
                    self.send_success_response(msg)
                else:
                    self.send_error_response(msg)
            except Exception as e:
                self.send_error_response(f"Payload parse failure: {e}")

        # 2. REST API: Run Expiry Validation Handshake (Execute)
        elif parsed_path.path == "/api/check":
            # Check if check process is already running via locking before spawning thread
            if os.path.exists(LOCK_FILE):
                # Read lock file and see if process is active
                try:
                    with open(LOCK_FILE, "r") as f:
                        pid = int(f.read().strip())
                    if is_pid_running(pid):
                        self.send_error_response("An active SSL Expiry Scan is currently executing. Try again in a few moments.")
                        return
                except Exception:
                    pass
            
            # Parse target organization name if provided in POST payload
            org_name = None
            if post_data:
                try:
                    payload = json.loads(post_data)
                    org_name = payload.get("org_name")
                except Exception:
                    pass
            
            # Spawn the concurrent thread validator in the background to prevent HTTP server blocks
            threading.Thread(target=run_monitor, args=(False, org_name), daemon=True).start()
            
            if org_name and org_name != "all":
                success_msg = f"SSL handshake verification task dispatched successfully for '{org_name}'! Refresh logs to watch execution thread progress."
            else:
                success_msg = "SSL handshake verification task dispatched successfully for All Organizations! Refresh logs to watch execution thread progress."
            
            self.send_success_response(success_msg)

        # 2b. REST API: Run Expiry Validation for a Single Domain
        elif parsed_path.path == "/api/check-domain":
            try:
                payload = json.loads(post_data)
                domain = payload.get("domain", "").strip()
                if not domain:
                    self.send_error_response("Domain value cannot be empty.")
                    return
                
                # Check if domain is in monitored registry
                domains = load_domains()
                if domain not in domains:
                    self.send_error_response(f"Domain '{domain}' is not in the monitored registry.")
                    return
                
                config = load_config()
                # Run single domain check synchronously
                result = check_domain(domain, config)
                
                # Save results to last_results.json
                save_last_results([result])
                
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "message": f"Successfully rechecked domain '{domain}'.",
                    "result": result
                }).encode("utf-8"))
                
                logger.info(f"Manual single-domain recheck completed for '{domain}'. Result: {result['severity']}")
            except Exception as e:
                self.send_error_response(f"Check failed: {e}")

        # 3. REST API: Add Recipient to Organization
        elif parsed_path.path == "/api/recipients":
            try:
                payload = json.loads(post_data)
                org_name = payload.get("org_name", "")
                email = payload.get("email", "").strip().lower()
                if not org_name or not email:
                    self.send_error_response("Both 'org_name' and 'email' are required.")
                    return
                
                # Load registry
                try:
                    with open(DEFAULT_DOMAINS_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}
                
                org_recipients = data.get("org_recipients", {})
                if not isinstance(org_recipients, dict):
                    org_recipients = {}
                
                if org_name not in org_recipients:
                    org_recipients[org_name] = []
                
                # Check for duplicates (case-insensitive)
                existing_lower = [e.lower() for e in org_recipients[org_name]]
                if email in existing_lower:
                    self.send_error_response(f"Recipient '{email}' already exists for '{org_name}'.")
                    return
                
                org_recipients[org_name].append(email)
                data["org_recipients"] = org_recipients
                
                with open(DEFAULT_DOMAINS_PATH, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                
                self.send_success_response(f"Recipient '{email}' added to '{org_name}' successfully.")
                logger.info(f"Recipient '{email}' added to organization '{org_name}'.")
            except Exception as e:
                self.send_error_response(f"Payload parse failure: {e}")

        # REST API: Save Configuration Settings
        elif parsed_path.path == "/api/config":
            try:
                payload = json.loads(post_data)
                
                # Check constraints if warning parameters are specified
                warning_days = payload.get("warning_days")
                high_priority_days = payload.get("high_priority_days")
                critical_days = payload.get("critical_days")
                
                if warning_days is not None and not isinstance(warning_days, int):
                    self.send_error_response("warning_days must be an integer.")
                    return
                if high_priority_days is not None and not isinstance(high_priority_days, int):
                    self.send_error_response("high_priority_days must be an integer.")
                    return
                if critical_days is not None and not isinstance(critical_days, int):
                    self.send_error_response("critical_days must be an integer.")
                    return
                
                w = warning_days if warning_days is not None else 30
                h = high_priority_days if high_priority_days is not None else 14
                c = critical_days if critical_days is not None else 7
                if not (0 < c <= h <= w):
                    self.send_error_response("Configuration constraints violated: must satisfy 0 < critical_days <= high_priority_days <= warning_days.")
                    return
                
                # Load current config to update it
                current_config = load_config()
                
                # Update settings keys
                config_keys = [
                    "warning_days", "high_priority_days", "critical_days", 
                    "timeout", "max_retries", "retry_delay", "max_workers", 
                    "send_daily_summary", "cron_enabled", "cron_schedule", 
                    "cron_time", "cron_weekly_day", "cron_monthly_day"
                ]
                for key in config_keys:
                    if key in payload:
                        current_config[key] = payload[key]
                
                # Write to file
                with open(DEFAULT_CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(current_config, f, indent=2)
                
                self.send_success_response("Configuration settings updated successfully.")
                logger.info("Configuration settings updated via Web Admin UI.")
            except Exception as e:
                self.send_error_response(f"Configuration update failed: {e}")
            
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        # Enforce Authentication check for all DELETE routes
        authenticated, _ = self.is_authenticated()
        if not authenticated:
            self.send_unauthorized_response("Unauthorized: Active session required.")
            return

        parsed_path = urllib.parse.urlparse(self.path)
        
        # 1. REST API: Delete Domain Target (Delete)
        if parsed_path.path == "/api/domains":
            query = urllib.parse.parse_qs(parsed_path.query)
            domain = query.get("domain", [""])[0]
            if not domain:
                self.send_error_response("Target 'domain' query parameter must be defined.")
                return
                
            success, msg = remove_domain_programmatic(domain)
            if success:
                self.send_success_response(msg)
            else:
                self.send_error_response(msg)

        # 2. REST API: Delete Organization (Delete Org)
        elif parsed_path.path == "/api/orgs":
            query = urllib.parse.parse_qs(parsed_path.query)
            org_name = query.get("org_name", [""])[0]
            if not org_name:
                self.send_error_response("Target 'org_name' query parameter must be defined.")
                return
                
            success, msg = remove_organization_programmatic(org_name)
            if success:
                self.send_success_response(msg)
            else:
                self.send_error_response(msg)

        # 3. REST API: Remove Recipient from Organization
        elif parsed_path.path == "/api/recipients":
            query = urllib.parse.parse_qs(parsed_path.query)
            org_name = query.get("org_name", [""])[0]
            email = query.get("email", [""])[0].strip().lower()
            if not org_name or not email:
                self.send_error_response("Both 'org_name' and 'email' query parameters are required.")
                return
            
            try:
                with open(DEFAULT_DOMAINS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}
            
            org_recipients = data.get("org_recipients", {})
            if not isinstance(org_recipients, dict):
                org_recipients = {}
            
            if org_name not in org_recipients:
                self.send_error_response(f"No recipients found for organization '{org_name}'.")
                return
            
            # Find and remove (case-insensitive)
            updated_list = [e for e in org_recipients[org_name] if e.lower() != email]
            if len(updated_list) == len(org_recipients[org_name]):
                self.send_error_response(f"Recipient '{email}' not found in '{org_name}'.")
                return
            
            org_recipients[org_name] = updated_list
            data["org_recipients"] = org_recipients
            
            with open(DEFAULT_DOMAINS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            
            self.send_success_response(f"Recipient '{email}' removed from '{org_name}' successfully.")
            logger.info(f"Recipient '{email}' removed from organization '{org_name}'.")
                
        else:
            self.send_response(404)
            self.end_headers()

    def send_success_response(self, message: str):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": True, "message": message}).encode("utf-8"))

    def send_error_response(self, error_message: str):
        self.send_response(400)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": False, "error": error_message}).encode("utf-8"))


# Premium, Responsive Glassmorphic Dark UI Login Template
LOGIN_UI_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Expiry Monitor - Administrator Login</title>
    <!-- Modern Premium Typography -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080b11;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --accent: #8b5cf6;
            --accent-glow: rgba(139, 92, 246, 0.15);
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.07);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --green: #10b981;
            --red: #ef4444;
            --amber: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }

        /* Glassmorphic Login Card */
        .login-card {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--card-border);
            border-radius: 24px;
            padding: 3rem 2.5rem;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        /* Subtle glowing background sphere */
        .login-card::before {
            content: '';
            position: absolute;
            top: -50px;
            right: -50px;
            width: 150px;
            height: 150px;
            background: radial-gradient(circle, var(--accent) 0%, transparent 70%);
            opacity: 0.15;
            pointer-events: none;
        }

        .login-header {
            text-align: center;
        }

        .login-logo {
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a5b4fc 0%, #c084fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
            margin-bottom: 0.5rem;
        }

        .login-subtitle {
            color: var(--text-muted);
            font-size: 0.9rem;
            font-weight: 300;
        }

        /* Forms styling */
        .form-group-login {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .input-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
            color: var(--text-muted);
        }

        .input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }

        .login-input {
            width: 100%;
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 0.9rem 3rem 0.9rem 1.2rem;
            color: white;
            font-size: 0.95rem;
            outline: none;
            transition: all 0.3s ease;
        }

        .login-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.2);
            background: rgba(0, 0, 0, 0.5);
        }

        .btn-toggle-visibility {
            position: absolute;
            right: 1rem;
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0.25rem;
            transition: color 0.2s ease;
        }

        .btn-toggle-visibility:hover {
            color: white;
        }

        .btn-submit {
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            border: none;
            color: white;
            padding: 1rem;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px var(--accent-glow);
            font-size: 1rem;
            margin-top: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .btn-submit:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.35);
            filter: brightness(1.1);
        }

        .btn-submit:active {
            transform: translateY(0);
        }

        .btn-submit:disabled {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
            box-shadow: none;
            cursor: not-allowed;
            transform: none;
        }

        /* Error box styling */
        .error-box {
            display: none;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 10px;
            padding: 0.8rem 1rem;
            color: #f87171;
            font-size: 0.85rem;
            align-items: center;
            gap: 0.6rem;
            animation: shake 0.4s ease-in-out;
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }

        /* Spinner for loading state */
        .spinner {
            animation: rotate 1s linear infinite;
        }
        @keyframes rotate {
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h1 class="login-logo">SSL Expiry Monitor</h1>
            <p class="login-subtitle">Dashboard Administration Portal</p>
        </div>

        <div class="error-box" id="login-error-container">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span id="login-error-text">Invalid security credentials provided.</span>
        </div>

        <form id="login-form" onsubmit="handleLoginSubmit(event)" style="display: flex; flex-direction: column; gap: 1.5rem;">
            <div class="form-group-login">
                <label class="input-label" for="dashboard-password">Dashboard Password</label>
                <div class="input-wrapper">
                    <input type="password" class="login-input" id="dashboard-password" placeholder="Enter secure key..." required autocomplete="current-password">
                    <button type="button" class="btn-toggle-visibility" onclick="togglePasswordVisibility()" title="Toggle Password Visibility">
                        <svg id="eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    </button>
                </div>
            </div>

            <button type="submit" class="btn-submit" id="btn-login-submit">
                Access Dashboard
            </button>
        </form>
    </div>

    <script>
        function togglePasswordVisibility() {
            const passwordInput = document.getElementById("dashboard-password");
            const eyeIcon = document.getElementById("eye-icon");
            
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                eyeIcon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>`;
            } else {
                passwordInput.type = "password";
                eyeIcon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
            }
        }

        async function handleLoginSubmit(event) {
            event.preventDefault();
            const passwordInput = document.getElementById("dashboard-password");
            const submitBtn = document.getElementById("btn-login-submit");
            const errorContainer = document.getElementById("login-error-container");
            const errorText = document.getElementById("login-error-text");
            
            const password = passwordInput.value;
            
            // UI state updates: loading
            submitBtn.disabled = true;
            submitBtn.innerHTML = `<svg class="spinner" width="16" height="16" viewBox="0 0 50 50" style="animation: rotate 1s linear infinite;"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" style="stroke-dasharray: 1, 150; stroke-dashoffset: 0; animation: dash 1.5s ease-in-out infinite;"></circle></svg> Authenticating...`;
            errorContainer.style.display = "none";
            
            try {
                const response = await fetch("/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password: password })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    // Success: Reload to load dashboard
                    window.location.reload();
                } else {
                    // Error response
                    errorText.innerText = data.error || "Authentication failed.";
                    errorContainer.style.display = "flex";
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = "Access Dashboard";
                }
            } catch (err) {
                errorText.innerText = "Network transmission error.";
                errorContainer.style.display = "flex";
                submitBtn.disabled = false;
                submitBtn.innerHTML = "Access Dashboard";
            }
        }
    </script>
    <style>
        @keyframes dash {
            0% { stroke-dasharray: 1, 150; stroke-dashoffset: 0; }
            50% { stroke-dasharray: 90, 150; stroke-dashoffset: -35; }
            100% { stroke-dasharray: 90, 150; stroke-dashoffset: -124; }
        }
    </style>
</body>
</html>
"""


# Premium, Responsive Glassmorphic Dark UI Dashboards Template
HTML_UI_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Expiry Monitor - Administrator Panel</title>
    <!-- Modern Premium Typography -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080b11;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --accent: #8b5cf6;
            --accent-glow: rgba(139, 92, 246, 0.15);
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.07);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --green: #10b981;
            --red: #ef4444;
            --amber: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.12) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem 3rem;
            display: flex;
            flex-direction: column;
        }

        .container {
            max-width: 100%;
            margin: 0 auto;
            flex: 1 0 auto;
        }

        @media (max-width: 1024px) {
            body {
                padding: 1.5rem 1.5rem;
            }
        }

        @media (max-width: 640px) {
            body {
                padding: 1rem 1rem;
            }
        }

        /* Glassmorphic Navbar / Header */
        header {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            flex-wrap: wrap;
            gap: 1.5rem;
        }

        .logo-section h1 {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a5b4fc 0%, #c084fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .logo-section p {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 2px;
            font-weight: 300;
        }

        .controls-section {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .org-switcher-container {
            display: flex;
            align-items: center;
            background: rgba(17, 24, 39, 0.6);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 0.4rem 0.75rem;
            border-radius: 12px;
            gap: 0.5rem;
            transition: border-color 0.3s ease;
        }

        .org-switcher-container:focus-within {
            border-color: var(--accent);
        }

        #org-selector {
            background: transparent;
            border: none;
            color: #ffffff;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            outline: none;
            padding-right: 0.5rem;
        }

        #org-selector option {
            background: #111827;
            color: #ffffff;
        }

        .btn-org-action {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e5e7eb;
            width: 24px;
            height: 24px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }

        .btn-org-action:hover {
            background: var(--accent);
            border-color: var(--accent);
            color: white;
            transform: scale(1.05);
        }

        .btn-org-action.delete:hover {
            background: var(--red);
            border-color: var(--red);
        }

        .server-time {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 0.5rem 1rem;
            border-radius: 10px;
            font-size: 0.85rem;
            color: #c084fc;
        }

        /* Call To Action - Pulsing Check Button */
        .btn-check-now {
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            border: none;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 0 15px var(--accent-glow);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-check-now:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 25px rgba(139, 92, 246, 0.4);
            filter: brightness(1.1);
        }

        .btn-check-now:active {
            transform: translateY(0);
        }

        /* Metric Grid Cards */
        .metrics-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
            transition: transform 0.3s ease;
        }

        .metric-card:hover {
            transform: translateY(-4px);
            border-color: rgba(255, 255, 255, 0.12);
        }

        .metric-label {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }

        .metric-value {
            font-size: 2.2rem;
            font-weight: 800;
            margin-top: 0.5rem;
            display: flex;
            align-items: baseline;
            gap: 0.5rem;
        }

        .metric-desc {
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 0.5rem;
            font-weight: 300;
        }

        /* Main Workspace Grid */
        .workspace-grid {
            display: grid;
            grid-template-columns: 4fr 3fr 5fr;
            gap: 1.5rem;
        }

        @media (max-width: 900px) {
            .workspace-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Cards Panel common */
        .panel-card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.25);
            display: flex;
            flex-direction: column;
        }

        .panel-title {
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 1.2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 0.75rem;
        }

        /* Custom CRUD Forms */
        .form-group {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }

        .input-field {
            flex: 1;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            color: white;
            font-size: 0.9rem;
            outline: none;
            transition: all 0.3s ease;
        }

        .input-field:focus {
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(99, 102, 241, 0.15);
            background: rgba(0, 0, 0, 0.5);
        }

        .btn-add {
            background: var(--primary);
            border: none;
            color: white;
            padding: 0.75rem 1.2rem;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }

        .btn-add:hover {
            background: var(--primary-hover);
        }

        /* Registry Search Field */
        .search-container {
            margin-bottom: 1rem;
            position: relative;
        }

        .search-input {
            width: 100%;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 0.5rem 1rem;
            color: white;
            font-size: 0.85rem;
            outline: none;
            transition: all 0.3s ease;
        }

        .search-input:focus {
            border-color: var(--accent);
            background: rgba(0, 0, 0, 0.2);
        }

        /* Registered Targets Scroll list */
        .domain-list-scroll {
            max-height: 520px;
            overflow-y: auto;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .domain-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.15rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            transition: all 0.25s ease;
        }

        .domain-item:last-child {
            border-bottom: none;
        }

        .domain-item:hover {
            background-color: rgba(255, 255, 255, 0.02);
            border-color: rgba(255, 255, 255, 0.07);
        }

        .domain-info {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            flex: 1;
            padding-right: 0.75rem;
        }

        .domain-header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .domain-name {
            font-weight: 600;
            font-size: 0.92rem;
            color: #f3f4f6;
            word-break: break-all;
        }

        .domain-meta-row {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.76rem;
            color: var(--text-muted);
            flex-wrap: wrap;
        }

        .meta-label {
            font-weight: 500;
            color: #9ca3af;
        }

        .meta-val {
            font-family: 'JetBrains Mono', monospace;
            color: #d1d5db;
        }

        .meta-separator {
            color: rgba(255, 255, 255, 0.12);
            font-weight: 300;
        }

        .domain-remarks {
            font-size: 0.75rem;
            color: #9ca3af;
            font-style: italic;
            border-top: 1px dashed rgba(255, 255, 255, 0.04);
            padding-top: 0.25rem;
            margin-top: 0.15rem;
        }

        /* Status Badge Glassmorphism Styles */
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 7px;
            border-radius: 5px;
            font-size: 0.68rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            backdrop-filter: blur(4px);
        }

        .status-badge.healthy {
            background-color: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.22);
            color: #34d399;
        }

        .status-badge.warning {
            background-color: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.22);
            color: #fbbf24;
        }

        .status-badge.high {
            background-color: rgba(249, 115, 22, 0.1);
            border: 1px solid rgba(249, 115, 22, 0.22);
            color: #fb923c;
        }

        .status-badge.critical {
            background-color: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.22);
            color: #f87171;
        }

        .status-badge.expired {
            background-color: rgba(220, 38, 38, 0.25);
            border: 1px solid rgba(220, 38, 38, 0.4);
            color: #ef4444;
            font-weight: 800;
        }

        .status-badge.failed {
            background-color: rgba(156, 163, 175, 0.1);
            border: 1px solid rgba(156, 163, 175, 0.2);
            color: #d1d5db;
        }

        .status-badge.pending {
            background-color: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.22);
            color: #a5b4fc;
        }

        /* Days Remaining highlight */
        .days-remaining {
            font-weight: bold;
        }
        .days-remaining.healthy { color: #34d399; }
        .days-remaining.warning { color: #fbbf24; }
        .days-remaining.critical { color: #f87171; }
        .days-remaining.expired { color: #ef4444; }
        .days-remaining.failed { color: #d1d5db; }

        .btn-delete {
            background: transparent;
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--red);
            width: 28px;
            height: 28px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            font-size: 0.8rem;
        }

        .btn-delete:hover {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--red);
            transform: scale(1.05);
        }

        /* Recipients Management Panel */
        .recipients-panel {
            margin-top: 1rem;
        }
        .recipients-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }
        .recipients-header .panel-title {
            margin-bottom: 0;
        }
        .recipient-list {
            max-height: 200px;
            overflow-y: auto;
            background: rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            margin-bottom: 0.75rem;
        }
        .recipient-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.65rem 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 0.85rem;
            color: var(--text-secondary);
            transition: background 0.2s ease;
        }
        .recipient-item:last-child {
            border-bottom: none;
        }
        .recipient-item:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        .recipient-item .email-text {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .recipient-item .email-text svg {
            opacity: 0.5;
            flex-shrink: 0;
        }
        .btn-remove-recipient {
            background: transparent;
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--red);
            cursor: pointer;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            transition: all 0.2s ease;
        }
        .btn-remove-recipient:hover {
            background: rgba(239, 68, 68, 0.15);
            border-color: var(--red);
        }

        .btn-recheck {
            background: transparent;
            border: 1px solid rgba(99, 102, 241, 0.3);
            color: #a5b4fc;
            cursor: pointer;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .btn-recheck:hover:not(:disabled) {
            background: rgba(99, 102, 241, 0.15);
            border-color: var(--primary);
            color: white;
            transform: scale(1.05);
        }
        .btn-recheck:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .btn-excel {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #10b981;
            cursor: pointer;
            padding: 0.45rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-excel:hover:not(:disabled) {
            background: rgba(16, 185, 129, 0.2);
            border-color: #10b981;
            color: white;
            transform: translateY(-1px);
        }
        .results-table th.sortable {
            cursor: pointer;
            user-select: none;
            transition: background-color 0.2s ease;
        }
        .results-table th.sortable:hover {
            background-color: rgba(255, 255, 255, 0.05);
            color: #ffffff;
        }
        .results-table th.sorted {
            color: var(--primary);
        }

        .recipient-empty {
            padding: 1.5rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            font-style: italic;
        }
        .add-recipient-form {
            display: flex;
            gap: 0.5rem;
        }
        .add-recipient-form input {
            flex: 1;
        }

        /* Live Log Terminal Simulator */
        .terminal-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: #04060a;
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: inset 0 4px 20px rgba(0,0,0,0.5);
            min-height: 480px;
        }

        .terminal-header {
            background: #0f131a;
            padding: 0.5rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }

        .terminal-dots {
            display: flex;
            gap: 6px;
        }

        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .dot.red { background-color: #ff5f56; }
        .dot.yellow { background-color: #ffbd2e; }
        .dot.green { background-color: #27c93f; }

        .terminal-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .btn-refresh-logs {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            padding: 0.25rem 0.5rem;
            font-size: 0.7rem;
            border-radius: 4px;
            cursor: pointer;
            font-family: 'JetBrains Mono', monospace;
            transition: all 0.2s ease;
        }

        .btn-refresh-logs:hover {
            background: rgba(255, 255, 255, 0.05);
            color: white;
            border-color: rgba(255, 255, 255, 0.2);
        }

        .terminal-body {
            flex: 1;
            padding: 1rem;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            color: #d1d5db;
            word-wrap: break-word;
            max-height: 430px;
        }

        .log-line {
            margin-bottom: 0.35rem;
            white-space: pre-wrap;
        }

        /* Colorized logs */
        .log-info { color: #818cf8; }
        .log-warning { color: #fbbf24; }
        .log-error { color: #f87171; }
        .log-success { color: #34d399; }

        /* Dynamic Toasts */
        #toast-container {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            max-width: 400px;
        }

        .toast {
            background: rgba(17, 24, 39, 0.9);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            padding: 1rem 1.25rem;
            border-radius: 12px;
            color: var(--text-main);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            border-left: 4px solid var(--primary);
        }

        .toast.success { border-left-color: var(--green); }
        .toast.error { border-left-color: var(--red); }

        @keyframes slideIn {
            from {
                transform: translateX(100%) translateY(10px);
                opacity: 0;
            }
            to {
                transform: translateX(0) translateY(0);
                opacity: 1;
            }
        }

        .toast.fade-out {
            animation: fadeOut 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes fadeOut {
            to {
                transform: translateY(20px);
                opacity: 0;
            }
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.08);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.15);
        }

        /* Settings View Styles */
        .settings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }
        .settings-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-bottom: 1.25rem;
        }
        .settings-group label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
        }
        .select-field {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            color: white;
            font-size: 0.9rem;
            outline: none;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .select-field option {
            background: #0f131a;
            color: white;
        }
        .select-field:focus {
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(99, 102, 241, 0.15);
        }
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            cursor: pointer;
            user-select: none;
            margin-bottom: 1.25rem;
        }
        .checkbox-container input {
            cursor: pointer;
            width: 18px;
            height: 18px;
            accent-color: var(--primary);
        }
        .checkbox-label {
            font-size: 0.9rem;
            font-weight: 500;
            color: white;
        }

        /* Tab Switcher Styles */
        .tab-switcher {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 0.35rem;
            border-radius: 12px;
            width: fit-content;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 0.5rem 1.25rem;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .tab-btn:hover {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.03);
        }

        .tab-btn.active {
            color: white;
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.25);
        }

        /* View Panels Visibility */
        .view-panel {
            display: none !important;
        }

        .view-panel.active {
            display: grid !important;
        }

        #table-view.view-panel.active {
            display: flex !important;
        }

        /* Results Table Premium Styles */
        .table-wrapper {
            overflow-x: auto;
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.04);
            margin-top: 0.5rem;
        }

        .results-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }

        .results-table th {
            padding: 1rem 1.25rem;
            border-bottom: 2px solid rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.75px;
            background: rgba(15, 23, 42, 0.3);
        }

        .results-table td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            color: var(--text-main);
            vertical-align: middle;
        }

        .results-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }

        .results-table tr:last-child td {
            border-bottom: none;
        }

        .results-table .status-badge {
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.7rem;
        }

        .btn-logout {
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--red);
            padding: 0.45rem 1rem;
            font-size: 0.85rem;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .btn-logout:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: var(--red);
            transform: translateY(-1px);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Dashboard Top Navigation Header -->
        <header>
            <div class="logo-section">
                <h1>SSL Expiry Monitor</h1>
                <p>Enterprise environment health dashboard</p>
            </div>
            <div class="controls-section">
                <div class="org-switcher-container">
                    <span style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted);">ORG:</span>
                    <select id="org-selector" onchange="changeOrganization()">
                        <!-- Dynamically populated options -->
                    </select>
                    <button class="btn-org-action" onclick="promptCreateOrg()" title="Create New Organization">+</button>
                    <button class="btn-org-action delete" onclick="deleteActiveOrg()" title="Delete Active Organization">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </div>
                <span class="server-time" id="clock-display">Loading server time...</span>
                <button class="btn-check-now" id="btn-run-check" onclick="triggerSSLCheck()">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                    Run Check Now
                </button>
                <button class="btn-logout" onclick="handleLogout()">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    Logout
                </button>
            </div>
        </header>

        <!-- Metric Analytics Row -->
        <div class="metrics-row">
            <div class="metric-card">
                <div class="metric-label">Total Domains</div>
                <div class="metric-value" id="stat-total" style="color: #6366f1;">0</div>
                <div class="metric-desc">Configured endpoints in domains.json</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Healthy Domains</div>
                <div class="metric-value" id="stat-healthy" style="color: var(--green);">0</div>
                <div class="metric-desc">SSL certificates fully valid and secure</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Warning Domains</div>
                <div class="metric-value" id="stat-warning" style="color: var(--amber);">0</div>
                <div class="metric-desc">Certificates nearing expiry warning</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical Domains</div>
                <div class="metric-value" id="stat-critical" style="color: #fb923c;">0</div>
                <div class="metric-desc">Certificates at critical expiry risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Expired Domains</div>
                <div class="metric-value" id="stat-expired" style="color: var(--red);">0</div>
                <div class="metric-desc">Certificates completely expired</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Failed Domains</div>
                <div class="metric-value" id="stat-failed" style="color: #9ca3af;">0</div>
                <div class="metric-desc">Connection and handshake failures</div>
            </div>
        </div>

        <!-- Glassmorphic Tab Switcher -->
        <div class="tab-switcher">
            <button class="tab-btn active" onclick="switchTab('table')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="9" y1="6" x2="20" y2="6"></line><line x1="9" y1="12" x2="20" y2="12"></line><line x1="9" y1="18" x2="20" y2="18"></line><line x1="5" y1="6" x2="5.01" y2="6"></line><line x1="5" y1="12" x2="5.01" y2="12"></line><line x1="5" y1="18" x2="5.01" y2="18"></line></svg>
                Last Scan Results
            </button>
            <button class="tab-btn" onclick="switchTab('dashboard')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
                Registry & Console
            </button>
            <button class="tab-btn" onclick="switchTab('settings')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                Scheduler & Settings
            </button>
        </div>

        <!-- View 1: Main Workspace Layout Grid -->
        <div id="dashboard-view" class="workspace-grid view-panel">
            
            <!-- Left Workspace Panel: CRUD domains registry list -->
            <div class="panel-card">
                <div class="panel-title">
                    <span>Manage Registry</span>
                    <span style="font-size: 0.8rem; font-weight: 400; color: var(--text-muted);" id="registry-count">0 domains</span>
                </div>
                
                <!-- Add Target Domain Form -->
                <div class="form-group">
                    <input type="text" class="input-field" id="new-domain-input" placeholder="e.g. sub.your-domain.co.in" onkeydown="if(event.key === 'Enter') addTargetDomain()">
                    <button class="btn-add" onclick="addTargetDomain()">Add Target</button>
                </div>

                <!-- Search/Filter Registry Targets -->
                <div class="search-container">
                    <input type="text" class="search-input" id="search-registry-input" placeholder="Search registry..." oninput="filterRegistryList()">
                </div>

                <!-- Targets list container -->
                <div class="domain-list-scroll" id="domains-list-container">
                    <!-- Loaded dynamically via AJAX -->
                    <div style="padding: 1.5rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                        Loading domain targets list...
                    </div>
                </div>
            </div>

            <!-- Center Panel: Email Recipients per Organization -->
            <div class="panel-card">
                <div class="panel-title">
                    <span>Email Recipients</span>
                    <span style="font-size: 0.8rem; font-weight: 400; color: var(--text-muted);" id="recipients-count">0 recipients</span>
                </div>
                
                <!-- Add Recipient Form (hidden in "All" mode) -->
                <div class="form-group add-recipient-form" id="add-recipient-form">
                    <input type="email" class="input-field" id="new-recipient-input" placeholder="user@example.com" onkeydown="if(event.key === 'Enter') addRecipient()">
                    <button class="btn-add" onclick="addRecipient()">Add</button>
                </div>

                <!-- Recipients list container -->
                <div class="recipient-list" id="recipients-list-container">
                    <div class="recipient-empty">Select an organization to manage recipients.</div>
                </div>

                <div style="margin-top: 0.5rem; font-size: 0.72rem; color: var(--text-muted); opacity: 0.7; line-height: 1.4;">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: -1px; margin-right: 2px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    Org-scoped scans email only these recipients. Falls back to <code style="font-size:0.7rem; background:rgba(0,0,0,0.3); padding:1px 4px; border-radius:3px;">.env</code> if empty.
                </div>
            </div>

            <!-- Right Workspace Panel: Live Console Logs Terminal -->
            <div class="panel-card">
                <div class="panel-title">
                    <span>Live Activity Console</span>
                    <button class="btn-refresh-logs" onclick="fetchLogs()">Clear Console Buffers</button>
                </div>
                
                <div class="terminal-container">
                    <div class="terminal-header">
                        <div class="terminal-dots">
                            <span class="dot red"></span>
                            <span class="dot yellow"></span>
                            <span class="dot green"></span>
                        </div>
                        <span class="terminal-title">logs/ssl_monitor.log</span>
                        <span class="btn-refresh-logs" id="status-terminal-label">Auto-polling logs</span>
                    </div>
                    <div class="terminal-body" id="terminal-log-output">
                        <!-- Loaded dynamically via AJAX -->
                        <div class="log-line log-info">Initialising connection to logs pipeline...</div>
                    </div>
                </div>
            </div>

        </div>

        <!-- View 2: Last Results Table View -->
        <div id="table-view" class="panel-card view-panel active">
            <div class="panel-title" style="margin-bottom: 1rem; flex-wrap: wrap; gap: 1rem;">
                <span>Detailed Verification History</span>
                <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                    <input type="text" class="search-input" id="table-search-input" placeholder="Filter domain/remarks..." oninput="filterResultsTable()" style="width: 200px; margin-bottom: 0; background: rgba(0,0,0,0.25);">
                    <select class="search-input" id="table-severity-filter" onchange="filterResultsTable()" style="width: 150px; margin-bottom: 0; background: rgba(0,0,0,0.25); color: var(--text-main); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 0.4rem 0.8rem; outline: none; cursor: pointer;">
                        <option value="all">All Statuses</option>
                        <option value="healthy">Healthy</option>
                        <option value="warning">Warning / High</option>
                        <option value="critical">Critical</option>
                        <option value="expired">Expired</option>
                        <option value="failed">Failed</option>
                    </select>
                    <button class="btn-excel" onclick="exportToExcel()">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
                        Export Excel
                    </button>
                    <span style="font-size: 0.8rem; font-weight: 400; color: var(--text-muted);" id="table-record-count">0 items</span>
                </div>
            </div>
            
            <div class="table-wrapper">
                <table class="results-table">
                    <thead>
                        <tr>
                            <th id="th-domain" class="sortable" onclick="toggleSort('domain')">Domain</th>
                            <th id="th-org" class="sortable" onclick="toggleSort('org')">Org</th>
                            <th id="th-status" class="sortable" onclick="toggleSort('status')">Status</th>
                            <th id="th-expiry_date" class="sortable" onclick="toggleSort('expiry_date')">Expiry Date</th>
                            <th id="th-remaining" class="sortable" onclick="toggleSort('remaining')">Remaining</th>
                            <th>Remarks</th>
                            <th id="th-checked_at" class="sortable" onclick="toggleSort('checked_at')">Checked At</th>
                            <th style="text-align: center;">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="table-results-body">
                        <tr>
                            <td colspan="8" style="padding: 2rem; text-align: center; color: var(--text-muted);">
                                Loading SSL validation results...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- View 3: Settings and Scheduler View -->
        <div id="settings-view" class="panel-card view-panel">
            <div class="panel-title" style="margin-bottom: 1.5rem;">
                <span>System & Scheduler Settings</span>
            </div>
            
            <form id="settings-form" onsubmit="saveSettings(event)">
                <div class="settings-grid">
                    <!-- Scheduler Settings Card -->
                    <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 1.5rem; display: flex; flex-direction: column;">
                        <h3 style="margin-top: 0; margin-bottom: 1.25rem; font-size: 1.1rem; color: var(--primary); display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                            Automated CRON Scheduler
                        </h3>
                        
                        <label class="checkbox-container" style="margin-bottom: 1.5rem;">
                            <input type="checkbox" id="setting-cron-enabled" onchange="toggleSchedulerFields()">
                            <span class="checkbox-label">Enable Background Scheduler</span>
                        </label>
                        
                        <div id="scheduler-fields" style="display: flex; flex-direction: column; gap: 1rem;">
                            <div class="settings-group">
                                <label for="setting-cron-schedule">Run Schedule Frequency</label>
                                <select id="setting-cron-schedule" class="select-field" onchange="toggleSchedulerFields()">
                                    <option value="daily">Daily</option>
                                    <option value="weekly">Weekly</option>
                                    <option value="monthly">Monthly</option>
                                </select>
                            </div>
                            
                            <div class="settings-group">
                                <label for="setting-cron-time">Execution Time (HH:MM)</label>
                                <input type="time" id="setting-cron-time" class="input-field" required>
                            </div>
                            
                            <div class="settings-group" id="group-cron-weekly" style="display: none;">
                                <label for="setting-cron-weekly-day">Execution Day of Week</label>
                                <select id="setting-cron-weekly-day" class="select-field">
                                    <option value="Monday">Monday</option>
                                    <option value="Tuesday">Tuesday</option>
                                    <option value="Wednesday">Wednesday</option>
                                    <option value="Thursday">Thursday</option>
                                    <option value="Friday">Friday</option>
                                    <option value="Saturday">Saturday</option>
                                    <option value="Sunday">Sunday</option>
                                </select>
                            </div>
                            
                            <div class="settings-group" id="group-cron-monthly" style="display: none;">
                                <label for="setting-cron-monthly-day">Execution Day of Month (1-28)</label>
                                <input type="number" id="setting-cron-monthly-day" class="input-field" min="1" max="28" value="1">
                            </div>
                        </div>
                    </div>
                    
                    <!-- Alert Threshold Settings -->
                    <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 1.5rem; display: flex; flex-direction: column;">
                        <h3 style="margin-top: 0; margin-bottom: 1.25rem; font-size: 1.1rem; color: #fbbf24; display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                            Alert Thresholds (Days)
                        </h3>
                        
                        <div class="settings-group">
                            <label for="setting-warning-days">Warning Threshold (Days remaining)</label>
                            <input type="number" id="setting-warning-days" class="input-field" min="1" required>
                        </div>
                        
                        <div class="settings-group">
                            <label for="setting-high-priority-days">High Priority Threshold (Days remaining)</label>
                            <input type="number" id="setting-high-priority-days" class="input-field" min="1" required>
                        </div>
                        
                        <div class="settings-group">
                            <label for="setting-critical-days">Critical Threshold (Days remaining)</label>
                            <input type="number" id="setting-critical-days" class="input-field" min="1" required>
                        </div>
                        
                        <label class="checkbox-container" style="margin-top: 0.5rem;">
                            <input type="checkbox" id="setting-send-daily-summary">
                            <span class="checkbox-label">Send summary email if no warnings exist</span>
                        </label>
                    </div>
                    
                    <!-- Network & Performance Settings -->
                    <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 1.5rem; display: flex; flex-direction: column;">
                        <h3 style="margin-top: 0; margin-bottom: 1.25rem; font-size: 1.1rem; color: #10b981; display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            Network & Performance
                        </h3>
                        
                        <div class="settings-group">
                            <label for="setting-max-workers">Maximum Concurrent Workers (Threads)</label>
                            <input type="number" id="setting-max-workers" class="input-field" min="1" max="100" required>
                        </div>
                        
                        <div class="settings-group">
                            <label for="setting-timeout">Network Connection Timeout (Seconds)</label>
                            <input type="number" id="setting-timeout" class="input-field" min="1" max="60" required>
                        </div>
                        
                        <div class="settings-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                            <div class="settings-group">
                                <label for="setting-max-retries">Retry Count</label>
                                <input type="number" id="setting-max-retries" class="input-field" min="0" max="5" required>
                            </div>
                            <div class="settings-group">
                                <label for="setting-retry-delay">Delay (Secs)</label>
                                <input type="number" id="setting-retry-delay" class="input-field" min="1" max="30" required>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div style="margin-top: 2rem; display: flex; justify-content: flex-end; gap: 1rem;">
                    <button type="button" class="tab-btn" onclick="fetchSettings()" style="border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.2);">Reset to Saved</button>
                    <button type="submit" class="btn-add" style="padding: 0.75rem 2rem;">Save System Configurations</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Footer Section -->
    <footer style="background: var(--card-bg); backdrop-filter: blur(12px); border: 1px solid var(--card-border); border-radius: 16px; padding: 1.25rem 2rem; margin-top: 3rem; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; flex-direction: column; gap: 0.25rem;">
            <p style="color: var(--text-muted); font-size: 0.85rem; font-weight: 400; margin: 0; text-align: left;">
                2026 SSL Expiry Monitor. All rights reserved.
            </p>
            <p style="color: rgba(255,255,255,0.15); font-size: 0.7rem; font-weight: 300; margin: 0; font-family: 'JetBrains Mono', monospace; text-align: left;">
                v1.1.0 &bull; Secure Enterprise Edition
            </p>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem;">
            <span style="color: var(--text-muted); font-weight: 300;">Designed & Developed by</span>
            <a href="https://www.linkedin.com/in/rupendrajangid/" target="_blank" rel="noopener noreferrer" style="color: var(--primary); font-weight: 600; text-decoration: none; cursor: pointer; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 0.35rem; text-shadow: 0 0 10px rgba(99, 102, 241, 0.1);" onmouseover="this.style.color='var(--accent)'; this.style.textShadow='0 0 15px var(--accent)';" onmouseout="this.style.color='var(--primary)'; this.style.textShadow='0 0 10px rgba(99, 102, 241, 0.1)';">
                <span>Rupendra Jangid &nbsp; (TAGID Team)</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.8; vertical-align: middle;"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path><rect x="2" y="9" width="4" height="12"></rect><circle cx="4" cy="4" r="2"></circle></svg>
            </a>
        </div>
    </footer>

    <!-- Container for dynamic visual toasts alerts -->
    <div id="toast-container"></div>

    <!-- AJAX Dashboard Core Logic Scripts -->
    <script>
        // Global error handlers for debugging
        window.onerror = function(message, source, lineno, colno, error) {
            const errorMsg = `Global JS Error:\nMessage: ${message}\nSource: ${source}\nLine: ${lineno}\nColumn: ${colno}\nError: ${error ? error.stack : 'N/A'}`;
            alert(errorMsg);
            console.error(errorMsg);
            return false;
        };

        window.onunhandledrejection = function(event) {
            const reason = event.reason;
            const errorMsg = `Unhandled Promise Rejection:\nReason: ${reason ? (reason.stack || reason) : 'N/A'}`;
            alert(errorMsg);
            console.error(errorMsg);
        };

        // Multi-Org Cache & Switcher State
        let allOrgsCache = {};
        let allDomainsCache = [];
        let allResultsCache = {};
        let allOrgRecipientsCache = {};
        let activeOrganization = localStorage.getItem("activeOrganization") || "Tagid";

        function getOrgForDomain(domain) {
            if (!allOrgsCache) return "N/A";
            for (const [org, domainsList] of Object.entries(allOrgsCache)) {
                if (Array.isArray(domainsList) && domainsList.includes(domain)) {
                    return org;
                }
            }
            return "N/A";
        }

        // Start running loops
        updateClock();
        setInterval(updateClock, 1000);
        
        // Initial registry and logs fetch
        fetchDomains();
        fetchLogs();
        fetchSettings();
        
        // Auto-refresh loops
        setInterval(fetchDomains, 8000);  // Registry updates
        setInterval(fetchLogs, 3000);     // Terminal log updates

        // 1. Digital IST Clock display logic
        function updateClock() {
            const now = new Date();
            const options = {
                timeZone: 'Asia/Kolkata',
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            };
            const istString = now.toLocaleString('en-IN', options) + ' IST';
            document.getElementById("clock-display").innerText = istString;
        }

        // 2. Fetch configured domains list and organizations
        async function fetchDomains() {
            try {
                const response = await fetch("/api/domains");
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                if (!response.ok) throw new Error("API load error");
                
                const data = await response.json();
                allDomainsCache = data.domains || [];
                allOrgsCache = data.orgs || {};
                allResultsCache = data.last_results || {};
                allOrgRecipientsCache = data.org_recipients || {};
                
                // Populate organization dropdown
                populateOrgSwitcher();

                // Run data filter & render
                filterAndRenderDashboard();
            } catch (err) {
                console.error("Failed to load domains registry:", err);
            }
        }

        // Populate organization dropdown selector dynamically
        function populateOrgSwitcher() {
            const selector = document.getElementById("org-selector");
            if (!selector) return;

            const currentSel = activeOrganization;
            let html = "";
            
            // consolidated All Organizations option at the top
            html += `<option value="all" ${currentSel === 'all' ? 'selected' : ''}>All Organizations</option>`;

            // List individual org keys alphabetically
            const orgNames = Object.keys(allOrgsCache).sort((a, b) => a.localeCompare(b));
            if (!orgNames.includes("Tagid")) {
                orgNames.unshift("Tagid");
            }

            orgNames.forEach(org => {
                if (org === "Tagid" && orgNames.indexOf("Tagid") !== orgNames.lastIndexOf("Tagid")) {
                    return;
                }
                html += `<option value="${org}" ${currentSel === org ? 'selected' : ''}>${org}</option>`;
            });

            selector.innerHTML = html;
            
            // Fallback if activeOrganization was deleted
            if (currentSel !== "all" && !allOrgsCache[currentSel]) {
                activeOrganization = "Tagid";
                localStorage.setItem("activeOrganization", activeOrganization);
                selector.value = "Tagid";
            }
        }

        // Filter domains and recalculate statistics in real-time
        function filterAndRenderDashboard() {
            let filteredDomains = [];
            if (activeOrganization === "all") {
                filteredDomains = allDomainsCache;
            } else {
                filteredDomains = allOrgsCache[activeOrganization] || [];
            }

            // Update stats
            document.getElementById("stat-total").innerText = filteredDomains.length;
            document.getElementById("registry-count").innerText = filteredDomains.length + " registered";
            
            // Compute health classifications from allResultsCache for the filtered domains
            let healthyCount = 0;
            let warningCount = 0;
            let criticalCount = 0;
            let expiredCount = 0;
            let failedCount = 0;
            
            filteredDomains.forEach(d => {
                const res = allResultsCache[d];
                if (res) {
                    const sev = res.severity || "Failed";
                    if (sev === "Healthy") {
                        healthyCount++;
                    } else if (sev === "Warning" || sev === "High") {
                        warningCount++;
                    } else if (sev === "Critical") {
                        criticalCount++;
                    } else if (sev === "Expired") {
                        expiredCount++;
                    } else if (sev === "Failed") {
                        failedCount++;
                    }
                }
            });
            
            document.getElementById("stat-healthy").innerText = healthyCount;
            document.getElementById("stat-warning").innerText = warningCount;
            document.getElementById("stat-critical").innerText = criticalCount;
            document.getElementById("stat-expired").innerText = expiredCount;
            document.getElementById("stat-failed").innerText = failedCount;
            
            // Update input placeholder based on selection
            const inputElement = document.getElementById("new-domain-input");
            if (inputElement) {
                if (activeOrganization === "all") {
                    inputElement.placeholder = "Select an org to add domains...";
                    inputElement.disabled = true;
                } else {
                    inputElement.placeholder = `Add domain to ${activeOrganization}...`;
                    inputElement.disabled = false;
                }
            }

            // Render tables & panels
            renderDomainsList(filteredDomains, allResultsCache);
            renderResultsTable(filteredDomains, allResultsCache);
            renderRecipients();
        }

        // Triggered on selector dropdown change
        function changeOrganization() {
            const selector = document.getElementById("org-selector");
            if (!selector) return;
            activeOrganization = selector.value;
            localStorage.setItem("activeOrganization", activeOrganization);
            filterAndRenderDashboard();
            showToast(`Switched view to: ${activeOrganization === 'all' ? 'All Organizations' : activeOrganization}`, "success");
        }

        // Administrative: Create New Organization
        async function promptCreateOrg() {
            const orgName = prompt("Enter the name of the new organization:");
            if (!orgName) return;
            const cleanOrg = orgName.trim();
            if (!cleanOrg) {
                showToast("Organization name cannot be empty.", "error");
                return;
            }
            if (cleanOrg.toLowerCase() === "all") {
                showToast("'All' is a reserved name.", "error");
                return;
            }

            try {
                const response = await fetch("/api/orgs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ org_name: cleanOrg })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Organization created!", "success");
                    activeOrganization = cleanOrg;
                    localStorage.setItem("activeOrganization", activeOrganization);
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to create organization.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // Administrative: Delete Active Organization
        async function deleteActiveOrg() {
            if (activeOrganization === "all") {
                showToast("Cannot delete the consolidated 'All Organizations' view.", "error");
                return;
            }
            if (activeOrganization === "Tagid") {
                showToast("The default organization 'Tagid' cannot be deleted.", "error");
                return;
            }

            if (!confirm(`Are you absolutely sure you want to delete organization '${activeOrganization}'?\n\nWARNING: This will permanently delete all domains belonging ONLY to this organization!`)) {
                return;
            }

            try {
                const response = await fetch(`/api/orgs?org_name=${encodeURIComponent(activeOrganization)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Organization deleted.", "success");
                    activeOrganization = "Tagid";
                    localStorage.setItem("activeOrganization", activeOrganization);
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to delete organization.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // Tab Switching Logic
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.view-panel').forEach(panel => panel.classList.remove('active'));
            
            if (tabId === 'dashboard') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="dashboard"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('dashboard-view');
                if (targetPanel) targetPanel.classList.add('active');
            } else if (tabId === 'table') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="table"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('table-view');
                if (targetPanel) targetPanel.classList.add('active');
                renderResultsTable(tableDomainsCache, tableResultsCache);
            } else if (tabId === 'settings') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="settings"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('settings-view');
                if (targetPanel) targetPanel.classList.add('active');
                fetchSettings();
            }
        }

        // Settings / Scheduler CRUD Management
        function toggleSchedulerFields() {
            const enabled = document.getElementById('setting-cron-enabled').checked;
            const fieldsDiv = document.getElementById('scheduler-fields');
            const freq = document.getElementById('setting-cron-schedule').value;
            
            if (enabled) {
                fieldsDiv.style.opacity = '1';
                fieldsDiv.style.pointerEvents = 'auto';
            } else {
                fieldsDiv.style.opacity = '0.5';
                fieldsDiv.style.pointerEvents = 'none';
            }
            
            document.getElementById('group-cron-weekly').style.display = (enabled && freq === 'weekly') ? 'flex' : 'none';
            document.getElementById('group-cron-monthly').style.display = (enabled && freq === 'monthly') ? 'flex' : 'none';
        }
        
        async function fetchSettings() {
            try {
                const response = await fetch('/api/config');
                if (response.status === 401) {
                    showToast("Session expired. Please log in again.", "error");
                    return;
                }
                const config = await response.json();
                
                document.getElementById('setting-cron-enabled').checked = config.cron_enabled || false;
                document.getElementById('setting-cron-schedule').value = config.cron_schedule || 'daily';
                document.getElementById('setting-cron-time').value = config.cron_time || '09:00';
                document.getElementById('setting-cron-weekly-day').value = config.cron_weekly_day || 'Monday';
                document.getElementById('setting-cron-monthly-day').value = config.cron_monthly_day || 1;
                
                document.getElementById('setting-warning-days').value = config.warning_days || 30;
                document.getElementById('setting-high-priority-days').value = config.high_priority_days || 14;
                document.getElementById('setting-critical-days').value = config.critical_days || 7;
                document.getElementById('setting-send-daily-summary').checked = config.send_daily_summary !== false;
                
                document.getElementById('setting-max-workers').value = config.max_workers || 20;
                document.getElementById('setting-timeout').value = config.timeout || 10;
                document.getElementById('setting-max-retries').value = config.max_retries || 3;
                document.getElementById('setting-retry-delay').value = config.retry_delay || 5;
                
                toggleSchedulerFields();
            } catch (err) {
                showToast("Failed to fetch system configurations.", "error");
            }
        }
        
        async function saveSettings(event) {
            event.preventDefault();
            
            const warning = parseInt(document.getElementById('setting-warning-days').value);
            const high = parseInt(document.getElementById('setting-high-priority-days').value);
            const critical = parseInt(document.getElementById('setting-critical-days').value);
            
            if (critical > high || high > warning || critical <= 0) {
                showToast("Constraint violation: Critical <= High Priority <= Warning is required.", "error");
                return;
            }
            
            const payload = {
                cron_enabled: document.getElementById('setting-cron-enabled').checked,
                cron_schedule: document.getElementById('setting-cron-schedule').value,
                cron_time: document.getElementById('setting-cron-time').value,
                cron_weekly_day: document.getElementById('setting-cron-weekly-day').value,
                cron_monthly_day: parseInt(document.getElementById('setting-cron-monthly-day').value),
                
                warning_days: warning,
                high_priority_days: high,
                critical_days: critical,
                send_daily_summary: document.getElementById('setting-send-daily-summary').checked,
                
                max_workers: parseInt(document.getElementById('setting-max-workers').value),
                timeout: parseInt(document.getElementById('setting-timeout').value),
                max_retries: parseInt(document.getElementById('setting-max-retries').value),
                retry_delay: parseInt(document.getElementById('setting-retry-delay').value)
            };
            
            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const resData = await response.json();
                if (response.ok && resData.success) {
                    showToast("Configurations saved successfully!", "success");
                } else {
                    showToast(resData.error || "Failed to update configurations.", "error");
                }
            } catch (err) {
                showToast("Network error saving configurations.", "error");
            }
        }

        // Table Sorting & Export Logic
        let currentSortColumn = "domain";
        let currentSortDirection = "asc";

        function toggleSort(column) {
            if (currentSortColumn === column) {
                currentSortDirection = currentSortDirection === "asc" ? "desc" : "asc";
            } else {
                currentSortColumn = column;
                currentSortDirection = "asc";
            }
            updateSortHeadersUI();
            renderResultsTable(tableDomainsCache, tableResultsCache);
        }

        function updateSortHeadersUI() {
            const columns = {
                domain: "Domain",
                org: "Org",
                status: "Status",
                expiry_date: "Expiry Date",
                remaining: "Remaining",
                checked_at: "Checked At"
            };
            
            for (const [colId, labelText] of Object.entries(columns)) {
                const th = document.getElementById(`th-${colId}`);
                if (!th) continue;
                
                if (currentSortColumn === colId) {
                    const arrow = currentSortDirection === "asc" ? " ▲" : " ▼";
                    th.innerHTML = `${labelText}<span style="color: var(--primary); font-size: 0.75rem;">${arrow}</span>`;
                    th.classList.add("sorted");
                } else {
                    th.innerHTML = `${labelText}<span style="opacity: 0.2; font-size: 0.75rem;"> ⇅</span>`;
                    th.classList.remove("sorted");
                }
            }
        }

        function exportToExcel() {
            const domains = tableDomainsCache;
            const lastResults = tableResultsCache;
            if (!domains || domains.length === 0) {
                showToast("No data available to export.", "error");
                return;
            }
            
            let csvContent = "Domain,Org,Status,Severity,Expiry Date,Remaining Days,Remarks,Checked At\\n";
            const sortedDomains = [...domains].sort((a, b) => a.localeCompare(b));
            
            sortedDomains.forEach(domain => {
                const res = lastResults[domain];
                let orgName = getOrgForDomain(domain);
                let statusText = "Pending";
                let severity = "Pending";
                let expiryDate = "Never checked";
                let remainingDays = "N/A";
                let remarksText = "Awaiting verification check...";
                let checkedAt = "Never";
                
                if (res) {
                    statusText = res.status || "Unknown";
                    severity = res.severity || "Failed";
                    expiryDate = res.expiry_date || "N/A";
                    remainingDays = res.days_remaining !== undefined ? res.days_remaining : "N/A";
                    remarksText = res.remarks || "";
                    checkedAt = res.checked_at || "N/A";
                }
                
                const escapeCSV = (val) => {
                    const str = String(val);
                    if (str.includes(",") || str.includes("\\\"") || str.includes("\\n") || str.includes("\\r")) {
                        return `"${str.replace(/"/g, '""')}"`;
                    }
                    return str;
                };
                
                csvContent += `${escapeCSV(domain)},${escapeCSV(orgName)},${escapeCSV(statusText)},${escapeCSV(severity)},${escapeCSV(expiryDate)},${escapeCSV(remainingDays)},${escapeCSV(remarksText)},${escapeCSV(checkedAt)}\\n`;
            });
            
            const blob = new Blob([new Uint8Array([0xEF, 0xBB, 0xBF]), csvContent], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            const url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            
            const timestamp = new Date().toISOString().slice(0, 10);
            link.setAttribute("download", `ssl_expiry_report_${timestamp}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast("Report exported successfully!", "success");
        }

        // Table Render Logic
        let tableDomainsCache = [];
        let tableResultsCache = {};
        function renderResultsTable(domains = [], lastResults = {}) {
            if (!domains) domains = [];
            tableDomainsCache = domains;
            if (Object.keys(lastResults).length > 0) {
                tableResultsCache = lastResults;
            } else {
                lastResults = tableResultsCache;
            }
            
            updateSortHeadersUI();

            const container = document.getElementById("table-results-body");
            if (!container) return;
            
            if (domains.length === 0) {
                container.innerHTML = `<tr><td colspan="8" style="padding: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No records available. Add domains and run check.</td></tr>`;
                const recordCountEl = document.getElementById("table-record-count");
                if (recordCountEl) {
                    recordCountEl.innerText = "0 items";
                }
                return;
            }
            
            // Build raw row data for sorting and filtering
            const rowData = domains.map(domain => {
                const res = lastResults[domain] || {};
                return {
                    domain: domain,
                    org: getOrgForDomain(domain),
                    status: res.status || "Pending",
                    severity: res.severity || "Pending",
                    expiry_date: res.expiry_date || "Never checked",
                    days_remaining: res.days_remaining !== undefined ? res.days_remaining : -999999,
                    remarks: res.remarks || "Awaiting verification check...",
                    checked_at: res.checked_at || "Never",
                    raw: res
                };
            });
            
            const searchInput = document.getElementById("table-search-input");
            const filterInput = document.getElementById("table-severity-filter");
            const searchQuery = searchInput ? searchInput.value.toLowerCase().trim() : "";
            const severityFilter = filterInput ? filterInput.value.toLowerCase().trim() : "all";
            
            // Filter Rows
            const filteredRows = rowData.filter(row => {
                if (searchQuery && 
                    !row.domain.toLowerCase().includes(searchQuery) && 
                    !row.remarks.toLowerCase().includes(searchQuery) &&
                    !row.org.toLowerCase().includes(searchQuery)) {
                    return false;
                }
                if (severityFilter !== "all") {
                    const sev = row.severity.toLowerCase();
                    if (severityFilter === "healthy" && sev !== "healthy") return false;
                    if (severityFilter === "warning" && (sev !== "warning" && sev !== "high")) return false;
                    if (severityFilter === "critical" && sev !== "critical") return false;
                    if (severityFilter === "expired" && sev !== "expired") return false;
                    if (severityFilter === "failed" && sev !== "failed") return false;
                }
                return true;
            });
            
            // Sort Rows
            filteredRows.sort((a, b) => {
                let comparison = 0;
                if (currentSortColumn === "domain") {
                    comparison = a.domain.localeCompare(b.domain);
                } else if (currentSortColumn === "org") {
                    comparison = a.org.localeCompare(b.org);
                    if (comparison === 0) {
                        comparison = a.domain.localeCompare(b.domain);
                    }
                } else if (currentSortColumn === "status") {
                    const severityWeight = (sev) => {
                        if (sev === "Expired") return 5;
                        if (sev === "Critical") return 4;
                        if (sev === "High") return 3;
                        if (sev === "Warning") return 2;
                        if (sev === "Failed") return 1;
                        if (sev === "Healthy") return 0;
                        return -1;
                    };
                    comparison = severityWeight(b.severity) - severityWeight(a.severity);
                    if (comparison === 0) {
                        comparison = a.domain.localeCompare(b.domain);
                    }
                } else if (currentSortColumn === "expiry_date") {
                    const aIsNav = (a.expiry_date === "Never checked" || a.expiry_date === "N/A");
                    const bIsNav = (b.expiry_date === "Never checked" || b.expiry_date === "N/A");
                    if (aIsNav && bIsNav) {
                        comparison = a.domain.localeCompare(b.domain);
                    } else if (aIsNav) {
                        comparison = 1;
                    } else if (bIsNav) {
                        comparison = -1;
                    } else {
                        comparison = new Date(String(a.expiry_date).replace(" IST", "")) - new Date(String(b.expiry_date).replace(" IST", ""));
                        if (isNaN(comparison)) comparison = 0;
                    }
                } else if (currentSortColumn === "remaining") {
                    comparison = a.days_remaining - b.days_remaining;
                    if (comparison === 0) {
                        comparison = a.domain.localeCompare(b.domain);
                    }
                } else if (currentSortColumn === "checked_at") {
                    const aIsNav = (a.checked_at === "Never" || a.checked_at === "N/A");
                    const bIsNav = (b.checked_at === "Never" || b.checked_at === "N/A");
                    if (aIsNav && bIsNav) {
                        comparison = a.domain.localeCompare(b.domain);
                    } else if (aIsNav) {
                        comparison = 1;
                    } else if (bIsNav) {
                        comparison = -1;
                    } else {
                        comparison = new Date(String(a.checked_at).replace(" IST", "")) - new Date(String(b.checked_at).replace(" IST", ""));
                        if (isNaN(comparison)) comparison = 0;
                    }
                }
                
                return currentSortDirection === "asc" ? comparison : -comparison;
            });
            
            let html = "";
            let matchCount = 0;
            
            filteredRows.forEach(row => {
                matchCount++;
                
                let statusText = row.status;
                let statusClass = row.severity.toLowerCase();
                let expiryDate = row.expiry_date;
                let remainingDaysText = "N/A";
                let daysClass = "failed";
                let remarksText = row.remarks;
                let checkedAt = row.checked_at;
                
                const res = row.raw;
                if (res && res.days_remaining !== undefined && res.days_remaining !== -1) {
                    remainingDaysText = `${res.days_remaining} days`;
                    
                    if (res.days_remaining <= 0) {
                        daysClass = "expired";
                    } else if (res.days_remaining < 7) {
                        daysClass = "critical";
                    } else if (res.days_remaining < 30) {
                        daysClass = "warning";
                    } else {
                        daysClass = "healthy";
                    }
                }
                
                html += `
                <tr>
                    <td style="font-weight: 600; color: #ffffff; font-size: 0.92rem;">${row.domain}</td>
                    <td style="color: var(--text-muted); font-size: 0.85rem; font-weight: 500;">${row.org}</td>
                    <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                    <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #e5e7eb;">${expiryDate}</td>
                    <td><span class="days-remaining ${daysClass}" style="font-weight: 700;">${remainingDaysText}</span></td>
                    <td style="color: var(--text-muted); font-size: 0.85rem; font-style: italic; max-width: 320px; overflow-wrap: break-word; white-space: normal; line-height: 1.4;">${remarksText}</td>
                    <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-muted);">${checkedAt}</td>
                    <td style="text-align: center;">
                        <button class="btn-recheck" onclick="recheckDomain(this, '${row.domain}')">
                             <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                            Recheck
                        </button>
                    </td>
                </tr>
                `;
            });
            
            if (matchCount === 0) {
                container.innerHTML = `<tr><td colspan="8" style="padding: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No matching domains found.</td></tr>`;
            } else {
                container.innerHTML = html;
            }
            
            const recordCountEl = document.getElementById("table-record-count");
            if (recordCountEl) {
                recordCountEl.innerText = `${matchCount} items`;
            }
        }


        function filterResultsTable() {
            renderResultsTable(tableDomainsCache, tableResultsCache);
        }

        // 3. Render loaded domains to registry lists
        let registeredDomainsCache = [];
        let lastResultsCache = {};
        function renderDomainsList(domains, lastResults = {}) {
            registeredDomainsCache = domains;
            if (Object.keys(lastResults).length > 0) {
                lastResultsCache = lastResults;
            } else {
                lastResults = lastResultsCache;
            }
            const container = document.getElementById("domains-list-container");
            
            if (domains.length === 0) {
                container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                    No domains monitored. Add a domain to start tracking!
                </div>`;
                return;
            }

            const searchQuery = document.getElementById("search-registry-input").value.toLowerCase().trim ? 
                document.getElementById("search-registry-input").value.toLowerCase().trim() : 
                document.getElementById("search-registry-input").value.toLowerCase();
            
            let html = "";
            let matchCount = 0;
            
            // Sort domains alphabetically for easy lookup in long lists
            const sortedDomains = [...domains].sort((a, b) => a.localeCompare(b));

            sortedDomains.forEach(domain => {
                if (searchQuery && !domain.includes(searchQuery)) {
                    return; // Skip if filter not matched
                }
                matchCount++;
                
                const res = lastResults[domain];
                
                let statusText = "Pending";
                let statusClass = "pending";
                let expiryDate = "Never checked";
                let remainingDaysText = "N/A";
                let daysClass = "failed";
                let remarksHtml = "";
                
                if (res) {
                    statusText = res.status || "Unknown";
                    const sev = res.severity || "Failed";
                    statusClass = sev.toLowerCase();
                    expiryDate = res.expiry_date || "N/A";
                    
                    if (res.days_remaining !== undefined && res.days_remaining !== -1) {
                        remainingDaysText = `${res.days_remaining} days`;
                        
                        if (res.days_remaining <= 0) {
                            daysClass = "expired";
                        } else if (res.days_remaining < 7) {
                            daysClass = "critical";
                        } else if (res.days_remaining < 30) {
                            daysClass = "warning";
                        } else {
                            daysClass = "healthy";
                        }
                    } else {
                        remainingDaysText = "N/A";
                        daysClass = "failed";
                    }
                    
                    if (res.remarks) {
                        remarksHtml = `<div class="domain-remarks">${res.remarks}</div>`;
                    }
                }
                
                html += `
                <div class="domain-item" data-domain="${domain}">
                    <div class="domain-info">
                        <div class="domain-header-row">
                            <span class="domain-name">${domain}</span>
                            <span class="status-badge ${statusClass}">${statusText}</span>
                        </div>
                        <div class="domain-meta-row">
                            <span class="meta-label">Expiry:</span> <span class="meta-val">${expiryDate}</span>
                            <span class="meta-separator">|</span>
                            <span class="meta-label">Remaining:</span> <span class="meta-val days-remaining ${daysClass}">${remainingDaysText}</span>
                        </div>
                        ${remarksHtml}
                    </div>
                    <button class="btn-delete" title="Delete Domain" onclick="deleteTargetDomain('${domain}')">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </div>
                `;
            });

            if (matchCount === 0 && searchQuery) {
                container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                    No matching subdomains found in registry.
                </div>`;
                return;
            }

            container.innerHTML = html;
        }

        // 4. Registry Filter Logic
        function filterRegistryList() {
            renderDomainsList(registeredDomainsCache, lastResultsCache);
        }

        // 5. Add new domain targets via AJAX
        async function addTargetDomain() {
            if (activeOrganization === "all") {
                showToast("Please select a specific organization to add domains.", "error");
                return;
            }
            const input = document.getElementById("new-domain-input");
            const domain = input.value.trim();
            if (!domain) {
                showToast("Please enter a valid domain address.", "error");
                return;
            }

            try {
                const response = await fetch("/api/domains", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain: domain, org_name: activeOrganization })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Domain registered!", "success");
                    input.value = "";
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to add domain.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 6. Delete domain targets via AJAX
        async function deleteTargetDomain(domain) {
            if (!confirm(`Are you sure you want to remove '${domain}' from SSL monitoring?`)) {
                return;
            }

            try {
                const response = await fetch(`/api/domains?domain=${encodeURIComponent(domain)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Domain deleted.", "success");
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to delete domain.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 7. Render recipients list
        function renderRecipients() {
            const container = document.getElementById("recipients-list-container");
            const countLabel = document.getElementById("recipients-count");
            const formContainer = document.getElementById("add-recipient-form");
            const inputField = document.getElementById("new-recipient-input");

            if (!container) return;

            if (activeOrganization === "all") {
                if (formContainer) formContainer.style.display = "none";
                
                // Show a combined list of all recipients for all organizations
                let allRecipients = [];
                for (const org in allOrgRecipientsCache) {
                    const emails = allOrgRecipientsCache[org] || [];
                    emails.forEach(email => {
                        allRecipients.push({ org, email });
                    });
                }

                if (allRecipients.length === 0) {
                    container.innerHTML = `<div class="recipient-empty">No recipients configured.</div>`;
                    countLabel.innerText = "0 recipients";
                    return;
                }

                allRecipients.sort((a, b) => a.email.localeCompare(b.email));

                let html = "";
                allRecipients.forEach(item => {
                    html += `
                    <div class="recipient-item">
                        <div class="email-text">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                            <span>${item.email} <small style="opacity: 0.6; font-size: 0.7rem;">(${item.org})</small></span>
                        </div>
                    </div>
                    `;
                });
                container.innerHTML = html;
                countLabel.innerText = `${allRecipients.length} total`;
            } else {
                if (formContainer) {
                    formContainer.style.display = "flex";
                }
                if (inputField) {
                    inputField.placeholder = `Add recipient to ${activeOrganization}...`;
                }

                const emails = allOrgRecipientsCache[activeOrganization] || [];
                countLabel.innerText = `${emails.length} recipients`;

                if (emails.length === 0) {
                    container.innerHTML = `<div class="recipient-empty">No recipients configured for this org.</div>`;
                    return;
                }

                const sortedEmails = [...emails].sort((a, b) => a.localeCompare(b));
                let html = "";
                sortedEmails.forEach(email => {
                    html += `
                    <div class="recipient-item">
                        <div class="email-text">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                            <span>${email}</span>
                        </div>
                        <button class="btn-remove-recipient" onclick="removeRecipient('${email}')">Remove</button>
                    </div>
                    `;
                });
                container.innerHTML = html;
            }
        }

        // 8. Add recipient via AJAX
        async function addRecipient() {
            if (activeOrganization === "all") {
                showToast("Please select a specific organization to add a recipient.", "error");
                return;
            }
            const input = document.getElementById("new-recipient-input");
            if (!input) return;
            const email = input.value.trim();
            if (!email) {
                showToast("Please enter a valid email address.", "error");
                return;
            }

            try {
                const response = await fetch("/api/recipients", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ org_name: activeOrganization, email: email })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Recipient added!", "success");
                    input.value = "";
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to add recipient.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 9. Remove recipient via AJAX
        async function removeRecipient(email) {
            if (activeOrganization === "all") return;
            if (!confirm(`Are you sure you want to remove recipient '${email}' from '${activeOrganization}'?`)) {
                return;
            }

            try {
                const response = await fetch(`/api/recipients?org_name=${encodeURIComponent(activeOrganization)}&email=${encodeURIComponent(email)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Recipient removed.", "success");
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to remove recipient.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 9b. Recheck single domain
        async function recheckDomain(btn, domain) {
            btn.disabled = true;
            const originalHTML = btn.innerHTML;
            btn.innerHTML = `<svg class="spinner" width="10" height="10" viewBox="0 0 50 50" style="animation: rotate 1s linear infinite; margin-right: 3px;"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" style="stroke-dasharray: 1, 150; stroke-dashoffset: 0; animation: dash 1.5s ease-in-out infinite;"></circle></svg> Checking...`;
            
            showToast(`Initiating manual check for '${domain}'...`, "success");
            
            try {
                const response = await fetch("/api/check-domain", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ domain: domain })
                });
                
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok && resData.success) {
                    showToast(resData.message, "success");
                    
                    // Update cache and re-render
                    if (resData.result) {
                        tableResultsCache[domain] = resData.result;
                        allResultsCache[domain] = resData.result;
                        
                        renderResultsTable(tableDomainsCache, tableResultsCache);
                        filterAndRenderDashboard();
                    }
                } else {
                    showToast(resData.error || `Failed to recheck domain '${domain}'.`, "error");
                    btn.disabled = false;
                    btn.innerHTML = originalHTML;
                }
            } catch (err) {
                showToast("Network dispatch error checking domain.", "error");
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        // 10. Trigger manual background scan check
        async function triggerSSLCheck() {
            const btn = document.getElementById("btn-run-check");
            btn.disabled = true;
            btn.innerHTML = `<svg class="spinner" width="14" height="14" viewBox="0 0 50 50" style="animation: rotate 1s linear infinite; margin-right: 5px;"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" style="stroke-dasharray: 1, 150; stroke-dashoffset: 0; animation: dash 1.5s ease-in-out infinite;"></circle></svg> Scanning...`;
            
            const scopeText = activeOrganization === "all" ? "All Organizations" : `'${activeOrganization}'`;
            showToast(`Dispatched certificate checks for ${scopeText} in the background...`, "success");

            try {
                const response = await fetch("/api/check", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ org_name: activeOrganization })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                
                if (response.ok) {
                    showToast(resData.message, "success");
                } else {
                    showToast(resData.error || "Could not complete check.", "error");
                }
            } catch (err) {
                showToast("Network dispatch error.", "error");
            } finally {
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Run Check Now`;
                    fetchLogs();
                }, 2000);
            }
        }

        // 11. Fetch rotating log files details
        let lastLogLinesSerialized = "";
        async function fetchLogs() {
            const container = document.getElementById("terminal-log-output");
            const label = document.getElementById("status-terminal-label");
            
            try {
                const response = await fetch("/api/logs");
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                if (!response.ok) throw new Error("Logs load error");
                
                const data = await response.json();
                const logs = data.logs || [];
                
                const serialized = logs.join("");
                if (serialized === lastLogLinesSerialized) {
                    return; // Skip if no new log outputs
                }
                
                lastLogLinesSerialized = serialized;
                
                if (logs.length === 0) {
                    container.innerHTML = `<div class="log-line log-warning">[Console] Log file is currently empty. Start standard scans to record checks activity.</div>`;
                    return;
                }

                // Render with styling codes
                let html = "";
                logs.forEach(line => {
                    let className = "log-info";
                    if (line.includes("[WARNING]")) {
                        className = "log-warning";
                    } else if (line.includes("[ERROR]")) {
                        className = "log-error";
                    } else if (line.includes("Success:") || line.includes("completed") || line.includes("dispatched successfully")) {
                        className = "log-success";
                    }
                    
                    // Simple HTML Escape
                    const escapedLine = line
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;");
                        
                    html += `<div class="log-line ${className}">${escapedLine}</div>`;
                });
                
                container.innerHTML = html;
                
                // Auto scroll to bottom
                container.scrollTop = container.scrollHeight;
                
                label.innerText = "Console Buffers Updated";
                setTimeout(() => { label.innerText = "Auto-polling logs"; }, 1500);
                
            } catch (err) {
                label.innerText = "Connection Dropped";
            }
        }

        // 12. Toast dynamic UI helper
        function showToast(message, type = "success") {
            const container = document.getElementById("toast-container");
            const toast = document.createElement("div");
            toast.className = `toast ${type}`;
            
            // Checkmark or Cross SVG icon
            const icon = type === "success" ? 
                `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="color: var(--green);"><polyline points="20 6 9 17 4 12"></polyline></svg>` : 
                `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="color: var(--red);"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;

            toast.innerHTML = `${icon} <span>${message}</span>`;
            container.appendChild(toast);

            // Trigger animation fade-out
            setTimeout(() => {
                toast.classList.add("fade-out");
                toast.addEventListener("animationend", () => {
                    toast.remove();
                });
            }, 4000);
        }

        async function handleLogout() {
            try {
                const response = await fetch("/api/logout", { method: "POST" });
                if (response.ok) {
                    showToast("Successfully logged out. Redirecting...", "success");
                    setTimeout(() => {
                        window.location.reload();
                    }, 800);
                } else {
                    showToast("Logout failed.", "error");
                }
            } catch (err) {
                showToast("Logout failed due to network error.", "error");
            }
        }
    </script>
    <style>
        /* Loading Spinner CSS Keyframes */
        @keyframes rotate {
            100% { transform: rotate(360deg); }
        }
        @keyframes dash {
            0% { stroke-dasharray: 1, 150; stroke-dashoffset: 0; }
            50% { stroke-dasharray: 90, 150; stroke-dashoffset: -35; }
            100% { stroke-dasharray: 90, 150; stroke-dashoffset: -124; }
        }
    </style>
</body>
</html>
"""


# ==========================================
# Application Server Management Entrypoints
# ==========================================

def start_web_server(port: int) -> None:
    """
    Spawns the built-in HTTP server listening on all local/public IP interfaces.
    """
    server_address = ("", port)
    try:
        # Start background cron scheduler daemon thread
        scheduler_thread = threading.Thread(target=background_scheduler, name="BackgroundScheduler", daemon=True)
        scheduler_thread.start()
        logger.info("Background Scheduler daemon thread successfully spawned.")

        httpd = http.server.HTTPServer(server_address, WebAdminHandler)
        logger.info(f"=== Web Admin UI Server started on bind port {port} ===")
        print(f"\n[+] SSL Monitor Web Admin Dashboard is online!")
        print(f"[+] Local Link: http://localhost:{port}")
        print(f"[+] VPS Domain Map: http://your-vps-ip:{port}")
        print("[+] Press Ctrl+C to terminate the daemon server process.\n")
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Web Server shutting down gracefully due to user keyboard interrupt.")
        print("\n[-] Web server terminated. Cleaning local system references.")
    except Exception as e:
        logger.error(f"Failed to initialize HTTP Web Server on port {port}: {e}")
        print(f"[!] Error: Web server failed to start: {e}")


def main() -> None:
    """
    Command Line Entrypoint. Parses commands for CRUD actions, web server hosting, or standard monitor checks.
    """
    import argparse
    parser = argparse.ArgumentParser(
        description="Production-Grade SSL Certificate Expiry Monitor CLI & Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run standard parallel SSL checks on all domains (default)
  python ssl_monitor.py
  
  # Start the web UI admin dashboard
  python ssl_monitor.py --web
  
  # Start the web UI admin dashboard on a custom port
  python ssl_monitor.py --web --port 8080

  # List all currently configured domains
  python ssl_monitor.py --list
  
  # Add domains to the registry
  python ssl_monitor.py --add google.com test.org
  
  # Remove domains from the registry
  python ssl_monitor.py --remove test.org
        """
    )
    parser.add_argument("--add", "-a", nargs="+", metavar="DOMAIN", help="Add one or more domains to the registry")
    parser.add_argument("--remove", "-r", nargs="+", metavar="DOMAIN", help="Remove one or more domains from the registry")
    parser.add_argument("--list", "-l", action="store_true", help="List all currently configured domains")
    parser.add_argument("--web", "-w", action="store_true", help="Start the built-in Web Admin UI dashboard server")
    parser.add_argument("--port", "-p", type=int, default=8800, help="Port to run the Web Admin UI on (default: 8800)")
    parser.add_argument("--encrypt-password", metavar="PASSWORD", help="Encrypt SMTP password and generate secret decryption key")

    args = parser.parse_args()

    if args.add:
        add_domains_cli(args.add)
        sys.exit(0)
    elif args.remove:
        remove_domains_cli(args.remove)
        sys.exit(0)
    elif args.list:
        list_domains_cli()
        sys.exit(0)
    elif args.web:
        start_web_server(args.port)
        sys.exit(0)
    elif args.encrypt_password:
        try:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key().decode()
            f = Fernet(key.encode())
            encrypted = f.encrypt(args.encrypt_password.encode()).decode()
            print("\n=== Encryption Results ===")
            print(f"SMTP_DECRYPTION_KEY={key}")
            print(f"SMTP_PASSWORD=enc:{encrypted}")
            print("\nAdd these two environment variables to your .env file.")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Encryption failed: {e}")
            sys.exit(1)

    # Default action: run the SSL validation check pipeline
    run_monitor(should_exit=True)


if __name__ == "__main__":
    main()
