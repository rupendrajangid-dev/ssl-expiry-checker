# Implementation Plan - Per-Organization Email Recipient Lists

We will add support for storing and managing a separate list of email recipients for each organization. When a scan runs for a specific org, alerts will be sent **only** to that org's recipients. When "All Organizations" is selected, alerts will be sent to all recipients across all orgs (deduplicated). The `.env` `SMTP_RECEIVER_EMAILS` will serve as the **global fallback** for any org without custom recipients.

---

## User Review Required

> [!IMPORTANT]
> **Data Storage**: Org recipients will be stored inside `domains.json` under a new `"org_recipients"` key alongside `"orgs"`, keeping all configuration in a single file. Example:
> ```json
> {
>   "domains": ["tagid.co.in", "smartiam.in"],
>   "orgs": {
>     "Tagid": ["tagid.co.in"],
>     "IESG Labs": ["smartiam.in"]
>   },
>   "org_recipients": {
>     "Tagid": ["admin@tagid.co.in", "devops@tagid.co.in"],
>     "IESG Labs": ["ops@iesglabs.com"]
>   }
> }
> ```

> [!IMPORTANT]
> **Email Routing Logic**:
> - **Org-scoped scan** (e.g. "Tagid"): Sends email **only** to recipients listed in `org_recipients["Tagid"]`. If the org has no custom recipients, falls back to the `.env` `SMTP_RECEIVER_EMAILS`.
> - **Global scan** ("All Organizations" / CLI Script Run / Cron): Splits check results by organization. For each organization, it generates a scoped report containing only that organization's domains and sends it **only** to that organization's recipients (or the global fallback). This prevents sending a full unified report to all recipients.

---

## Open Questions

None. The schema extension is backward-compatible — `org_recipients` is optional and self-healing.

---

## Proposed Changes

### Core Monitoring Engine & API Handlers

#### [MODIFY] [ssl_monitor.py](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py)

##### 1. Schema Extension — `migrate_and_load_registry`
- Load the new `org_recipients` key from `domains.json` (default to `{}` if missing).
- Return it as a third tuple value: `Tuple[List[str], Dict[str, List[str]], Dict[str, List[str]]]`.
- Update all callers to unpack the new return value (add `_` where recipients aren't needed).

##### 2. Backend CRUD — New Recipient Management Endpoints
- **`GET /api/recipients`**: Returns `org_recipients` dictionary from `domains.json`.
- **`POST /api/recipients`**: Accepts `{"org_name": "Tagid", "email": "user@example.com"}` and adds the email to that org's recipient list.
- **`DELETE /api/recipients`**: Accepts `?org_name=Tagid&email=user@example.com` and removes that email from the org's list.

##### 3. Email Routing — Update `send_email_alert` and `run_monitor`
- Add `org_name` parameter to `send_email_alert`.
- When `org_name` is set and not `"all"`:
  - Load `org_recipients` from registry and use only that org's list.
  - Fall back to `.env` `SMTP_RECEIVER_EMAILS` if the org has no custom recipients.
- When `org_name` is `"all"` or `None`:
  - Merge all `org_recipients` values + `.env` fallback, deduplicate.
- Pass `org_name` from `run_monitor` through to `send_email_alert`.

##### 4. Frontend UI — Recipient Management Panel
- Add a **"Manage Recipients"** section inside the dashboard view, visible when a specific org is selected.
- Shows a list of current recipients for the active org with delete buttons.
- Includes an input field + "Add" button to add new recipient emails.
- "All Organizations" view shows a consolidated read-only list of all recipients across all orgs.

---

## Verification Plan

### Automated Tests
1. Start the server, authenticate, and test CRUD operations:
   - `POST /api/recipients` with `{"org_name": "Tagid", "email": "test@example.com"}` → verify `200` success.
   - `GET /api/recipients` → verify `test@example.com` appears under `"Tagid"`.
   - `DELETE /api/recipients?org_name=Tagid&email=test@example.com` → verify `200` success.
   - `GET /api/recipients` → verify `test@example.com` is removed.

### Manual Verification
1. Open the Web UI, select "Tagid", add a recipient email via the UI.
2. Switch to "IESG Labs", add a different recipient.
3. Verify `domains.json` contains the correct `org_recipients` structure.
4. Trigger a scoped check for "Tagid" and confirm server logs reference only Tagid's recipients.
