# Implementation Plan - Secure SMTP Password Encryption

We will add support for storing the SMTP password in a symmetrically encrypted format inside the `.env` file. This prevents the plain-text password from being readable to anyone with access to the server or file system without the separate decryption key.

We will use the **Fernet** symmetric encryption standard (which uses AES-128 in CBC mode with HMAC-SHA256) from Python's standard `cryptography` package. The decryption key will be managed separately as a distinct environment variable (`SMTP_DECRYPTION_KEY`).

---

## User Review Required

> [!IMPORTANT]
> **Dependency Update**:
> This adds the `cryptography` package as a dependency in `requirements.txt`.
>
> **Key Management**:
> - The decryption key (`SMTP_DECRYPTION_KEY`) must **not** be stored in your code repository.
> - To be fully secure, the `SMTP_DECRYPTION_KEY` should be set in the host server's system environment variables (e.g., in the Systemd service configuration or Docker Compose secrets/env), while `.env` stores only the encrypted password `SMTP_PASSWORD=enc:...`.

---

## Proposed Changes

### Dependencies

#### [MODIFY] [requirements.txt](file:///e:/Tagid/ssl-expiry-checker/requirements.txt)
- Add `cryptography` dependency for encryption/decryption routines.

### Core Monitoring Script

#### [MODIFY] [ssl_monitor.py](file:///e:/Tagid/ssl-expiry-checker/ssl_monitor.py)

##### 1. Command Line encryption helper
- Add a new CLI argument `--encrypt-password` in `main()` to allow users to generate an encryption key and encrypt their plain password securely.
- If run with `python ssl_monitor.py --encrypt-password "your_password"`, it will output the keys to copy-paste into `.env`.

##### 2. Runtime decryption logic
- Modify `send_email_alert` credentials fetch:
  - Check if `smtp_pass` starts with `enc:`.
  - If so, retrieve `SMTP_DECRYPTION_KEY` from the environment.
  - Decrypt `smtp_pass` using Fernet.
  - Fail gracefully (log error, skip mail) if decryption fails or the decryption key is missing.

### Environment Templates

#### [MODIFY] [.env.example](file:///e:/Tagid/ssl-expiry-checker/.env.example)
- Add placeholder for `SMTP_DECRYPTION_KEY` and comment explaining the format for encrypted passwords.

### Documentation

#### [MODIFY] [docs/deployment_guide.md](file:///e:/Tagid/ssl-expiry-checker/docs/deployment_guide.md)
- Document the steps to generate the encrypted password, set up the decryption key, and secure the daemon configurations.

---

## Verification Plan

### Automated Tests
1. Generate an encrypted password using:
   ```bash
   python ssl_monitor.py --encrypt-password "test-password"
   ```
2. Verify that it prints both `SMTP_DECRYPTION_KEY` and `SMTP_PASSWORD=enc:...`.
3. Run the unit tests we wrote in `verify_sender_name.py`, expanding them to cover password decryption:
   - Verify that an encrypted password + correct key decrypts successfully and sends mail.
   - Verify that an encrypted password + missing/incorrect key fails cleanly.
