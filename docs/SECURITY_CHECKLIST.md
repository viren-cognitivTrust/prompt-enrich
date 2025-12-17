## Security Checklist & Validation Guide

This document summarizes key security controls implemented in this project and how to validate them.

### 1. Authentication & Session Management

- **Controls**
  - Bcrypt password hashing with cost factor ≥ 12.
  - Password strength policy: min 12 chars with upper, lower, number, symbol.
  - Password history: last 5 passwords stored, preventing reuse (extension point in `PasswordHistory`).
  - Account lockout after 5 failed login attempts for 15 minutes.
  - Session cookies:
    - `HttpOnly`, `Secure`, `SameSite=Strict`
    - Idle timeout: 30 minutes
    - Absolute lifetime: 8 hours
  - Double-submit cookie CSRF protection for state-changing requests.

- **How to test**
  - Attempt to log in with a wrong password > 5 times and verify lockout.
  - Inspect cookies in browser dev tools:
    - Confirm `HttpOnly`, `Secure`, `SameSite=Strict` on session cookie.
  - Call a POST/PUT/DELETE API without `X-CSRF-Token` or with mismatched value and verify `403`.

### 2. Access Control & RBAC

- **Controls**
  - Roles: `admin`, `user`, `guest` (see `UserRole` enum).
  - Per-request authorization using FastAPI dependencies.
  - Resource-level checks on items (user can only access their own; admin can access all).

- **How to test**
  - Create two normal users and ensure they cannot read/update/delete each other’s items.
  - Ensure endpoints return `403` for insufficient role and `401` for unauthenticated access.

### 3. Input Validation, Sanitization & Injection Protection

- **Controls**
  - Pydantic models for all API inputs and outputs.
  - Strong length/format checks on strings, emails, and IDs.
  - ORM-based DB access using SQLAlchemy; no string-concatenated SQL.
  - `bleach` sanitization on user-generated HTML fields.

- **How to test**
  - Try to submit overlong strings, invalid emails, and boundary values → expect `422` / validation errors.
  - Use SQL injection payloads (manual or `sqlmap`) and verify they do not succeed.
  - Test XSS payloads in item content and confirm they are neutralized in the UI.

### 4. Cryptography & Data Protection

- **Controls**
  - AES-256-GCM encryption for PII fields (email) at application layer.
  - Encrypted data stored as `(key_id, nonce, ciphertext)`; keys abstracted via provider.
  - Email stored hashed (SHA-256) for lookups; decrypted only for display.

- **How to test**
  - Inspect DB and confirm email values are encrypted and not readable.
  - Verify email lookups (login/registration) still work correctly.

### 5. Communications & Network Security

- **Controls**
  - Nginx configured for **TLS 1.3 only** and strong cipher suites.
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers at Nginx and backend.
  - CORS restricted to configured origins, no `*` in production.

- **How to test**
  - Run SSL Labs scan against the deployed endpoint; target **A+**.
  - Use `curl -v` to confirm TLS 1.3 and header presence (HSTS, CSP, etc.).
  - Try calling the API from a non-whitelisted origin and verify CORS failure.

### 6. Rate Limiting & DoS Resilience

- **Controls**
  - Nginx:
    - `auth_zone`: ~5 requests/minute for `/api/v1/auth/*`.
    - `general_zone`: ~100 requests/minute for general endpoints.
  - Backend:
    - SlowAPI rate limiting decorators for auth and item endpoints.

- **How to test**
  - Script repeated login attempts > limit and confirm `429 Too Many Requests`.
  - Observe `Retry-After` headers where applicable.

### 7. Logging, Monitoring & Incident Response (Hooks)

- **Controls**
  - Structured JSON logging via `structlog`.
  - Security events logged:
    - Login success/failure, account lockout.
    - Session expiry and logout.
    - Authorization failures and validation errors.
  - Logs are stdout-friendly for aggregation by ELK / cloud logging.

- **How to test**
  - Tail container logs during auth failures and access-denied events; confirm presence and lack of PII.
  - Integrate with your log stack and create alerts for:
    - ≥5 failed logins for same account in 5 minutes.
    - Spikes in `4xx`/`5xx` errors.

### 8. Dependency & Container Security

- **Controls**
  - Pinned backend dependencies in `backend/requirements.txt`.
  - Non-root users in backend and Nginx containers.
  - Read-only root filesystems with explicit writable mounts.

- **How to test**
  - Run `pip-audit` in `backend/` and `npm audit` in `frontend/`.
  - Scan container images with Trivy:

    ```bash
    trivy image secure-backend-image
    trivy image secure-nginx-image
    ```

  - Confirm containers do not run as `root` (e.g., `docker exec whoami`).

### 9. Pre-Deployment Checklist (Summary)

- All secrets sourced from a secret manager / KMS (no `.env` in production).
- TLS 1.3 with strong ciphers; valid CA certificates.
- HSTS, CSP, XFO, XCTO headers present and correct.
- Authentication and authorization verified.
- Rate limiting enforced at Nginx and application layers.
- DB credentials and roles aligned with principle of least privilege.
- Security logging integrated with centralized logging system.
- Automated backups operational and tested.


