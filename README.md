## Secure Full-Stack Demo Application

This project is a production-grade, security-focused web application stack:

- **Frontend**: React + TypeScript + Tailwind CSS (SPA)
- **Backend**: FastAPI + SQLAlchemy + PostgreSQL
- **Reverse Proxy**: Nginx (TLS 1.3, security headers, rate limiting)
- **Infrastructure**: Docker / Docker Compose

It is designed around **OWASP Top 10 (2021)**, **ASVS Level 2**, and **ISO 27001** alignment, with security built into every layer.

### High-Level Architecture

- **Nginx**
  - Terminates TLS 1.3
  - Serves the built React SPA
  - Proxies `/api/` traffic to the FastAPI backend
  - Enforces rate limiting and security headers (defense in depth with backend)
- **FastAPI backend**
  - Session-based authentication using secure, `HttpOnly`, `Secure`, `SameSite=Strict` cookies
  - CSRF protection using double-submit cookie pattern
  - RBAC with `admin`, `user`, `guest` roles
  - Encrypted PII fields using AES-256-GCM
  - Strong password policy and password history
  - Structured security logging and rate limiting
- **PostgreSQL**
  - Access via a least-privilege application user
  - All queries through SQLAlchemy ORM (no string-concatenated SQL)

### Local Development (Non-Production)

1. **Backend**

   ```bash
   cd backend
   cp .env.example .env  # edit values as needed
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install --upgrade pip
   pip install -r requirements.txt
   # Run DB migrations (once Alembic migrations are generated)
   # alembic upgrade head
   uvicorn app.main:app --reload
   ```

2. **Frontend**

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

3. **Docker Compose (full stack)**

   ```bash
   docker compose up --build
   ```

   - Nginx: `https://localhost` (TLS 1.3, self-signed by default)
   - API: proxied via Nginx at `/api/v1/...`

> **Important**: The included `.env.example` and Docker config are **for local development only**. In production, all secrets (DB credentials, encryption keys, JWT keys) must come from a **cloud secret manager / KMS**, not from `.env` files or environment variables stored in version control.

### Security Highlights

- **Authentication & Sessions**
  - Bcrypt password hashing with cost ≥ 12
  - Password strength policy (min 12 chars, upper/lower/number/symbol)
  - Password history (last 5 hashes) to prevent reuse
  - Account lockout after 5 failed attempts (15 minutes)
  - Session timeout: 30 minutes idle, 8 hours absolute
  - Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- **Authorization**
  - Centralized dependencies for `current_user` and role checks
  - Resource-level checks so users can only access their own data
- **Data Protection**
  - AES-256-GCM encryption for PII (email) at the application layer
  - Email stored as hash (for lookup) + encrypted value (for display)
  - PII never logged or returned in clear text; masked in API responses
- **Input Validation & Sanitization**
  - Pydantic models for all request/response schemas
  - Strict length, type, and format validation
  - HTML content sanitized server-side with `bleach`
- **XSS & Clickjacking**
  - React’s default escaping on the frontend
  - No `dangerouslySetInnerHTML` used
  - CSP, HSTS, `X-Frame-Options=DENY`, `X-Content-Type-Options=nosniff`
- **Rate Limiting**
  - Global per-IP limits for general endpoints
  - Stricter limits for authentication endpoints (e.g., 5/minute)
- **Logging & Monitoring**
  - JSON structured logs via `structlog`
  - Security events logged (auth attempts, access denied, validation failures)

### Security Testing Pointers

Use the `docs/SECURITY_CHECKLIST.md` for a concise list of:

- SAST / DAST tools to run (Bandit, npm audit, Trivy, OWASP ZAP, etc.)
- Checklist for OWASP Top 10 coverage
- Pre-deployment and post-deployment verification steps

This project is intended as a **secure-by-default reference** that you can extend and harden further for your specific cloud environment (AWS/GCP/Azure). For production, integrate:

- Managed PostgreSQL (RDS / Cloud SQL / Azure Database for PostgreSQL)
- Cloud secret management & KMS for keys
- Centralized logging (ELK / CloudWatch / Stackdriver / Azure Monitor)
- WAF / CDN in front of Nginx


"# prompt-enrich" 
"# prompt-enrich" 
