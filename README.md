# LockList Security (One‑time scan MVP)

A **one‑time Microsoft 365 security checkup** web app:

- User signs in with Microsoft 365 (Entra ID)
- App runs a scan via Microsoft Graph using the user's delegated token
- Results are stored (SQLite by default)
- Download reports: **PDF / CSV / JSONL**

## Setup (Azure app registration)

Create an App Registration in Azure (Entra ID) and configure:

1) **Supported account types**: "Accounts in any organizational directory" (multi‑tenant) is easiest.
2) **Authentication**:
   - Add a **SPA** redirect URI: `http://localhost:8000/`
   - Enable "Access tokens" and "ID tokens" (implicit/hybrid is OK for local dev)
3) **API permissions (Delegated)** (admin consent required for most):
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `RoleManagement.Read.Directory`
   - `UserAuthenticationMethod.Read.All`
   - `Organization.Read.All`

> Tip: after adding permissions, click **Grant admin consent**.

## Local run

```bat
cd C:\Users\<you>\...\locklistsecurity-onetime
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

copy .env.template .env
notepad .env  # set AZURE_CLIENT_ID

uvicorn main:app --reload
```

Open: http://127.0.0.1:8000

## What the scan checks (MVP)

- Conditional Access MFA (admins, all users)
- Block legacy auth (best‑effort heuristic)
- Privileged role assignments
- Directory roles + membership counts
- MFA registration coverage
- Per-user auth methods (sample)
- Sign-in logs (sample)
- Directory audit logs (sample)
- Applied Conditional Access policies visibility
- Tenant licensing (subscribed SKUs)

## Security notes

- This MVP does **not** store Microsoft tokens. The browser gets an access token and sends it to the backend for the one scan.
- For production, add stricter JWT validation, rate limiting, and hard tenant isolation.

