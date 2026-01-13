# LockList Security

M365 security/compliance scanner (SOC2-lite) that connects to Microsoft Graph (app-only), runs security posture checks, and generates gap reports + evidence exports.

This repo contains a working FastAPI skeleton and the database models. You can add your Graph client, checks, scan engine, and report generation under `core/`.

## Quickstart (local)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.template .env
# edit .env

uvicorn main:app --reload
```

Open:
- App: http://localhost:8000
- API Docs: http://localhost:8000/api/v1/docs

## What to commit vs. never commit

✅ Commit:
- All source code in `core/` and `api/`
- `requirements.txt`
- `.env.template` (placeholders only)
- `README.md`

❌ Never commit:
- `.env`
- any client secrets/certificates
- scan outputs (PDF/CSV/JSONL), databases, or evidence blobs

## Project layout

```
.
├─ api/
│  ├─ __init__.py
│  └─ m365_routes.py
├─ core/
│  ├─ __init__.py
│  ├─ database.py
│  └─ m365_models.py
├─ frontend/
│  └─ index.html
├─ main.py
├─ requirements.txt
├─ .env.template
└─ .gitignore
```
