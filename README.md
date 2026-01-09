# LockList Security

M365 security/compliance scanner (SOC2-lite) that runs checks against Microsoft Graph and produces gap reports + evidence exports.

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.template .env
# edit .env
uvicorn main:app --reload
