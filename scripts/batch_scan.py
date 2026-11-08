"""Queue a list of websites for auditing through the admin API.

Usage:  .venv/bin/python scripts/batch_scan.py sites/eu_sites.txt [--base http://127.0.0.1:8000]
The admin password is read from CC_ADMIN_PASSWORD, or from runs/.admin_password.
"""

import argparse
import os
import sys
from pathlib import Path

import httpx

ap = argparse.ArgumentParser()
ap.add_argument("file")
ap.add_argument("--base", default="http://127.0.0.1:8000")
ap.add_argument("--user", default=os.environ.get("CC_ADMIN_USER", "admin"))
a = ap.parse_args()

password = os.environ.get("CC_ADMIN_PASSWORD") or (Path(__file__).resolve().parent.parent / "runs/.admin_password").read_text().strip()
urls = [l.strip() for l in Path(a.file).read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]

with httpx.Client(base_url=a.base, timeout=30) as c:
    r = c.post("/api/auth/login", json={"user": a.user, "password": password})
    if r.status_code != 200:
        sys.exit(f"login failed: {r.text}")
    r = c.post("/api/admin/batch", json={"urls": urls})
    if r.status_code != 200:
        sys.exit(f"batch failed: {r.text}")
    body = r.json()
    print(f"queued {body['queued']} audits; invalid: {body['invalid'] or 'none'}")
