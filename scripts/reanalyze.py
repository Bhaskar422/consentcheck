"""Re-score saved audits with the current analysis rules, from the stored evidence.

The network logs, cookies and screenshots are not touched; findings.json,
report_summary.json, the manifest and scan.json are rewritten, and an event
records that the audit was re-scored. Run it while the server is stopped.

Usage: .venv/bin/python scripts/reanalyze.py
"""

import json
import sys
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sandbox"))

# runner.py imports Playwright at module level; only its classifier is needed here.
_pw = types.ModuleType("playwright.sync_api")
_pw.Error, _pw.sync_playwright = Exception, None
sys.modules.setdefault("playwright", types.ModuleType("playwright"))
sys.modules.setdefault("playwright.sync_api", _pw)

from runner import classify  # noqa: E402

from app import orchestrator  # noqa: E402
from app.analysis import analyze  # noqa: E402

changed = 0
for scan_file in sorted(orchestrator.RUNS_DIR.glob("*/scan.json")):
    d = scan_file.parent
    scan = json.loads(scan_file.read_text())
    old = scan.get("result")
    if scan.get("status") != "done" or not old or not (d / "requests.json").exists():
        continue
    if old["verdict"] == "CONTAINED" or "time limit" in old.get("headline", ""):
        continue  # decided by the sandbox, not by the network evidence

    title, kinds = "", set()
    for e in scan["events"]:
        if e["title"] == "Opened the page":
            title = e["detail"].rsplit(" · ", 1)[0]
        elif e["title"].startswith("Skipped “"):
            kinds.add(classify(e["title"][len("Skipped “"):-1]))
        elif e["title"].startswith("Clicking “"):
            cand = (e.get("data") or {}).get("candidate") or {}
            text = e["title"][len("Clicking “"):-1]
            kind = classify(text)
            # Same rule as the sandbox: a known consent platform's reject button
            # counts unless its label says otherwise (Quantcast's is ambiguous).
            if cand.get("cmp") and cand["cmp"] != "Quantcast" and kind is None:
                kind = "reject"
            kinds.add(kind)
    # A click only counts as a refusal if, under today's rules, it is one
    # (derived from the recorded clicks, so re-running this script is idempotent).
    click_failed = any(e["title"] == "Click failed" for e in scan["events"])
    choice_made = bool(kinds & {"reject", "save"}) and not click_failed
    proxy_log = []
    if (d / "proxy_log.jsonl").exists():
        proxy_log = [json.loads(l) for l in (d / "proxy_log.jsonl").read_text().splitlines() if l.strip()]

    findings = analyze(page_url=scan["url"], requests=json.loads((d / "requests.json").read_text()),
                       cookies=json.loads((d / "cookies.json").read_text()), proxy_log=proxy_log,
                       choice_made=choice_made, banner_found=old["banner_found"],
                       page_title=title, seen_kinds=kinds)
    findings["sandbox_secret_env_vars"] = old.get("sandbox_secret_env_vars", [])
    if findings["verdict"] == old["verdict"] and findings["headline"] == old["headline"]:
        continue

    summary = orchestrator.template_report(findings)
    scan["result"], scan["summary"] = findings, summary
    (d / "findings.json").write_text(json.dumps(findings, indent=1, default=list))
    (d / "report_summary.json").write_text(json.dumps(summary, indent=1))
    scan["evidence"] = orchestrator.build_manifest(d)
    scan["events"].append({
        "i": len(scan["events"]), "t": round(time.time() - scan["created"], 2), "kind": "evidence",
        "title": f"Re-scored with updated rules: {old['verdict']} → {findings['verdict']}",
        "detail": findings["headline"], "image": None, "data": None,
    })
    scan_file.write_text(json.dumps(scan, indent=2, default=list))
    changed += 1
    print(f"{old['verdict']:>12} -> {findings['verdict']:<12} {scan['url'][:45]:45} {findings['headline'][:70]}")

print(f"\nre-scored {changed} audits")
