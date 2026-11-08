"""Aggregate statistics for the admin dashboard, computed from saved scans."""

import re
from collections import Counter, defaultdict

from .analysis import EU_VANTAGE

DEMO_SUFFIX = ".consentcheck.test"

COUNTRY = {
    "de": "Germany", "fr": "France", "uk": "United Kingdom", "it": "Italy", "es": "Spain",
    "nl": "Netherlands", "se": "Sweden", "no": "Norway", "dk": "Denmark", "pl": "Poland",
    "at": "Austria", "be": "Belgium", "ie": "Ireland", "pt": "Portugal", "gr": "Greece",
    "cz": "Czechia", "hu": "Hungary", "fi": "Finland", "ch": "Switzerland", "ro": "Romania",
    "eu": "EU (.eu)",
}


def _host(scan):
    r = scan.get("result") or {}
    return (r.get("host") or scan["url"].split("/")[2]).lower()


def country_of(host: str, url: str = "") -> str:
    tld = host.rstrip(".").rsplit(".", 1)[-1]
    if tld in COUNTRY:
        return COUNTRY[tld]
    # Country sections on .com sites, e.g. ikea.com/de/de/ or zara.com/fr/
    m = re.match(r"https?://[^/]+/([a-z]{2})(?:[/-]|$)", url.lower())
    if m and m.group(1) in COUNTRY:
        return COUNTRY[m.group(1)]
    return "International (." + tld + ")"


def country_code(host: str, url: str = "") -> str:
    tld = host.rstrip(".").rsplit(".", 1)[-1]
    if tld in COUNTRY:
        return "." + tld
    m = re.match(r"https?://[^/]+/([a-z]{2})(?:[/-]|$)", url.lower())
    return f".{tld}/{m.group(1)}" if m and m.group(1) in COUNTRY else "." + tld


def row(scan) -> dict:
    r = scan.get("result") or {}
    c = r.get("counts") or {}
    vendors = [v for v in r.get("vendors", []) if v.get("severity") in ("high", "medium") and v.get("after_reject")]
    host = _host(scan)
    destroyed = ((scan.get("containment") or {}).get("destroyed") or {}).get("destroyed")
    return {
        "id": scan["id"], "url": scan["url"], "host": host, "status": scan["status"],
        "created": scan["created"], "finished": scan.get("finished"),
        "verdict": r.get("verdict"), "headline": r.get("headline"),
        "demo": host.endswith(DEMO_SUFFIX), "country": country_of(host, scan["url"]),
        "code": country_code(host, scan["url"]),
        "after_reject": c.get("trackers_after_reject", 0),
        "before_choice": c.get("trackers_before_choice", 0),
        "cookies": c.get("tracking_cookies_after_reject", 0),
        "blocked": c.get("blocked_by_guard", 0),
        "vendors": [v["vendor"] for v in vendors],
        "lied": any(v.get("consent_signal_after_reject") == "granted" for v in r.get("vendors", [])),
        "banner_found": r.get("banner_found"), "choice_made": r.get("choice_made"),
        "approved": (scan.get("approval") or {}).get("decision"),
        "consent_or_pay": bool(r.get("consent_or_pay")),
        "destroyed": bool(destroyed),
    }


def stats(scans) -> dict:
    rows = [row(s) for s in sorted(scans, key=lambda s: s["created"], reverse=True)]
    done = [r for r in rows if r["status"] == "done" and r["verdict"]]
    # Site-level figures use the latest finished audit of each site (rows are newest first).
    real, seen_hosts = [], set()
    for r in done:
        if not r["demo"] and r["host"] not in seen_hosts:
            seen_hosts.add(r["host"])
            real.append(r)
    verdicts = Counter(r["verdict"] for r in real)
    # Tracking figures only count sites where a verdict was possible.
    concl = [r for r in real if r["verdict"] in ("FAIL", "PASS", "REVIEW")]
    conclusive = verdicts["FAIL"] + verdicts["PASS"] + verdicts["REVIEW"]

    vendor_sites = Counter()
    for r in concl:
        for v in set(r["vendors"]):
            vendor_sites[v] += 1

    by_country = defaultdict(lambda: {"audits": 0, "fail": 0, "codes": Counter()})
    for r in real:
        if r["verdict"] in ("FAIL", "PASS", "REVIEW"):
            by_country[r["country"]]["audits"] += 1
            by_country[r["country"]]["fail"] += r["verdict"] == "FAIL"
            by_country[r["country"]]["codes"][r["code"]] += 1
    countries = sorted(({"country": k, "audits": v["audits"], "fail": v["fail"], "fail_rate": v["fail"] / v["audits"],
                         "code": v["codes"].most_common(1)[0][0]} for k, v in by_country.items()),
                       key=lambda x: (-x["audits"], x["country"]))

    finished = [r for r in rows if r["status"] in ("done", "error")]
    ai_calls = [c for s in scans for c in (s.get("ai") or {}).get("calls", [])]
    latencies = [c["latency_ms"] for c in ai_calls if c.get("latency_ms")]

    return {
        "totals": {
            "audits": len(rows),
            "real_sites": len(real),
            "demo_runs": sum(r["demo"] for r in done),
            "queued": sum(r["status"] == "queued" for r in rows),
            "running": sum(r["status"] == "running" for r in rows),
            "errors": sum(r["status"] == "error" for r in rows),
            "conclusive": conclusive,
            "fail": verdicts["FAIL"],
            "fail_rate": verdicts["FAIL"] / conclusive if conclusive else None,
            "sites_tracking_after_reject": sum(r["after_reject"] > 0 for r in concl),
            "sites_tracking_before_choice": sum(r["before_choice"] > 0 for r in concl),
            "sites_lying_to_google": sum(r["lied"] for r in concl),
            "consent_or_pay": sum(r["consent_or_pay"] for r in real),
            "blocked_bot": sum(bool(r["headline"] and "blocked or challenged" in r["headline"]) for r in real),
            "no_banner_shown": sum(bool(r["headline"] and "No consent banner was shown" in r["headline"]) for r in real),
            "eu_vantage": EU_VANTAGE,
            "trackers_after_reject": sum(r["after_reject"] for r in concl),
            "tracking_cookies_after_reject": sum(r["cookies"] for r in concl),
            "attacks_blocked": sum(r["blocked"] for r in done),
            "contained": sum(r["verdict"] == "CONTAINED" for r in done),
            "sandboxes_destroyed": sum(r["destroyed"] for r in finished),
            "sandboxes_finished": len(finished),
            "approved": sum(r["approved"] == "approved" for r in rows),
            "ai_calls": len(ai_calls),
            "ai_avg_latency_ms": round(sum(latencies) / len(latencies)) if latencies else None,
        },
        "verdicts": {k: verdicts.get(k, 0) for k in ("FAIL", "REVIEW", "PASS", "INCONCLUSIVE", "CONTAINED")},
        "top_vendors": [{"vendor": v, "sites": n} for v, n in vendor_sites.most_common(12)],
        "countries": countries,
        "rows": rows,
    }
