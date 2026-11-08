"""Turn raw sandbox evidence into findings.

This step is deliberately deterministic: the verdict is computed from network
requests and cookies, never from what a model (or the page) claims. A page
that prompt-injects the agent can't change a single number here.
"""

import fnmatch
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TRACKERS = json.loads((Path(__file__).parent / "trackers.json").read_text())

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "com.br", "com.mx", "co.in", "net.in", "co.za", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.cn", "com.ar", "co.kr", "com.pl", "com.es", "com.pt", "co.il",
}
# Consent platforms and plain CDNs: expected after a refusal, not trackers.
INFRASTRUCTURE = (
    "onetrust.com", "cookielaw.org", "privacy-mgmt.com", "sp-prod.net", "cookiebot.com", "usercentrics.eu",
    "didomi.io", "consentmanager.net", "iubenda.com", "trustarc.com", "truste.com", "osano.com",
    "cookieyes.com", "termly.io", "cookiefirst.com", "quantcast.mgr.consensu.org", "fundingchoicesmessages.google.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com", "gstatic.com", "cdnjs.cloudflare.com",
    "jsdelivr.net", "unpkg.com", "cloudfront.net", "akamaized.net", "akamaihd.net", "fastly.net",
    "cloudflare.com", "cloudinary.com", "imgix.net", "shopifycdn.com", "shopify.com", "jquery.com",
    "bootstrapcdn.com", "typekit.net", "use.fontawesome.com", "recaptcha.net", "hcaptcha.com",
    "youtube-nocookie.com", "vimeocdn.com", "ytimg.com", "stripe.com", "paypal.com",
)
SUSPICIOUS = re.compile(
    r"(^|[.\-])(ads?|adserv\w*|advert\w*|track\w*|pixel|analytics?|metrics?|collect|beacon|stats?|sync|rtb|bid\w*|"
    r"tag|tags|telemetry|insight|measure\w*|retarget\w*|audience\w*|match|segment|cdp|exfil)([.\-]|$)",
    re.I,
)
AFTER_PHASES = {"after_reject", "after_reject_reload"}
HIGH_CATEGORIES = {"advertising", "analytics", "session_replay"}
# Resource types that only download a vendor's code, not send a tracking hit.
LIBRARY_TYPES = {"script", "stylesheet", "font"}
# Whether the scanner sits in the EU. Many sites show cookie banners only to EU
# visitors, so "no banner" can only be judged from an EU vantage point.
EU_VANTAGE = os.environ.get("CC_EU_VANTAGE", "").lower() in ("1", "true", "yes")
BOT_WALL = re.compile(
    r"access denied|just a moment|confirm you are human|verifying|verify you are|are you a robot|kein roboter|"
    r"captcha|could not be satisfied|attention required|forbidden|invalid url|maintenance|schiefgelaufen|oops|"
    r"zugriff verweigert|you have been blocked|bist du ein mensch|security check", re.I)
CONSENT_GATE = re.compile(r"privacy gate|consent wall", re.I)
LIBRARY_PATH = re.compile(r"\.(m?js|css)(\.gz)?$|\.gz\.js$", re.I)
CATEGORY_LABEL = {
    "advertising": "Advertising", "analytics": "Analytics",
    "session_replay": "Session replay", "tag_manager": "Tag manager",
}


def site_of(host: str) -> str:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


GOOGLE_HOST = re.compile(r"(^|\.)google\.[a-z]{2,3}(\.[a-z]{2})?$")
GOOGLE_ADS = next(t for t in TRACKERS if t["vendor"].startswith("Google Ads"))


def _match_tracker(host: str, path: str):
    # Remarketing pings go to google.<any ccTLD>/pagead/...
    if GOOGLE_HOST.search(host) and path.startswith(("/pagead", "/ads/")):
        return GOOGLE_ADS
    for t in TRACKERS:
        for m in t["match"]:
            dom, _, pfx = m.partition("/")
            if host == dom or host.endswith("." + dom):
                if not pfx or path.lstrip("/").startswith(pfx):
                    return t
    return None


def _match_cookie(name: str):
    for t in TRACKERS:
        for pat in t["cookies"]:
            if fnmatch.fnmatchcase(name, pat):
                return t
    return None


def _consent_signal(url: str):
    """Google Consent Mode: gcs=G1<ad_storage><analytics_storage>."""
    try:
        gcs = parse_qs(urlparse(url).query).get("gcs", [None])[0]
    except ValueError:
        return None
    if not gcs or len(gcs) < 4 or not gcs.startswith("G1"):
        return None
    return "granted" if "1" in gcs[2:4] else "denied"


def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def analyze(*, page_url: str, requests: list, cookies: dict, proxy_log: list,
            choice_made: bool, banner_found: bool, page_title: str = "", seen_kinds=()) -> dict:
    first_party = site_of(urlparse(page_url).hostname or "")
    proxy_allowed_hosts = {e.get("host") for e in proxy_log if e.get("action") in ("allowed", "demo")}
    blocked = [e for e in proxy_log if e.get("action") == "blocked"]

    vendors = {}
    unclassified = Counter()
    third_party_after = 0

    def vendor_entry(t):
        v = vendors.get(t["vendor"])
        if v is None:
            v = vendors[t["vendor"]] = {
                "vendor": t["vendor"], "category": t["category"],
                "category_label": CATEGORY_LABEL.get(t["category"], t["category"]),
                "before_choice": 0, "after_reject": 0, "hits_before_choice": 0, "hits_after_reject": 0,
                "examples": {"before_choice": [], "after_reject": []},
                "cookies_before": [], "cookies_after": [],
                "consent_signals": set(), "hosts": set(), "proxy_confirmed": False,
                "fix": t["fix"],
            }
        return v

    for r in requests:
        url = r.get("url", "")
        if not url.startswith(("http://", "https://")):
            continue
        if r.get("blocked_by_guard"):
            continue
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if not host:
            continue
        phase = r.get("phase") if choice_made else "before_choice"
        bucket = "after_reject" if phase in AFTER_PHASES else "before_choice"
        is_third = site_of(host) != first_party
        if is_third and bucket == "after_reject":
            third_party_after += 1
        t = _match_tracker(host, u.path)
        if t is None:
            infra = any(host == d or host.endswith("." + d) for d in INFRASTRUCTURE)
            if is_third and bucket == "after_reject" and not infra:
                unclassified[host] += 1
            continue
        v = vendor_entry(t)
        v[bucket] += 1
        if r.get("type") not in LIBRARY_TYPES and not LIBRARY_PATH.search(u.path):
            v["hits_" + bucket] += 1   # an actual beacon/pixel/XHR, not just the script file
        v["hosts"].add(host)
        if len(v["examples"][bucket]) < 3:
            v["examples"][bucket].append({"url": url[:400], "t": r.get("t"), "status": r.get("status")})
        sig = _consent_signal(url)
        if sig and bucket == "after_reject":
            v["consent_signals"].add(sig)

    tracking_cookies_after = []
    # A cookie that already existed before the click is evidence of tracking
    # *before* the choice; only cookies that appear after the refusal count as
    # set after Reject all.
    before_keys = {(c.get("name"), c.get("domain")) for c in cookies.get("before_choice", [])}
    for label, bucket in (("before_choice", "cookies_before"), ("after_choice", "cookies_after")):
        for c in cookies.get(label, []):
            t = _match_cookie(c.get("name", ""))
            if t is None:
                continue
            if bucket == "cookies_after" and (c.get("name"), c.get("domain")) in before_keys:
                continue
            v = vendor_entry(t)
            if c["name"] not in v[bucket]:
                v[bucket].append(c["name"])
            if bucket == "cookies_after" and choice_made:
                tracking_cookies_after.append({"name": c["name"], "domain": c.get("domain"), "vendor": t["vendor"]})

    out_vendors = []
    for v in vendors.values():
        v["proxy_confirmed"] = bool(v["hosts"] & proxy_allowed_hosts)
        signals = v.pop("consent_signals")
        v["consent_signal_after_reject"] = (
            "granted" if "granted" in signals else ("denied" if "denied" in signals else None)
        )
        v["hosts"] = sorted(v["hosts"])
        if not choice_made:
            v["cookies_after"] = []
        fired_after = v["after_reject"] > 0 or bool(v["cookies_after"])
        library_only = v["after_reject"] > 0 and not v.pop("hits_after_reject") and not v["cookies_after"]
        before_real = v.pop("hits_before_choice") > 0 or bool(v["cookies_before"])
        v["_before_real"] = before_real
        if v["category"] not in HIGH_CATEGORIES:
            v["severity"] = "info"
        elif library_only and v["consent_signal_after_reject"] != "granted":
            v["severity"] = "medium"
            v["note"] = ("Only the vendor's script file was downloaded after Reject all; no tracking request or "
                         "cookie was seen. The download still reaches the vendor's servers.")
        elif fired_after and v["consent_signal_after_reject"] == "denied" and not v["cookies_after"]:
            v["severity"] = "medium"  # cookieless Consent Mode ping
            v["note"] = "Cookieless Consent Mode ping (consent marked denied). Still sends data to Google."
        elif fired_after:
            v["severity"] = "high"
            if v["consent_signal_after_reject"] == "granted":
                v["note"] = "Told Google that consent was GRANTED after the visitor rejected."
        elif before_real:
            v["severity"] = "high"
            v["note"] = "Fired before the visitor made any choice."
        else:
            v["severity"] = "info"
        out_vendors.append(v)

    sev_rank = {"high": 0, "medium": 1, "info": 2}
    out_vendors.sort(key=lambda v: (sev_rank[v["severity"]], -(v["after_reject"] + v["before_choice"])))

    high_after = [v for v in out_vendors if v["severity"] == "high" and (v["after_reject"] or v["cookies_after"])]
    high_before = [v for v in out_vendors if v["category"] in HIGH_CATEGORIES and v["_before_real"]]
    for v in out_vendors:
        v.pop("_before_real", None)
    medium = [v for v in out_vendors if v["severity"] == "medium"]
    any_tracker = [v for v in out_vendors if v["severity"] in ("high", "medium")]
    lied = [v for v in out_vendors if v.get("consent_signal_after_reject") == "granted"]
    suspicious = [h for h in unclassified if SUSPICIOUS.search(h) or SUSPICIOUS.search(h.split(".")[0])]

    web_requests = sum(1 for r in requests if r.get("url", "").startswith(("http://", "https://")))
    bot_wall = BOT_WALL.search(page_title or "")
    if bot_wall or (not banner_found and web_requests < 15 and not any_tracker):
        verdict = "INCONCLUSIVE"
        headline = (f"The site blocked or challenged the automated browser, or the page barely loaded "
                    f"(“{(page_title or 'empty page')[:60]}”). No verdict about its cookie banner.")
    elif not banner_found and CONSENT_GATE.search(page_title or ""):
        verdict, headline = "INCONCLUSIVE", "Full-page consent gate that the agent could not operate. Needs a manual check."
    elif not banner_found and not EU_VANTAGE:
        verdict = "INCONCLUSIVE"
        headline = ("No consent banner was shown to the scanner"
                    + (f", yet {_n(len(any_tracker), "tracker")} loaded" if any_tracker else "")
                    + ". Many sites show banners only to EU visitors: re-run from an EU region to judge.")
    elif not banner_found:
        if any_tracker:
            verdict, headline = "FAIL", f"No way to refuse: no consent banner was found, yet {_n(len(any_tracker), "tracker")} loaded."
        else:
            verdict, headline = "PASS", "No consent banner was detected, and no known trackers ran during the visit."
    elif not choice_made and "pay_or_consent" in seen_kinds:
        verdict, headline = "INCONCLUSIVE", ("Consent-or-pay wall: the banner offers Accept or a paid subscription, "
                                             "with no free way to refuse. Legally contested; needs a human look.")
    elif not choice_made:
        verdict, headline = "INCONCLUSIVE", ("A banner was found, but the agent found no button that refuses all "
                                             "tracking (e.g. only Accept, a paid subscription, or a single-vendor opt-out).")
    elif high_after and "pay_or_consent" in seen_kinds:
        # Consent-or-pay sites: the free refusal path is contested; flag, don't convict.
        verdict = "REVIEW"
        headline = (f"Consent-or-pay site: {_n(len(high_after), "tracker")} still ran after refusing through the "
                    "settings. Needs a human look.")
    elif high_after:
        verdict = "FAIL"
        headline = f"Reject all is ignored: {_n(len(high_after), "tracker")} still ran after the visitor rejected."
        if lied:
            headline += " The site even told Google that consent was granted."
    elif high_before:
        verdict, headline = "FAIL", f"{_n(len(high_before), "tracker")} ran before the visitor made any choice."
    elif medium:
        verdict, headline = "REVIEW", (f"No tracking hits or cookies after rejection, but {len(medium)} tracking "
                                       "vendor(s) were still contacted (script download or cookieless ping). "
                                       "Needs a human look.")
    elif suspicious:
        verdict, headline = "REVIEW", (f"No known trackers after rejection, but {len(suspicious)} unlisted "
                                       "ad/tracking-looking host(s) were contacted. Needs a human look.")
    else:
        verdict, headline = "PASS", "Reject all was respected: no known trackers ran after the visitor rejected."

    return {
        "verdict": verdict,
        "headline": headline,
        "page_title": (page_title or "")[:200],
        "consent_or_pay": "pay_or_consent" in seen_kinds,
        "eu_vantage": EU_VANTAGE,
        "site": first_party,
        "banner_found": banner_found,
        "choice_made": choice_made,
        "counts": {
            "requests_total": len(requests),
            "third_party_after_reject": third_party_after,
            "trackers_before_choice": len(high_before),
            "trackers_after_reject": len(high_after),
            "tracking_cookies_after_reject": len(tracking_cookies_after),
            "blocked_by_guard": len(blocked),
            "proxy_logged_requests": len(proxy_log),
        },
        "vendors": out_vendors,
        "host": urlparse(page_url).hostname,
        "unclassified_after_reject": [
            {"host": h, "count": n, "suspicious": h in suspicious} for h, n in unclassified.most_common(15)
        ],
        "cookies_after_reject": tracking_cookies_after,
        "blocked_egress": [
            {"url": e.get("url", "")[:300], "reason": e.get("reason")} for e in blocked[:30]
        ],
    }
