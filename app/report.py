"""Printable evidence report (server-rendered HTML, A4, always light). Styled after the design handoff."""

import datetime as dt
from html import escape


def e(value) -> str:
    return escape("" if value is None else str(value))


ICONS = {
    "FAIL": '<circle cx="8" cy="8" r="6.4"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8"/>',
    "REVIEW": '<path d="M8 1.9l6.6 11.6H1.4z"/><path d="M8 6.4v3.1M8 11.5v.1"/>',
    "PASS": '<circle cx="8" cy="8" r="6.4"/><path d="M5.1 8.3l2 2 3.9-4.3"/>',
    "INCONCLUSIVE": '<circle cx="8" cy="8" r="6.4" stroke-dasharray="2.4 2"/><path d="M5.2 8h5.6"/>',
    "CONTAINED": '<path d="M8 1.4l5.6 2.1v4.2c0 3.3-2.3 5.8-5.6 6.9-3.3-1.1-5.6-3.6-5.6-6.9V3.5z"/><path d="M5.8 8l1.6 1.6 2.9-3.1"/>',
}
LIED = " The site even told Google that consent was granted."


def _ts(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%d %b %Y %H:%M:%S UTC") if t else "n/a"


def _tag(v):
    return (f'<span class="vt {e(v)}"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">{ICONS.get(v, ICONS["INCONCLUSIVE"])}</svg>{e(v)}</span>')


def render_report(scan: dict) -> str:
    r = scan["result"]
    s = scan.get("summary") or {}
    c = r["counts"]
    ev = scan.get("evidence") or {}
    files = ev.get("files", {})
    mh = ev.get("manifest_sha256", "")
    exhibit = f"A-{scan['id'][:6].upper()}"
    shots = [n for n in sorted(files) if n.endswith(".jpg")]
    cont = scan.get("containment") or {}
    prof = cont.get("profile", {})
    appr = scan.get("approval")
    ai = scan.get("ai", {})
    duration = f"{(scan.get('finished') or scan['created']) - scan['created']:.1f} s"
    lied = LIED.strip() in r["headline"]
    headline = r["headline"].replace(LIED, "") if lied else r["headline"]
    tracked = [v for v in r["vendors"] if v["severity"] != "info"]
    confirmed = sum(1 for v in tracked if v["proxy_confirmed"])

    if appr and appr.get("decision") == "approved":
        draft_banner = ""
    elif appr:
        draft_banner = ('<div class="draft rej"><b>REJECTED BY REVIEWER</b><span>A human reviewer rejected this automated '
                        'result. Do not rely on it.</span></div>')
    else:
        draft_banner = ('<div class="draft"><b>DRAFT · NOT YET REVIEWED</b><span>Automated result. A human reviewer has not '
                        'approved it yet, so it must not be shared or relied on.</span></div>')

    sub = []
    if lied:
        sub.append("The site also told Google that consent was granted.")
    if c["blocked_by_guard"]:
        n = c["blocked_by_guard"]
        sub.append(f"The page attempted {n} request{'' if n == 1 else 's'} to internal addresses; "
                   f"{'it was' if n == 1 else 'all were'} blocked.")
    review = ("Approved ✓" if appr and appr["decision"] == "approved" else
              "Rejected ✕" if appr else "Pending")
    review_color = "var(--pass)" if appr and appr["decision"] == "approved" else "var(--fail)" if appr else "var(--text-3)"

    def foot(n, left):
        return f'<div class="foot"><span>{e(left)}</span><span>{n} / 5</span></div>'

    rows = []
    for v in r["vendors"]:
        if v["severity"] == "info" and not (v["before_choice"] or v["after_reject"]):
            continue
        granted = ' <span class="fl">(“granted”)</span>' if v.get("consent_signal_after_reject") == "granted" else ""
        note = f'<div class="nt">{e(v["note"])}</div>' if v.get("note") and not granted else ""
        rows.append(
            f'<tr><td class="vn">{e(v["vendor"])}{granted}{note}</td><td>{e(v["category_label"])}</td>'
            f'<td>{e(v["severity"].title())}</td><td class="r m">{v["before_choice"] or "—"}</td>'
            f'<td class="r m{" bad" if v["after_reject"] else ""}">{v["after_reject"] or "—"}</td>'
            f'<td class="m">{e(", ".join(v["cookies_after"])) or "—"}</td><td>{"✓" if v["proxy_confirmed"] else "—"}</td></tr>')
    vendor_rows = "".join(rows) or '<tr><td colspan="7" class="empty">No known trackers detected.</td></tr>'

    examples = []
    for v in r["vendors"]:
        for x in v["examples"]["after_reject"][:1]:
            status = x.get("status") or "—"
            examples.append(f'<div class="req"><b>{e(v["vendor"])} · {e(status)} · +{x["t"]} s</b><br>{e(x["url"][:400])}</div>')
    examples_html = "".join(examples[:6]) or '<p class="t2">No tracker requests after Reject all.</p>'

    labels = {"01": "Landing", "02": "After click", "03": "Fresh page view"}
    shot_html = "".join(
        f'<figure><img src="/api/scans/{e(scan["id"])}/files/{e(n)}" alt=""><figcaption>{e(labels.get(n[:2], n))} · {e(n)}</figcaption></figure>'
        for n in shots[:3])
    prof_rows = "".join(f'<div><dt>{e(k.replace("_", " ").title())}</dt><dd>{e(v)}</dd></div>' for k, v in prof.items())
    blocked = "".join(f'<li><span class="m">{e(b["url"][:160])}</span><br><span class="t2">{e(b["reason"])}</span></li>'
                      for b in r["blocked_egress"][:12]) or '<li class="t2">None. The page made no requests to internal addresses.</li>'
    actions = "".join(f"<li>{e(a)}</li>" for a in s.get("actions", []))
    manifest_rows = "".join(f'<tr><td class="m">{e(n)}</td><td class="m h">{e(h)}</td></tr>' for n, h in files.items())
    ai_line = (f"Vultr Serverless Inference: planner {e(ai.get('agent_model'))}, verifier {e(ai.get('verifier_model'))}, "
               f"report {e(ai.get('report_model'))}" if ai.get("enabled") else "Offline heuristic mode (no model calls)")
    destroyed = "yes, verified" if (cont.get("destroyed") or {}).get("destroyed") else "no"
    stamp = (f'<div class="stamp {e(appr["decision"])}"><b>{"APPROVED" if appr["decision"] == "approved" else "REJECTED"}</b>'
             f'<span>{e(appr["reviewer"])} · {_ts(appr["at"])}</span>'
             f'{"<span>" + e(appr["note"]) + "</span>" if appr.get("note") else ""}'
             f'<span>approval sha256 {e(appr["approval_sha256"])}</span></div>'
             if appr else '<div class="stamp draft"><b>DRAFT</b><span>Not yet approved by a human reviewer.</span></div>')
    rt = prof.get("runtime", "")
    stats = [
        (c["trackers_after_reject"], "trackers after Reject all", "var(--fail)" if c["trackers_after_reject"] else "var(--text)"),
        (c["trackers_before_choice"], "trackers before any choice", "var(--text)"),
        (c["tracking_cookies_after_reject"], "tracking cookies after Reject all", "var(--text)"),
        (f"{confirmed}/{len(tracked)}" if tracked else "0", "confirmed by egress guard", "var(--pass)" if tracked else "var(--text)"),
        (c["blocked_by_guard"], "attacks blocked", "var(--contained)" if c["blocked_by_guard"] else "var(--text)"),
    ]
    stat_html = "".join(f'<div><b style="color:{col}">{e(n)}</b><span>{e(l)}</span></div>' for n, l, col in stats)

    return f"""<!doctype html><html lang="en" data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence report · {e(r['site'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap">
<style>
:root{{--font-ui:"IBM Plex Sans",system-ui,sans-serif;--font-mono:"JetBrains Mono",ui-monospace,Menlo,monospace;
--bg:#f4f4f2;--surface-2:#f0f0ed;--line:#dcdcd6;--line-strong:#bfc0ba;--text:#131517;--text-2:#454b4f;--text-3:#5d6367;
--fail:#b8342a;--fail-bg:rgba(184,52,42,.07);--fail-line:rgba(184,52,42,.38);--fail-solid:#c43a2f;
--review:#8a5800;--review-bg:rgba(186,124,0,.09);--review-line:rgba(160,106,0,.38);--pass:#1b7444;--pass-bg:rgba(27,116,68,.08);--pass-line:rgba(27,116,68,.34);
--inc:#596064;--inc-bg:rgba(89,96,100,.08);--inc-line:rgba(89,96,100,.30);--contained:#5b3fc0;--contained-bg:rgba(91,63,192,.08);--contained-line:rgba(91,63,192,.36)}}
*{{box-sizing:border-box}} html,body{{margin:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font-ui);-webkit-font-smoothing:antialiased;padding:24px 12px}}
.bar{{max-width:210mm;margin:0 auto 12px;display:flex;justify-content:flex-end;gap:8px}}
.bar button,.bar a{{height:36px;padding:0 14px;border:1px solid var(--line-strong);border-radius:6px;background:#fff;font:500 14px var(--font-ui);color:var(--text);cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}}
.page{{width:210mm;min-height:297mm;margin:0 auto 16px;background:#fff;padding:52px 56px 40px;display:flex;flex-direction:column;gap:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.m{{font-family:var(--font-mono)}} .t2{{color:var(--text-2)}} .r{{text-align:right}}
.top{{display:flex;justify-content:space-between;align-items:center;padding-bottom:14px;border-bottom:2px solid var(--text)}}
.brand{{display:flex;align-items:center;gap:10px;font-weight:600;font-size:16px}}
.logo{{width:18px;height:18px;border:1.5px solid var(--text);border-radius:3px;display:grid;place-items:center}} .logo i{{width:7px;height:7px;background:var(--fail-solid)}}
.ex{{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;color:var(--text-2)}}
.vt{{display:inline-flex;align-items:center;gap:8px;align-self:flex-start;padding:7px 12px 7px 10px;border:1px solid;border-radius:3px;font:700 16px var(--font-mono);letter-spacing:.07em}}
.vt svg{{width:18px;height:18px}}
.vt.FAIL{{color:var(--fail);background:var(--fail-bg);border-color:var(--fail-line)}} .vt.PASS{{color:var(--pass);background:var(--pass-bg);border-color:var(--pass-line)}}
.vt.REVIEW{{color:var(--review);background:var(--review-bg);border-color:var(--review-line)}} .vt.INCONCLUSIVE{{color:var(--inc);background:var(--inc-bg);border-color:var(--inc-line)}}
.vt.CONTAINED{{color:var(--contained);background:var(--contained-bg);border-color:var(--contained-line)}}
.cover{{display:flex;flex-direction:column;gap:14px;padding-top:20px}}
.cover .site{{font:600 20px var(--font-mono);overflow-wrap:anywhere}}
h1{{margin:0;font-size:32px;line-height:1.15;letter-spacing:-.02em;font-weight:600}}
.cover p{{margin:0;font-size:16px;line-height:1.5;color:var(--text-2)}}
dl.meta{{margin:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px;font-size:13px}}
dl.meta div{{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-top:1px solid var(--line)}}
dl.meta div:nth-last-child(-n+2){{border-bottom:1px solid var(--line)}}
dl.meta dt{{color:var(--text-2)}} dl.meta dd{{margin:0;font-family:var(--font-mono);text-align:right}}
h2.eb{{margin:0;font:600 11px var(--font-mono);letter-spacing:.14em;color:var(--text-2)}}
h2.sec{{margin:0;font-size:20px;font-weight:600}}
.blk{{display:flex;flex-direction:column;gap:10px}}
.draft{{display:flex;flex-direction:column;gap:4px;padding:12px 16px;border:2px dashed var(--review);border-radius:6px;color:var(--review);font-family:var(--font-mono)}} .draft b{{font-size:14px;letter-spacing:.12em}} .draft span{{font-family:var(--font-ui);font-size:13px;color:var(--text-2)}} .draft.rej{{border-color:var(--fail);color:var(--fail)}}
.stats{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line-strong)}}
.stats div{{padding:12px;border-right:1px solid var(--line)}} .stats div:last-child{{border-right:0}}
.stats b{{display:block;font:600 28px var(--font-mono)}} .stats span{{font-size:11.5px;line-height:1.3;color:var(--text-2)}}
p.body{{margin:0;font-size:14.5px;line-height:1.6}}
ol.fix{{margin:0;padding-left:22px;font-size:14px;line-height:1.55;display:flex;flex-direction:column;gap:4px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
thead tr{{text-align:left;border-bottom:1.5px solid var(--text)}} th{{padding:6px;font-weight:600}}
td{{padding:7px 6px;border-bottom:1px solid var(--line);vertical-align:top}}
td.vn{{font-weight:600}} td.bad{{font-weight:700;color:var(--fail)}} .fl{{font-weight:400;color:var(--fail)}} .nt{{font-weight:400;font-size:11px;color:var(--text-2);margin-top:2px}}
td.empty{{text-align:center;color:var(--text-3);padding:18px}}
.small{{margin:0;font-size:11.5px;color:var(--text-3)}}
.req{{padding:8px 10px;border:1px solid var(--line);background:var(--surface-2);font:11px/1.5 var(--font-mono);overflow-wrap:anywhere}}
.req b{{color:var(--fail)}}
.shots{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}
figure{{margin:0;display:flex;flex-direction:column;gap:6px}} figure img{{width:100%;aspect-ratio:16/10;object-fit:cover;object-position:top;border:1px solid var(--line)}}
figcaption{{font:11px var(--font-mono);color:var(--text-2)}}
dl.prof{{margin:0;font-size:12.5px}} dl.prof div{{display:grid;grid-template-columns:120px 1fr;gap:12px;padding:7px 0;border-top:1px solid var(--line)}}
dl.prof dt{{color:var(--text-2)}} dl.prof dd{{margin:0;font-family:var(--font-mono);font-size:12px}}
ul.blocked{{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px;font-size:12px}}
ul.blocked li{{padding:8px 10px;border:1px solid var(--contained-line);background:var(--contained-bg);overflow-wrap:anywhere}}
td.h{{font-size:10.5px;overflow-wrap:anywhere;word-break:break-all}}
.hash{{padding:10px 12px;border:1px solid var(--line-strong);font:12px var(--font-mono);overflow-wrap:anywhere}}
.stamp{{align-self:flex-start;margin-top:12px;padding:16px 22px;border:4px double;transform:rotate(-3deg);display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);max-width:100%}}
.stamp b{{font-size:24px;letter-spacing:.14em}} .stamp span{{font-size:11px;color:var(--text-2);overflow-wrap:anywhere}}
.stamp.approved{{color:var(--pass);border-color:var(--pass)}} .stamp.rejected{{color:var(--fail);border-color:var(--fail)}} .stamp.draft{{color:var(--text-3);border-color:var(--line-strong)}}
.foot{{margin-top:auto;display:flex;justify-content:space-between;gap:12px;font:10.5px var(--font-mono);color:var(--text-3);padding-top:10px;border-top:1px solid var(--line)}}
@page{{size:A4;margin:0}}
@media print{{body{{background:#fff;padding:0}} .bar{{display:none}} .page{{margin:0;box-shadow:none;break-after:page;width:auto;min-height:297mm}}}}
@media (max-width:820px){{.page{{width:auto;min-height:0;padding:28px 20px}} .stats{{grid-template-columns:repeat(2,1fr)}} .shots{{grid-template-columns:1fr}} dl.meta{{grid-template-columns:1fr}}}}
</style></head><body>
<div class="bar"><a href="/#/scan/{e(scan['id'])}">← Back to audit</a><button id="print" type="button">Print / save as PDF</button></div><script src="/report.js" defer></script>

<section class="page">
  <div class="top"><span class="brand"><span class="logo"><i></i></span>ConsentCheck</span><span class="ex">EVIDENCE REPORT · EXHIBIT {exhibit}</span></div>
  {draft_banner}
  <div class="cover">{_tag(r['verdict'])}<span class="site">{e(scan['url'])}</span><h1>{e(headline)}</h1>
    {'<p>' + e(' '.join(sub)) + '</p>' if sub else ''}</div>
  <dl class="meta">
    <div><dt>Audited</dt><dd>{_ts(scan['created'])}</dd></div><div><dt>Duration</dt><dd>{duration}</dd></div>
    <div><dt>Sandbox</dt><dd>{'gVisor (runsc)' if rt == 'runsc' else e(rt or 'container')}</dd></div><div><dt>AI model</dt><dd>{e(ai.get('agent_model')) if ai.get('enabled') else 'heuristic mode'}</dd></div>
    <div><dt>Scan ID</dt><dd>{e(scan['id'])}</dd></div><div><dt>Review</dt><dd style="color:{review_color}">{review}</dd></div>
  </dl>
  <div class="blk"><h2 class="eb">STATS</h2><div class="stats">{stat_html}</div></div>
  <div class="blk"><h2 class="eb">SUMMARY</h2><p class="body">{e(s.get('summary', ''))}</p></div>
  {foot(1, exhibit + ' · sha256:' + mh[:8] + '…' + mh[-7:])}
</section>

<section class="page">
  <div class="blk"><h2 class="sec">Legal context</h2><p class="body t2">{e(s.get('legal_context', ''))}</p></div>
  <div class="blk"><h2 class="sec">Fixes</h2><ol class="fix">{actions}</ol></div>
  <div class="blk"><h2 class="sec">Tracker table</h2>
    <table><thead><tr><th>Vendor</th><th>Type</th><th>Severity</th><th class="r">Before</th><th class="r">After RA</th><th>Cookies after RA</th><th>Guard</th></tr></thead>
    <tbody>{vendor_rows}</tbody></table>
    <p class="small">Counts are network requests. RA = Reject all. Guard ✓ = also recorded by the independent egress guard.</p></div>
  {foot(2, exhibit + ' · ' + (r.get('host') or r['site']))}
</section>

<section class="page">
  <div class="blk"><h2 class="sec">Example requests after Reject all</h2>{examples_html}</div>
  <div class="blk"><h2 class="sec">Screenshots</h2><div class="shots">{shot_html}</div></div>
  {foot(3, exhibit + ' · ' + (r.get('host') or r['site']))}
</section>

<section class="page">
  <div class="blk"><h2 class="sec">Containment profile</h2><dl class="prof">{prof_rows}
    <div><dt>Destroyed</dt><dd>{destroyed}</dd></div>
    <div><dt>Secrets in sandbox</dt><dd>{e(', '.join(r.get('sandbox_secret_env_vars') or [])) or 'none'}</dd></div></dl></div>
  <div class="blk"><h2 class="sec">Blocked requests</h2><ul class="blocked">{blocked}</ul></div>
  <div class="blk"><h2 class="sec">Method</h2><p class="body t2">The site was opened in a disposable browser sandbox. The agent located the consent banner and
    clicked the refusal control; a policy gate in code prevents it from ever accepting, and it never clicks a paid "reject and subscribe" option.
    It then waited and loaded a fresh page view as a returning visitor. Every request was recorded by the browser and, independently, by an egress
    proxy the page cannot influence. Findings and counts are computed from that evidence; AI models only located the button, verified the click and
    wrote the summary. {ai_line}. This report describes one automated visit and is technical evidence, not legal advice.</p></div>
  {foot(4, exhibit + ' · ' + (r.get('host') or r['site']))}
</section>

<section class="page">
  <div class="blk"><h2 class="sec">Evidence manifest</h2><div class="hash">manifest sha256:{e(mh)}</div>
    <table><thead><tr><th>File</th><th>SHA-256</th></tr></thead><tbody>{manifest_rows}</tbody></table></div>
  <div class="blk"><h2 class="sec">Human review</h2>{stamp}</div>
  {foot(5, exhibit + ' · sha256:' + mh[:8] + '…' + mh[-7:])}
</section>
</body></html>"""
