(function () {
  "use strict";
  var app = document.getElementById("app");
  var pollTimer = null, clockTimer = null;
  var health = null;
  var admin = null;       // signed-in admin username, or null
  var MINE = "cc_my_scans";

  // ------------------------------------------------------------ helpers
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function api(path, opts) {
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) {
          var d = body.detail, err = new Error((d && d.message) || (typeof d === "string" ? d : "") || ("HTTP " + r.status));
          err.status = r.status; err.data = (d && typeof d === "object") ? d : {};
          throw err;
        }
        return body;
      });
    });
  }
  function post(path, data) {
    return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });
  }
  function ago(ts) {
    var s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  }
  function prettyUrl(u) { return String(u || "").replace(/^https?:\/\//, "").replace(/\/$/, ""); }
  function hostOf(u) { try { return new URL(u).host; } catch (e) { return prettyUrl(u); } }
  function clock(sec) { sec = Math.max(0, Math.floor(sec)); return ("0" + Math.floor(sec / 60)).slice(-2) + ":" + ("0" + sec % 60).slice(-2); }
  function timeOf(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
  function dateOf(ts) { return new Date(ts * 1000).toLocaleString([], { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
  function myScans() { try { return JSON.parse(localStorage.getItem(MINE) || "[]"); } catch (e) { return []; } }
  function rememberScan(id) {
    try { localStorage.setItem(MINE, JSON.stringify([id].concat(myScans().filter(function (x) { return x !== id; })).slice(0, 20))); } catch (e) {}
  }

  // ------------------------------------------------------------ icons
  var P = {
    fail: '<circle cx="8" cy="8" r="6.4"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8"/>',
    review: '<path d="M8 1.9l6.6 11.6H1.4z"/><path d="M8 6.4v3.1M8 11.5v.1"/>',
    pass: '<circle cx="8" cy="8" r="6.4"/><path d="M5.1 8.3l2 2 3.9-4.3"/>',
    inc: '<circle cx="8" cy="8" r="6.4" stroke-dasharray="2.4 2"/><path d="M5.2 8h5.6"/>',
    shield: '<path d="M8 1.4l5.6 2.1v4.2c0 3.3-2.3 5.8-5.6 6.9-3.3-1.1-5.6-3.6-5.6-6.9V3.5z"/>',
    shieldOk: '<path d="M8 1.4l5.6 2.1v4.2c0 3.3-2.3 5.8-5.6 6.9-3.3-1.1-5.6-3.6-5.6-6.9V3.5z"/><path d="M5.8 8l1.6 1.6 2.9-3.1"/>',
    shieldX: '<path d="M8 1.4l5.6 2.1v4.2c0 3.3-2.3 5.8-5.6 6.9-3.3-1.1-5.6-3.6-5.6-6.9V3.5z"/><path d="M6 6l4 4M10 6l-4 4"/>',
    step: '<circle cx="8" cy="8" r="2.6" fill="currentColor"/>',
    ai: '<path d="M8 1.8l6.2 6.2L8 14.2 1.8 8z"/><circle cx="8" cy="8" r="1.4" fill="currentColor"/>',
    lock: '<rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 015 0v2"/>',
    doc: '<path d="M4 1.8h5.5L12.5 5v9.2H4z"/><path d="M9.5 1.8V5h3M6 8.5h4.5M6 11h4.5"/>',
    check: '<path d="M3.2 8.4l3 3 6.6-7"/>',
    sun: '<circle cx="8" cy="8" r="3"/><path d="M8 1v1.6M8 13.4V15M1 8h1.6M13.4 8H15M3 3l1.1 1.1M11.9 11.9L13 13M3 13l1.1-1.1M11.9 4.1L13 3"/>',
    moon: '<path d="M13.5 9.6A5.6 5.6 0 016.4 2.5a5.6 5.6 0 107.1 7.1z"/>'
  };
  function svg(path, size, extra) {
    return '<svg width="' + (size || 16) + '" height="' + (size || 16) + '" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' + (extra || "") + ">" + path + "</svg>";
  }
  var VICON = { FAIL: P.fail, REVIEW: P.review, PASS: P.pass, INCONCLUSIVE: P.inc, CONTAINED: P.shieldOk, ERROR: P.review, RUNNING: P.step, QUEUED: P.step };
  function tag(v, size) {
    v = String(v || "INCONCLUSIVE").toUpperCase();
    return '<span class="vt ' + esc(v) + (size ? " " + size : "") + '" role="img" aria-label="Verdict: ' + esc(v) + '">' +
      svg(VICON[v] || P.inc) + "<span>" + esc(v) + "</span></span>";
  }

  // ------------------------------------------------------------ theme
  function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("cc_theme", t); } catch (e) {}
    var b = $("#theme-btn");
    b.innerHTML = svg(t === "dark" ? P.sun : P.moon, 16);
    b.setAttribute("aria-label", t === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }
  $("#theme-btn").addEventListener("click", function () {
    setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
  });
  setTheme(document.documentElement.getAttribute("data-theme") || "dark");

  // ------------------------------------------------------------ header
  function renderPills() {
    var el = $("#pills");
    if (!health) { el.innerHTML = ""; return; }
    var html = health.ai
      ? '<span class="pill"><span class="pd" style="background:var(--pass)"></span>Vultr Serverless Inference · ' + esc(health.models.agent) + "</span>"
      : '<span class="pill"><span class="pd" style="background:var(--review)"></span>AI offline · heuristic mode</span>';
    html += '<span class="pill">' + svg(P.shield, 12, ' style="color:var(--contained)"') + "sandbox: " +
      esc(health.runtime === "runsc" ? "gVisor" : health.runtime) + "</span>";
    el.innerHTML = html;
  }
  function renderNav() {
    $("#nav-login").hidden = !!admin;
    $("#nav-who").hidden = !admin;
    $("#nav-user").textContent = admin || "";
    var on = location.hash.indexOf("#/dashboard") === 0;
    $("#nav-dash").classList.toggle("on", on);
    if (on) $("#nav-dash").setAttribute("aria-current", "page"); else $("#nav-dash").removeAttribute("aria-current");
  }

  // ------------------------------------------------------------ router
  function route() {
    clearTimeout(pollTimer); clearInterval(clockTimer);
    renderNav();
    var h = location.hash, m = h.match(/^#\/scan\/([\w-]+)/);
    if (m) showScan(m[1]);
    else if (h.indexOf("#/login") === 0) showLogin();
    else if (h.indexOf("#/dashboard") === 0) showDashboard(h.indexOf("/batch") > 0);
    else showHome();
    window.scrollTo(0, 0);
  }
  function mount(id) { app.innerHTML = ""; app.appendChild($("#" + id).content.cloneNode(true)); }

  // ------------------------------------------------------------ home
  function showHome() {
    mount("tpl-home");
    $("#ex-site").innerHTML = tag("FAIL") + "<span>shop.consentcheck.test</span>";
    var form = $("#scan-form"), input = $("#url"), err = $("#form-error");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var url = input.value.trim();
      if (!url) { input.focus(); return; }
      err.hidden = true;
      var btn = form.querySelector("button");
      btn.disabled = true; btn.firstChild.nodeValue = "Starting sandbox… ";
      post("/api/scans", { url: url })
        .then(function (r) { rememberScan(r.id); location.hash = "#/scan/" + r.id; })
        .catch(function (e2) { err.textContent = e2.message; err.hidden = false; btn.disabled = false; btn.firstChild.nodeValue = "Audit this site "; });
    });
    $$(".demo").forEach(function (c) {
      c.addEventListener("click", function () {
        $$(".demo").forEach(function (x) { x.setAttribute("aria-pressed", String(x === c)); });
        input.value = c.dataset.url;
        form.querySelector("button").focus();
      });
    });
    input.focus();
    var ids = myScans();
    if (!ids.length) return;
    api("/api/scans?ids=" + encodeURIComponent(ids.join(","))).then(function (list) {
      if (!list.length) return;
      $("#recent-list").innerHTML = list.map(function (s) {
        var v = s.verdict || s.status;
        return '<li><a href="#/scan/' + esc(s.id) + '"><span class="tg">' + tag(v) + '</span><span class="st">' + esc(prettyUrl(s.url)) +
          '</span><span class="hd">' + esc(s.headline || "In progress…") + '</span><span class="tm">' + esc(ago(s.created)) + "</span></a></li>";
      }).join("");
    }).catch(function () {});
  }

  // ------------------------------------------------------------ live audit
  var KIND = {
    step: { label: "STEP", tone: "var(--text-3)", icon: P.step },
    llm: { label: "AI CALL", tone: "var(--info)", icon: P.ai },
    policy: { label: "POLICY", tone: "var(--pass)", icon: P.lock },
    containment: { label: "CONTAINMENT", tone: "var(--contained)", icon: P.shieldX },
    evidence: { label: "EVIDENCE", tone: "var(--text-2)", icon: P.doc },
    done: { label: "VERDICT", tone: "var(--text)", icon: P.doc },
    error: { label: "ERROR", tone: "var(--review)", icon: P.review }
  };
  var DONE_TONE = { FAIL: ["var(--fail)", P.fail], PASS: ["var(--pass)", P.pass], REVIEW: ["var(--review)", P.review],
    INCONCLUSIVE: ["var(--inc)", P.inc], CONTAINED: ["var(--contained)", P.shieldOk] };
  var SHOTS = [
    { key: "01", label: "Landing" }, { key: "02", label: "After click" }, { key: "03", label: "Fresh page view" }
  ];
  var CHECKS = [
    ["Runtime", function (p) { return p.runtime === "runsc" ? "gVisor (runsc)" : (p.runtime || "runc") + " container"; }],
    ["Network", function () { return "internal-only"; }],
    ["Egress", function () { return "blocked · guard proxy only"; }],
    ["Filesystem", function () { return "read-only root"; }],
    ["User", function () { return "non-root · all caps dropped"; }],
    ["Limits", function () { return "1 GB RAM · 1 CPU · 512 PIDs"; }],
    ["Secrets", function () { return "none mounted"; }],
    ["Lifecycle", function () { return "destroyed after scan"; }]
  ];

  function showScan(id) {
    mount("tpl-scan");
    var st = { id: id, since: 0, shots: {}, selected: null, userPicked: false, overlays: {}, lastImage: null,
      scan: null, rendered: false, blocked: [], decision: "approved" };
    $$(".report-link").forEach(function (a) { a.href = "/report/" + id; });
    $("#checks").innerHTML = CHECKS.map(function (c) {
      return "<li>" + svg(P.check, 15, ' style="color:var(--pass)"') + '<span class="k">' + esc(c[0]) + '</span><span class="v">' + esc(c[1]({})) + "</span></li>";
    }).join("");
    renderThumbs(st);
    clockTimer = setInterval(function () { if (st.scan) renderState(st); }, 1000);
    poll(st);
  }

  function poll(st) {
    api("/api/scans/" + st.id + "?since=" + st.since).then(function (scan) {
      var first = !st.scan;
      st.scan = scan;
      if (first) renderHeadOnce(st);
      appendEvents(st, scan.events);
      st.since = scan.event_count;
      renderState(st);
      renderContainment(st);
      if (scan.status === "done" || scan.status === "error") {
        clearInterval(clockTimer);
        if (!st.rendered) { st.rendered = true; renderResults(st); }
        return;
      }
      pollTimer = setTimeout(function () { poll(st); }, 900);
    }).catch(function (e) {
      $("#timeline").innerHTML = '<li class="waiting">' + esc(e.status === 404 ? "This audit does not exist." : e.message) + "</li>";
    });
  }

  function renderHeadOnce(st) {
    var s = st.scan;
    $("#scan-url").textContent = s.url;
    $("#addr").textContent = prettyUrl(s.url) + "/";
    var rt = (s.containment && s.containment.profile && s.containment.profile.runtime) || (health && health.runtime) || "";
    $("#scan-meta").textContent = "audit " + s.id + " · sandbox " + (rt === "runsc" ? "gVisor" : rt || "container") +
      " · " + (s.ai && s.ai.enabled ? s.ai.agent_model : "heuristic mode") + " · started " + timeOf(s.created);
  }

  function renderState(st) {
    var s = st.scan, el = $("#scan-state");
    var run = s.status === "running" || s.status === "queued";
    el.className = "state " + s.status;
    if (s.status === "queued") el.innerHTML = '<span class="dot"></span>QUEUED · waiting for a sandbox slot';
    else if (run) el.innerHTML = '<span class="dot"></span>RUNNING · ' + clock(Date.now() / 1000 - s.created);
    else if (s.status === "error") el.textContent = "FAILED · " + ((s.finished || s.created) - s.created).toFixed(1) + " s";
    else el.textContent = "FINISHED IN " + ((s.finished || s.created) - s.created).toFixed(1) + " s";
    var badge = $("#sbx-badge"), c = s.containment || {};
    if (c.destroyed && c.destroyed.destroyed) badge.innerHTML = '<span class="badge gone">sandbox destroyed ✓</span>';
    else if (run) badge.innerHTML = '<span class="badge live"><span class="dot"></span>sandbox live · ' + clock(Date.now() / 1000 - s.created) + "</span>";
    else badge.innerHTML = "";
  }

  function appendEvents(st, events) {
    var ol = $("#timeline");
    if (events.length && ol.querySelector(".waiting")) ol.innerHTML = "";
    events.forEach(function (ev) {
      var k = KIND[ev.kind] || KIND.step, tone = k.tone, icon = k.icon, cls = "k-" + ev.kind, label = k.label;
      if (ev.kind === "policy" && /inject/i.test(ev.title)) { tone = "var(--review)"; icon = P.review; cls = "k-inject"; label = "POLICY · INJECTION"; }
      if (ev.kind === "containment" && /destroyed|is up|Provisioning/i.test(ev.title)) icon = P.shieldOk;
      if (ev.kind === "done") {
        var v = (ev.title.match(/Verdict: (\w+)/) || [])[1] || "";
        var dt = DONE_TONE[v] || DONE_TONE.INCONCLUSIVE; tone = dt[0]; icon = dt[1]; cls += " " + v;
      }
      var li = document.createElement("li");
      li.className = cls;
      li.innerHTML = '<span class="tm">' + ev.t.toFixed(1) + 's</span><span class="ic" style="color:' + tone + '">' + svg(icon, 18) + "</span>" +
        '<span class="bd"><span class="hd"><span class="kd" style="color:' + tone + '">' + esc(label) + '</span><span class="tt">' + esc(ev.title) + "</span></span>" +
        (ev.detail ? '<span class="dt">' + esc(ev.detail) + "</span>" : "") + "</span>";
      ol.appendChild(li);
      // a click is drawn on the screenshot that was on screen when the agent chose it
      var cand = ev.data && ev.data.candidate;
      if (cand && cand.box && st.lastImage) {
        st.overlays[st.lastImage] = { box: cand.box, label: "CLICKED · " + String(cand.kind || "").toUpperCase() + (cand.cmp ? " · " + cand.cmp : "") };
      }
      if (ev.data && ev.data.blocked) st.blocked = ev.data.blocked;
      if (ev.image) addShot(st, ev.image, ev.t);
    });
    ol.scrollTop = ol.scrollHeight;
    $("#ev-count").textContent = (st.scan ? st.scan.event_count : events.length) + " events";
  }

  function addShot(st, name, t) {
    var key = name.slice(0, 2);
    st.shots[key] = { name: name, t: t, src: "/api/scans/" + st.id + "/files/" + encodeURIComponent(name) };
    st.lastImage = name;
    if (!st.userPicked) st.selected = key;
    renderThumbs(st); renderStage(st);
  }

  function renderThumbs(st) {
    var box = $("#thumbs");
    box.innerHTML = SHOTS.map(function (s) {
      var sh = st.shots[s.key];
      return '<button type="button" role="tab" data-k="' + s.key + '" aria-selected="' + (st.selected === s.key) + '"' + (sh ? "" : " disabled") + ">" +
        '<span class="tb"' + (sh ? ' style="background-image:url(' + esc(sh.src) + ')"' : "") + "></span>" +
        '<span class="tl2"><span>' + esc(s.label) + "</span><span>" + (sh ? sh.t.toFixed(1) + " s" : "") + "</span></span></button>";
    }).join("");
    $$("button", box).forEach(function (b) {
      b.addEventListener("click", function () { st.selected = b.dataset.k; st.userPicked = true; renderThumbs(st); renderStage(st); });
    });
  }

  function renderStage(st) {
    var sh = st.shots[st.selected], stage = $("#stage");
    if (!sh) return;
    var html = '<img src="' + esc(sh.src) + '" alt="">';
    var ov = st.overlays[sh.name];
    if (ov) {
      var b = ov.box;
      html += '<div class="ov" style="left:' + (b.x / 12.8) + "%;top:" + (b.y / 8) + "%;width:" + (b.width / 12.8) + "%;height:" + (b.height / 8) + '%"><span>' + esc(ov.label) + "</span></div>";
    }
    var r = st.scan && st.scan.result;
    if (st.selected === "03" && r && r.counts && r.counts.trackers_after_reject) {
      var lines = [];
      r.vendors.forEach(function (v) {
        if (v.severity === "high" && v.after_reject) (v.examples.after_reject || []).slice(0, 1).forEach(function (x) { lines.push(x.url); });
      });
      html += '<div class="ticker"><b>' + r.counts.trackers_after_reject + " TRACKERS STILL RUNNING AFTER REJECT ALL</b>" +
        lines.slice(0, 4).map(function (l) { return "<span><i>●</i> " + esc(l.replace(/^https?:\/\//, "")) + "</span>"; }).join("") + "</div>";
    }
    var label = (SHOTS.filter(function (s) { return s.key === st.selected; })[0] || {}).label;
    html += '<span class="cap">' + esc(label + " · " + sh.t.toFixed(1) + " s") + "</span>";
    stage.innerHTML = html;
    stage.setAttribute("aria-label", "Screenshot: " + label);
  }

  function parseBlocked(b) {
    var raw = String(b.url || "").replace(/^(GET|POST|CONNECT|HEAD|PUT) /, "");
    var m = raw.match(/^(?:https?:\/\/)?([^\/]+)(\/.*)?$/) || [];
    return { host: m[1] || raw, path: (m[2] || "").slice(0, 80), why: b.reason || "" };
  }

  function renderContainment(st) {
    var s = st.scan, c = s.containment || {}, p = c.profile || {};
    if (p.runtime) {
      $$("#checks .v")[0].textContent = CHECKS[0][1](p);
    }
    var blocked = (s.result && s.result.blocked_egress) || st.blocked || [];
    $("#blocked-n").textContent = blocked.length;
    $("#blocked-empty").hidden = !!blocked.length;
    if (blocked.length) {
      var ul = $("#blocked");
      if (ul.children.length !== blocked.length) {
        ul.innerHTML = blocked.slice(0, 12).map(function (b) {
          var x = parseBlocked(b);
          return "<li>" + svg(P.shieldX, 16, ' style="color:var(--contained);margin-top:2px"') +
            '<span><span class="u">' + esc(x.host) + "<em>" + esc(x.path) + '</em></span><span class="w">' + esc(x.why) + '</span></span><span class="x">BLOCKED</span></li>';
        }).join("");
      }
    }
    $("#contain-panel").classList.toggle("hot", !!blocked.length || !!c.killed);
    $("#killed").innerHTML = c.killed ? '<div class="killed">' + esc(c.killed) + ". The host and other scans were unaffected.</div>" : "";
    var r = s.result;
    if (r && r.sandbox_secret_env_vars) {
      var sec = $("#secrets");
      sec.hidden = false;
      sec.innerHTML = "Credential-like environment variables inside the sandbox: <b>" +
        (r.sandbox_secret_env_vars.length ? esc(r.sandbox_secret_env_vars.join(", ")) : "none") + "</b>";
    }
  }

  var VERDICT_SUB = {
    FAIL: "Reject all is not respected.", PASS: "Reject all is respected.", REVIEW: "Needs a human look.",
    INCONCLUSIVE: "No verdict was possible on this visit.", CONTAINED: "The page was stopped inside its sandbox."
  };
  var LIED = " The site even told Google that consent was granted.";

  function renderResults(st) {
    var scan = st.scan, r = scan.result;
    renderStage(st);
    if (!r) {
      var errs = scan.events.filter(function (e) { return e.kind === "error"; });
      $("#verdict").className = "vbanner INCONCLUSIVE";
      $("#verdict").innerHTML = '<div class="l">' + tag("ERROR", "lg") + "<h1>The audit could not finish.</h1><p>" +
        esc((errs[errs.length - 1] || {}).detail || "See the timeline for details.") + "</p></div>";
      $("#finished").hidden = false;
      $$("#finished > section:not(#verdict)").forEach(function (x) { x.hidden = true; });
      return;
    }
    var lied = r.headline.indexOf(LIED.trim()) >= 0;
    var h1 = lied ? r.headline.replace(LIED, "") : r.headline;
    var blockedN = (r.blocked_egress || []).length;
    var sub = lied ? 'The site even told Google that consent was <span class="gr">granted</span>.' : esc(VERDICT_SUB[r.verdict] || "");
    if (blockedN) sub += " It also tried to reach internal addresses; all " + blockedN + " attack request" + (blockedN === 1 ? " was" : "s were") + " blocked.";
    sub += ' <span class="t3 mono" style="font-size:13px">· ' + esc(r.host || r.site) + " · " + esc(dateOf(scan.created)) + "</span>";
    var v = $("#verdict");
    v.className = "vbanner " + r.verdict;
    v.innerHTML = '<div class="l">' + tag(r.verdict, "lg") + "<h1>" + esc(h1) + "</h1><p>" + sub + "</p></div>" +
      '<div><a class="btn btn-primary report-link" href="/report/' + esc(scan.id) + '" target="_blank" rel="noopener">' +
      svg('<path d="M4 6V1.8h8V6M4 12H2.2V6h11.6v6H12M4 9.5h8v4.7H4z"/>', 15) + "Printable report</a></div>";

    var c = r.counts;
    var tracked = r.vendors.filter(function (x) { return x.severity !== "info"; });
    var confirmed = tracked.filter(function (x) { return x.proxy_confirmed; }).length;
    $("#stats").innerHTML = [
      [c.trackers_after_reject, "trackers after Reject all", c.trackers_after_reject ? "c-fail" : ""],
      [c.trackers_before_choice, "trackers before any choice", c.trackers_before_choice ? "c-fail" : ""],
      [c.tracking_cookies_after_reject, "tracking cookies after Reject all", ""],
      [tracked.length ? confirmed + "/" + tracked.length : "0", "findings confirmed by the egress guard", tracked.length ? "c-pass" : ""],
      [c.blocked_by_guard, "attacks blocked", c.blocked_by_guard ? "c-cont" : ""]
    ].map(function (x) {
      return '<div class="stat"><span class="n ' + x[2] + '">' + esc(x[0]) + '</span><span class="l">' + esc(x[1]) + "</span></div>";
    }).join("");

    var rows = r.vendors.filter(function (x) { return x.severity !== "info" || x.before_choice || x.after_reject; });
    var head = '<thead><tr><th scope="col">Vendor</th><th scope="col">Type</th><th scope="col">Severity</th><th scope="col" class="r">Before choice</th>' +
      '<th scope="col" class="r">After Reject all</th><th scope="col">Cookies after Reject all</th><th scope="col">Egress guard</th></tr></thead>';
    var body = rows.length ? rows.map(function (x) {
      return '<tr><th scope="row" style="white-space:nowrap">' + esc(x.vendor) +
        (x.consent_signal_after_reject === "granted" ? '<span class="flag">consent signal “granted”</span>' : "") +
        (x.note && x.consent_signal_after_reject !== "granted" ? '<span class="vnote">' + esc(x.note) + "</span>" : "") + "</th>" +
        '<td class="t2">' + esc(x.category_label) + "</td>" +
        '<td><span class="sev ' + esc(x.severity) + '"><i aria-hidden="true"><b></b><b></b><b></b></i>' + esc(x.severity) + "</span></td>" +
        '<td class="r num t2">' + (x.before_choice || "—") + "</td>" +
        '<td class="r num" style="font-weight:600;color:' + (x.after_reject ? "var(--fail)" : "var(--text-3)") + '">' + (x.after_reject || "—") + "</td>" +
        '<td class="num t2" style="font-size:13px">' + (x.cookies_after.length ? esc(x.cookies_after.join(", ")) : "—") + "</td>" +
        '<td class="num" style="font-size:13px;white-space:nowrap;color:' + (x.proxy_confirmed ? "var(--pass)" : "var(--text-3)") + '">' + (x.proxy_confirmed ? "confirmed ✓" : "—") + "</td></tr>";
    }).join("") : '<tr><td colspan="7" class="empty-row">No known trackers detected.</td></tr>';
    $("#vendors").innerHTML = head + "<tbody>" + body + "</tbody>";

    var hosts = (r.unclassified_after_reject || []).slice().sort(function (a, b) { return (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0); });
    if (hosts.length) {
      var sus = hosts.filter(function (h) { return h.suspicious; }).length;
      $("#hosts").hidden = false;
      $("#hosts").innerHTML = '<div class="hosts-h"><h2>Other third-party hosts</h2><span class="t3" style="font-size:14px">' +
        (sus ? sus + " suspicious, need a human look" : "contacted after Reject all · not in the tracker list") + "</span></div><ul>" +
        hosts.map(function (h) {
          return '<li class="chip' + (h.suspicious ? " sus" : "") + '">' + (h.suspicious ? svg(P.review, 13) : "") + esc(h.host) +
            ' <span class="t3">×' + h.count + "</span>" + (h.suspicious ? "<b>SUSPICIOUS</b>" : "") + "</li>";
        }).join("") + "</ul>";
    }

    var s = scan.summary || {};
    $("#summary").textContent = s.summary || "";
    $("#legal").textContent = s.legal_context || "";
    $("#actions").innerHTML = (s.actions || []).map(function (a, i) {
      return "<li><span>" + ("0" + (i + 1)).slice(-2) + "</span><span>" + esc(a) + "</span></li>";
    }).join("");
    var reporter = (scan.ai.calls || []).filter(function (x) { return x.role === "reporter"; })[0];
    $("#report-by").textContent = reporter ? "written by " + reporter.model + " from the computed evidence" : "template report · numbers come from evidence";

    renderEvidence(st);
    $("#finished").hidden = false;
    $("#evidence").hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function renderEvidence(st) {
    var scan = st.scan, ev = scan.evidence || { files: {} }, names = Object.keys(ev.files || {});
    $("#manifest").textContent = "sha256:" + (ev.manifest_sha256 || "n/a");
    $("#manifest-label").textContent = "Evidence manifest · SHA-256 over " + names.length + " files";
    $("#copy-hash").onclick = function () {
      var b = this;
      (navigator.clipboard ? navigator.clipboard.writeText(ev.manifest_sha256 || "") : Promise.reject()).then(function () {
        b.textContent = "Copied ✓"; setTimeout(function () { b.textContent = "Copy"; }, 1600);
      }).catch(function () {});
    };
    $("#files").innerHTML = names.map(function (n) {
      return '<li><a href="/api/scans/' + esc(scan.id) + "/files/" + esc(n) + '" target="_blank" rel="noopener">' + esc(n) + "</a><span>" + esc(ev.files[n].slice(0, 12)) + "…" + esc(ev.files[n].slice(-6)) + "</span></li>";
    }).join("");
    $("#files-label").textContent = "Show " + names.length + " evidence files";
    $("#files-toggle").onclick = function () {
      var open = this.getAttribute("aria-expanded") !== "true";
      this.setAttribute("aria-expanded", String(open));
      $("#files").hidden = !open;
      $("#files-label").textContent = (open ? "Hide " : "Show ") + names.length + " evidence files";
    };
    renderReview(st);
  }

  function renderReview(st) {
    var scan = st.scan, a = scan.approval, box = $("#review-box");
    var mh = (scan.evidence || {}).manifest_sha256 || "";
    if (a) {
      box.innerHTML = '<div class="stamp ' + esc(a.decision) + '"><b>' + (a.decision === "approved" ? "APPROVED ✓" : "REJECTED ✕") + "</b>" +
        "<span>" + esc(a.reviewer) + " · " + esc(dateOf(a.at)) + " · manifest " + esc(mh.slice(0, 4) + "…" + mh.slice(-4)) + "</span>" +
        (a.note ? '<span style="color:var(--text)">' + esc(a.note) + "</span>" : "") +
        "<span>approval sha256 " + esc((a.approval_sha256 || "").slice(0, 16)) + "…</span></div>";
      return;
    }
    if (!admin) {
      box.innerHTML = '<div class="pending"><b>Human review pending</b><span>This is an automated draft. A human reviewer must approve it before the report is filed or the site is named on the public dashboard.</span>' +
        '<a href="#/login" style="font-size:14px;font-weight:500">Sign in to review →</a></div>';
      return;
    }
    box.innerHTML = '<form class="review" id="review-form"><b>Human review</b>' +
      '<div class="radios" role="radiogroup" aria-label="Decision">' +
      '<button type="button" role="radio" class="ap" data-d="approved" aria-checked="' + (st.decision === "approved") + '">✓ Approve</button>' +
      '<button type="button" role="radio" class="rj" data-d="rejected" aria-checked="' + (st.decision === "rejected") + '">✕ Reject</button></div>' +
      '<label>Reviewer note<textarea id="review-note" rows="3" maxlength="500" placeholder="e.g. Verified against the egress-guard log; GA4 gcs=G111 after refusal."></textarea></label>' +
      '<p class="err" id="review-err" hidden></p>' +
      '<button type="submit" class="btn btn-primary">Sign and file review</button></form>';
    $$("#review-form [role=radio]").forEach(function (b) {
      b.addEventListener("click", function () {
        st.decision = b.dataset.d;
        $$("#review-form [role=radio]").forEach(function (x) { x.setAttribute("aria-checked", String(x === b)); });
      });
    });
    $("#review-form").addEventListener("submit", function (e) {
      e.preventDefault();
      post("/api/scans/" + st.id + "/approve", { reviewer: "", note: $("#review-note").value, decision: st.decision })
        .then(function (res) { st.scan.approval = res; renderReview(st); })
        .catch(function (err) {
          if (err.status === 401) { admin = null; renderNav(); renderReview(st); return; }
          $("#review-err").textContent = err.message; $("#review-err").hidden = false;
        });
    });
  }

  // ------------------------------------------------------------ login
  function showLogin() {
    if (admin) { location.hash = "#/dashboard"; return; }
    mount("tpl-login");
    var form = $("#login-form"), alertBox = $("#login-alert"), pass = $("#login-pass"), user = $("#login-user");
    pass.focus();
    function lock(retryAt) {
      [user, pass, $("#login-btn")].forEach(function (x) { x.disabled = true; });
      $("#login-btn").textContent = "Locked";
      var when = retryAt ? new Date(retryAt * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
      alertBox.innerHTML = '<div class="alert alert-review" role="alert">' + svg(P.lock) + "<span>Too many failed logins. Wait five minutes." +
        (when ? "<small>try again at " + esc(when) + "</small>" : "") + "</span></div>";
      if (retryAt) setTimeout(function () { if (location.hash.indexOf("#/login") === 0) showLogin(); }, Math.max(1000, retryAt * 1000 - Date.now()));
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      alertBox.innerHTML = "";
      post("/api/auth/login", { user: user.value, password: pass.value })
        .then(function (r) { admin = r.user; location.hash = "#/dashboard"; })
        .catch(function (err) {
          if (err.status === 429) { lock(err.data.retry_at); return; }
          [user, pass].forEach(function (x) { x.setAttribute("aria-invalid", "true"); });
          var left = err.data.attempts_left;
          alertBox.innerHTML = '<div class="alert alert-fail" role="alert">' + svg(P.fail) + "<span>" + esc(err.message) +
            (left != null ? "<small>" + left + (left === 1 ? " attempt" : " attempts") + " left before a 5-minute lockout</small>" : "") + "</span></div>";
          pass.select();
        });
    });
  }

  // ------------------------------------------------------------ dashboard
  var VERDICT_ORDER = ["FAIL", "REVIEW", "PASS", "INCONCLUSIVE", "CONTAINED"];
  var dash = { filter: "", q: "", hideDemos: false, data: null };
  function pct(x) { return x == null ? "—" : Math.round(x * 100) + "%"; }

  function showDashboard(focusBatch) {
    mount("tpl-dashboard");
    var maxBatch = admin ? 200 : 10;
    $("#qb").textContent = admin ? "Queue a batch of audits" : "Audit up to 10 sites";
    $("#batch-help").textContent = admin
      ? "One URL per line, up to 200. Each site gets its own disposable sandbox; results appear above as they finish."
      : "One URL per line, up to 10, no account needed. Each site gets its own disposable sandbox; your results appear in the table above as they finish.";
    var search = $("#row-search"); search.value = dash.q;
    search.addEventListener("input", function () { dash.q = search.value.trim().toLowerCase(); renderRows(); });
    var sw = $("#hide-demos"); sw.setAttribute("aria-checked", String(dash.hideDemos));
    sw.addEventListener("click", function () { dash.hideDemos = !dash.hideDemos; sw.setAttribute("aria-checked", String(dash.hideDemos)); renderRows(); });
    var ta = $("#batch-urls"), bbtn = $("#batch-btn"), msg = $("#batch-msg");
    function validLines() {
      return ta.value.split(/\n/).map(function (x) { return x.trim(); }).filter(function (x) { return x && x.charAt(0) !== "#" && /\./.test(x); });
    }
    ta.addEventListener("input", function () {
      var n = validLines().length, over = n > maxBatch;
      bbtn.disabled = !n || over;
      bbtn.textContent = over ? "At most " + maxBatch + " sites" : n ? "Audit " + n + (n === 1 ? " site" : " sites") : "Audit sites";
      msg.className = "msg"; msg.textContent = over ? "Remove " + (n - maxBatch) + (n - maxBatch === 1 ? " line." : " lines.") : "";
    });
    $("#batch-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var urls = validLines();
      if (!urls.length) return;
      bbtn.disabled = true;
      post("/api/scans/batch", { urls: urls }).then(function (r) {
        r.ids.slice().reverse().forEach(rememberScan);
        msg.className = "msg";
        msg.textContent = "✓ " + r.queued + " queued" + (r.invalid.length ? " · " + r.invalid.length + " skipped (not valid addresses)" : "");
        ta.value = ""; bbtn.textContent = "Audit sites";
        loadDashboard();
      }).catch(function (err) { msg.className = "msg err"; msg.textContent = err.message; bbtn.disabled = false; });
    });
    loadDashboard();
    if (focusBatch) setTimeout(function () { $(".batch").scrollIntoView({ block: "center" }); ta.focus(); }, 60);
  }

  function loadDashboard() {
    clearTimeout(pollTimer);
    api("/api/stats?mine=" + encodeURIComponent(myScans().join(","))).then(function (d) {
      if (location.hash.indexOf("#/dashboard") !== 0) return;
      dash.data = d;
      renderDashboard(d);
      pollTimer = setTimeout(loadDashboard, d.totals.queued + d.totals.running ? 4000 : 20000);
    }).catch(function (e) { $("#dash-sub").textContent = e.message; });
  }

  function renderDashboard(d) {
    var t = d.totals;
    $("#dash-sub").textContent = t.audits + " audits: " + t.real_sites + " real sites, " + t.demo_runs + " demo runs" + (t.errors ? ", " + t.errors + " failed to run" : "");
    var q = $("#dash-queue"), busy = t.queued + t.running;
    q.className = "queue" + (busy ? " on" : "");
    q.innerHTML = busy ? '<span class="dot"></span>' + t.running + " running · " + t.queued + " queued" : "queue idle";

    var pub = d.view === "public", pn = $("#pubnote");
    pn.hidden = !pub;
    if (pub) {
      pn.innerHTML = svg(P.lock) + "<span><b>Public view.</b> The figures cover every audit, anonymously. The table names a real site only after a " +
        "human reviewer has approved its audit, so no company is named on an unchecked automated result" +
        (d.unpublished ? " (" + d.unpublished + " awaiting review)" : "") + ". Your own audits always appear. " +
        '<a href="#/login">Reviewer sign-in</a></span>';
    }
    $("#all").firstChild.nodeValue = pub ? "Reviewed audits and yours " : "All audits ";
    var vp = $("#vantage");
    vp.hidden = !!t.eu_vantage;
    vp.innerHTML = svg(P.review) + "<span><b>Scanner location: outside the EU.</b> Many sites only show cookie banners to EU visitors, so a site that shows " +
      "no banner here is marked INCONCLUSIVE rather than judged. Deploy on a Vultr EU region (e.g. Frankfurt) with <code>CC_EU_VANTAGE=1</code> for complete results.</span>";

    var has = t.conclusive > 0;
    $("#kpis").innerHTML = [
      [has ? pct(t.fail_rate) : "—", "of conclusive real-site audits FAIL", has ? t.fail + " of " + t.conclusive + " sites" : "no conclusive audits yet", t.fail ? "c-fail" : ""],
      [has ? t.sites_tracking_after_reject : "—", "sites kept tracking after Reject all", t.trackers_after_reject + " tracker findings", t.sites_tracking_after_reject ? "c-fail" : ""],
      [has ? t.sites_tracking_before_choice : "—", "sites tracked before any choice", "no prior consent", t.sites_tracking_before_choice ? "c-fail" : ""],
      [has ? t.sites_lying_to_google : "—", "sites told Google consent was “granted”", "after the visitor refused", t.sites_lying_to_google ? "c-fail" : ""],
      [has ? t.tracking_cookies_after_reject : "—", "tracking cookies set after Reject all", "across conclusive sites", ""]
    ].map(function (k) {
      return '<div class="stat"><span class="n ' + k[3] + '">' + esc(k[0]) + '</span><span class="l">' + esc(k[1]) + '</span><span class="s">' + esc(k[2]) + "</span></div>";
    }).join("");

    var total = VERDICT_ORDER.reduce(function (a, k) { return a + d.verdicts[k]; }, 0);
    $("#verdict-total").textContent = total + " real sites · latest audit per site";
    if (!total) {
      $("#vb-body").innerHTML = '<div class="empty-box">No verdicts yet. Queue a batch of audits below.</div>';
    } else {
      var segs = VERDICT_ORDER.filter(function (k) { return d.verdicts[k]; });
      var why = [];
      if (t.blocked_bot) why.push(t.blocked_bot + " blocked or challenged the automated browser");
      if (t.no_banner_shown) why.push(t.no_banner_shown + " showed no banner to a non-EU visitor");
      if (t.consent_or_pay) why.push(t.consent_or_pay + " are consent-or-pay walls");
      $("#vb-body").innerHTML =
        '<div class="vbar" role="img" aria-label="' + esc(segs.map(function (k) { return k + " " + d.verdicts[k]; }).join(", ")) + '">' +
        segs.map(function (k) {
          var n = d.verdicts[k];
          return '<div class="seg-' + k + '" style="flex:' + n + ' 0 0" title="' + esc(k + ": " + n + " sites") + '">' + (n / total > 0.1 ? esc(k + " " + n) : "") + "</div>";
        }).join("") + "</div>" +
        '<ul class="vleg">' + VERDICT_ORDER.map(function (k) {
          return "<li>" + tag(k, "sm") + "<b>" + d.verdicts[k] + "</b><span>" + Math.round(d.verdicts[k] / total * 100) + "%</span></li>";
        }).join("") + "</ul>" +
        (why.length ? '<p class="why">Why sites were inconclusive: ' + esc(why.join(" · ")) + ".</p>" : "");
    }

    $("#cont").innerHTML = [
      ["Attacks blocked", t.attacks_blocked, "var(--contained)"],
      ["Runaway pages contained", t.contained, "var(--contained)"],
      ["Sandboxes destroyed", t.sandboxes_destroyed + " / " + t.sandboxes_finished, t.sandboxes_destroyed === t.sandboxes_finished ? "var(--pass)" : "var(--review)"],
      ["Reports approved", t.approved, "var(--text)"],
      ["Vultr AI calls · avg latency", t.ai_calls ? t.ai_calls + " · " + t.ai_avg_latency_ms + " ms" : "offline", "var(--text)"]
    ].map(function (c) { return "<div><dt>" + esc(c[0]) + '</dt><dd style="color:' + c[2] + '">' + esc(c[1]) + "</dd></div>"; }).join("");

    var vmax = d.top_vendors.reduce(function (m, v) { return Math.max(m, v.sites); }, 0) || 1;
    $("#vendor-bars").innerHTML = d.top_vendors.length ? '<ol class="bars">' + d.top_vendors.map(function (v) {
      return '<li title="' + esc(v.vendor + ": " + v.sites + " sites") + '"><span>' + esc(v.vendor) + '</span><span class="trk"><i style="width:' + (v.sites / vmax * 100) + '%"></i></span><span class="v">' + v.sites + "</span></li>";
    }).join("") + "</ol>" : '<div class="empty-box">No trackers seen after Reject all yet.</div>';

    var minN = t.real_sites > 20 ? 3 : 1;
    var cs = d.countries.filter(function (c) { return c.audits >= minN; });
    $("#country-bars").innerHTML = cs.length ? '<ol class="bars">' + cs.map(function (c) {
      return '<li title="' + esc(c.country + ": " + c.fail + " of " + c.audits + " fail") + '"><span>' + esc(c.country) + (c.code ? ' <span class="tld">' + esc(c.code) + "</span>" : "") +
        '</span><span class="trk"><i style="width:' + (c.fail_rate * 100) + '%"></i></span><span class="v">' + pct(c.fail_rate) + " <small>n=" + c.audits + "</small></span></li>";
    }).join("") + "</ol>" + (minN > 1 ? '<p class="t3" style="margin:0;font-size:12.5px">Countries with at least ' + minN + " conclusive audits.</p>" : "")
      : '<div class="empty-box">Needs conclusive audits of real sites.</div>';

    renderFilters();
    renderRows();
  }

  function rowMatches(r, f) {
    if (f === "active") return r.status === "queued" || r.status === "running";
    if (f === "error") return r.status === "error";
    return !f || r.verdict === f;
  }
  function renderFilters() {
    var d = dash.data, base = d.rows.filter(function (r) { return !(dash.hideDemos && r.demo); });
    var opts = [["", "ALL"]].concat(VERDICT_ORDER.map(function (k) { return [k, k]; }));
    if (base.some(function (r) { return rowMatches(r, "active"); })) opts.push(["active", "IN PROGRESS"]);
    if (base.some(function (r) { return rowMatches(r, "error"); })) opts.push(["error", "ERRORS"]);
    var box = $("#verdict-filter");
    box.innerHTML = opts.map(function (o) {
      var n = base.filter(function (r) { return rowMatches(r, o[0]); }).length;
      return '<button type="button" data-v="' + o[0] + '" aria-pressed="' + (dash.filter === o[0]) + '">' + esc(o[1]) + " <span>" + n + "</span></button>";
    }).join("");
    $$("button", box).forEach(function (b) {
      b.addEventListener("click", function () { dash.filter = b.dataset.v; renderFilters(); renderRows(); });
    });
  }

  function renderRows() {
    var d = dash.data; if (!d) return;
    var rows = d.rows.filter(function (r) {
      if (dash.hideDemos && r.demo) return false;
      if (!rowMatches(r, dash.filter)) return false;
      if (dash.q && (r.host + " " + r.vendors.join(" ")).toLowerCase().indexOf(dash.q) < 0) return false;
      return true;
    });
    $("#rows-count").textContent = "showing " + rows.length + " of " + d.rows.length;
    var head = '<thead><tr><th scope="col">Site</th><th scope="col">Verdict</th><th scope="col" class="r">After Reject</th><th scope="col" class="r">Before choice</th>' +
      '<th scope="col" class="r">Cookies</th><th scope="col">Kept running</th><th scope="col">Review</th><th scope="col" class="r">Audited</th></tr></thead>';
    var body = rows.slice(0, 400).map(function (r) {
      var v = r.verdict || r.status;
      var chips = r.vendors.slice(0, 3).map(function (x) { return '<span class="mini">' + esc(x) + "</span>"; }).join("") +
        (r.vendors.length > 3 ? '<span class="mini">+' + (r.vendors.length - 3) + "</span>" : "");
      var rev = r.approved === "approved" ? ['<span class="c-pass">✓ Approved</span>'] : r.approved === "rejected" ? ['<span class="c-fail">✕ Rejected</span>']
        : r.status === "done" ? ['<span class="t2">● Pending review</span>'] : ['<span class="t3">—</span>'];
      return '<tr data-id="' + esc(r.id) + '"><th scope="row"><a class="site" href="#/scan/' + esc(r.id) + '">' + esc(r.host) + "</a>" +
        (r.demo ? '<span class="demo-b">DEMO</span>' : "") + (r.mine ? '<span class="mine-b">YOURS</span>' : "") + "</th>" +
        "<td>" + tag(v, "sm") + "</td>" +
        '<td class="r num" style="font-weight:600;color:' + (r.after_reject ? "var(--fail)" : "var(--text-3)") + '">' + r.after_reject + "</td>" +
        '<td class="r num t2">' + r.before_choice + "</td>" +
        '<td class="r num t2">' + r.cookies + "</td>" +
        '<td><span class="chips">' + (chips || '<span class="t3">—</span>') + "</span></td>" +
        '<td style="white-space:nowrap;font-size:13px">' + rev[0] + "</td>" +
        '<td class="r when">' + esc(ago(r.created)) + "</td></tr>";
    }).join("");
    var empty = d.rows.length ? ["No audits match these filters.", "Try another verdict or clear the search."]
      : d.view === "public" ? ["No reviewed audits yet.", "Audit up to 10 sites below; your results appear here."]
      : ["No audits yet.", "Queue a batch below or run one from the home page."];
    $("#audits").innerHTML = head + "<tbody>" + (body || '<tr><td colspan="8" class="empty-row"><b style="color:var(--text);display:block;margin-bottom:4px">' +
      esc(empty[0]) + "</b>" + esc(empty[1]) + "</td></tr>") + "</tbody>";
    $$("#audits tbody tr[data-id]").forEach(function (tr) {
      tr.addEventListener("click", function (e) { if (e.target.tagName !== "A") location.hash = "#/scan/" + tr.dataset.id; });
    });
  }

  // ------------------------------------------------------------ boot
  api("/api/health").then(function (h) { health = h; renderPills(); }).catch(function () {});
  $("#nav-logout").addEventListener("click", function () {
    post("/api/auth/logout").catch(function () {}).then(function () { admin = null; location.hash = "#/"; route(); });
  });
  window.addEventListener("hashchange", route);
  api("/api/auth/me").then(function (r) { admin = r.user; }).catch(function () {}).then(route);
})();
