# Submission kit

## lablab.ai form

**Links**
- Live demo: https://consentcheck.mindgears.dev (Vultr Cloud Compute, Frankfurt; no sign-in needed)
- Source: https://github.com/Bhaskar422/consentcheck
- Slides: `submission/slides.pdf` · Cover image: `submission/cover.png` (1920x1080)

**Project title**
ConsentCheck: does "Reject all" actually reject?

**Short description** (one line)
An AI agent that clicks "Reject all" inside a disposable gVisor sandbox on Vultr and proves, with two independent network logs, which trackers kept running.

**Long description**
Many websites show a "Reject all" button and then load ad pixels and analytics anyway. That breaks the ePrivacy Directive and GDPR, which require consent before tracking and say refusing must be as easy as accepting. Privacy teams still check this by hand in DevTools, one site at a time.

ConsentCheck automates the check. You paste a URL. A fresh browser sandbox starts on Vultr Cloud Compute, isolated with gVisor on an internal-only network with no secrets and hard memory, CPU and PID limits. A vision model on Vultr Serverless Inference (qwen3.8-flash-next) finds the consent banner across frames, shadow DOM, 16 consent platforms and 15+ languages, and proposes the refusal click. A deterministic policy gate makes sure the agent can never click "Accept", even when the page tries to prompt-inject it. A second model from a different family (minimax-m3.1-flash) checks the before and after screenshots. The sandbox then watches every request, including a fresh page view as a returning visitor.

The verdict is computed from evidence, not from the AI. The browser's own request log and an independent egress-guard proxy (the sandbox's only route out) both record the traffic, so each finding is confirmed by two witnesses. ConsentCheck flags trackers after rejection, trackers before any choice, tracking cookies, and sites that tell Google consent was "granted" after you refused. mimo-v2.6-flash writes a plain-English summary with legal context and fixes. Every artifact is SHA-256 hashed, and a human reviewer approves the report before it is shared.

Containment is the product. A website under audit is untrusted code, so our demo shop attacks the auditor. It hides a prompt injection in its banner and tries to reach cloud metadata (169.254.169.254), internal IPs and the orchestrator itself. The policy gate ignores the injection and the egress guard blocks and logs every probe. A memory-bomb page crashes only its own sandbox, while the host and other scans keep running. After every scan the sandbox is destroyed and the teardown is verified.

It works on real sites. Anyone can audit up to 10 sites at once and open a public dashboard; a human reviewer approves each real-site result before the site is named publicly. In a first benchmark of 113 popular European websites, 13 of the 29 sites where a verdict was possible kept tracking after Reject all or before any choice. Google Ads and Google Analytics were the vendors most often still running.

The agent is deliberately conservative:
- It skips "reject and subscribe" paywall buttons and single-vendor opt-outs.
- It treats sites that block bots, or show no banner outside the EU, as inconclusive rather than guessing.

**Technology tags**
Vultr, Vultr Serverless Inference, Vultr Cloud Compute, gVisor, Docker, Playwright, mitmproxy, FastAPI, Caddy, Qwen, MiniMax, MiMo

**Category tags**
Privacy, Compliance, Security, AI Agents, Browser Automation, RegTech

## Demo video script (about 2:30)

| Time | Show | Say |
|---|---|---|
| 0:00–0:15 | Any big site's cookie banner, cursor on "Reject all" | "You click Reject all. Do the trackers stop? Often they don't, and that's illegal in the EU. Today privacy teams check it by hand. ConsentCheck does it with an AI agent that can't be turned against you." |
| 0:15–0:30 | ConsentCheck home page | "Paste a URL. Everything runs on Vultr: a gVisor sandbox per scan on Cloud Compute, and Serverless Inference for the AI." |
| 0:30–1:15 | Click **Hostile shop**. Narrate the timeline as it fills in | "A fresh sandbox comes up: internal-only network, no secrets, 1 GB cap. The vision model reads the banner. This page hides a prompt injection telling AI agents to click Accept. The policy gate means the agent can only ever click reject. It clicks Reject all, a second model verifies the screenshot, then it reloads like a returning visitor." |
| 1:15–1:45 | Verdict FAIL, tracker table, stats | "FAIL. Six trackers ran after we rejected, the site told Google consent was granted, and the cookies are right here. Each finding is confirmed by the egress guard's independent log, not by the AI." |
| 1:45–2:05 | **Containment moment:** the blocked-requests panel, then run **Memory bomb** | "The page also tried to steal cloud credentials from the metadata service and reach our own server. All blocked and logged. This page tries to crash the auditor: the sandbox dies at its memory cap, and nothing else notices. Then it's destroyed and we verify nothing is left." |
| 2:05–2:20 | Evidence manifest, approve as reviewer, printable report | "Every artifact is hashed, a human approves, and the DPO gets a printable report." |
| 2:20–2:30 | IKEA PASS result or the architecture slide | "It works on real sites too. ConsentCheck: an agent that does real work, safely." |

**Recording tips:** record at 1280×800 or 1440×900 and zoom the browser to 110%. Run the hostile shop once before recording so Docker images are warm. Keep the timeline and screenshot visible at the same time.

## Slides (5–6)

1. **Title.** ConsentCheck: you clicked Reject all. Did the trackers stop?
2. **Problem.** Fake "Reject all" buttons. EU law requires prior consent and easy refusal. Today it's checked manually.
3. **Demo screenshot.** FAIL verdict with tracker table.
4. **Architecture.** The diagram from the README. Emphasise Vultr Cloud Compute + gVisor, Serverless Inference with three model roles, and the two witnesses.
5. **Containment.** The table: injection ignored, metadata blocked, memory bomb contained, no secrets, destroyed after every scan.
6. **Business value and what's next.** DPOs, agencies and vendor due diligence; scheduled monitoring, multi-region scans, a CMP fix assistant.
