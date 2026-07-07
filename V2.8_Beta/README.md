# Perimeter — black-box vulnerability enumeration console

Ten Claude-powered agents, one per OWASP Top 10 category, triaging live
HTTP traffic from an OWASP ZAP scan of your own running application.
Scanning and AI triage are deliberately separate steps: running a scan
never requires an Anthropic API key or spends any tokens, and AI review
only happens when you explicitly approve it, governed by an optional
token budget.

This is black-box only, by design: no credentials, no login, no
assumptions about what's running underneath - the same vantage point a
real attacker has. What makes it strong from that vantage point is
thoroughness, not access: every scan runs the classic spider *and* a
JavaScript-aware Ajax Spider (most modern targets are single-page apps
the classic spider alone can't fully see), pushes the active scan policy
to its highest attack strength and most sensitive alert threshold, and
separately checks a curated list of commonly-exposed sensitive paths
(`.git/config`, `.env`, backup files, exposed admin/debug endpoints).
That breadth is then filtered by ten category-expert agents that decide
what's actually real and exploitable versus noise - cast a wide net
technically, then apply real judgment on top of it.

This tool only enumerates and helps remediate vulnerabilities in
applications you own and are authorized to test. It does not perform any
exploitation - never point it at a target outside your own environment.

## Architecture

```
running app - black-box, external vantage point
        |
        v
   classic spider + Ajax (JS-aware) spider
        |
        v
   active scan @ max attack strength, lowest alert threshold
        |
        v
   + exposed-sensitive-paths check (.git, .env, backups, debug endpoints)
        |
        v
  pending findings queue, tagged by app          <- no Anthropic key needed up to here
        |
        v
  [ explicit approval: "Approve AI triage" ]      <- the only point tokens get spent
        |
        v
  10 OwaspAgent instances (Claude triage + remediation guidance, batched)
        |              \
        v               v
   findings store   token usage log (governed by an optional budget)
        |
        v
  FastAPI backend (/api/*)  <---  Browser UI (Dashboard / Scanning / Settings)
```

## Setup

1. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Run OWASP ZAP in daemon mode, pointed at an **environment you control
   and are authorized to test**:
   ```
   zap.sh -daemon -port 8090 -config api.key=<your-zap-api-key>
   ```
   On Kali, ZAP is in the repos: `sudo apt install zaproxy`, then run
   `zaproxy -daemon -port 8090 -config api.key=<your-zap-api-key>`.
3. Either copy `.env.example` to `.env` and fill it in, or skip this
   entirely and enter everything (API key, ZAP details, Slack webhook) from
   the Settings tab in the browser UI once it's running - whichever is set
   most recently wins.

## Maximizing black-box coverage

This is where "best at enumeration" actually comes from - not a single
trick, but stacking several:

- **Classic + Ajax Spider.** The classic spider only sees links present
  in raw HTML. The Ajax Spider actually renders the page in a browser and
  clicks around, so JavaScript-rendered navigation and SPA routes get
  discovered too. Both run on every scan automatically.
- **Maximum active-scan thoroughness.** Before the active scan starts,
  the scan policy is pushed to `attackStrength=HIGH` and
  `alertThreshold=LOW` - ZAP's most aggressive, most sensitive settings.
  This surfaces more real issues, and also more borderline/noisy ones -
  which is fine, because that's exactly what the triage agents exist to
  sort out afterward. Casting a wide net technically and then applying
  real judgment is the whole strategy.
- **Exposed-paths check.** A short, curated list of paths that commonly
  get left exposed by accident (`.git/config`, `.env`, backup/SQL dumps,
  cloud credential files, debug/actuator endpoints) gets a direct GET
  request each, independent of whatever the spiders found. See
  `scanners/exposed_paths.py` to extend the list.
- **AI judgment on top, not instead of.** None of the above replaces
  expert review - it generates the raw material the ten OWASP agents then
  triage, batched, with your own app's context from `knowledge_base.yaml`
  factored in.

## Running through Azure AI Foundry instead of the direct API

If your organization routes Claude usage through Azure (e.g. for billing
or governance reasons), set **AI provider** to "Azure AI Foundry" in
Settings instead of using a direct Anthropic API key. You'll need:

- **Azure Foundry endpoint** - the full base URL, e.g.
  `https://<resource-name>.services.ai.azure.com/anthropic`.
- **Azure Foundry API key** - from your Foundry resource's Keys and
  Endpoint page.
- **Model / deployment name** - the deployment name you created in
  Foundry (e.g. `claude-opus-4-6`), in the same "Model / deployment name"
  field used for the direct API.

Everything else - batching, the token budget, the manual AI-enable
toggle, the per-app pending queue - works identically either way, since
both providers go through the same `OwaspAgent` code and the same
Messages API request shape. Only the authentication and routing differ.

Requires a reasonably recent `anthropic` Python package (the one that
ships `AnthropicFoundry`). If switching providers raises an import error,
run `pip install -U anthropic`.

One unrelated but important note: if you're pasting Azure or Anthropic
credentials anywhere to test things (chat, scripts, docs), treat that
credential as compromised the moment it's been shared outside the
Settings tab and rotate it - don't just continue using it.

## Scanning multiple applications

Every finding is tagged with an app name, so one dashboard can cover as
many applications as you want - you just scan them one at a time (a
second scan can't start while one's already running, to avoid two active
scans hitting ZAP at once).

- **CLI**: `python cli.py scan https://app1.example.com --app-name "Checkout service"`.
  Leave `--app-name` off and it defaults to the URL's hostname.
- **Browser UI**: the Scanning tab's form has an optional "App name" field
  with the same default-to-hostname behavior. An "Application" selector
  on the Dashboard lets you switch between applications, or leave it on
  "All applications" for the combined view.
- **API**: `POST /api/scan` accepts an optional `app_name`; `GET /api/findings`,
  `/api/summary/severity`, and `/api/summary/category` all accept an
  `?app_name=` query parameter, and `GET /api/apps` lists every app name
  seen so far.

If you're upgrading an existing `findings.db` from before this existed,
nothing to do - the store adds the column automatically on first run and
backfills old rows as `"unspecified"`.

## Browser UI

```
python cli.py serve
```

Then open `http://localhost:9000`. Three tabs:

- **Dashboard** — open-finding counts by severity and category, an app
  selector, and the full filterable/expandable list of *triaged* findings
  (after AI review), with buttons to mark a finding in review, patched,
  or dismissed.
- **Scanning** — run a scan here (no API key needed - it only collects
  findings). Once a scan finishes, every raw finding shows up in a list
  right there, each with its severity badge and an expandable
  description, plus buttons to download them all as JSON or CSV. AI
  triage is a separate, optional button on the same screen - it's there
  whenever you want it, not required to see or use the raw results.
- **Settings** — AI provider (direct Anthropic API or Azure Foundry) and
  credentials, agent model/deployment name, ZAP connection details,
  optional Slack webhook, and **cost & token governance**: the
  skip-informational-findings toggle, an optional token limit, a live
  used/limit/remaining display, and a button to reset the usage counter.
  Saved settings are read fresh on every action - no restart needed. Keys
  are never echoed back to the browser in full, only as a masked preview.

Settings entered through the UI are stored in `runtime_settings.json`
locally (gitignored) and take priority over `.env` values, so you can run
the server once with no `.env` at all and configure everything from the
browser instead.

This UI has no authentication of its own - it's meant to run on your own
machine or an internal network, not be exposed to the public internet.

## Cost controls

AI triage is the only part of this tool that costs money, so it's gated
behind an explicit approval click, an on/off switch, and an optional
budget - and the calls themselves are structured to minimize cost.

**Batched calls, not one-per-finding.** Findings are grouped by OWASP
category and sent to that category's agent in batches of up to 15 in a
single Claude call, instead of one call per finding. This is the main
cost lever in the whole tool: the system prompt (category instructions +
any app-specific context from `knowledge_base.yaml`) gets paid for once
per batch instead of once per finding. For a category with 30 findings,
that's 2 calls instead of 30 - in testing this cut total tokens by roughly
80% for that case, purely from not repeating the system prompt 30 times.
`MAX_BATCH_SIZE` in `agents/agent.py` controls the cap if you want it
larger or smaller. Maximizing scan thoroughness (above) generally means
*more* raw findings, so this matters more here than it would otherwise.

**Skip informational findings.** On by default (toggle in Settings),
this drops Informational-severity alerts - usually the highest-volume,
lowest-value findings - before they're even queued, so they never reach
triage at all.

**Prompt caching, with a caveat for Opus specifically.** Each call marks
the system prompt as cacheable, which can mean a 90% discount on repeat
reads. The catch: Anthropic's minimum cacheable size is 4,096 tokens for
Opus (vs. 1,024 for Sonnet), and this tool's system prompts are usually
well under that unless your `knowledge_base.yaml` gets quite large - so
don't expect this to do much on Opus by itself. If cost matters more than
squeezing the most out of Opus specifically, the single biggest lever
left is switching **Model / deployment name** in Settings to a cheaper
model - everything else in this section applies identically regardless
of which model you pick.

**Token budget.**
- Set a **token limit** in Settings (0 means unlimited, the default).
- The limit is checked before each batch, not pre-calculated for the
  whole run - so it can overshoot by roughly one batch's worth of tokens
  on the call that crosses the line, never more. If triage stops early
  for this reason, the UI tells you how many findings are still pending.
- Usage accumulates across every scan and every app until you reset it
  from Settings - resetting only zeroes the counter, it doesn't change
  your limit.
- `python cli.py tokens` shows the same numbers from the command line.

## Usage (command line)

Everything above is also available without the browser, useful for CI or
scripting.

Run a scan (no API key needed - just queues findings):

```
python cli.py scan https://your-app.com --app-name "Checkout service"
```

Approve AI triage for what's queued (this is the step that spends tokens,
and the one place you need credentials set):

```
python cli.py triage --app-name "Checkout service"
```

Check token usage and budget:

```
python cli.py tokens
```

Print a quick severity summary of triaged findings:

```
python cli.py report
```

Full API surface (same one the browser UI calls, all under `/api`):
- `POST /api/scan` — run a scan, no API key required (`{"target_url": "...", "app_name": "..."}`)
- `GET /api/scan/status` — poll while a scan is running
- `GET /api/pending` — count, category breakdown, and the full list of raw findings awaiting triage (`?app_name=` to filter)
- `POST /api/triage` — approve AI triage of pending findings (`{"app_name": "..."}` - requires credentials and an available token budget)
- `GET /api/triage/status` — poll while triage is running
- `GET /api/findings` — full list of *triaged* findings (`?app_name=` to filter)
- `PATCH /api/findings/{id}` — update a finding's status
- `GET /api/summary/severity` / `GET /api/summary/category` — counts (`?app_name=` to filter)
- `GET /api/apps` — every app name seen so far
- `GET /api/tokens` / `POST /api/tokens/reset` — usage, limit, remaining; reset the counter
- `GET /api/settings` / `POST /api/settings` — read/update runtime settings

## Teaching the agents about your app

There's no model fine-tuning involved - "training" the agents means giving
them more context, via `knowledge_base.yaml`. Edit that file directly, no
code changes needed:

- `app_context` (tech stack, auth flow, sensitive endpoints) is shared
  across every agent.
- Each OWASP category section takes `business_rules` (app-specific
  invariants, e.g. "users can only access their own orders"),
  `known_false_positives` (scanner alerts you've already confirmed are
  noise for this app), and `past_examples` (real findings you've seen
  before, with the severity you assigned and why - this is what calibrates
  the agent's judgment on borderline cases).

This file is read fresh every time AI triage runs, so updates take effect
immediately without restarting anything. Start small - even one or two
real false positives per category meaningfully cuts down noise.

## A note on coverage

Black-box DAST sees the application from the outside, the same way an
attacker would, so it's strong on access control, injection,
misconfiguration, and SSRF - especially with the maximum-thoroughness
settings above. It's inherently weaker on categories that depend on
things outside login-free testing entirely - A07 findings will mostly be
limited to what's visible pre-authentication, and A08/A09 (software/data
integrity and logging/monitoring failures) depend on things this vantage
point can't observe directly at all. The A08/A09 agent prompts are
written to flag low-confidence findings as such rather than overstating
certainty. If full coverage of authenticated flows or those two
categories matters, you'll eventually want grey-box/authenticated testing
or a SAST/CI-integrity check alongside this, even though this build is
deliberately black-box-only DAST by design.

## Extending

- **Add another DAST tool**: e.g. Nuclei or Nikto - subclass
  `scanners.base.BaseScanner`, implement `scan()`, and run it alongside
  `ZapScanner` in `Orchestrator.scan()`.
- **Tune scan thoroughness**: `_SCAN_POLICY_NAME`, the attack strength,
  and the alert threshold are all set near the top of
  `scanners/zap_scanner.py`.
- **Extend the exposed-paths list**: `_COMMON_PATHS` in
  `scanners/exposed_paths.py`.
- **Tune an agent**: edit its prompt in `agents/prompts.py` — each one is
  independent, so refining A03's prompt doesn't affect A07.
- **Change cadence**: full active scans are slow - wire `cli.py scan` into
  a nightly job rather than running it on every commit.
- **Remediation**: `TriagedFinding.remediation` holds Claude's fix guidance
  as text, not a ready diff (black-box has no source code to patch
  directly) - wire this into a ticket rather than treating it as mergeable.

## Security notes

- This tool accumulates a live map of your own weaknesses — restrict
  access to its database and API the same way you'd restrict a
  vulnerability management system.
- `runtime_settings.json` holds your API key in plaintext once you save it
  from the Settings tab, the same tradeoff as a `.env` file. It's
  gitignored - keep it that way, and don't run this UI on a shared or
  internet-facing machine.
- Maximum attack strength means more active probing, not more risk to
  data you don't own - this still only ever targets the URL you give it.
  Only ever point the scanner at infrastructure you own and are
  authorized to test.
