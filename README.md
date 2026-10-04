# Vibe Coding Inspector

Vibe Coding Inspector inspects a running web app, and optionally its source code, for runtime, static-code, security
and compliance issues. Every finding is backed by evidence a reviewer can check: where it is, what was checked, and
the exact excerpt that was observed.

## What it does

- crawls a target URL in **authorised localhost** mode (can also read a local repository) or **public read-only** mode
  (passive HTTP only, respects `robots.txt`, never reads source code)
- runs four modules concurrently and reports per-module coverage: state, duration, what was scanned, notes, and the
  error if a module failed (a failed module never shows up as "0 issues")
- shows evidence first for every finding, separates directly observed issues from pattern-based *hypotheses*, and
  masks secrets in the UI and in exports
- supports human review: confirm / reject / escalate (reject and escalate require a reason, enforced by the API) and a
  fix-approval step that is only available for confirmed findings and never changes code automatically
- exports Markdown and JSON reports with coverage, evidence and review decisions; **Print / PDF** prints the full report

## What each module checks

| Module | Checks (each finding includes the evidence listed) |
| --- | --- |
| Runtime | Broken links and error responses (status line + the page and HTML line that links to it); visible stack traces or error text; missing `<title>`, `lang`, viewport meta; unlabelled form controls; images without `alt`; mixed content. Site-wide issues are grouped into one finding listing every page/element. |
| Static code | Relative imports (JS/TS and Python) that point to files that do not exist, listing the paths tried; `setInterval` without `clearInterval`; listeners added without removal; `debugger` statements; TODO/FIXME markers. Comments and string literals are ignored. |
| Security | Missing CSP, framing protection (accepts CSP `frame-ancestors`), `nosniff`, HSTS (https only); plain HTTP on public sites; version-revealing headers; wildcard CORS with credentials; cookies missing `HttpOnly`/`SameSite`/`Secure`; hard-coded secrets (provider formats plus quoted secret-like assignments, placeholders ignored, values masked); `eval`, `new Function`, HTML injection sinks, `shell=True`, disabled TLS verification, `pickle`; `.env` files that are not git-ignored; `npm audit` (or a note saying why it did not run). |
| Compliance | Privacy policy, terms, contact and about links searched across every crawled page (the evidence lists the pages and links inspected); cookie consent is only required when cookies or known trackers are actually observed. |

The runtime module is passive HTTP + HTML inspection: JavaScript is not executed, so client-rendered content and console
errors are not captured. The coverage notes say so on every scan.

## Settings

All preferences live in one **Settings** drawer (gear icon, top right), apply immediately and persist in the browser:

- **Theme**: System / Light / Dark (System follows the OS and updates live)
- **Density**: Comfortable / Compact (touch screens keep 44 px targets either way)
- **Motion**: Follow system / Reduce
- **Reviewer name**: recorded with every review and fix decision
- **Scan limits**: max pages to crawl (1–50) and request timeout (1–60 s), sent with each scan and enforced by the backend

The launch form shows the current limits with a link to change them rather than repeating the controls.

## Run

### Backend

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

The API only accepts cross-origin requests from the Vite dev server (`http://localhost:5173`, `http://127.0.0.1:5173`).
Override with `INSPECTOR_CORS_ORIGINS` (comma-separated) if you serve the UI elsewhere.

### Frontend

```bash
npm install
npm run dev
```

The dev server proxies `/api` to `http://127.0.0.1:8000`. Try it against the bundled sample site:
`cd tmp_test_site && python -m http.server 8765`, then scan `http://localhost:8765/` with repository path
`<this repo>/tmp_test_repo`.

## Tests

```bash
pip install -r backend/requirements-dev.txt
python -m pytest -q          # backend: analyzers run against a local HTTP fixture server
npm test                     # frontend: settings, launch form, findings, polling
npm run build                # type-check + production build
```

## Architecture

- `backend/app.py`: FastAPI service, request validation, Markdown/JSON report rendering
- `backend/orchestrator.py`: scan store, concurrent module execution, coverage reports, deduplication
- `backend/context.py`: per-scan shared state (one crawl, one repository index, single-flight HTTP cache)
- `backend/analyzers/web.py`: HTTP fetcher (each URL fetched once per scan) and breadth-first, concurrent crawler
- `backend/analyzers/repo.py`: repository index that skips vendor/build directories and large or binary files
- `backend/analyzers/common.py`: finding factory and evidence formatting shared by all modules
- `backend/analyzers/{runtime,static_analysis,security,compliance}.py`: the four modules
- `src/App.tsx`: page layout; `src/components/`: panels and shared UI primitives (`ui.tsx`)
- `src/lib/settings.tsx`: settings model, persistence and appearance; `src/lib/meta.ts`: labels, icons, formatting
- `src/hooks/useScan.ts`: polling that stops when the scan completes
- `src/api/client.ts`: the single frontend API adapter; `src/contracts/finding.ts`: mirrors `backend/schemas.py`

## API

- `POST /api/scans` — `{target_url, repo_path?, authorization_confirmed, inspection_mode, max_pages?, timeout_seconds?}`
- `GET /api/scans/{scan_id}` — status, options, per-module reports (`modules`) and summary counts
- `GET /api/scans/{scan_id}/findings`
- `PATCH /api/findings/{finding_id}/review` — reason required for `rejected` / `escalated`
- `PATCH /api/findings/{finding_id}/fix-review` — `approved` requires a confirmed finding
- `GET /api/scans/{scan_id}/report?format=markdown|json` — `text/markdown` or `application/json`

Each finding's `evidence` contains `snippet` (the observed excerpt), `captured_output` (how it was obtained, e.g. the
request and response status), `check` (the rule that was evaluated) and `occurrences`.

## Create a new GitHub repository and push

```bash
chmod +x scripts/create_github_repo_and_push.sh
GITHUB_TOKEN=your_github_token ./scripts/create_github_repo_and_push.sh \
  --repo-name vibe-coding-inspector \
  --visibility private \
  --description "Vibe Coding Inspector" \
  --message "Initial commit"
```

Requires `git`, a `GITHUB_TOKEN` with repository creation permissions, and `git config user.name` / `user.email`.

## Limitations

- no browser automation yet: console errors and client-rendered pages are not inspected
- scans are kept in memory (last 50) and are lost when the backend restarts
- dependency checks use `npm audit` and need a `package-lock.json` plus network access
