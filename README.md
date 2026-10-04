# Vibe Coding Inspector

This project implements Vibe Coding Inspector, a modular inspection system for websites and webpages using an orchestrated workflow derived from the loaded runtime, static-analysis, security, compliance, frontend, and backend skill definitions.

## What it does

- inspects a target URL in either authorized localhost mode or passive public-readonly mode
- optionally inspects a local source repository for static and secret findings
- aggregates runtime, static, security, and compliance findings into a shared schema
- exposes a backend API for scan lifecycle, findings review, fix review, and report export
- provides a React dashboard for inspection launch, progress tracking, finding review, and report preview

## Safety model

- localhost mode supports deeper inspection but still stays read-oriented
- public-readonly mode is limited to passive HTTP inspection without repo-dependent deep analysis
- evidence is rendered as plain text in the UI
- secrets are masked in displayed evidence
- fix approval is gated behind confirmed findings and never auto-applies a patch

## Architecture

- `backend/app.py`: FastAPI service and REST API
- `backend/orchestrator.py`: scan lifecycle, status tracking, deduplication, reporting
- `backend/analyzers/runtime.py`: passive crawl, title/form/runtime-state heuristics
- `backend/analyzers/static_analysis.py`: repo heuristics for lifecycle and code smells
- `backend/analyzers/security.py`: security headers, secret scanning, optional npm audit ingestion
- `backend/analyzers/compliance.py`: trust/legal page discovery checks
- `src/App.tsx`: frontend dashboard
- `src/api/client.ts`: single frontend API adapter
- `src/contracts/finding.ts`: shared client contract mirroring backend schema

## Run

### Backend

```bash
PIP_USER=0 /workspace/venv/bin/pip install -r /workspace/backend/requirements.txt
/workspace/venv/bin/uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```bash
npm install
npm run dev
```

The frontend dev server proxies `/api` to `http://127.0.0.1:8000`.

## Create a new GitHub repository and push

Use the helper script:

```bash
chmod +x scripts/create_github_repo_and_push.sh
GITHUB_TOKEN=your_github_token ./scripts/create_github_repo_and_push.sh \
  --repo-name vibe-coding-inspector \
  --visibility private \
  --description "Vibe Coding Inspector" \
  --message "Initial commit"
```

Requirements:
- `git` installed
- `GITHUB_TOKEN` with repository creation permissions
- local `git config user.name` and `git config user.email` already set

## API

- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `PATCH /api/findings/{finding_id}/review`
- `PATCH /api/findings/{finding_id}/fix-review`
- `GET /api/scans/{scan_id}/report?format=markdown|json`

## Important limitations

- the runtime module currently performs passive HTTP + HTML inspection rather than full browser automation
- client-side console and network capture are represented as extensibility targets, not full Playwright-grade instrumentation yet
- dependency vulnerability detection currently relies on optional `npm audit` output when a Node project exists
