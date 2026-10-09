# Vibe Coding Inspector Backend

```bash
pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

- `orchestrator.py` runs the runtime, static, security and compliance modules concurrently and records a coverage
  report per module (state, duration, what was scanned, notes, error).
- `context.py` shares one crawl, one repository index and one HTTP cache between modules, so each URL and file is
  fetched or read once per scan.
- Every finding is built with `analyzers/common.py:new_finding` from a `Rule` (what is checked and why it matters) plus
  the observed evidence (location, excerpt, how it was captured).

Tests: `pip install -r backend/requirements-dev.txt && python -m pytest -q` from the repository root.
