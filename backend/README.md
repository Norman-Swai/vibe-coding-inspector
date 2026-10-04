# Vibe Coding Inspector Backend

Run with:

```bash
/workspace/venv/bin/uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

This backend provides:
- scan orchestration across runtime, static, security, and compliance analyzers
- a shared finding schema
- evidence-first findings with review and fix-review APIs
- markdown or JSON export
