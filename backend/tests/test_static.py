from backend.analyzers.repo import RepoIndex
from backend.analyzers.static_analysis import analyse_repo

from .helpers import titles, write_files


def scan(tmp_path, files):
    findings, _ = analyse_repo(RepoIndex(write_files(tmp_path, files)))
    return findings


def test_interval_is_only_flagged_when_never_cleared(tmp_path):
    findings = scan(
        tmp_path,
        {
            'leaky.js': 'export function start() {\n  setInterval(tick, 1000);\n  setTimeout(once, 10);\n}\n',
            'clean.js': 'const id = setInterval(tick, 1000);\nexport const stop = () => clearInterval(id);\n',
            'timeout-only.js': 'setTimeout(() => go(), 5);\n',
        },
    )
    assert [(f.title, f.location.file, f.location.line_start) for f in findings] == [
        ('setInterval() without a matching clearInterval()', 'leaky.js', 2),
    ]
    assert findings[0].evidence.snippet.startswith('L2: setInterval(tick, 1000);')


def test_listeners_with_cleanup_or_once_are_not_flagged(tmp_path):
    findings = scan(
        tmp_path,
        {
            'balanced.ts': "window.addEventListener('resize', fit);\nwindow.removeEventListener('resize', fit);\n",
            'once.ts': "button.addEventListener('click', go, { once: true });\n",
            'leaky.ts': "useEffect(() => {\n  window.addEventListener('scroll', onScroll);\n}, []);\n",
        },
    )
    assert [(f.location.file, f.location.line_start) for f in findings] == [('leaky.ts', 2)]


def test_unresolved_relative_imports_are_reported_with_paths_tried(tmp_path):
    findings = scan(
        tmp_path,
        {
            'src/main.ts': (
                "import { present } from './present';\n"
                "import util from './util.js';\n"
                "import { gone } from './components/Gone';\n"
                "import React from 'react';\n"
            ),
            'src/present.ts': 'export const present = 1;\n',
            'src/util.ts': 'export default 1;\n',
            'pkg/__init__.py': '',
            'pkg/views.py': 'from .models import User\nfrom .missing import thing\n',
            'pkg/models.py': 'class User: ...\n',
        },
    )
    by_file = {f.location.file: f for f in findings if f.title == 'Import points to a file that does not exist'}
    assert set(by_file) == {'src/main.ts', 'pkg/views.py'}
    assert by_file['src/main.ts'].location.line_start == 3
    assert './components/Gone — tried src/components/Gone, src/components/Gone.ts' in by_file['src/main.ts'].evidence.snippet
    assert by_file['pkg/views.py'].location.line_start == 2


def test_vendor_directories_and_comments_are_skipped(tmp_path):
    findings = scan(
        tmp_path,
        {
            'node_modules/lib/index.js': 'setInterval(x, 1);\ndebugger;\n',
            'dist/bundle.js': 'setInterval(x, 1);\n',
            'src/app.js': '// setInterval(old, 1)\nfunction f() {\n  debugger;\n}\n',
        },
    )
    assert titles(findings) == ['debugger statement left in code']
    assert findings[0].location.file == 'src/app.js'
