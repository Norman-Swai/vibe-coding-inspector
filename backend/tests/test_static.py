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


def test_strings_docstrings_and_comments_never_trigger_code_checks_and_todos_only_count_in_comments(tmp_path):
    findings = scan(
        tmp_path,
        {
            'src/app.js': (
                'const banner = `\n'
                "import x from './nope-in-string';\n"
                'setInterval(tick, 1);\n'
                '`;\n'
                'const s = "some text # TODO not a comment";\n'
                '/* FIXME: block comment\n'
                ' * debugger;\n'
                ' */\n'
                '// TODO: line comment\n'
                "import real from './missing';\n"
            ),
            'src/tool.py': '"""Docstring.\nfrom .nope import thing\n"""\nfrom .also_missing import other  # TODO later\n',
        },
    )
    unresolved, todo = 'Import points to a file that does not exist', 'Unresolved TODO / FIXME markers'
    by_key = {(f.location.file, f.title): f for f in findings}

    assert set(by_key) == {('src/app.js', unresolved), ('src/app.js', todo), ('src/tool.py', unresolved), ('src/tool.py', todo)}
    assert (by_key[('src/app.js', unresolved)].location.line_start, by_key[('src/app.js', unresolved)].evidence.occurrences) == (10, 1)
    assert by_key[('src/app.js', todo)].evidence.snippet.splitlines() == ['L6: /* FIXME: block comment', 'L9: // TODO: line comment']
    assert by_key[('src/tool.py', unresolved)].location.line_start == 4
    assert by_key[('src/tool.py', todo)].location.line_start == 4


def test_regex_literals_and_unclosed_quotes_do_not_hide_the_rest_of_the_line():
    from backend.analyzers.common import tokenize

    code = tokenize("const q = /['\"]/g; setInterval(tick, 1) // note\nx = a / b / c; setInterval(tock, 2)\n<p>Don't</p>; setInterval(last, 3)\n", python=False).code
    assert code.splitlines() == [
        "const q = /['\"]/g; setInterval(tick, 1)        ",
        "x = a / b / c; setInterval(tock, 2)",
        "<p>Don't</p>; setInterval(last, 3)",
    ]
    assert tokenize("return /\\/\\/x/.test(s); eval(s)", python=False).code == "return /\\/\\/x/.test(s); eval(s)"
    assert tokenize("const s = 'closed'; eval(s)", python=False).code == "const s = '      '; eval(s)"
