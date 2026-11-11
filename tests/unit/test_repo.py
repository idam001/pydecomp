"""Invariants of the repository itself, run as part of the unit suite.

These are the checks that would otherwise rot quietly: the single-file build
drifting from the package, a table going stale, a stray `exec` appearing in the
engine, or a documented file disappearing.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def run_tool(name: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOLS / name), *args],
                          capture_output=True, text=True, timeout=600)


def test_single_file_build_is_current():
    if not (ROOT / "dist" / "pydecomp.py").exists():
        pytest.skip("no single-file build yet: python3 tools/build_single.py")
    done = run_tool("build_single.py", "--check", "--quiet")
    assert done.returncode == 0, done.stdout + done.stderr


def test_engine_stays_static_only():
    done = run_tool("check_static_only.py")
    assert done.returncode == 0, done.stdout


def test_opcode_tables_are_coherent():
    done = run_tool("gen_opcode_tables.py", "--check")
    assert done.returncode == 0, done.stdout


def test_fixtures_are_reproducible():
    done = run_tool("make_fixtures.py", "--check")
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("name", [
    "README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    "SECURITY.md", "GOVERNANCE.md", "CITATION.cff", "pyproject.toml", "mkdocs.yml",
    "Dockerfile", ".pre-commit-config.yaml", ".editorconfig", ".gitignore",
])
def test_repository_furniture_exists(name):
    assert (ROOT / name).is_file(), f"{name} is missing"


@pytest.mark.parametrize("name", [
    "CONTRIBUTING.md", "SECURITY.md", "GOVERNANCE.md", "CHANGELOG.md", "CODE_OF_CONDUCT.md",
])
def test_readme_links_resolve(name):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert name in readme, f"README does not link {name}"
    assert (ROOT / name).is_file()


def test_docs_pages_are_in_the_nav():
    nav = yaml.safe_load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    pages = {path.relative_to(ROOT / "docs").as_posix()
             for path in (ROOT / "docs").rglob("*.md")}

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)
        elif isinstance(node, str):
            yield node

    listed = {entry for entry in walk(nav["nav"]) if entry.endswith(".md")}
    missing = sorted(pages - listed)
    assert missing == [], f"not in the nav: {missing}"


def test_workflows_are_valid_yaml():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "jobs" in document, f"{path.name} has no jobs"


def test_issue_templates_are_valid_yaml():
    folder = ROOT / ".github" / "ISSUE_TEMPLATE"
    for path in sorted(folder.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert document, f"{path.name} is empty"


def test_no_analysed_output_is_tracked():
    forbidden = ("_deob.py", ".report.json", ".report.md")
    offenders = [str(path.relative_to(ROOT))
                 for path in (ROOT / "src").rglob("*")
                 if path.is_file() and path.name.endswith(forbidden)]
    assert offenders == []
