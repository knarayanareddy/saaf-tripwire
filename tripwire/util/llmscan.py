"""Shared AST helpers for the AI / agent-integrity rules (TW-LLM*, TW-GATE*, TW-KEY*)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..model import Context
from .safeio import is_safe_file, read_text as _read_text

TEST_PATH = re.compile(r"(^|/)(tests?|testing|fixtures|examples?|docs)/|(^|/)test_[^/]*\.py$|_test\.py$|conftest\.py$")
LLM_IMPORT = re.compile(r"^\s*(?:import\s+(?:[\w.]+\s*,\s*)*|from\s+)(anthropic|openai|langchain\w*|litellm|google\.generativeai|google\.genai|ollama|mistralai|cohere|claude_agent_sdk|claude_code_sdk)\b", re.M)


def py_files(ctx: Context, include_tests: bool = False):
    """Yield (relpath, source, tree) for every parseable tracked .py file."""
    for p in ctx.files or [q for q in Path(ctx.root).rglob("*.py")]:
        if p.suffix != ".py" or not is_safe_file(p, ctx.root):
            continue
        rel = p.relative_to(ctx.root).as_posix()
        if not include_tests and TEST_PATH.search(rel):
            continue
        if any(part in {".venv", "venv", "node_modules", "site-packages", "__pycache__"} for part in p.parts):
            continue
        try:
            src = _read_text(p, 2_000_000)
            if not src or len(src) > 2_000_000:
                continue
            tree = ast.parse(src)
        except (SyntaxError, ValueError, OSError):
            continue
        yield rel, src, tree


LLM_URL_RE = re.compile(r"api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis|openai\.azure\.com")


def repo_uses_llm(ctx: Context) -> bool:
    for _, src, _ in py_files(ctx, include_tests=False):
        if LLM_IMPORT.search(src) or LLM_URL_RE.search(src) or (re.search(r"[\"']-p[\"']", src) and re.search(r"claude", src, re.I)):
            return True
    return False


def call_name(node: ast.AST) -> str:
    """Dotted name of a call target, e.g. 'client.messages.create'."""
    if isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(call_name(node) + "()")
    return ".".join(reversed(parts))


def last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def str_consts(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def functions(tree: ast.AST):
    """Module pseudo-function plus every (possibly nested) function definition."""
    yield tree
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def own_statements(fn: ast.AST):
    """Statements of fn in source order, without descending into nested defs/classes."""
    out = []

    def visit(stmts):
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            out.append(s)
            for field in ("body", "orelse", "finalbody"):
                visit(getattr(s, field, []) or [])
            for h in getattr(s, "handlers", []) or []:
                visit(h.body)
            if isinstance(s, ast.Match):
                for c in s.cases:
                    visit(c.body)
    visit(getattr(fn, "body", []))
    return out


def line_text(src: str, line: int, limit: int = 120) -> str:
    lines = src.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:limit]
    return ""
