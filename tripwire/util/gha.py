"""GitHub Actions helpers shared by the TW-CI* and TW-DEP1 rules.

Loads workflow / composite-action YAML into plain dicts and lists that remember line numbers, so rules can
report file:line without regex-parsing YAML. Offline and deterministic.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..model import Context


class LDict(dict):
    """dict that remembers the 1-based line of the mapping and of each key's value."""
    line: int = 0
    vlines: dict
    vstyle: dict


class LList(list):
    line: int = 0


def _conv(node):
    if isinstance(node, yaml.MappingNode):
        d = LDict()
        d.line = node.start_mark.line + 1
        d.vlines, d.vstyle = {}, {}
        for k, v in node.value:
            key = k.value if isinstance(k, yaml.ScalarNode) else str(k.value)
            d[key] = _conv(v)
            d.vlines[key] = v.start_mark.line + 1
            d.vstyle[key] = getattr(v, "style", None)
        return d
    if isinstance(node, yaml.SequenceNode):
        lst = LList(_conv(v) for v in node.value)
        lst.line = node.start_mark.line + 1
        return lst
    return node.value  # scalars stay strings (so `on:` stays "on", not True)


def files_of(ctx: Context) -> list[Path]:
    if ctx.files:
        return ctx.files
    from ..engine import tracked_files  # lazy: avoids an import cycle with engine -> rules
    return tracked_files(ctx.root)


def rel(ctx: Context, p: Path) -> str:
    try:
        return p.relative_to(ctx.root).as_posix()
    except ValueError:
        return p.as_posix()


def is_workflow_path(relpath: str) -> bool:
    return bool(re.match(r"^\.github/workflows/[^/]+\.ya?ml$", relpath))


def is_action_path(relpath: str) -> bool:
    return relpath.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")


@dataclass
class Step:
    job: str
    data: LDict
    line: int
    env: dict = field(default_factory=dict)       # job env merged with step env
    job_data: LDict | None = None

    def run_lines(self):
        """Yield (lineno, text) for each line of this step's `run:` (or github-script `script:`)."""
        for owner, key in ((self.data, "run"), (self.data.get("with") if isinstance(self.data.get("with"), dict) else None, "script")):
            if owner is None or key not in owner or not isinstance(owner[key], str):
                continue
            if key == "script" and "github-script" not in str(self.data.get("uses", "")):
                continue
            start = owner.vlines[key]
            block = owner.vstyle.get(key) in ("|", ">")
            for i, text in enumerate(owner[key].splitlines()):
                yield (start + 1 + i if block else start), text


@dataclass
class Workflow:
    path: Path
    rel: str
    text: str
    doc: LDict | None
    kind: str  # "workflow" | "action"

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def triggers(self) -> set[str]:
        if not isinstance(self.doc, dict):
            return set()
        on = self.doc.get("on", self.doc.get("true"))
        if isinstance(on, str):
            return {on}
        if isinstance(on, (list, dict)):
            return {str(x) for x in on}
        return set()

    def jobs(self) -> dict:
        if not isinstance(self.doc, dict):
            return {}
        j = self.doc.get("jobs")
        return j if isinstance(j, dict) else {}

    def steps(self) -> list[Step]:
        out: list[Step] = []
        if not isinstance(self.doc, dict):
            return out
        top_env = self.doc.get("env") if isinstance(self.doc.get("env"), dict) else {}
        if self.kind == "action":
            runs = self.doc.get("runs")
            steps = runs.get("steps") if isinstance(runs, dict) else None
            for s in steps or []:
                if isinstance(s, LDict):
                    out.append(Step("(composite)", s, s.line, {**top_env, **(s.get("env") or {})}, None))
            return out
        for name, job in self.jobs().items():
            if not isinstance(job, LDict):
                continue
            jenv = job.get("env") if isinstance(job.get("env"), dict) else {}
            for s in job.get("steps") or []:
                if isinstance(s, LDict):
                    senv = s.get("env") if isinstance(s.get("env"), dict) else {}
                    out.append(Step(name, s, s.line, {**top_env, **jenv, **senv}, job))
        return out


def load_workflows(ctx: Context) -> list[Workflow]:
    out = []
    for p in files_of(ctx):
        r = rel(ctx, p)
        kind = "workflow" if is_workflow_path(r) else "action" if is_action_path(r) else None
        if not kind:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            node = yaml.compose(text, Loader=yaml.SafeLoader)
            doc = _conv(node) if node is not None else None
        except yaml.YAMLError:
            doc = None
        if not isinstance(doc, LDict):
            doc = None
        if kind == "action" and not (doc and isinstance(doc.get("runs"), dict)):
            continue  # some other file called action.yml
        out.append(Workflow(p, r, text, doc, kind))
    return out


USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)""")


def uses_lines(wf: Workflow):
    """Yield (lineno, ref, is_job_level) for every `uses:` in the file (works even if YAML failed to parse)."""
    for i, line in enumerate(wf.lines, 1):
        m = USES_RE.match(line)
        if m:
            ref = m.group(1)
            yield i, ref, "/.github/workflows/" in ref or ref.startswith("./.github/workflows/")


def references_secrets(wf: Workflow) -> bool:
    """True if the workflow reads a repository secret other than the default GITHUB_TOKEN."""
    for m in re.finditer(r"secrets\.([A-Za-z0-9_]+)", wf.text):
        if m.group(1) != "GITHUB_TOKEN":
            return True
    return bool(re.search(r"secrets:\s*inherit", wf.text))
