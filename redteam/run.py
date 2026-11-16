"""Materialise red-team cases into redteam/<RULE>/<case>/ and run each rule against them. Writes RESULTS.md."""
import json, shutil, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent)); sys.path.insert(0, str(HERE))
from tripwire import engine
from cases import CASES

rows, detail = [], []
for rule, cases in CASES.items():
    tried = evaded = fps = ctl_ok = ctl_n = 0
    for name, (kind, readme, files) in cases.items():
        d = HERE / rule / name
        if d.exists(): shutil.rmtree(d)
        d.mkdir(parents=True)
        for fn, content in files.items():
            p = d / fn; p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, tuple):
                p.write_bytes(content[1].encode("utf-16"))
            else:
                p.write_text(content)
        case_files = [p for p in d.rglob("*") if p.is_file() and p.name != "README"]
        if not case_files:
            raise SystemExit(f"redteam: {rule}/{name} produced no files")
        found = [f for f in engine.run(d, history=False, only={rule}, files=case_files) if f.rule == rule]
        blocking = [f for f in found if f.severity in ("critical", "high", "medium")] if rule == "TW-SEC1" else found
        fired = bool(blocking) if rule != "TW-SEC1" else any(f.severity in ("critical", "high") for f in found)
        if kind == "evades":
            tried += 1; verdict = "CAUGHT" if fired else "EVADED"; evaded += not fired
        elif kind == "fp":
            verdict = "FALSE POSITIVE" if found else "ok (silent)"; fps += bool(found)
        else:
            ctl_n += 1; ctl_ok += fired; verdict = "control fired" if fired else "CONTROL MISSED"
        (d / "README").write_text(f"{kind}: {readme}\nlast result: {verdict}" +
                                  (f" -> {[ (f.severity, f.file, f.line) for f in found ]}" if found else "") + "\n")
        detail.append((rule, name, verdict, "; ".join(f"{f.severity} {f.file}:{f.line}" for f in found)[:90]))
    nfp = sum(1 for n, c in cases.items() if c[0] == "fp")
    rows.append((rule, tried, evaded, f"{fps}/{nfp}", f"{ctl_ok}/{ctl_n}"))

out = ["# SAAF Tripwire red-team results", "",
       "Run: `.venv/bin/python redteam/run.py` (regenerates every case dir and this file). "
       "TW-SEC1 counts as caught only at high/critical (info = passes `--fail-on high`).", "",
       "| Rule | Evasions tried | Evaded | False positives found | Control fired |", "|---|---|---|---|---|"]
out += [f"| {r} | {t} | {e} | {f} | {c} |" for r, t, e, f, c in rows]
out += ["", "## Per case", "", "| Rule | Case | Verdict | Findings |", "|---|---|---|---|"]
out += [f"| {r} | `{n}` | {v} | {x} |" for r, n, v, x in detail]
(HERE / "RESULTS.md").write_text("\n".join(out) + "\n")
print("\n".join(out))
