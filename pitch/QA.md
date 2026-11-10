# SAAF Tripwire: judge Q&A

Short answers first. The line after "Detail" is there if a judge pushes.

---

**1. Won't it cry wolf? What about false positives?**

It blocks only on serious findings (high and above, by default). Medium and low findings show up as notes, not as a failed build.
Detail: every rule ships with "safe" look-alike test cases that must stay quiet, and each rule is run on SAAF repos where it should not fire, with what it found recorded in `docs/evidence/`. Placeholder keys, test fixtures and documentation examples are skipped. A team can mute a folder with `.tripwireignore` or accept a known finding with a baseline.

**2. GitHub already has secret scanning. And there is Semgrep. Why this?**

Those are general tools. Tripwire is built from SAAF's own proven weaknesses, and secrets are only one of its rules.
Detail: it also catches servers open to any website, unescaped HTML, AI prompts without a fence, CI pipelines an outsider can hijack, and approval gates that log a failure and carry on. Every rule names the SAAF repos where we saw the problem. It needs no account, no paid plan and no internet. It runs fine next to GitHub secret scanning or Semgrep; it does not replace them.

**3. Why plain rules and not an AI model doing the review?**

A guard has to give the same answer every time, and it must not be talked out of its verdict.
Detail: an AI reviewer reading a repo can be steered by text in that repo, which is the exact attack we found in several SAAF agents. Tripwire has no AI inside, works offline, costs nothing per run, and gives the same result twice. The AI part lives in the skill, where the guard's job is to keep the AI honest.

**4. Our repo already has lots of old problems. Do we have to fix everything on day one?**

No. Record today's findings once as a baseline; from then on the check fails only on new problems.
Detail: `tripwire scan . --write-baseline tripwire-baseline.json` once, then pass `baseline: tripwire-baseline.json` in the workflow. You can also start with `fail-on: critical` and tighten it over time.

**5. What does it NOT catch?**

Anything that needs judgement about what the business rule should be, and anything that only shows in a running system.
Detail: it checks that a gate fails closed, not whether the gate's rule is right. It does not judge whether an AI verdict is correct (the skill only checks that quoted evidence is real). It does not test live servers. Dependency advisories are an optional online step. And the 34 audit candidates still waiting for a checker are not in its rule set. The confirmed weaknesses it misses are listed in `docs/evidence/SUMMARY.json`.

**6. How do we know it actually works?**

We ran it on the real SAAF repos and checked each hit against the audit's confirmed findings.
Detail: it catches {{RECALL}} of the confirmed weaknesses its rules aim at, with {{RULES}} rules and {{TESTS}} tests. Run `python3 demo/run_demo.py` to see it live.

**7. Could an attacker switch the guard off?**

We closed the ways we found. The guard is pinned to a fixed release, so nobody can swap its code, and the scanned repo cannot plant a fake copy of it.
Detail: the audit found exactly that trick in saaf-guard (SA-41): a repo added a folder with the guard's name and the check always passed. Tripwire runs with Python's `-P` flag and from its own install, and has a rule (TW-CI3) that flags the pattern in other repos. If the scan itself errors, the check fails instead of passing quietly.

**8. Will it leak the secrets it finds?**

No. Every key it reports is masked after the first 4 characters, in the log and in the GitHub report.
Detail: it never uses or tests a key it finds. The fix for a leaked key is to rotate it; deleting it from the file is not enough, because it stays in git history.
