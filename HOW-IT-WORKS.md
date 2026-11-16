# How SAAF Tripwire works

## In one sentence
SAAF Tripwire is one security guard for every SAAF repository. It checks code for the weaknesses we actually found in the SAAF agents, and it stops the change before a bad actor can use them.

## The problem it solves
We audited the SAAF-Project organisation. The audit register lists **65 confirmed weaknesses** in 45 repositories: 5 critical, 32 high and 28 medium. 40 of them were proven with a live test. We also disproved 84 suspected issues.

Most of these were not one-off bugs. The same few mistakes came back again and again in different repos:

| Mistake that keeps coming back | What a bad actor does with it |
|---|---|
| A server open to the whole network with no login | Calls every route, spends the API key, reads or changes data |
| Any website allowed to call the server (CORS `*`) | A web page the auditor visits quietly drives the tool |
| An auditee's document pasted straight into the AI prompt | Plants "auditor notes" that steer the verdict |
| The AI's answer trusted without a check | A made-up quote or a fake "found: yes" becomes the audit result |
| A check that only logs a failure and carries on | An invoice for an order that doesn't exist still gets paid |
| Reports built without escaping text | A file name or title runs as code in the viewer's browser |
| Keys left in git history | Anyone who can read the repo can take them, even after deletion |
| Outside GitHub add-ons not pinned to an exact version | Whoever controls that add-on can change what runs with your token |

Fixing one repo doesn't stop the next one repeating the mistake. A guard that every repo runs does.

## What it is: one engine, three ways to use it

```
            a push or pull request in any SAAF repo
                              │
                              ▼
               ┌──────────────────────────────┐
               │       Tripwire engine         │
               │ 16 rules · offline · no AI    │
               │ every file + full git history │
               └──────────────────────────────┘
                 │              │              │
                 ▼              ▼              ▼
            CI check        Workflow         Skill
         blocks the PR   3 lines, every   documents are data,
                         push, history    not orders
```

### The engine
- **16 rules**, each built from a weakness we found and confirmed in real SAAF code. Every rule names the repos where it was seen.
- **Deterministic and offline.** It makes no AI calls, so the same code always gets the same answer, in a few seconds per repo.
- **Reads the full git history**, so a key deleted last month still gets caught.
- **Never prints a secret.** Values are masked after 4 characters.
- **Tested both ways.** Each rule has examples that must trigger it and safe examples that must not. 287 tests in total.
- **Attacked on purpose.** A red-team agent wrote code designed to slip past each rule. Every trick it found became a new test, until it stopped getting through.

### 1. The CI check: blocks the bad change
- Runs on every push and pull request.
- Findings appear **inline on the pull request**, on the exact line, with the fix. It uses SARIF, the format GitHub code scanning reads.
- Fails the build at the level the team chooses, for example `--fail-on high`.
- A **baseline file** lets an existing repo adopt it gradually: today's known issues are parked, and anything new is blocked.
- Optional online step: a dependency audit that fails on critical advisories.

### 2. The reusable workflow: three lines for any repo
Any SAAF repo turns Tripwire on by adding one file:

```yaml
jobs:
  tripwire:
    uses: SAAF-Project/saaf-tripwire/.github/workflows/tripwire.yml@<commit-sha>
```

The workflow follows its own rules:
- full-history checkout, so the secret scan sees deleted keys;
- least-privilege permissions;
- every outside action pinned to an exact commit;
- the guard runs isolated (`python -P`), so the scanned repo can't swap in a fake version of it.

**Tripwire passes its own scan.**

### 3. The Claude skill: guards the agents themselves
Some weaknesses only show up when an agent runs. The skill covers those:
- **`tripwire.fence`** wraps every auditee document in a tag with a random ID before it reaches the AI. A planted instruction stays inside the tag as data and can't pose as the auditor. Variants that tried to break out in the audit are blocked, including the fake closing tag, the newline inside the tag, the code-block escape and the forged "auditor context" block.
- **`check_quotes`** checks that every quote the AI claims is "verbatim" really appears in the source document. Made-up quotes are rejected.
- **The audit method on one page:** map every entry point, attack each one, prove each finding with a test that fails before the fix and passes after, let an independent checker try to disprove it, and report honestly what was not checked.

## How it works across all repositories
1. **One source of truth.** The rules live in one repo, `SAAF-Project/saaf-tripwire`. Improve a rule once and every repo gets it.
2. **Same guard everywhere.** Every repo that adds the three lines runs the same checks on every push.
3. **Gradual adoption.** The baseline lets a repo with old issues start today without being blocked on day one.
4. **Learning loop.** A new weakness found in any repo becomes a new rule plus its tests. From then on, every repo is checked for it.

## Proof
- **Live demo** (`demo/run_demo.py`, offline, no API key): we planted an "auditor note" in a code file scanned by llm_owasp.
  - **Before:** the note reaches the AI as an instruction, a made-up quote is accepted, and the report says PASS.
  - **After:** the note stays inside the data tag, `check_quotes` rejects the quote, and the result fails safe.
- **On the real repos:** Tripwire flags the same file for **32 of the 65** confirmed weaknesses in the register, including 22 of the 40 live-tested ones.
- **287 tests pass**, and Tripwire passes its own scan at `--fail-on medium`.

## What it does not do
- It doesn't replace an audit. Static rules can't see everything: business logic, live AI behaviour and how the app is deployed still need a person or an agent. That is what the skill's method is for.
- A rule finding the right file is a strong signal to look, not proof that an attack works. The live-tested findings in the register are the proof.
- Keys found in history still have to be **rotated** by their owners. Tripwire finds them; it can't revoke them.

## Try it
```bash
pip install ./saaf-tripwire          # from a checkout of the repo
tripwire scan path/to/repo           # human-readable report
tripwire scan . --fail-on high       # what CI runs
tripwire rules                       # all 16 rules: what each stops and where it was seen
python demo/run_demo.py              # the before/after injection demo
```
