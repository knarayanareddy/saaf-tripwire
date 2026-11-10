# SAAF Tripwire: 3-minute talk track

About 430 spoken words. Times are a guide. Show `pitch.html` behind you; run the demo in the Proof part.

---

## 1. The bad actor (0:00 to 0:35)

Picture an auditor. She runs Agent-Auditor, one of the SAAF agents, on her laptop. Then she opens an ordinary web page, maybe a blog post.

That page quietly talks to the tool running on her laptop. It tells it: create a branch, and commit this text, to any GitHub repo she can write to. Under her name.

She never clicks anything. Two lines of code made it possible: the tool accepts calls from any website, and it asks for no login.

We did not imagine this. We reproduced it with a test: a fake evil website sent the request, and the tool went straight to the commit step.

## 2. What we found across 50 repos (0:35 to 1:05)

That was one of many. We attacked all 50 repositories in the SAAF organisation.

- **44 weaknesses confirmed.** Each one has a test that fails before the fix and passes after.
- **6 of them high.** An invoice with an unknown purchase order still gets approved and paid. Anyone who can reach one server can read its files. Real-looking API keys are still sitting in git history.
- **40 suspects thrown out** by an independent checker, and 34 more still waiting for a checker, so we did not count them.

The same mistakes kept coming back, repo after repo. That is the point: if they repeat, a guard can catch them.

## 3. The one guard: SAAF Tripwire (1:05 to 1:55)

So we built one guard, with three faces.

At its heart is one engine. Plain code, no AI inside, same answer every time, and fast.

**Face one: a CI check.** It runs on every push and every pull request. If it finds something serious, the merge is blocked and the problem shows up on the exact line.

**Face two: a reusable workflow.** One shared workflow for every SAAF repo. It also reads the full history of the repo, because deleting a key from a file does not delete it from the past.

**Face three: a Claude skill.** SAAF agents read documents written by the people being audited. The skill wraps those documents so the AI treats them as evidence, never as orders. And it rejects any quote the AI claims is in a document, if it is not really there.

## 4. Adoption (1:55 to 2:15)

Any SAAF repo, three lines:

1. Copy one file into `.github/workflows`.
2. Pin it to a fixed Tripwire release.
3. Push.

Got an old repo full of old problems? Record today's list once as a baseline. From then on, it only fails on new problems.

## 5. Proof (2:15 to 2:40)

*(Run `python3 demo/run_demo.py`.)*

We ran Tripwire on the real SAAF repos. It catches **{{RECALL}}** of the confirmed weaknesses its rules aim at, including the Agent-Auditor attack I opened with.

That is **{{RULES}}** rules, and every rule names the SAAF repos where we saw the problem. And **{{TESTS}}** tests make sure each rule fires on the bad pattern and stays quiet on safe look-alikes.

## 6. Why it wins (2:40 to 3:00)

Most security checklists are generic. This one comes from evidence: every rule traces back to a weakness we proved in a SAAF repo.

It is honest about its limits. We publish what it does not catch.

And it costs a team three lines to switch on.

The bad actor trips the wire before the code ships. That is SAAF Tripwire.
