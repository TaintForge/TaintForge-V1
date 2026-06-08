---
name: hypothesize
description: "Generate top-down business-logic vulnerability hypotheses grounded in what THIS service actually does - its real user/admin flows and the invariants those flows must preserve. Use at the START of an assessment, right after the Code Model, before/alongside vuln hunting. The catalog (domain patterns) and CWE pool are only RAW MATERIAL / checklists; the real hypotheses are the ones YOU derive from this service's business logic and bind to its real endpoints. Produces workspace/HYPOTHESES.json. Triggers - hypotheses, business logic, threat model, invariants, attacker goals, what could go wrong."
---

# hypothesize

Bottom-up scanning (A: sinks, B: authz gates) finds *patterns*. CWE tells you *categories of
weakness exist*. Neither tells you **what an attacker actually wants to achieve in THIS
service, and which rule they'd break to get it**. That is what this step produces, and it is
the valuable part - the catalog and CWE pool are just reference material you consult while
doing it, not the answer.

A real hypothesis is service-specific and testable:
> *"Because this is an X where users do Y, action Z on endpoint **E** can break invariant
> **R**, letting an attacker achieve **G**."*

It names a real endpoint (E), the rule that should hold (R), and the attacker's goal (G).
"CWE-367 TOCTOU exists" is NOT a hypothesis - it's a lens. Turn it into: "the wallet
**/api/transfer** does read-balance-then-debit without a lock (R: balance never goes
negative), so concurrent requests let an attacker withdraw more than they have (G: mint
money)."

## Step 1 - Seed the raw material (deterministic, already run in SEED)

`gen_hypotheses.py` has populated `workspace/HYPOTHESES.json` with domain + universal +
(capped) CWE-derived entries. **Treat these as a checklist, not as findings.** Most have empty
`target_endpoints` - that is the tell that they are not yet real hypotheses. Your job is to
turn the relevant ones into concrete, endpoint-bound hypotheses and to ADD the service-specific
ones the catalog could never know.

## Step 2 - Reconstruct the business model & flows (from the code)

Read the Code Model entry points and the actual handlers. Write down, in your own words:
- **What the service is and what's valuable in it** - money, repos, reputation, PII, admin power.
- **User flow:** signup -> auth -> the core value actions (transfer / push / post / book / pay)
  -> state changes. Follow each across files via the call graph (cross-file is where the bugs hide).
- **Admin/privileged flow:** who can grant roles, change settings, moderate, export, impersonate.
- **Where money / permission / ownership / state actually changes**, and which endpoint does it.

## Step 3 - For each flow, state the INVARIANTS (the rules that must hold)

This is the core. An invariant is a rule the business logic must never violate. Examples:
- finance: "an account balance never goes negative"; "a transfer debits exactly once".
- vcs: "only a reviewer who is not the author approves an MR"; "a fork pipeline never gets
  parent secrets".
- commerce: "the price charged is the server's price for the items actually in the order".
- community: "a blocked user cannot reach the blocker by any path".
- generic: "a user only acts on resources they own"; "state S is reachable only after step S-1".

List the invariants explicitly. Each invariant is a target: a vuln is a way to violate it.

## Step 4 - Derive hypotheses two ways, then bind them to endpoints

For every invariant, generate hypotheses from BOTH directions:

1. **Invariant-breaking (defensive view):** "How could the code fail to enforce R?" - missing
   check, TOCTOU, client-trusted value, wrong order, race, replay. (Use the catalog/CWE pool
   here as a checklist of *how* invariants commonly break - this is the only role CWE plays.)
2. **Attacker-goal (offensive view):** "What does an attacker want here (G), and what's the
   cheapest path to it?" - mint money, read others' data, gain admin, run code, exhaust quota
   - then work backward to the endpoint and parameter that would get them there.

Write each as a hypothesis with `source:"llm"` and, crucially, a filled `target_endpoints`
(real routes from the Code Model). Also fill `target_endpoints` on any catalog/CWE entry you
judge relevant to a real flow; **delete or ignore** the rest rather than leaving the producers
hundreds of endpoint-less abstractions. The file should end up dominated by concrete,
endpoint-bound, invariant+goal hypotheses - not by the raw catalog/CWE seed.

Hypothesis shape (keep the fields):
```
{ "id":"H...", "source":"llm", "class":"...", "name":"short claim",
  "flow":"which business flow", "invariant":"rule R that must hold",
  "attacker_goal":"G the attacker achieves by breaking R",
  "target_endpoints":["POST /api/...", "..."],
  "why":"why this is plausible in THIS code", "check_how":"exact way to verify in code/live",
  "status":"open" }
```

## Step 5 - Hand off

Producers A/B read `HYPOTHESES.json` and verify each OPEN, endpoint-bound hypothesis against
the code: confirmed -> write a finding, set its `hypothesis_id`, mark the hypothesis
`verified`; disproved -> mark `refuted` with a one-line reason. C prioritizes reproducing
findings that validate a hypothesis; D weaponizes the critical ones.

The point: drive the assessment from **what an attacker wants to achieve in this specific
service and which invariant they'd break**, using the catalog/CWE only as a checklist of how
invariants commonly fail - never as the hypotheses themselves.