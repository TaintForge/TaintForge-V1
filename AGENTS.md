# AGENTS.md — Whitebox Security Assessment Pipeline

This repo is an **AI-agent white-box security assessment pipeline**. It runs in two
separable stages — **source code analysis** (build a reusable Code Model) and
**vulnerability analysis** (consume it) — and a streaming **convergence** stage that
cross-validates, reproduces, and triages findings.

> Build order: contracts (this stage) → source-model → ONE thin vertical slice
> (one vuln class end-to-end) → widen → streaming orchestrator LAST.
> Get a sequential run correct before parallelizing.

## Folder layout

```
secaudit/                          ← git repo root
  AGENTS.md                        ← you are here (Codex reads before any work)
  .agents/skills/                  ← Codex scans here, cwd → repo root
    source-model/
      SKILL.md
      scripts/build_code_model.sh
    vuln-track-a/
      SKILL.md
      scripts/run_semgrep.sh
      rules/                       ← semgrep taint rules (mode: taint)
    vuln-track-b/
      SKILL.md
    convergence/
      SKILL.md
      scripts/reproduce.sh
  schemas/
    code_model.schema.json         ← contract: source-model output
    finding.schema.json            ← contract: one finding (drives convergence)
  targets/                         ← the code under assessment (read-only)
  workspace/
    CODE_MODEL.json                ← produced by source-model, validated vs schema
    findings/<id>.json             ← APPEND-ONLY, one file per finding
    report/report.md               ← final deliverable
```

> Locations matter: Codex discovers skills only under `.agents/skills/` (repo) or
> `~/.agents/skills` (personal/global). A skill bundles its own `scripts/`. AGENTS.md is
> read from the repo root down; a global `~/.codex/AGENTS.md` can layer under it.

## Hard rules (scope & safety)

- Only analyze code under `targets/`. Never read or exfiltrate anything outside this repo.
- `targets/` is **read-only**. Never modify the code under assessment.
- `workspace/findings/` is **append-only**: write `<id>.json`, never overwrite a different
  finding. To update a finding, rewrite its own file and append a `history` entry.
- Reproduction runs only against the **warm target env** in the sandbox, never an external host.
- Findings must validate against `schemas/finding.schema.json`. CODE_MODEL against `schemas/code_model.schema.json`.

## Tooling commands

Language-agnostic stack. Verify availability before use; if missing, report it.

**AST / structural (source-model):** tree-sitter
```bash
# parse + dump AST/symbols per file
.agents/skills/source-model/scripts/build_code_model.sh targets/<app>
```

**Track A SAST — primary: Semgrep (OSS CLI), 30+ languages, taint mode:**
```bash
# broad first pass (intraprocedural OSS taint), SARIF out, CWE in rule metadata
semgrep --config auto --sarif -o workspace/_semgrep.sarif targets/<app>
# custom taint rules (mode: taint, pattern-sources/-sinks/-sanitizers)
semgrep --config .agents/skills/vuln-track-a/rules/ --sarif -o workspace/_semgrep.sarif targets/<app>
```
- Deep cross-file taint is a Semgrep **Pro** feature. If you need it without the paid
  platform, swap the binary for **OpenGrep** (drop-in: same rule format + SARIF):
  `opengrep --config .agents/skills/vuln-track-a/rules/ --sarif -o ...`

**Convergence deep cross-validation — CodeQL** (heavier; selective, high-value findings only):
```bash
codeql database create db --language=<lang> --source-root=targets/<app>
codeql database analyze db --format=sarifv2.1.0 -o workspace/_codeql.sarif <queries>
```

## Stage contracts (read / write)

| Stage | Reads | Writes | Driver |
|---|---|---|---|
| source-model | `targets/` | `workspace/CODE_MODEL.json` | tools (tree-sitter) + LLM |
| vuln-track-a | CODE_MODEL `.structural` + semgrep SARIF | `findings/*.json` (status=candidate) | semgrep + LLM |
| vuln-track-b | CODE_MODEL `.comprehension` | `findings/*.json` (status=candidate) | LLM |
| convergence | `findings/*.json` | updates same files; `report/report.md` | tools + LLM |

## Findings lifecycle (status flag)

```
candidate ──cross-val──> cross_validated ──repro──> reproduced ──> confirmed
                                              │
                                  repro fails │
                                              ├──> false_positive   (discard)
                                              └──> needs_reanalysis  (feedback → re-queue to track)
```

- Convergence consumes `findings/` continuously (streaming). It does NOT wait for the
  producer to finish.
- Triage is **rolling** (live ranking) + a **final global** pass once the producer signals
  done and the queue is drained.
- `needs_reanalysis` is the feedback loop: convergence flips the flag, the producer re-picks it up.

## Conventions

- Every finding carries a `correlation_id` so multiple paths to one root cause de-dup.
- Severity from the producer is provisional; reproduction outcome dominates final ranking.
- All tool output normalized to the `finding` schema before entering `findings/`.