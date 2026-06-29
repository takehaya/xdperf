---
description: Run an AI-powered multi-agent code review on your changes.
name: "OCR: Review"
category: Code Review
tags: [ocr, review, code-review]
---

**Usage**
```
/ocr-review [target] [--fresh] [--team <ids>] [--reviewer "<description>"]
```

**Arguments**
- `target` (optional): Branch, commit, or file to review. Defaults to staged changes.
- `--fresh` (optional): Clear any existing session for today's date and start from scratch.
- `--team` (optional): Override the default reviewer team. Format: `reviewer-id:count,reviewer-id:count`. Example: `--team principal:2,martin-fowler:1`.
- `--reviewer` (optional, repeatable): Add an ephemeral reviewer described in natural language. The Tech Lead will synthesize a focused reviewer persona from the description. Does not persist. Example: `--reviewer "Focus on error handling in the auth flow"`.

**Examples**
```
/ocr-review                    # Review staged changes
/ocr-review --fresh            # Clear today's session and start fresh
/ocr-review HEAD~3             # Review last 3 commits
/ocr-review feature/auth       # Review branch vs main
/ocr-review src/api/           # Review specific directory
/ocr-review --team principal:2,security:1   # Custom team composition
/ocr-review --reviewer "Review as a junior developer would"
/ocr-review --team principal:1 --reviewer "Focus on error handling" --reviewer "Check accessibility"
```

**Steps**

1. **Session State Check** (CRITICAL - do this first!)
2. Load the OCR skill from `.ocr/skills/SKILL.md`
3. Execute the 8-phase review workflow defined in `.ocr/skills/references/workflow.md`
4. Store results in `.ocr/sessions/{date}-{branch}/`

---

## Session State Check (Phase 0)

Before starting any review work, you MUST verify the current session state:

### Step 1: Check for existing session

```bash
# Find today's session directory
ls -la .ocr/sessions/$(date +%Y-%m-%d)-* 2>/dev/null
```

### Step 2: If session exists, verify state

Use `ocr state show` to read current session state AND verify actual files match (see `references/session-files.md` for authoritative names):

```bash
ocr state show
```

| Phase | Verify file exists |
|-------|-------------------|
| context | `.ocr/sessions/{id}/discovered-standards.md` |
| change-context | `.ocr/sessions/{id}/context.md` |
| analysis | `.ocr/sessions/{id}/context.md` (with Tech Lead guidance section) |
| reviews | At least 2 files in `.ocr/sessions/{id}/rounds/round-{n}/reviews/` |
| discourse | `.ocr/sessions/{id}/rounds/round-{n}/discourse.md` |
| synthesis | `.ocr/sessions/{id}/rounds/round-{n}/final.md` |

> **Note**: Phase completion is derived from filesystem (file existence), not from session state. The `current_phase` field indicates which phase is active.

### Step 3: Determine action

- **If `--fresh` flag**: Delete the session directory and start from Phase 1
- **If session exists and status is `closed`**: Start new round (round-{n+1}) — reuse existing `discovered-standards.md` and `context.md`, create new `rounds/round-{n+1}/` directory
- **If session exists, status is `active`, and files match**: Resume from `current_phase`
- **If session exists but state and files mismatch**: Report discrepancy and ask user which to trust
- **If no state in SQLite but session files exist**: Start new round — use `ocr state begin` to recreate/resume the session, then start round-{n+1} from Phase 4 (reuse existing standards and context)
- **If no session exists**: Start fresh from Phase 1

---

## CRITICAL: Required Artifacts (Must Create In Order)

> **See `references/session-files.md` for the authoritative file manifest.**

You MUST create these files sequentially. **Do NOT skip to `final.md`.**

```
.ocr/sessions/{YYYY-MM-DD}-{branch}/
├── discovered-standards.md # Phase 1: merged project standards
├── requirements.md         # Phase 1: user requirements (if provided)
├── context.md              # Phase 2+3: change summary + Tech Lead guidance
└── rounds/
    └── round-1/            # Review round (increments on re-review)
        ├── reviews/
        │   ├── principal-1.md  # Phase 4: reviewer output
        │   ├── principal-2.md  # Phase 4: reviewer output
        │   ├── quality-1.md    # Phase 4: reviewer output
        │   └── quality-2.md    # Phase 4: reviewer output
        ├── discourse.md        # Phase 6: reviewer cross-discussion
        └── final.md            # Phase 7: ONLY after all above exist
```

State is managed via `ocr state` CLI commands (stored in SQLite at `.ocr/data/ocr.db`).

### State Management Commands

Prefer the **atomic, invariant-checked** verbs (v2.0). The CLI enforces the
lifecycle — `finish` refuses to close a workflow whose current round was never
finalized, so "completed too soon" cannot happen.

| Command | When to Use |
|---------|-------------|
| `ocr state begin --session-id <id> --branch <branch> --workflow-type review --session-dir <path>` | Phase 1: Create/resume the session (returns round + completeness) |
| `ocr state advance --phase <phase> [--current-round <N>]` | Each phase boundary (graph-validated; phase number derived) |
| `ocr state status --json` | On resume: "is it done, and what's missing?" |
| `ocr state complete-round --stdin` | Phase 7: atomically finalize the round (validate + record + transition) — only after `synthesis` |
| `ocr state finish` | Phase 8: close the session (`--abort` to abandon) |

> v2.0.0 **retired** `ocr state init` / `transition` / `round-complete` / `map-complete` / `close` — use the atomic verbs above. Calling a retired verb exits `2` with a pointer to its replacement.

### Checkpoint Rules

1. **Before Phase 2** (Change Analysis): `discovered-standards.md` MUST exist
2. **Before Phase 4** (Spawn Reviewers): `context.md` MUST exist
3. **Before Phase 6** (Discourse): At least 2 files in `rounds/round-{n}/reviews/` MUST exist
4. **Before Phase 7** (Synthesis): `rounds/round-{n}/discourse.md` MUST exist
5. **NEVER** write `rounds/round-{n}/final.md` without completing Phases 1-6

### Why This Matters

The `ocr progress` CLI reads session state from SQLite for real-time progress display. If you skip phases or don't call `ocr state advance`, the progress display breaks and users see incorrect state. The CLI also rejects illegal phase jumps and refuses a premature `finish`, so the recorded lifecycle always matches reality.

---

**Reference**
- See `.ocr/skills/SKILL.md` for full Tech Lead instructions
- See `.ocr/skills/references/workflow.md` for detailed workflow phases
