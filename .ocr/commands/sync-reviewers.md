---
description: Sync reviewer metadata from markdown files to reviewers-meta.json for the dashboard.
name: "OCR: Sync Reviewers"
category: Code Review
tags: [ocr, reviewers, sync]
---

**Usage**
```
/ocr:sync-reviewers
```

**What it does**

Reads all reviewer markdown files in `.ocr/skills/references/reviewers/`, extracts structured metadata from each, and pipes the result to the CLI for validated, atomic persistence to `reviewers-meta.json`.

**When to run**

- After adding or editing a reviewer in `.ocr/skills/references/reviewers/`
- After changing `default_team` in `.ocr/config.yaml`

**Steps**

1. **Read config**: Parse `.ocr/config.yaml` and extract the `default_team` keys (reviewer IDs mapped to weights).

2. **Read all reviewer files**: List every `.md` file in `.ocr/skills/references/reviewers/`. For each file, read its contents and extract:
   - **id**: Filename without `.md` (e.g., `architect`, `martin-fowler`)
   - **name**: From the `# Title` heading — strip trailing "Reviewer", "— Reviewer", etc.
   - **tier**: Classify using the lists below, or `custom` if not recognized
   - **icon**: Assign from the icon table below, defaulting to `brain` for personas and `user` for custom
   - **description**: The opening paragraph that describes what this reviewer does (first substantive non-heading, non-blockquote line)
   - **focus_areas**: Bold items from the `## Your Focus Areas` section (the text before the colon/dash)
   - **is_default**: `true` if the id is a key in `config.yaml`'s `default_team`
   - **is_builtin**: `true` if the id appears in any of the built-in lists below
   - **known_for** (persona only): From `> **Known for**: ...` blockquote
   - **philosophy** (persona only): From `> **Philosophy**: ...` blockquote

   Use your understanding of the markdown — reviewer files may have minor structural variations. Extract the semantically correct value even if formatting differs slightly from the template.

3. **Build the JSON payload**:
   ```json
   {
     "schema_version": 1,
     "generated_at": "<ISO 8601 timestamp>",
     "reviewers": [<array of reviewer objects>]
   }
   ```

4. **Pipe to CLI for validation and persistence**:
   ```bash
   echo '<json>' | ocr reviewers sync --stdin
   ```
   The CLI validates the schema, checks for duplicate IDs and invalid tiers, and writes `reviewers-meta.json` atomically. If validation fails, fix the JSON and retry.

5. **Report**: Confirm the count and tier breakdown from the CLI output.

**Built-in reviewer IDs**

Holistic: `architect`, `fullstack`, `reliability`, `staff-engineer`, `principal`

Specialist: `frontend`, `backend`, `infrastructure`, `performance`, `accessibility`, `data`, `devops`, `dx`, `mobile`, `security`, `quality`, `testing`, `ai`

Persona: `martin-fowler`, `kent-beck`, `john-ousterhout`, `anders-hejlsberg`, `vladimir-khorikov`, `kent-dodds`, `tanner-linsley`, `kamil-mysliwiec`, `sandi-metz`, `rich-hickey`

**Icon assignments**

| ID | Icon |
|---|---|
| architect | blocks |
| fullstack | layers |
| reliability | activity |
| staff-engineer | compass |
| principal | crown |
| frontend | layout |
| backend | server |
| infrastructure | cloud |
| performance | gauge |
| accessibility | accessibility |
| data | database |
| devops | rocket |
| dx | terminal |
| mobile | smartphone |
| security | shield-alert |
| quality | sparkles |
| testing | test-tubes |
| ai | bot |
| *(persona)* | brain |
| *(custom)* | user |

**Notes**

- The `ocr` CLI path may be provided in the CLI Resolution section above. If so, use that path instead of bare `ocr`.
- The CLI's `--stdin` mode is the mechanism that ensures the final `reviewers-meta.json` is valid. Always pipe through it rather than writing the file directly.
