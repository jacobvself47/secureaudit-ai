# Stage 3 Spec: Group Access Appropriateness — Finalization

## Goal

Finalize the `groups_with_access[]` pipeline so the report-agent can reason about every
non-system Group with any K8s binding. The core plumbing is already in place — `analyze.py`
already produces `groups_with_access[]` and `users_with_access[]` in `audit-findings.json`,
and `report-agent/SKILL.md` already describes how to consume them.

One code gap remains: `_collect_groups_with_access()` is missing the `owners` field from
entra group data, which the report-agent explicitly requires (SKILL.md line 118: "List group
owners"). Everything else just needs tests and CLAUDE.md cleanup.

---

## Gap 1 — Missing `owners` Field

### Problem
`_collect_groups_with_access()` in `analyze.py` (lines 722–729) captures `display_name`,
`members`, `member_count`, and `orphaned` from entra group data — but not `owners`.
The report-agent SKILL.md says to list group owners for every group in Section 4, so the
field must be present in the artifact.

### Fix
Add one line to the `seen[gid]` dict initializer in `_collect_groups_with_access()`:

```python
"owners": eg.get("owners", []) if eg else [],
```

Place it after the `"members"` line. No other changes to `analyze.py`.

### Files In Scope
- `.claude/skills/risk-agent/scripts/analyze.py` — `_collect_groups_with_access()` only

---

## Gap 2 — Tests

### Test File
`tests/test_groups_with_access.py`

Follow the exact pattern from `tests/test_cis_admin_edit_cluster.py`:
- Import `run_checks` from `analyze`
- Build minimal grant and entra dicts in-memory (no external calls)
- Call `run_checks(grants, entra=entra)` and unpack as `_, groups, _`

### Required Test Cases

| Test | Expected |
|------|----------|
| Single group with one grant | 1 entry, correct object_id, role, binding |
| Same group with two grants | 1 entry, both roles present (deduplicated, sorted) |
| System group (`system:masters`) | excluded — 0 entries |
| Group with entra data | display_name, member_count, members, owners all populated |
| Group without entra (`entra=None`) | entry present, entra fields are None/[] |
| Two different groups | 2 entries |
| User and ServiceAccount grants mixed in | not included in groups result |

---

## Gap 3 — CLAUDE.md Cleanup

Remove the Known Gaps section entirely from `.claude/CLAUDE.md` — all gaps are now resolved.
Or if the section heading should remain, replace the body with:
`All known gaps resolved as of Stage 3.`

---

## Files In Scope
- `.claude/skills/risk-agent/scripts/analyze.py` — `_collect_groups_with_access()` only (line ~727)
- `tests/test_groups_with_access.py` — new file
- `.claude/CLAUDE.md` — remove Known Gaps section

## Files Off-Limits
- `.claude/skills/contracts/` — schemas are frozen, do not touch
- `.claude/skills/report-agent/SKILL.md` — already correct, no changes needed
- `_collect_users_with_access()` — no change needed

---

## Success Criteria

Self-evaluate all of the following before signaling completion:

- [ ] `owners` field is present in `_collect_groups_with_access()` output
- [ ] `owners` is populated from entra data when available
- [ ] `owners` is `[]` when entra is None or group not in entra
- [ ] System groups (`system:masters`, `system:*` prefixed) are excluded from result
- [ ] Multiple grants for same group produce one entry with merged, deduplicated roles
- [ ] User and ServiceAccount grants are not included in groups result
- [ ] All new test cases pass
- [ ] All existing 27 tests still pass
- [ ] CLAUDE.md Known Gaps section removed or marked all-resolved
- [ ] No files outside the in-scope list were modified

---

## Constraints
- Do not modify artifact contract schemas
- Do not modify report-agent SKILL.md
- Do not add new dependencies to `requirements.txt`
- Append all non-obvious decisions to `.claude/DECISIONS.md`

---

## Definition of Done
All success criteria checked and passing. Commit message:
`"feat: add owners field to groups_with_access and add tests"`
