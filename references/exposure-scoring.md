# Managed Exposure Scoring

Produce a coverage-qualified 0-100 Managed exposure score from completed `dtmgd` hunt evidence and any explicitly authorized official Managed API-only attack pivots. This score is not equivalent to a Grail score because Managed `dtmgd` does not search spans or Platform security-event datasets.

Always report both:

- **Managed exposure score:** numeric score or `NOT SCORED`.
- **Coverage statement:** which Managed sources were searched and which relevant sources were unavailable or incomplete.

## Score Eligibility

A numeric score is allowed only when every planned Managed leg completed or was intentionally excluded before execution. Use `NOT SCORED` when:

- a required command failed because of authentication or permissions;
- a planned source was incomplete because of timeout, truncation, pagination, or API failure;
- the user asked for a source that `dtmgd` cannot query directly and no official Managed substitute was accepted;
- scope or timing is too ambiguous to interpret the result.

Do not assign `0` if planned evidence sources failed or were incomplete.

## Managed Score Bands

| Evidence state | Score |
|---|---|
| All planned Managed legs completed with no matches | `0` |
| CVE/security-problem match only, no log/event/problem correlation | `20-59` |
| Event or problem context only, no IoC/CVE match | `10-39` |
| Single Managed log match or authorized Attacks API match for an IoC or behavior term | `60-79` |
| Log or attack match plus matching entity, event, problem, or CVE context | `80-89` |
| Multiple corroborating Managed sources on the same entity/window | `90-100` |

Keep the score inside the assigned band. Use analyst judgment only to position within the band.

## Fine-Tuning Within a Band

Adjust upward within the band for:

- recent evidence in the approved window;
- multiple affected entities;
- high-confidence IoC specificity, such as a full hash or exact exploit URL;
- affected production or high-criticality management zones;
- open critical/high security problems affecting the same process group or host;
- authorized Managed Attacks API results in `EXPLOITED` state;
- related problems or events in a tight time window.

Adjust downward within the band for:

- generic terms with many benign explanations;
- stale or low-confidence threat intelligence;
- weak entity correlation;
- incomplete surrounding telemetry that limits interpretation.

Never let threat reputation alone raise a clean completed hunt above `0`.

## Clean-Zero Rule

A score of `0` means every planned Managed command and accepted API-only Managed pivot completed successfully and no relevant evidence was found in the searched window and scope. The coverage statement must still explain that direct span coverage has no Managed read substitute in this skill.

Example:

```markdown
**Managed exposure score:** 0%
**Coverage:** Completed Managed log searches for 12 IoCs, CVE security-problem checks for 2 CVEs, authorized Attacks API checks for 3 attacker IPs, and event/problem checks on the approved entities. Direct span search has no Managed read substitute in this skill, so span evidence was not part of this Managed score.
```

## Incomplete Leg Rule

If a planned leg is incomplete, do not score it as clean. Use `NOT SCORED` or score only the completed subset if the report clearly says it is a partial score.

Preferred wording:

```markdown
**Managed exposure score:** NOT SCORED
**Reason:** Log searches completed, but security-problem access failed with `PERMISSION_DENIED`; CVE exposure could not be evaluated.
```

## Report Structure

Output pure Markdown:

1. Threat summary and Managed score.
2. Coverage statement.
3. Evidence summary by source, including API-only attacks if used.
4. CVE/security-problem details if any.
5. Matched IoC details and secondary observables.
6. Affected and related entities.
7. Assessment, limitations, and next pivots.

## Section 1 Template

```markdown
## Managed-Threat-Exposure-Score: <score>%

**Threat:** <threat name or hypothesis>
**Score rationale:** <1-2 sentences>
**Coverage:** <logs/security-problems/attacks-api/events/problems/entities/metrics searched; unavailable sources>
```

Use `Managed-Threat-Exposure-Score: NOT SCORED` when scoring is not valid.

## Evidence Tables

Matched IoCs:

| IoC value | Type | Primary/Secondary | Sources matched | Count | Entity/context |
|---|---|---|---|---|---|

Unmatched planned searches:

| Value | Type | Sources searched | Window | Status |
|---|---|---|---|---|

Incomplete searches:

| Source | Command or route | Failure/limit | Impact |
|---|---|---|---|

## Guardrails

- Do not merge Managed and Grail scores without explicitly separating data planes.
- Do not infer compromise from one log match, one CVE, one problem, or one event.
- Include exact searched windows and scopes.
- Pair every high or medium finding with a bounded next action.
