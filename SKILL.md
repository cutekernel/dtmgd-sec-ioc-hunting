---
name: dtmgd-sec-ioc-hunting
description: Hunt threat intelligence, IoCs, and suspicious behavior through the dtmgd CLI against Dynatrace Managed classic APIs. Use for authorized read-only Managed log searches, CVE/security-problem checks, event/problem pivots, entity correlation, and coverage-qualified exposure reporting when Grail/DQL is not available.
license: Internal
metadata:
  version: 1.2.0
  author: Toma Taylor Makoundou
  tags: dynatrace-managed, dtmgd, threat-hunting, ioc, mitre-attack, behavioral-analysis
---

# Managed Threat Hunting with dtmgd

Use this skill for authorized, read-only threat hunting in Dynatrace Managed environments through `dtmgd`. It is the Managed-classic counterpart to Grail-based IoC hunting: it uses the official `dtmgd` command surface and official Dynatrace Environment APIs for logs, events, problems, monitored entities, metrics, security problems, and documented API-only application-security attacks.

Do not use Grail or DQL templates here. `dtmgd` does not expose a span-search command or a `security.events` query surface. For unsupported features, use only official Managed substitutes when they exist; otherwise remove that leg from the Managed hunt and state the coverage gap.

## Operating Model

Use a threat-informed Prepare -> Execute -> Act loop:

1. **Prepare:** define the hypothesis, authorized context, UTC window, scope, expected observables, and which Managed evidence sources can test them.
2. **Execute:** validate `dtmgd` access, normalize indicators, run bounded read-only commands, preserve query status, and collect only the evidence needed for the finding.
3. **Act:** classify each result, document coverage limits, score only completed planned legs, and recommend bounded next pivots.

Every hunt should answer: what do we expect to find, where can Managed expose it, what result is positive/negative/inconclusive, and what is the next verification step?

## Evidence Sources

Use these Managed evidence sources only:

| Evidence source | dtmgd command | Use for |
|---|---|---|
| Logs | `dtmgd query logs` | IPs, domains, URLs, emails, file hashes, process names, paths, user agents, request IDs, and behavior strings visible in log content. |
| Log counts | `dtmgd query log-counts` | Sanity checks by entity/process group when an entity scope is known. |
| Security problems | `dtmgd get security-problems`, `dtmgd describe security-problem` | CVE exposure, vulnerable packages, Davis risk, affected process groups/hosts, and management zones. |
| Events | `dtmgd get events`, `dtmgd describe event` | Deployment, custom, availability, error, resource, and other Managed event pivots in the hunt window. |
| Problems | `dtmgd get problems`, `dtmgd describe problem` | Operational impact and affected entities near suspicious activity. |
| Entities and relations | `dtmgd get entities`, `dtmgd describe entity`, `dtmgd describe entity-relations` | Entity discovery, topology, tags, management zones, and relationship-based correlation. |
| Metrics | `dtmgd query metrics` | Supporting rate, error, duration, host, process, or service context when a metric ID is known. |

Official Managed API-only substitutions not exposed by current `dtmgd` commands:

| Need | Official Managed substitute | Scope |
|---|---|---|
| Detection-style attacker activity | Attacks API: `GET /api/v2/attacks` and `GET /api/v2/attacks/{id}` | Requires explicit authorization and `attacks.read`; use source IP, request path, process group, management zone, technology, vulnerability ID, state, and attack type selectors. |
| Trace/span search | No Environment API read substitute found | Remove the span leg from Managed scoring. The official trace endpoint is ingest-only; Managed trace searching remains UI/Platform-specific, not a dtmgd read command. |

Unsupported in this skill as executable guidance: `fetch spans`, `fetch logs`, `fetch security.events`, Runtime Vulnerability Analytics DQL snapshots, and DQL exposure scoring.

## Preconditions

1. Confirm the CLI and selected context:

```bash
dtmgd version
dtmgd config view
dtmgd config use-context <context>
```

2. Validate access with bounded read-only commands. Keep stdout and stderr separate when parsing JSON or agent envelopes.

```bash
dtmgd get entities --selector 'type(HOST)' --limit 1 -o json
dtmgd query logs --query 'error' --from now-15m --to now --limit 1 -o json
```

3. Required token scopes depend on the planned hunt. Full `dtmgd` coverage generally needs `DataExport`, `entities.read`, `events.read`, `logs.read`, `metrics.read`, `problems.read`, `securityProblems.read`, and `slo.read`. API-only attack pivots require `attacks.read`. Never print or store token values in prompts, generated reports, or source control.

Classify failures as `AUTHENTICATION_FAILED`, `PERMISSION_DENIED`, `NOT_FOUND`, `QUERY_FAILED`, `TIMEOUT_OR_LIMIT`, or `INCONCLUSIVE`; never turn a failed command into `NO MATCH IN WINDOW`.

## Hunt Workflow

### 1. Build a Managed Hypothesis

```markdown
## Hunt hypothesis - H-01: [behavior]

**Statement:** We believe [behavior/IOC/threat] may appear in [Managed context]
              because [intelligence or local evidence].
**Window:** [UTC start -> end]
**Scope:** [environment, management zone, entity selector, or unscoped]
**Managed sources:** [logs, security problems, attacks API if authorized, events, problems, entities, metrics]
**Positive:** [what evidence would raise priority]
**Negative:** [which completed commands would support no observed exposure]
**Inconclusive:** [missing source, permission failure, timeout, ambiguous match]
```

Use ATT&CK as a taxonomy for behavior, not proof of actor attribution.

### 2. Normalize Indicators

Load `references/ioc-intake.md`. Refang only for searching, preserve original forms for reporting, deduplicate, and route each IoC to Managed-supported sources:

- IP/domain/URL/email/hash/process/path strings -> `dtmgd query logs`.
- CVEs -> `dtmgd get security-problems --selector 'cveId("CVE-...")'` and `dtmgd describe security-problem`.
- MITRE IDs -> report as behavior context; search only derived process names, paths, commands, URLs, or other concrete observables.

### 3. Run Bounded Searches

Load the relevant reference before each leg:

- `hunt-logs.md` for literal log searches.
- `hunt-security-events.md` for Managed security-problem, API-only attack, event, and problem pivots.
- `hunt-spans.md` for the no-substitute span decision and adjacent Managed pivots that must not be reported as span evidence.
- `timeframe-gating.md` for windows, widening, limits, pagination, and incomplete results.

Search each attribution-sensitive IoC independently unless the user explicitly asks for coarse discovery. Use `-o json` or `-A` for machine-readable output, and record the command, window, limit, context, and result status.

### 4. Correlate Managed Evidence

Correlate by timestamp proximity, entity IDs, process group IDs, host IDs, service IDs, management zones, tags, event/problem IDs, request IDs, source IPs, user identities, URLs, package names, and CVEs. Use `dtmgd describe entity-relations <entity-id>` when entity relationships matter.

A single match is not compromise. Raise confidence when independent Managed sources align: for example, a suspicious IP in logs near a problem on the same process group, plus an open CVE affecting that process group.

### 5. Extract Secondary Observables

Load `secondary-observable-extraction.md` after log matches. Extract public IPs from matched log content and structured fields, deduplicate against already searched IPs, and re-run bounded `dtmgd query logs` searches in the same window and scope. Do not recurse automatically beyond one level.

## Findings Labels

Use these labels consistently:

- **CONFIRMED MATCH:** command completed and matching evidence was returned.
- **NO MATCH IN WINDOW:** command completed successfully with zero relevant results.
- **INCONCLUSIVE:** command timed out, hit a limit, returned partial data, lacked source coverage, or produced ambiguous evidence.
- **AUTHENTICATION/ACCESS FAILURE:** command could not execute because of auth or permissions.
- **SUSPICIOUS CORRELATION:** multiple Managed observations align, but compromise is not proven.
- **POSSIBLE COMPROMISE:** Managed evidence shows suspicious behavior plus corroborating activity consistent with execution, persistence, exfiltration, or impact.

## Required Report Format

```markdown
## dtmgd threat-hunt findings

**Context:** [dtmgd context]
**Environment:** [environment ID/name if available]
**Window:** [UTC start -> end]
**Scope:** [unscoped or entity/management zone selector]
**Execution status:** [completed / partial / auth failure]
**Coverage:** [logs/security-problems/attacks-api/events/problems/entities/metrics searched; unavailable sources]
**Managed exposure score:** [0-100 or NOT SCORED]

| Priority | Hunt | Result | Evidence | Confidence |
|---|---|---|---|---|
| High | ... | ... | ... | ... |

### Assessment
[Observed facts, inferred meaning, limitations]

### Secondary observables
[Derived public IPs, or none found]

### Recommended next pivots
[Bounded read-only searches or incident-response actions]
```

For substantial hunts, include source references, collection time, extraction/source/context/maliciousness confidence, ATT&CK mapping as hypothesis or observed behavior, logging gaps, false-positive explanations, and exact command status.

## Relationship to dt-sec-ioc-hunting

Use this skill when the target is Dynatrace Managed classic data accessed through `dtmgd` and official Managed Environment APIs. Use the Grail-based `dt-sec-ioc-hunting` skill only when the user has authorized Platform/Grail access and needs DQL-backed logs, spans, or Platform `security.events`. For Managed attacker activity, prefer the official Attacks API when authorized; do not send users to Grail only because `dtmgd` lacks an attacks wrapper.

## References

- `references/ioc-intake.md`
- `references/hunt-logs.md`
- `references/hunt-security-events.md`
- `references/hunt-spans.md`
- `references/timeframe-gating.md`
- `references/secondary-observable-extraction.md`
- `references/exposure-scoring.md`
- Official dtmgd CLI: https://github.com/dynatrace-oss/dtmgd
- Dynatrace Environment API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api
- Dynatrace Attacks API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/attacks/get-attacks
- Dynatrace OpenTelemetry trace ingest API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/opentelemetry/post-traces
- MITRE ATT&CK Framework: https://attack.mitre.org/
