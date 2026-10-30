# Timeframe Gating

Use bounded windows for every `dtmgd` command. The goal is to reduce false confidence, keep searches affordable, and make no-match results meaningful.

## Default Windows

| Source | Default window | Rationale |
|---|---|---|
| Log search | `now-30m` | Best first pass for unanchored IoCs and behavior terms. |
| Event-anchored log search | event time +/- 30m | Captures setup, trigger, and immediate aftermath. |
| Security problems | `now-30d` | The API default is oriented around recent vulnerability state; use explicit windows for report clarity. |
| Attacks API | `now-24h` | API-only attacker activity pivot; widen only when incident timing requires it. |
| Events | `now-24h` | Useful operational context near suspicious activity. |
| Problems | `now-24h` | Captures active/recent impact; widen only when incident timing requires it. |
| Entity discovery | Source-dependent | Use `--from` and `--to` when the entity must have been observed in the hunt window. |
| Metrics | Same as related event/log window | Metrics are support context, not primary IoC evidence. |

Honor the user's requested window when provided. Convert timestamps to UTC in reporting.

## Managed Time Syntax

`dtmgd` accepts the Environment API time formats, including:

- relative: `now-30m`, `now-1h`, `now-24h`, `now-30d`;
- absolute ISO-style times: `2026-10-29T12:00:00Z`;
- epoch milliseconds when accepted by the underlying API.

Always record the exact `--from` and `--to` values used.

## Event-Anchored Hunts

When an IoC comes from a timestamped log, event, problem, alert, ticket, or user-provided incident time, start with a bounded anchored window:

```text
from: <event_time - 30m>
to:   <event_time + 30m, capped at now>
```

If multiple source events are supplied, either run one window per event or use a combined window from earliest-minus-30m to latest-plus-30m. State which approach was used.

## Expansion Rules

For interactive use, widen only after reporting the current result and receiving approval. Default sequence:

```text
30m -> 1h -> 3h -> 24h -> 7d only when explicitly requested
```

Do not run wider windows in parallel with narrower windows. Do not treat a short clean window as proof that a broader period is clean.

For autonomous sub-agent use with no user in the loop:

1. Run the planned initial window.
2. If zero matches, report the clean window and recommend expansion.
3. Do not auto-expand beyond the initial window unless the parent instruction explicitly authorizes it.

## Timeout, Limit, and Partial Result Handling

Managed API failures vary by endpoint and tenant. Classify carefully:

| Observation | Classification |
|---|---|
| CLI exits non-zero because of auth or permission | `AUTHENTICATION/ACCESS FAILURE` |
| CLI exits non-zero because of usage or selector syntax | `QUERY_FAILED` |
| API returns a timeout, server error, or rate/size limit | `INCONCLUSIVE` |
| Results hit `--limit` and more data may exist | `INCONCLUSIVE` unless enough data was intentionally sampled |
| Pagination remains after `--max-pages` or agent envelope says more exists | `INCONCLUSIVE` for completeness |
| Command succeeds with zero relevant records | `NO MATCH IN WINDOW` |

When output is incomplete, do not lower exposure score as if the source was clean. Recommend narrowing scope, increasing limits, fetching additional pages, or running entity-scoped follow-up.

## Pagination and Limits

`dtmgd` list commands can page automatically. Use:

- `--limit <n>` to cap returned items intentionally;
- `--max-pages <n>` when you need a hard API-cost bound;
- `-o json` for API-shaped output;
- `-A` for an agent envelope with context metadata.

In reports, state when a limit was applied. If the limit could hide additional matches, mark the leg incomplete.

## Scope Controls

Use entity selectors and security-problem selectors only when justified by user scope or prior evidence.

Entity selector examples:

```text
type(HOST),entityId("HOST-0123456789ABCDEF")
type(PROCESS_GROUP),tag("[Environment]Production")
type(SERVICE),entityName.equals("checkout-service")
```

Attack selector examples, for authorized API-only attack pivots:

```text
sourceIps("203.0.113.10")
requestPathContains("/admin")
state("EXPLOITED")
processGroupNameContains("checkout")
vulnerabilityId("<security-problem-id>")
```

Security-problem selector examples:

```text
cveId("CVE-2025-12345")
affectedPgIds("PROCESS_GROUP-0123456789ABCDEF")
relatedHostIds("HOST-0123456789ABCDEF")
managementZones("production")
```

Unscoped IoC discovery is valid when the user has not supplied entity context. Do not silently add a scope that can miss evidence.

## Official References

- Environment API time formats: https://docs.dynatrace.com/docs/dynatrace-api/environment-api
- Attacks API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/attacks/get-attacks
- Entity selector syntax: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/entity-v2/entity-selector
