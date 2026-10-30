# Hunt Security Events

This filename is preserved for compatibility. In the Managed `dtmgd` skill, it does not mean Grail `security.events`. It covers Managed security-problem, event, and problem pivots available through the official `dtmgd` CLI, plus the official Managed Attacks API when attacker-activity substitution is authorized.

Use this reference for:

- CVE exposure through `dtmgd get security-problems` and `dtmgd describe security-problem`.
- Event context through `dtmgd get events` and `dtmgd describe event`.
- Operational impact through `dtmgd get problems` and `dtmgd describe problem`.
- Attacker activity through the API-only Managed Attacks API (`GET /api/v2/attacks`) when authorized.
- Correlation with entities discovered from logs, attack results, or CVE details.

Removed from Managed executable guidance: Platform Detection Finding queries, Platform attacker IP arrays, and DQL vulnerability snapshots. Use the Managed Attacks API as the official substitute for attacker request activity; use security problems for CVE exposure.

## CVE and Vulnerability Hunt

For each CVE, list matching Managed security problems:

```bash
dtmgd get security-problems \
  --selector 'cveId("CVE-2025-12345")' \
  --from now-30d \
  --to now \
  --sort=-riskAssessment.riskScore \
  --limit 100 \
  -o json
```

If the user only wants open exposure:

```bash
dtmgd get security-problems \
  --status OPEN \
  --selector 'cveId("CVE-2025-12345")' \
  --from now-30d \
  --limit 100 \
  -o json
```

Describe each relevant result:

```bash
dtmgd describe security-problem <security-problem-id-or-display-id> -o json
```

Record:

- security problem ID and display ID;
- status;
- CVE IDs;
- package, vulnerable component, and technology;
- Davis risk level and score;
- CVSS/base risk when present;
- public exploit, exposure, and data assets fields when present;
- affected entities and vulnerable component entity counts;
- management zones;
- URL to the vulnerability details page if present.

## Entity-Scoped CVE Checks

The Managed vulnerabilities API uses a security-problem selector rather than a general entity selector. Scope with supported selector criteria when entity IDs are known:

```bash
dtmgd get security-problems \
  --status OPEN \
  --selector 'affectedPgIds("PROCESS_GROUP-0123456789ABCDEF")' \
  --limit 100 \
  -o json
```

Other useful selector criteria include `relatedHostIds`, `affectedPgiIds`, `managementZoneIds`, and `managementZones`. Use the exact selector names documented by the Dynatrace Vulnerabilities API.


## Managed Attacks API Pivot

The official Dynatrace Managed Attacks API lists detected attacks on applications. This is the closest Managed substitute for Platform Detection Finding-style attacker activity, but it is API-only in this skill because `dtmgd` does not expose an attacks command.

Use only when the user authorizes API-only access and the token has `attacks.read`. Do not print or persist token values.

Endpoint shape:

```text
GET https://{activegate-domain}:9999/e/{environment-id}/api/v2/attacks
GET https://{activegate-domain}:9999/e/{environment-id}/api/v2/attacks/{id}
```

Useful `attackSelector` criteria from the official docs:

| Need | Selector |
|---|---|
| Source IP | `sourceIps("93.184.216.34")` |
| Request path | `requestPathContains("/path")` |
| Process group name | `processGroupNameContains("name")` |
| Vulnerability linkage | `vulnerabilityId("<id>")` |
| State | `state("EXPLOITED")`, `state("BLOCKED")`, `state("ALLOWLISTED")` |
| Attack type | `attackType("SQL_INJECTION")` or another documented value |
| Management zone | `managementZones("production")` or `managementZoneIds("123")` |
| Technology | `technology("JAVA")` or another documented value |

Record attack ID, display name, attack type, state, source IP, request path, timestamp, affected process group, linked vulnerability ID, and management zone when returned. Treat attack results as a separate Managed API source in the coverage statement.

## Event Correlation

Use events to look for deployment, custom, resource, availability, or anomaly context near observed log or CVE evidence.

```bash
dtmgd get events \
  --from now-24h \
  --to now \
  --limit 100 \
  -o json
```

Entity-scoped event search:

```bash
dtmgd get events \
  --from now-24h \
  --to now \
  --entity 'type(PROCESS_GROUP),entityId("PROCESS_GROUP-0123456789ABCDEF")' \
  --limit 100 \
  -o json
```

Event-type filtering, when a specific type is relevant:

```bash
dtmgd get events \
  --from now-24h \
  --to now \
  --type CUSTOM_DEPLOYMENT \
  --limit 100 \
  -o json
```

Describe relevant events:

```bash
dtmgd describe event <event-id> -o json
```

Events are correlation context, not proof of maliciousness.

## Problem Correlation

Use problems to understand operational impact around suspicious activity:

```bash
dtmgd get problems \
  --from now-24h \
  --to now \
  --limit 100 \
  -o json
```

Entity-scoped problem search:

```bash
dtmgd get problems \
  --from now-24h \
  --to now \
  --entity 'type(HOST),entityId("HOST-0123456789ABCDEF")' \
  --limit 100 \
  -o json
```

Describe relevant problems:

```bash
dtmgd describe problem <problem-id> -o json
```

Use the internal problem ID returned by dtmgd. If an ID starts with `-`, pass it after `--` so the shell does not treat it as a flag.

## Correlation Keys

Call out these keys in findings so evidence can be joined:

| From source | Join keys |
|---|---|
| Logs | timestamp, `event` fields, process group, host, service, request ID, source IP, URL, user identity |
| Security problems | CVE, package, affected process group, affected host, management zone, risk score |
| Attacks API | attack ID, attack type, source IP, request path, process group, linked vulnerability ID, state, timestamp |
| Events | event ID, event type, affected entity, start/end time |
| Problems | problem ID, affected entities, impacted entities, severity, start/end time |
| Entities | entity ID, entity type, display name, tags, management zone, relationships |

## Result Classification

- `CONFIRMED MATCH`: matching security problem, attack, event, or problem returned and relevant to the hypothesis.
- `NO MATCH IN WINDOW`: command completed with no relevant records.
- `INCONCLUSIVE`: the command failed, partial results were returned, pagination/limits prevented completeness, or the source cannot represent the requested evidence.
- `SUSPICIOUS CORRELATION`: separate Managed sources align in time and entity scope but do not prove compromise.

## Official References

- dtmgd CLI: https://github.com/dynatrace-oss/dtmgd
- Vulnerabilities API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/vulnerabilities/get-vulnerabilities
- Attacks API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/attacks/get-attacks
- Events API v2: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/events-v2/get-events
- Problems API v2: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2/problems/get-problems-list
