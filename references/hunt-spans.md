# Hunt Spans

This filename is preserved for compatibility with the original IoC-hunting skill layout. In the Managed `dtmgd` skill, there is no direct span hunt. The official `dtmgd` command surface exposes logs, metrics, SLOs, events, problems, entities, relations, and security problems, but not a trace/span search command.

Do not claim span coverage from this skill. Official Dynatrace docs for the Environment API document trace ingestion and trace-ingest controls, not a Managed read/search API for spans. Therefore direct span hunting has no Managed read substitute in this skill. Remove the span leg from Managed scoring and use only adjacent Managed evidence sources below.

## Adjacent Managed Pivots

When the original hypothesis expects span evidence, use these supported Managed sources as adjacent pivots without labeling them as span results or span substitutes.

| Original intent | Adjacent Managed pivot | Command |
|---|---|---|
| Inbound request from IP/domain/URL | Search access/application logs | `dtmgd query logs --query '<ip-or-url>' --from <window> --to now -o json` |
| Outbound call to domain/IP | Search application/proxy/firewall logs | `dtmgd query logs --query '<domain-or-ip>' --from <window> --to now -o json` |
| Affected service or process context | Discover entities and relations | `dtmgd get entities`, `dtmgd describe entity-relations` |
| Service health or impact | Query problems/events | `dtmgd get problems`, `dtmgd get events` |
| Rate/error/duration support | Query known metrics | `dtmgd query metrics --metric <metric-id> --from <window> --to now -o json` |

## Request and Dependency Pivots

If a log match contains service, process group, host, endpoint, or request identifiers:

1. Extract entity IDs or names from the log record.
2. Describe the entity:

```bash
dtmgd describe entity <entity-id> -o json
```

3. Inspect relationships:

```bash
dtmgd describe entity-relations <entity-id> -o json
```

4. Search related entities only if the relationship is relevant to the hypothesis and the user-approved scope permits it.

## Metric Pivots

Use metrics as supporting context only. Select a metric ID from known Managed metrics or discover relevant metrics:

```bash
dtmgd get metrics --search '<service-or-host-term>' --limit 50 -o json
```

Then query a known metric:

```bash
dtmgd query metrics \
  --metric builtin:service.response.time \
  --from now-1h \
  --to now \
  -o json
```

Do not present metric anomalies as IOC matches. They can support correlation, impact assessment, or next pivots.

## Reporting Language

Use precise coverage language:

- Correct: `No dtmgd span-search source is available; Managed log and entity pivots were searched instead.`
- Correct: `Logs matched the suspicious URL on PROCESS_GROUP-..., and related events were checked.`
- Incorrect: `No spans matched.`
- Incorrect: `Span leg completed cleanly.`

## When to Remove the Span Leg

Remove the span leg from the Managed hunt when the user needs:

- span attributes such as `client.ip`, `server.address`, `url.full`, or request headers;
- trace IDs, root spans, or service dependency paths from trace data;
- joins across logs and spans.

Report: `No Managed Environment API read/search substitute for spans was found in official docs; span coverage is not part of this Managed score.`

If a separate Platform/Grail investigation is later authorized, keep those results in a separate evidence section and do not merge scores without saying which data plane produced each finding.

## Official References

- OpenTelemetry trace ingest API: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/opentelemetry/post-traces
- Trace ingest control settings schema: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/schemas/builtin-trace-ingest-control
- Metrics API v2: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/metric-v2
