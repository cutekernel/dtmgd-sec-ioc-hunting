# Hunt Logs

Use `dtmgd query logs` for Managed log searches. This is the primary IoC surface for IPs, domains, URLs, emails, file hashes, process names, paths, command fragments, request IDs, and other literal observables.

Official basis: `dtmgd query logs` calls the Dynatrace Log Monitoring API v2 search endpoint. The CLI requires `--query` and `--from`; `--to` defaults to `now`; `--limit` defaults to 100 in dtmgd; `--sort=-timestamp` returns newest first. Managed log search is text-oriented, so do not use Grail or DQL syntax.

## Supported IoC Types

| Type | Command route | Notes |
|---|---|---|
| IP | `--query '<ip>'` | Search each attribution-sensitive IP independently. |
| Domain/hostname | `--query '<domain>'` | Include meaningful subdomains when supplied. |
| URL/URI | `--query '<url-or-path>'` | Long URLs should be searched independently; also consider domain and path pivots. |
| Email | `--query '<email>'` | Useful in audit, identity, and application logs. |
| Hash | `--query '<hash>'` | Search MD5, SHA-1, and SHA-256 literally. |
| Behavior term | `--query '<literal term>'` | Use for process names, command fragments, user agents, filenames, and request IDs. |

CVEs belong in `hunt-security-events.md` via `dtmgd get security-problems`, not log search unless the user specifically wants logs that mention a CVE string.

## Canonical Commands

Unscoped search:

```bash
dtmgd query logs \
  --query '<literal search term>' \
  --from now-30m \
  --to now \
  --sort=-timestamp \
  --limit 100 \
  -o json
```

Scoped search when a Managed entity selector is known:

```bash
dtmgd query logs \
  --query '<literal search term>' \
  --from now-30m \
  --to now \
  --entity 'type(PROCESS_GROUP),entityId("PROCESS_GROUP-0123456789ABCDEF")' \
  --sort=-timestamp \
  --limit 100 \
  -o json
```

Agent-envelope output, useful when an AI orchestrator needs status metadata:

```bash
dtmgd query logs \
  --query '<literal search term>' \
  --from now-30m \
  --to now \
  --limit 100 \
  -A
```

Multi-environment search, only when authorized:

```bash
dtmgd query logs \
  --env ALL_ENVIRONMENTS \
  --query '<literal search term>' \
  --from now-30m \
  --to now \
  --limit 100 \
  -o json
```

## Query Construction Rules

- Use literal search terms. Do not use DQL, `content:<term>`, or field projection syntax.
- Quote shell metacharacters safely. Prefer single quotes around values unless the value contains a single quote.
- Search attribution-sensitive IoCs one at a time so evidence can be tied to the specific IoC.
- Preserve the exact searched term, window, limit, context, and scope in the report.
- Use `--limit` intentionally. A hit at the limit may indicate truncation, not complete evidence.
- Use `--sort=-timestamp` for investigation-first output.
- Keep stderr separate from stdout when parsing `-o json`.

## Result Classification

| CLI outcome | Classification | Reporting rule |
|---|---|---|
| Command succeeds and relevant records are returned | `CONFIRMED MATCH` | Summarize timestamps, content excerpts, source fields, and entity IDs when present. |
| Command succeeds with zero records | `NO MATCH IN WINDOW` | State the searched term, window, scope, and limit. |
| Command succeeds but output is truncated or ambiguous | `INCONCLUSIVE` | State why the result is incomplete and propose narrower or higher-limit follow-up. |
| Auth, permission, context, or API failure | `AUTHENTICATION/ACCESS FAILURE` or `QUERY_FAILED` | Do not convert to no-match. |

## Summarize-First Output

Do not dump full raw log sets by default. Build a compact summary:

| Field | Include |
|---|---|
| Search term | Literal searched value and original IoC if different. |
| Window and scope | `from`, `to`, entity selector, environment/context. |
| Match count | Returned count and whether the configured limit may have truncated results. |
| Timestamps | First and last returned timestamp when available. |
| Evidence excerpts | Short redacted content snippets sufficient to justify the finding. |
| Entity fields | Process group, host, service, Kubernetes, cloud, or custom fields if present in `event` or top-level data. |
| Secondary observables | Public IPs extracted from proxy headers or structured content. |

## Entity Scoping

Start unscoped when the only input is an IoC list. Add `--entity` only when scope is provided by the user or by prior evidence. Useful selectors include:

```text
type(HOST),entityId("HOST-0123456789ABCDEF")
type(PROCESS_GROUP),entityId("PROCESS_GROUP-0123456789ABCDEF")
type(SERVICE),entityName.equals("checkout-service")
type(PROCESS_GROUP),tag("[Environment]Production")
```

Managed Classic logs are commonly attributed to process groups. When starting from a service, dtmgd may translate service-based log counts to process groups, but log search scoping should still be reported exactly as run.

## Large IoC Sets

For many literals:

1. Deduplicate and group by type.
2. Run independent searches when attribution matters.
3. For coarse discovery, chunk by 25 terms, or 10 for long URLs, hashes, and emails.
4. Record one status per term or chunk.
5. A no-match conclusion is valid only when every planned term/chunk completed successfully.

## Secondary Observable Extraction

After confirmed log matches, load `secondary-observable-extraction.md`. Inspect matched log content and structured `event` fields for public IPs in headers such as `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, and `Akamai-True-Client-IP`. Re-hunt derived public IPs with the same window and scope.

## Official References

- dtmgd CLI: https://github.com/dynatrace-oss/dtmgd
- Log Monitoring API v2 search: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/log-monitoring-v2/get-search-logs
- Entity selector syntax: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/entity-v2/entity-selector
