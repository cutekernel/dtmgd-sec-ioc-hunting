# Secondary Observable Extraction

When a primary Managed log hunt returns matches, inspect those matched records for additional public IPs that were not in the original IoC set. These are secondary observables.

This Managed reference extracts secondary observables from log content and structured log fields only. It does not extract from spans or Platform detection records because those sources are not available through `dtmgd`.

## What Counts as a Secondary Observable

Only public IP addresses are promoted automatically. Domains, URLs, hashes, and emails embedded in evidence can be noisy; report them as possible follow-up rather than auto-hunting unless the user asks.

Skip by default:

- RFC 1918 private ranges;
- loopback and link-local addresses;
- container-only addresses;
- already searched primary IPs;
- values that are not valid IPv4 or IPv6 literals.

Include private/internal IPs only when the hunt is explicitly scoped to internal movement.

## Sources to Inspect

Inspect the returned top-level log fields, `content`, and structured `event` map for:

| Header or field | Notes |
|---|---|
| `X-Forwarded-For` | May contain a comma-separated chain. Search all public values. |
| `Forwarded` | Extract `for=` values from RFC 7239 syntax. |
| `X-Real-IP` | Common reverse-proxy client IP. |
| `X-Client-IP` | Common proxy field. |
| `True-Client-IP` | CDN/WAF client IP. |
| `CF-Connecting-IP` | Cloudflare client IP. |
| `Fastly-Client-IP` | Fastly client IP. |
| `Akamai-True-Client-IP` | Akamai client IP. |
| `clientIP`, `src_ip`, `source.ip`, `remote_addr`, `actor.ip` | Common structured log fields. |
| `xff`, `x_forwarded_for` | Common abbreviated structured forms. |

Percent-decode and HTML-decode content before extraction when evidence appears encoded, but preserve the raw representation as provenance.

## Extraction Steps

1. Review only records returned by a completed primary log hunt.
2. Extract candidate IPs from named headers and fields. Do not guess from unlabeled numeric strings unless the surrounding content clearly identifies an IP field.
3. Split chains on commas and semicolons where appropriate.
4. Validate IP syntax.
5. Remove private, loopback, link-local, and already searched IPs unless the hunt is internal.
6. Build a derived-IP queue with provenance for each value.

## Re-Hunt Policy

Re-hunt each derived public IP with the same window and scope that produced the primary evidence:

```bash
dtmgd query logs \
  --query '<derived-public-ip>' \
  --from <same-from> \
  --to <same-to> \
  --sort=-timestamp \
  --limit 100 \
  -o json
```

If the primary hunt used `--entity`, use the same `--entity`. Do not widen the window during secondary re-hunts.

Apply one level of automatic secondary extraction only. If secondary results contain more new public IPs, report them as queued follow-up and ask before hunting them.

## Queue Size

If the derived-IP queue exceeds 25 IPs:

1. Report the queue size and top provenance sources.
2. Chunk into groups of 25 only if the user or parent instruction approves broad secondary hunting.
3. Prefer one-IP-per-command when attribution matters.

## Reporting Template

```markdown
### Secondary observables

| Derived IP | Source primary IoC | Header/field | Record timestamp | Re-hunt status | Notes |
|---|---|---|---|---|---|
| `203.0.113.10` | `198.51.100.9` | `X-Forwarded-For` | `2026-10-29T12:03:10Z` | `CONFIRMED MATCH` | Same entity scope |
```

If no secondary IPs are found, state `No public secondary IPs found in matched log records`.
