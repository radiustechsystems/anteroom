# Configuration upgrades

Anteroom rejects unknown TOML keys and tables at startup. Errors name the file
and full key path, with a migration hint for known removed settings. Check table
placement as well as spelling: after `[bypass]`, `json_accept` means
`bypass.json_accept`, not `triage.json_accept`.

Keys must match the lowercase spelling in `anteroom.example.toml`. Older builds
accepted case variants through the TOML decoder; configurations containing both
`inject` and `Inject` could select a value according to map iteration order.
They now fail explicitly. Consolidate such keys into one correctly spelled
setting with the intended value. Non-finite puzzle difficulties, including TOML
`nan`, are also rejected.

## Removed settings

These settings appeared in earlier development configurations. They are not
silently translated: several have no semantics-preserving replacement.

| Old path | Upgrade |
| --- | --- |
| `bypass.crawlers` | Use `bypass.verified_crawlers` with supported provider names. The old setting was inert; the new one authenticates sources and bypasses both PoW and payments. |
| `payments.rails.v1_network` | Remove. Keep `network` as a CAIP-2 identifier, such as `eip155:8453`, and use an x402 v2 client. |
| `payments.rules.grant` | Remove. Time-based access is specified by the rule's `paths`, `price`, and `paid_ttl`. Request-count grants are unsupported. |
| `payments.rules.scheme` | Remove if it selected `exact`, the only supported scheme. There is no equivalent configuration for `upto` or `batch-settlement`. |
| `payments.rules.challenge` | Remove. PoW uses top-level `difficulty` and `renew_difficulty`; per-rule challenge selection is unsupported. |

`triage.json_accept` and `triage.ok_body_agents` still exist. They control
response presentation, not admission.

## Changes that unknown-key validation cannot catch

An omitted setting or a supported key with changed semantics cannot be diagnosed
as a typo. Review these when upgrading from an earlier development build:

- `triage.allow_hosted_fetchers` now defaults to `true`. Source-verified
  `Claude-User/`, `ChatGPT-User/`, and `Google-Agent;` requests bypass PoW and
  payments, including priced routes. Set it explicitly to `false` to remove
  this exception; those clients then receive a strict 403, not an x402 offer.
  Claude Code is excluded from this hosted-fetcher classification.
- Payment grants now use durable storage. By default `payments.state_file` is
  `anteroom-payments.db` beside the configuration file. If that directory is
  read-only, set an explicit path on writable persistent storage. Relative paths
  resolve against the configuration directory. Retain the database on upgrades
  and restarts to preserve existing payment grants and replay protection.
- `payments.rules.paid_ttl` must be at least `"1s"`. Earlier `"0s"` behavior was
  per-request/no-pass admission and is no longer supported. Selecting a positive
  TTL allows repeated requests during that interval; it is a billing-policy
  change, not a transparent conversion.

Pin the deployed version and review its release notes before changing it.
When changing configuration keys, defaults, or admission semantics, update this
page and include the change and operator action in the release notes. Do not
use an unknown-key check as a substitute for documenting changed defaults.
