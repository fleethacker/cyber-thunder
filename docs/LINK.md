# Link observations and explicit test mode

Production does not assume a 56 kbps / 500 ms connection. Before a real request,
reachability, application rate and physical latency are unknown. The legacy
`connected` field means **permission to attempt a request**, so unknown permits
an explicitly requested content check or pull. It is not proof of connectivity.

## Controls

Settings → Link observations and controls provides:

- **Operator offline**: blocks content requests and probes independently of test
  mode. `CT_LINK_OFFLINE=true` or legacy `CT_LINK_CONNECTED=false` enforces
  offline at the environment level; the UI cannot release an environment override.
- **Enable test emulation**: an explicit, human-attributed `link.change` audit event.
  Only this mode accepts configured rate/delay or simulated connected/disconnected
  state. Downloads remain unpaced unless their separate test pacing option is set.
  Disabling test mode stops paced work and restores production semantics.
- **Probe once**: one bounded HEAD request to the selected official endpoint.
- **Probe every 30 seconds for 15 minutes**: an audited, expiring opt-in session.
  It is off by default. Enabling it persists an expiry, never an endless network
  poll. The runtime only schedules requests while that session remains enabled.
  Turning it off, operator offline or the kill switch cancels an active probe.

The two probe URLs are exactly `https://www.cyber.mil/` and
`https://dl.dod.cyber.mil/`. No arbitrary URLs, proxies, credentials, redirects
or response bodies are allowed. A disposable worker has a five-second deadline
enforced by its parent, including DNS/connection/read time; termination is followed
by bounded process cleanup. HTTP errors and redirects count as failed probes.
Successful HEAD requests establish only endpoint reachability, not a transfer rate
or network round-trip latency. Read-only GETs never start probes.

Examples:

```sh
cyberthunder link set --offline true
cyberthunder link set --offline false
cyberthunder link set --mode test --kbps 56 --latency-ms 500 --connected false
cyberthunder link set --mode production
cyberthunder link set --probe-enabled true
```

Legacy saved numeric values and environment defaults never enable emulation.
Legacy saved `connected=false` migrates conservatively to operator offline.
The legacy connected setter in production changes only that offline override;
`connected=true` never establishes measured reachability.

## Observations and reports

Existing index/catalog/HEAD/content HTTP requests retain at most 64 observations
in the selected JSON or SQLite state backend. Each includes UTC timestamp,
endpoint without query/credentials, method, HTTP status, success/failure,
response-body application bytes actually consumed, elapsed request seconds,
and optional observed application kbps. Reads include partial failures and resumed
requests independently; they do not reuse the size of an already downloaded file.
HTTP transfer success does not imply that downloaded content passed validation or import.

The rate is application body bytes divided by request duration, including
connection setup and application processing. Compressed bodies remain compressed
byte counts. It is **not physical bandwidth**; request duration is **not physical
latency**. Failed or zero-byte/zero-duration requests have no rate. Test observations
are labelled and cannot supply production rates. Observations older than 120
seconds become unknown. A received HTTP error can show a reachable endpoint and a
failed content operation simultaneously.

Production configured-time estimates are null. Test estimates are explicitly
labelled. The outbox currently moves files locally into `synced/`: that is local
staging, not evidence of shore delivery or network throughput. Historical modeled
transfer times are labelled estimates, never reinterpreted as observations.
Content reconnect checks now default off; explicitly saved reconnect preferences
continue to apply and all reconnect work remains kill-switch guarded.

## CON-04 acceptance

Implemented: honest production defaults, separate offline/test controls,
bounded passive observations, bounded official-source probes, optional temporary
failure/recovery detection, guarded local outbox staging on observed recovery,
and honest UI/API/report labels. Network validation is deliberately excluded from
the focused test run; requests and processes are mocked or use local fixtures.

**Partial acceptance:** unattended detection within a minute is available only
while the operator enables a probe session and the runtime is running. Production
does not start indefinite probing by default. Real shore outbox delivery remains
unimplemented, so its network throughput and successful delivery cannot be
claimed. Physical bandwidth and round-trip latency remain unknown.
