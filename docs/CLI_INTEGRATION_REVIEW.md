# CLI integration fixture lifecycle review

This bounded review starts from integrated revision
`64306dbee82e47616806ad8a1a040abb870001da`. The parent independently recorded an
uninstrumented full client run of 142 passed and one platform skip on that exact
revision. A preceding run had stalled while closing the AnyIO portal. Its stack
showed no active HTTP handler, so that stack alone did not establish a cause.
The task-enumeration diagnostic plugin that made another run pass is not a fix.

## Confirmed fixture defect and correction

The TLS bridge remained open while `TestClient.__exit__` closed the ASGI portal.
Its daemon request threads were not joined by `server_close()`. Thus the fixture
could close the portal and state store while an owned request was still using
them, including after its external client timed out or disconnected.

A controlled concurrent-read probe entered the real TLS/verified API path, then
unwound the fixture while two requests were still active. With the original
teardown order, this reproduced a portal-join hang. A stack-only capture again
showed an idle portal and no remaining HTTP handler. The owned probe processes
were stopped and their isolated temporary directory removed. This establishes a
controlled teardown failure; it does not prove the earlier uninstrumented run
failed for exactly the same reason.

The fixture now uses joinable HTTP handler threads and stops/drains the TLS
bridge **inside** the TestClient context's `finally` block. Only after those
handlers finish does the ASGI portal close, followed by the state store. The
outer cleanup also handles setup failures. The fixture's existing separation
policy callback and all policy assertions are unchanged.

This is a recommended fixture correction for a demonstrated ownership race.
It is required for reliable teardown of the controlled concurrent/abandoned
requests; no runtime authentication or transport-policy change is established
as necessary. It is not a claim that every possible portal hang is resolved.

## Focused verification and limits

The new probes use the actual loopback TLS bridge, signed login and verified API
with both JSON and SQLite. They cover the real client's timeout/worker teardown,
an explicit TLS disconnect, a test-body assertion while a request is active,
and two concurrent reads. They require zero active ASGI requests and zero live
owned HTTP handlers when TestClient exit starts. Successful reads still have to
return only the permitted target; the intentional assertion must remain visible
to its caller. No unrelated task is cancelled.

Readiness is established with a successful authenticated request before the
controlled event gate. The probes use events and bounded waits, not arbitrary
sleeps. The observer releases its own gate on either shutdown path to bound the
old-order reproducer; it is not the parent task-enumeration plugin and does not
claim uninstrumented coverage. The existing 16 API integration cases are also
run without this observer. Exact Windows/Linux outputs, source hashes and the
before-change stack are retained with the separate local review handoff. No full
client suite or full release gate is repeated for this review.

A handler that never returns can still prevent orderly draining; extending
timeouts or cancelling all portal tasks would conceal that defect. This review
does neither. General ASGI cancellation behavior and the exact cause of the
parent's earlier intermittent failure remain open. The prior 19-check Keycloak
receipt and its runtime-source attribution are preserved unchanged.
