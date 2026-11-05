# Optional model endpoint authentication

The existing compatible explanation backend can authenticate to a configured
local or enclave model server with a bearer API key. No new backend, runtime
dependency, endpoint default, or agent harness is required.

## Configuration

Keep the existing backend, model, and endpoint settings. Supply
`CT_LLM_API_KEY` in the application process environment through the launcher or
your existing secret injection mechanism. Obtain the credential from the model
server operator; this document contains no sample credential.

An unset, empty, or whitespace-only value sends no authentication header and
preserves unauthenticated local operation. Leading and trailing whitespace is
trimmed. The configured key is sent only as an `Authorization: Bearer` header on
the compatible backend's `GET /v1/models` and `POST /v1/chat/completions` requests,
including a retry without JSON response formatting. Other backends and callers
of the shared HTTP helper do not inherit this environment variable.

Keep the key out of endpoint URLs, prompts, command-line arguments, checked-in
configuration, and saved files. It is not a settings field and is not included
in settings serialization, request bodies, application logs, status details,
audit entries, or explanation reports. Responses reflecting the request's key
are rejected before their content can become a saved explanation. Completion
content is also checked after the same JSON extraction and decoding used by the
explanation validator, including escaped text, code fences, and surrounding prose.

## Rotation and availability

Each request attempt reads the current process environment. Updating that
environment affects subsequent requests without recreating the backend or
restarting the application; a request already in flight uses its original key.
Changing a separate shell's environment does not update an already running
process. Arrange rotation through the process host or restart with the new
environment when the host cannot update it in place.

Authenticated availability checks always probe the server, so cached success
cannot hide revocation and cached failure cannot delay recovery after rotation.
Unauthenticated checks retain the existing 30-second availability cache.
Generation failures clear that cache. Authentication failures return an
unavailable status or no generated text, allowing the existing deterministic
explanation fallback. They do not trigger the JSON-format retry.

## Transport and diagnostics

Authenticated redirects are refused, including redirects within the same
origin. Configure the final endpoint directly. A credential is never forwarded
to a redirected origin, host, port, or scheme. Use the enclave's trusted HTTPS
endpoint for traffic crossing a network; a bearer header over plain HTTP is not
encrypted. No external service or live network is needed to test this feature.

Status and warning messages use fixed diagnostics. They omit remote error
bodies, exception strings, response headers, URLs, and server-provided model
lists, which may contain reflected credentials. Authentication errors identify
the credential setting to check without displaying its value.

This credential authenticates only the explanation backend to its model server.
Application login and authorization, operator approval, and scan/remediation
target credentials remain separate and unchanged.
