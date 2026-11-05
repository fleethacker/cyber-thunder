"""Public, deliberately non-sensitive errors for database management."""


class VulnerabilityError(ValueError):
    """Invalid database input (HTTP 400)."""


class VulnerabilityUnavailable(VulnerabilityError):
    """Required engine, database, or link is unavailable (HTTP 409)."""


class VulnerabilityConflict(VulnerabilityError):
    """Concurrent operation or stale settings revision (HTTP 409)."""


class UpdateStopped(VulnerabilityUnavailable):
    """An in-flight operation was stopped by a control or resource limit."""
