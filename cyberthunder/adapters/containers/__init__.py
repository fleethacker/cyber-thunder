"""Container host adapter: docker/podman inspect checks (CIS Docker Benchmark), ATT&CK-cited hunt, Trivy image
CVEs, stop-and-disable with rollback, re-create runbooks, simulated docker host."""
from .adapter import ContainersAdapter

__all__ = ["ContainersAdapter"]
