"""Human-readable attribution alongside the immutable canonical audit actor."""
from cyberthunder.findings.review import principal_from_evidence

UNVERIFIED = "Unverified (self-asserted)"


def attribution(actor, evidence=None, *, human=True):
    try:
        principal = principal_from_evidence(actor, evidence, human=human)
    except (ValueError, TypeError):
        return {"actor": actor, "display_name": actor or "Not recorded", "verified": False,
                "label": UNVERIFIED, "text": f"{actor or 'Not recorded'}; {UNVERIFIED}"}
    label = f"Verified at decision ({principal.via}); iss={principal.issuer}; sub={principal.subject}"
    return {"actor": actor, "display_name": principal.display_name, "verified": True,
            "issuer": principal.issuer, "subject": principal.subject, "label": label,
            "text": f"{principal.display_name}; {label}; audit actor={actor}"}
