from __future__ import annotations

from schemas import AuthenticationResults

AUTH_STATUSES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "unavailable",
}


def normalize_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized if normalized in AUTH_STATUSES else "unavailable"


def organizational_domain(value: str | None) -> str | None:
    if not value:
        return None
    labels = value.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


def apply_observed_results(
    authentication: AuthenticationResults,
    from_domain: str | None = None,
    spf: str | None = None,
    dkim: str | None = None,
    dmarc: str | None = None,
) -> AuthenticationResults:
    authentication.spf = normalize_status(spf) or normalize_status(authentication.spf)
    authentication.dkim = normalize_status(dkim) or normalize_status(authentication.dkim)
    authentication.dmarc = normalize_status(dmarc) or normalize_status(authentication.dmarc)

    visible_domain = organizational_domain(from_domain)
    spf_domain = organizational_domain(authentication.spf_domain)
    dkim_domain = organizational_domain(authentication.dkim_domain)
    authentication.aligned = (
        None
        if not visible_domain or not (spf_domain or dkim_domain)
        else any(domain == visible_domain for domain in (spf_domain, dkim_domain) if domain)
    )
    return authentication


def authentication_anomalies(authentication: AuthenticationResults) -> list[str]:
    anomalies = []
    if authentication.spf in {"fail", "softfail", "permerror"}:
        anomalies.append("spf_failure")
    if authentication.dkim in {"fail", "permerror"}:
        anomalies.append("dkim_failure")
    if authentication.dmarc in {"fail", "permerror"}:
        anomalies.append("dmarc_failure")
    if authentication.aligned is False:
        anomalies.append("authentication_alignment_failure")
    return anomalies