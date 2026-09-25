from __future__ import annotations

from difflib import SequenceMatcher
from urllib.parse import urlsplit

from schemas import BrandSpoofResult, DomainIntelResult

BRAND_DOMAINS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "biz", "info", "online", "site"}


def normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    return candidate.strip(". ") or None


def analyze_domain(domain: str | None) -> DomainIntelResult:
    normalized = normalize_domain(domain)
    if not normalized:
        return DomainIntelResult()
    labels = normalized.split(".")
    tld = labels[-1] if labels else ""
    best_brand = None
    best_similarity = 0.0
    for brand, trusted_domain in BRAND_DOMAINS.items():
        trusted_label = trusted_domain.split(".")[0]
        similarity = SequenceMatcher(None, labels[-2] if len(labels) > 1 else normalized, trusted_label).ratio()
        if brand in normalized and normalized != trusted_domain:
            similarity = max(similarity, 0.82)
        if similarity > best_similarity:
            best_brand, best_similarity = brand, similarity
    lookalike = bool(best_brand and best_similarity >= 0.78 and normalized != BRAND_DOMAINS[best_brand])
    facts = []
    risk_signals = []
    if lookalike:
        risk_signals.append("domain_lookalike")
    if tld in SUSPICIOUS_TLDS:
        risk_signals.append("suspicious_tld")
    mx_records = []
    dns_records = {}
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 2.0
        for record_type in ("MX", "TXT"):
            try:
                dns_records[record_type] = resolver.resolve(normalized, record_type)
            except Exception:
                dns_records[record_type] = []
        mx_records = sorted(str(record.exchange).rstrip(".") for record in dns_records.get("MX", []))
        txt_records = [str(record) for record in dns_records.get("TXT", [])]
        if any("v=spf1" in record.lower() for record in txt_records):
            facts.append("spf_record_present")
        try:
            dmarc_records = resolver.resolve(f"_dmarc.{normalized}", "TXT")
            if any("v=dmarc1" in str(record).lower() for record in dmarc_records):
                facts.append("dmarc_record_present")
        except Exception:
            pass
    except ImportError:
        pass
    return DomainIntelResult(
        domain=normalized,
        is_lookalike=lookalike,
        matched_brand=best_brand if lookalike else None,
        similarity=round(best_similarity, 3),
        suspicious_tld=tld in SUSPICIOUS_TLDS,
        mx_records=mx_records,
        reputation_signals=facts + risk_signals,
        risk_signals=risk_signals,
    )


def assess_brand_spoof(display_name: str | None, domain: DomainIntelResult, auth_failure: bool, alignment_failure: bool) -> BrandSpoofResult:
    display_match = bool(display_name and domain.matched_brand and domain.matched_brand in display_name.lower())
    suspected = domain.is_lookalike and (auth_failure or alignment_failure or display_match)
    return BrandSpoofResult(
        suspected=suspected,
        display_name_match=display_match,
        domain_lookalike=domain.is_lookalike,
        authentication_failure=auth_failure,
        alignment_failure=alignment_failure,
        matched_brand=domain.matched_brand,
    )