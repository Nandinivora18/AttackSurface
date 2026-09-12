"""
Evidence Engine
==============
Provides the canonical data structures and helpers for evidence-driven finding
generation inside SentinelScan's scanner modules.

Design goals
------------
- Every finding emitted by a detector must be traceable back to specific
  observed HTTP/TLS/DNS data (the "evidence").
- Evidence objects carry enough context to answer:
    "Why was this finding raised?"
    "What was actually observed?"
    "What was expected instead?"
    "How confident is the detector in this observation?"
- FindingBuilder assembles a standard finding dict from one or more Evidence
  objects, ensuring the 'technical_details' field always contains a
  machine-readable evidence chain (JSON).

Usage example
-------------
    from app.scanner.evidence import Evidence, EvidenceType, FindingBuilder

    ev = Evidence(
        detector_id="header.hsts.missing",
        detector_name="HSTS Header Analyzer",
        evidence_type=EvidenceType.HEADER_ABSENT,
        evidence_source="HTTP response headers from https://example.com",
        observed_value="<header not present>",
        expected_value="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        reliability_score=1.0,
        explanation="The Strict-Transport-Security response header was absent. "
                    "Without HSTS, SSL-strip attacks can downgrade connections to HTTP.",
    )

    finding = FindingBuilder(
        category="Transport Security",
        title="Missing HTTP Strict Transport Security (HSTS)",
        severity="high",
        cvss_score=6.5,
        recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ).add_evidence(ev).build()
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# EvidenceType — exhaustive set of observation types SentinelScan can collect
# ---------------------------------------------------------------------------

class EvidenceType(str, Enum):
    """Categorises the kind of observation that forms the basis of evidence."""
    HEADER_PRESENT   = "header_present"    # A security-relevant HTTP header was found
    HEADER_ABSENT    = "header_absent"     # An expected HTTP header was missing
    HEADER_VALUE     = "header_value"      # An HTTP header was present but misconfigured
    TLS_HANDSHAKE    = "tls_handshake"     # Result of a live TLS/SSL handshake
    DNS_RECORD       = "dns_record"        # DNS record query result (A, MX, TXT, SPF, DMARC…)
    HTTP_RESPONSE    = "http_response"     # HTTP status code or body content observation
    CONTENT_MATCH    = "content_match"     # Pattern found in response body / file content
    CVE_MATCH        = "cve_match"         # A known CVE matched a detected technology version
    TECH_FINGERPRINT = "tech_fingerprint"  # Technology detected via multi-signal fingerprinting
    COOKIE_ATTRIBUTE = "cookie_attribute"  # Cookie flag missing or misconfigured


# ---------------------------------------------------------------------------
# Evidence — a single atomic observation produced by a detector
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """
    A single, atomic piece of observed data that supports a security finding.

    Attributes
    ----------
    detector_id       Stable dot-namespaced ID, e.g. "header.hsts.missing"
    detector_name     Human-readable name of the detector
    evidence_type     Category of observation (see EvidenceType enum)
    evidence_source   Where the data came from, e.g. "HTTP GET https://example.com"
    observed_value    What was actually seen (string representation)
    expected_value    What should have been seen instead
    reliability_score Float [0.0, 1.0] — how reliable this observation is
                      (1.0 = direct TLS handshake; 0.6 = content heuristic)
    explanation       Plain-English sentence explaining what was observed and why
                      it matters, written for a security engineer reading the report.
    standards         Optional list of authoritative references, e.g.
                      ["RFC 6797", "OWASP ASVS 9.1.3"]
    """
    detector_id:       str
    detector_name:     str
    evidence_type:     EvidenceType
    evidence_source:   str
    observed_value:    str
    expected_value:    str
    reliability_score: float
    explanation:       str
    standards:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence_type"] = self.evidence_type.value
        return d


# ---------------------------------------------------------------------------
# EvidenceChain — ordered list of Evidence supporting one finding
# ---------------------------------------------------------------------------

@dataclass
class EvidenceChain:
    """
    An ordered sequence of Evidence objects that collectively justify a finding.
    The chain records the full observation → inference → recommendation flow.
    """
    evidence_list: list[Evidence] = field(default_factory=list)

    def add(self, ev: Evidence) -> "EvidenceChain":
        self.evidence_list.append(ev)
        return self

    @property
    def overall_reliability(self) -> float:
        """Mean reliability of all evidence in the chain."""
        if not self.evidence_list:
            return 0.0
        return sum(e.reliability_score for e in self.evidence_list) / len(self.evidence_list)

    @property
    def confidence(self) -> str:
        """
        Derives a 'high' / 'medium' / 'low' confidence string from the mean
        reliability score, matching the Confidence enum in Finding model.
        """
        r = self.overall_reliability
        if r >= 0.8:
            return "high"
        if r >= 0.5:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [e.to_dict() for e in self.evidence_list],
            "overall_reliability": round(self.overall_reliability, 3),
            "confidence": self.confidence,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# FindingBuilder — constructs a canonical finding dict from evidence
# ---------------------------------------------------------------------------

class FindingBuilder:
    """
    Assembles a standard finding dict (compatible with engine.py's all_findings
    list) from one or more Evidence objects.

    The builder pattern ensures:
    - Every finding has an associated evidence chain
    - technical_details always contains the machine-readable JSON evidence chain
    - confidence is derived from evidence reliability, not hand-coded per finding
    - The 'why this severity' and 'why this confidence' questions are answerable
      from the stored evidence

    Example
    -------
        finding = (
            FindingBuilder(
                category="Transport Security",
                title="Missing HSTS Header",
                severity="high",
                cvss_score=6.5,
                recommendation="Add Strict-Transport-Security header.",
            )
            .add_evidence(hsts_evidence)
            .set_references(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"])
            .build()
        )
    """

    def __init__(
        self,
        *,
        category:       str,
        title:          str,
        severity:       str,
        cvss_score:     float | None = None,
        cwe_id:         str | None = None,
        recommendation: str = "",
        description:    str = "",
        problem:        str = "",
        impact:         str = "",
        fix_steps:      list[str] | None = None,
        is_passed_control: bool = False,
    ) -> None:
        self._category        = category
        self._title           = title
        self._severity        = severity
        self._cvss_score      = cvss_score
        self._cwe_id          = cwe_id
        self._recommendation  = recommendation
        self._description     = description
        self._problem         = problem
        self._impact          = impact
        self._fix_steps       = fix_steps or []
        self._is_passed       = is_passed_control
        self._chain           = EvidenceChain()
        self._references: list[str] = []

    def add_evidence(self, ev: Evidence) -> "FindingBuilder":
        self._chain.add(ev)
        return self

    def set_references(self, refs: list[str]) -> "FindingBuilder":
        self._references = refs
        return self

    def build(self) -> dict[str, Any]:
        """
        Build the final finding dict.

        technical_details is populated with the full evidence chain JSON so that
        reports can display the observation → inference → recommendation flow.
        confidence is derived from the evidence chain reliability score.
        evidence (plain text) is a human-readable summary of the first piece of
        evidence for backwards compatibility with existing report rendering.
        """
        chain_dict = self._chain.to_dict()

        # Plain-text evidence summary (first item, for legacy compatibility)
        plain_evidence_parts = []
        for ev in self._chain.evidence_list:
            plain_evidence_parts.append(
                f"[{ev.evidence_type.value.upper()}] {ev.observed_value}"
            )
        plain_evidence = " | ".join(plain_evidence_parts) if plain_evidence_parts else ""

        # Build the description from evidence explanations if not explicitly set
        description = self._description
        if not description and self._chain.evidence_list:
            description = self._chain.evidence_list[0].explanation

        return {
            "category":           self._category,
            "title":              self._title,
            "severity":           self._severity,
            "cvss_score":         self._cvss_score,
            "cwe_id":             self._cwe_id,
            "description":        description,
            "problem":            self._problem,
            "impact":             self._impact,
            "recommendation":     self._recommendation,
            "fix_steps":          self._fix_steps,
            "references":         self._references,
            "evidence":           plain_evidence,
            "confidence":         self._chain.confidence if self._chain.evidence_list else "medium",
            "technical_details":  self._chain.to_json(),
            "is_passed_control":  self._is_passed,
        }


# ---------------------------------------------------------------------------
# Convenience factory — build a single-evidence finding in one call
# ---------------------------------------------------------------------------

def make_finding(
    *,
    detector_id:       str,
    detector_name:     str,
    evidence_type:     EvidenceType,
    evidence_source:   str,
    observed_value:    str,
    expected_value:    str,
    reliability_score: float,
    explanation:       str,
    category:          str,
    title:             str,
    severity:          str,
    cvss_score:        float | None = None,
    cwe_id:            str | None = None,
    recommendation:    str = "",
    description:       str = "",
    problem:           str = "",
    impact:            str = "",
    fix_steps:         list[str] | None = None,
    references:        list[str] | None = None,
    standards:         list[str] | None = None,
    is_passed_control: bool = False,
) -> dict[str, Any]:
    """
    Convenience wrapper: create a single-evidence finding in one call.
    Returns a finding dict ready to be appended to all_findings in engine.py.
    """
    ev = Evidence(
        detector_id=detector_id,
        detector_name=detector_name,
        evidence_type=evidence_type,
        evidence_source=evidence_source,
        observed_value=observed_value,
        expected_value=expected_value,
        reliability_score=reliability_score,
        explanation=explanation,
        standards=standards or [],
    )
    return (
        FindingBuilder(
            category=category,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            recommendation=recommendation,
            description=description,
            problem=problem,
            impact=impact,
            fix_steps=fix_steps,
            is_passed_control=is_passed_control,
        )
        .add_evidence(ev)
        .set_references(references or [])
        .build()
    )
