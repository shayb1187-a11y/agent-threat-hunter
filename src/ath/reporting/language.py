"""Calibrated language: how claims are rendered in prose, and a check that they stay honest.

Why this module exists on its own
----------------------------------
Everywhere else in this project, the FACT/INFERENCE/HYPOTHESIS distinction is enforced
as *data*: a `Claim` cannot be constructed without evidence, a model cannot author a
FACT. But a report is prose, and prose is where calibration quietly leaks. It is
entirely possible to take a well-typed HYPOTHESIS and render it as "The attacker
exfiltrated the archive" -- grammatically confident, semantically overclaiming, and
technically still "backed by" a Claim object. The type system does not protect you from
your own sentence templates.

So this module does two things:

1. Defines the phrasing each claim type is rendered with, so a HYPOTHESIS always reads
   as unverified and a FACT always reads as established. The prefix is not decoration;
   it is the only thing standing between "the model suggested this" and "the report
   asserted this".
2. Provides :func:`find_overclaiming`, a lint pass over the *rendered sentence*, not the
   Claim object -- because that is where a careless template edit would actually
   surface. It flags absolute language ("proves", "certainly", "conclusively") appearing
   in anything that is not a FACT, and is run as a test against every claim this project
   currently produces, not just a hypothetical example.

This is not a general-purpose fact-checker. It catches the specific failure mode this
project cares about: a hedge word quietly dropped from a template.
"""

from __future__ import annotations

from ath.agent.claims import Claim, ClaimType

# Prefixes make the claim type visible even if a report section header gets cut off in
# an export or a copy-paste. Redundant with the section heading by design.
CLAIM_PREFIXES: dict[ClaimType, str] = {
    ClaimType.FACT: "Confirmed",
    ClaimType.INFERENCE: "Assessed",
    ClaimType.HYPOTHESIS: "Unconfirmed hypothesis",
}

# Words that assert certainty. Acceptable in FACT prose (which is, definitionally,
# established from telemetry) but never acceptable attached to an INFERENCE or a
# HYPOTHESIS -- an inference is a probabilistic read of evidence, and a hypothesis is
# explicitly unverified. Case-insensitive substring match on the rendered sentence.
OVERCLAIMING_TERMS: tuple[str, ...] = (
    "proves", "proof that", "certainly", "definitely", "undeniably",
    "conclusively", "without doubt", "guaranteed", "confirms that",
)

# Words that undersell a FACT. A confirmed, telemetry-backed statement should not read
# as tentative -- if it needs a hedge, it was not actually a FACT.
UNDERCLAIMING_TERMS: tuple[str, ...] = (
    "might have", "may have", "possibly", "perhaps", "it is thought",
)


def render_claim(claim: Claim) -> str:
    """Render one claim as a calibrated sentence.

    The prefix carries the epistemic weight; the statement (already written by a
    detector, a specialist, or a verified model claim) supplies the content. Evidence
    ids and confidence are appended so a reader never has to take the sentence on
    faith -- they can go and look at exactly what it rests on.
    """
    prefix = CLAIM_PREFIXES[claim.claim_type]
    sentence = f"{prefix}: {claim.statement}"
    if claim.confidence is not None:
        sentence += f" (confidence {claim.confidence:.2f})"
    return sentence


def find_overclaiming(claim: Claim) -> list[str]:
    """Return any overclaiming terms found in a non-FACT claim's own statement.

    FACTs are exempt: they come from telemetry or deterministic detection, so certainty
    language is earned. INFERENCE and HYPOTHESIS claims must not carry it -- if a
    template writer wants to say "conclusively", that is the tell that the claim should
    have been a FACT, or should not have been written that way at all.
    """
    if claim.claim_type is ClaimType.FACT:
        return []
    lowered = claim.statement.lower()
    return [term for term in OVERCLAIMING_TERMS if term in lowered]


def find_underclaiming(claim: Claim) -> list[str]:
    """Return any hedge terms found in a FACT claim's own statement.

    A claim that needs "might have" or "possibly" to be readable was not, in fact,
    directly supported by telemetry -- it should have been an INFERENCE or a
    HYPOTHESIS. This is the inverse check: it catches a FACT that was actually written
    like a guess.
    """
    if claim.claim_type is not ClaimType.FACT:
        return []
    lowered = claim.statement.lower()
    return [term for term in UNDERCLAIMING_TERMS if term in lowered]


def audit_calibration(claims: list[Claim]) -> dict[str, list[str]]:
    """Run the overclaiming/underclaiming lint across a batch of claims.

    Returns:
        A mapping of ``claim.statement -> [issues]`` for any claim that failed either
        check. An empty dict means every claim passed. Used both as a build-time sanity
        check when assembling a report and as a regression test against the claims this
        project actually produces.
    """
    issues: dict[str, list[str]] = {}
    for claim in claims:
        found = find_overclaiming(claim) + find_underclaiming(claim)
        if found:
            issues[claim.statement] = found
    return issues
