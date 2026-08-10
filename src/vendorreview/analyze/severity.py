"""Severity, computed from the engagement rather than chosen.

Ask a model for a rating and it anchors on the drama of its own prose: a vividly
described theoretical risk outranks a dull real one, and the ratings move between
runs on identical input. For a tool whose output is a verdict a contract is
signed against, that is disqualifying -- the cut line has to sit still.

Two tables, and both are here so they can be argued with in one place.

**Control gaps** start from the catalog's own rating and move by at most one band
for this particular engagement. The bound matters in both directions:

* Upward, because a tool that escalates every objective to critical when the word
  "regulated" appears produces a review of forty critical findings, which is a
  review of none.
* Downward, and this is the half nobody notices. A requester who wants a signature
  writes "routine" in the criticality box and "internal" in the data box, and if
  the adjustment were unbounded that would move an absent DPA from critical to
  low and the exit code from 1 to 0. One band is enough for the honest case and
  not enough to move anything out of the range where somebody acts on it.

**Not-evidenced objectives are capped**, at :data:`UNKNOWN_CAP`. Silence in a SOC
2 report is not a control failure, and a review that rates "the report does not
mention key management" as critical is a review the vendor's security lead will
take apart line by line -- correctly. It stays in the report, as a question, at a
severity that says how much is actually known.

**Findings** are rated from blast radius and data class, with a capped penalty
for each unverified assumption. The model supplies the two inputs it can ground
in the evidence and the band is derived here, by arithmetic anyone can check and
disagree with specifically.
"""

from __future__ import annotations

from ..models import Attestation, Blast, Criticality, DataClass, Severity, VendorIntake

# The ceiling on anything nothing in the pack settles. MEDIUM rather than LOW:
# an unknown that matters should still appear above the fold in a report that is
# read for four minutes, and the questions section is the deliverable most vendor
# reviews actually need.
UNKNOWN_CAP = Severity.MEDIUM

# How far the engagement may move a catalog rating, in bands, in either
# direction. See the module docstring for why this is bounded downward.
MAX_ADJUSTMENT = 1

# Data outranks reach. A vendor holding health records for two hundred people is
# a worse day than one with a webhook into a system holding the press releases,
# and a scheme that weighted reach first would sort the report the wrong way up.
_DATA_WEIGHT = 1.5

# Each unverified assumption costs a finding some standing: a chain needing four
# unproven things is a worse bet than one needing none.
_ASSUMPTION_PENALTY = 0.75

# ...but the penalty is capped. Uncapped, the model set its own band by choosing
# how many assumptions to list -- six moved everything from critical to medium
# while each individual claim still passed the gate. That is the suppression half
# of prompt injection, and a vendor supplies the documents the model reads.
_MAX_PENALISED = 3

_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (8.0, Severity.CRITICAL),
    (6.0, Severity.HIGH),
    (3.5, Severity.MEDIUM),
    (1.5, Severity.LOW),
)

_BY_RANK: dict[int, Severity] = {s.rank: s for s in Severity}


def _band(rank: int) -> Severity:
    return _BY_RANK[max(Severity.INFO.rank, min(Severity.CRITICAL.rank, rank))]


def engagement_adjustment(intake: VendorIntake) -> int:
    """How far this engagement moves a catalog rating. Always within ±1.

    Deliberately coarse. The inputs are the two things a requesting team can
    answer without guessing -- what data goes in, and what breaks without it --
    and both are declared rather than verified, which is the other reason not to
    let them move a rating far.
    """
    adjustment = 0
    sensitive = intake.max_data_class().rank >= DataClass.PII.rank
    if sensitive or intake.criticality is Criticality.CRITICAL:
        adjustment += 1
    if (
        intake.max_data_class().rank <= DataClass.INTERNAL.rank
        and intake.criticality is Criticality.ROUTINE
    ):
        adjustment -= 1
    return max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, adjustment))


def gap_severity(base: Severity, attestation: Attestation, intake: VendorIntake) -> Severity:
    """Rate one control result. Bounded above and below; capped when unknown."""
    rated = _band(base.rank + engagement_adjustment(intake))
    if attestation.is_attested:
        return rated
    if attestation.is_unknown:
        # A cap, never a floor. An objective the catalog rates LOW does not
        # become MEDIUM because nobody answered it.
        return min(rated, UNKNOWN_CAP)
    return rated


def explain_gap(base: Severity, attestation: Attestation, intake: VendorIntake) -> str:
    """One line stating why an objective scored what it did.

    Printed beside the rating so a reader who thinks it is overblown can name the
    input they disagree with, rather than concluding the tool is noisy.
    """
    parts = [f"catalog rating {base.value}"]
    adjustment = engagement_adjustment(intake)
    if adjustment > 0:
        parts.append(
            f"raised one band for {intake.max_data_class().value} data"
            if intake.max_data_class().rank >= DataClass.PII.rank
            else "raised one band because the vendor is business-critical"
        )
    elif adjustment < 0:
        parts.append("lowered one band: routine criticality, no sensitive data")
    if attestation.is_unknown:
        parts.append(f"capped at {UNKNOWN_CAP.value}: not evidenced either way")
    return ", ".join(parts)


def score(blast: Blast, data: DataClass, assumptions: int = 0) -> float:
    """Raw finding score. Exposed so tests and readers can check the arithmetic."""
    raw = blast.rank + data.rank * _DATA_WEIGHT
    raw -= min(max(0, assumptions), _MAX_PENALISED) * _ASSUMPTION_PENALTY
    return max(0.0, raw)


def rate(blast: Blast, data: DataClass, assumptions: int = 0) -> Severity:
    """Derive a finding's band.

    Public data is capped at LOW however far the blast radius reaches: there is
    no confidentiality consequence to reaching what is already published, and
    letting reach alone push it upward is how a report ends up leading with the
    vendor's marketing site.
    """
    value = score(blast, data, assumptions)
    for threshold, severity in _THRESHOLDS:
        if value >= threshold:
            rating = severity
            break
    else:
        rating = Severity.INFO
    if data is DataClass.PUBLIC and rating.rank > Severity.LOW.rank:
        return Severity.LOW
    return rating


def explain(blast: Blast, data: DataClass, assumptions: int = 0) -> str:
    """One line stating why a finding scored what it did."""
    parts = [f"reaches {blast.value}", f"puts {data.value} data at risk"]
    if assumptions:
        counted = min(assumptions, _MAX_PENALISED)
        note = f"{assumptions} unverified assumption{'s' if assumptions > 1 else ''}"
        if assumptions > counted:
            note += f" ({counted} counted)"
        parts.append(note)
    if data is DataClass.PUBLIC:
        parts.append("capped at low: no confidentiality impact")
    return ", ".join(parts)
