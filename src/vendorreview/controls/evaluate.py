"""Applicability, results and the decision. All computed, none of it reasoned.

This module is why vendorreview can be trusted with a verdict. Everything here is
a pure function of the declared engagement and the extracted evidence: which
objectives are in scope, what the evidence settles about each, what is therefore
outstanding, and what the review decides. Run it twice on the same pack and you
get the same answer, and if you disagree with the answer you can point at the
line that produced it.

The language model never touches any of this. It contributes chains and residual
risk on top, which is the part a rule genuinely cannot do -- but the verdict
somebody signs against is arithmetic over what the vendor supplied.

Three distinctions carry most of the weight:

**Applicable is not the same as failed.** An objective that does not apply is
absent from the review entirely rather than present and marked N/A. A review that
lists forty irrelevant objectives to demonstrate thoroughness is a review that
gets skimmed, and the four that mattered are in the middle of it.

**Absent is not the same as not evidenced.** This is the whole tool. "The vendor
told us there is no SCIM" is a gap. "Nothing in the pack mentions SCIM" is a
question. They are stated differently, rated differently, and only the first can
block. Merging them is the top false-positive class in third-party review, and
one false accusation is enough for a vendor's security lead to stop reading
anything this produces.

**Blocking is not the same as severe.** A HIGH gap can usually be carried as a
condition with a date. A blocking gap cannot, because signing would mean an
obligation is already being breached -- sending personal data to a processor with
no agreement in place, for instance. Severity says how bad; blocking says whether
it can wait.
"""

from __future__ import annotations

from ..analyze.severity import explain_gap, gap_severity
from ..models import (
    Attestation,
    Confidence,
    ControlGap,
    Decision,
    Question,
    Severity,
    VendorIntake,
)
from .catalog import BUILTIN_CONTROLS, Control, combine

# The number of blank intake questions listed individually. Every blank is a real
# gap in the form, but a review that opens with thirty is read as a rejection of
# the requester rather than a list they can work through -- and the ones that
# matter are already surfaced as blocking questions. The rest are counted, so
# nothing is hidden.
_MAX_LISTED_BLANKS = 8


def applicable_controls(intake: VendorIntake) -> list[Control]:
    """Objectives in scope for this engagement, in catalog order.

    A predicate that raises is treated as not applicable and is not allowed to
    take the review down with it: one malformed answer should cost one objective,
    not the whole assessment.
    """
    in_scope: list[Control] = []
    for entry in BUILTIN_CONTROLS:
        try:
            if entry.applies(intake):
                in_scope.append(entry)
        except (AttributeError, TypeError, ValueError):
            continue
    return in_scope


def _sources(entry: Control, intake: VendorIntake) -> tuple[Attestation, str | None]:
    try:
        return combine(entry.evidence(intake))
    except (AttributeError, TypeError, ValueError):
        return Attestation.NOT_EVIDENCED, None


def evaluate(
    intake: VendorIntake,
) -> tuple[list[ControlGap], list[Question], list[str], list[str], list[str]]:
    """Evaluate every applicable objective.

    Returns (gaps, questions, applicable ids, attested ids, conflicts). The gaps
    list holds both the absent and the not-evidenced results; they are separated
    for display by :meth:`~vendorreview.models.Review.absent_gaps` and
    :meth:`~vendorreview.models.Review.unevidenced`, and they are kept in one
    list here because they are the same computation and splitting them earlier
    invites a caller to handle one and forget the other.
    """
    gaps: list[ControlGap] = []
    questions: list[Question] = []
    applicable: list[str] = []
    attested: list[str] = []
    conflicts: list[str] = []

    for entry in applicable_controls(intake):
        applicable.append(entry.id)
        state, disagreement = _sources(entry, intake)
        if disagreement:
            conflicts.append(f"{entry.id} · {entry.title}: {disagreement}")

        if state.is_attested:
            attested.append(entry.id)
            continue

        severity = gap_severity(entry.severity, state, intake)
        gaps.append(
            ControlGap(
                control_id=entry.id,
                title=entry.title,
                attestation=state,
                why_applicable=f"Applies because {entry.why_template}.",
                what_is_missing=entry.objective,
                severity=severity,
                severity_reason=explain_gap(entry.severity, state, intake),
                frameworks=entry.frameworks,
                evidence_facts=entry.evidence_facts,
                condition=entry.condition,
                question=entry.question,
                # Only an established absence can block. An unknown cannot,
                # because nobody has established that anything is wrong -- see
                # the module docstring.
                blocking=entry.blocking and state.is_absent,
            )
        )

        if state.is_unknown:
            # Materiality is the catalog's own rating, and neither of the two
            # nearby numbers will do.
            #
            # Not `severity` above: that is capped at UNKNOWN_CAP because nothing
            # is evidenced, and the cap sits a band below the threshold, so
            # reading it here made it arithmetically impossible for an unknown to
            # block anything. The cap exists to stop unknowns being overstated in
            # the report; it had quietly disabled the one mechanism that turns an
            # unknown into more-information-needed.
            #
            # Not the engagement-adjusted rating either. That raises every
            # objective a band for a vendor touching personal data, which is
            # right for how an item is *rated* and wrong for whether it holds the
            # decision: it made every MEDIUM objective blocking, and a review
            # that opens with twenty-four questions gets two of them answered.
            # Whether an objective is material is a property of the objective and
            # is the same question for every vendor.
            questions.append(
                Question(
                    text=entry.question,
                    why_it_matters=(
                        f"{entry.id} · {entry.title}. Applies because {entry.why_template}. "
                        "Nothing in the pack settles it either way."
                    ),
                    # An objective nobody has answered, on something that would
                    # change the outcome, is exactly the case where guessing in
                    # either direction is worse than asking. So it holds the
                    # decision rather than resolving it.
                    blocks_decision=entry.blocking or entry.severity.rank >= Severity.HIGH.rank,
                )
            )

    gaps.sort(
        key=lambda g: (not g.blocking, not g.attestation.is_absent, -g.severity.rank, g.control_id)
    )
    questions.sort(key=lambda q: (not q.blocks_decision, q.text))
    return gaps, questions, applicable, attested, conflicts


def decide(
    gaps: list[ControlGap],
    questions: list[Question],
    finding_severities: list[Severity],
) -> tuple[Decision, str]:
    """Derive the decision and the sentence explaining it.

    Deliberately not the model's call. A vendor review's output is a verdict
    somebody signs a contract against, and a verdict that shifts between runs on
    the same evidence is worth nothing -- to procurement, who cannot plan against
    it, or to the security team, who cannot defend it in a year's time.

    The order of the checks is the policy, and it is short enough to argue with:

    1. A blocking absent objective means this cannot be signed as described.
    2. An unanswered question that would change the outcome means we ask rather
       than guess. Guessing generously waves through real exposure; guessing
       harshly accuses a vendor of something nobody asked them about.
    3. Anything else outstanding becomes conditions.
    4. Otherwise, approve.
    """
    blocking = [g for g in gaps if g.blocking]
    if blocking:
        names = ", ".join(g.control_id for g in blocking[:3])
        return (
            Decision.DO_NOT_PROCEED,
            f"{len(blocking)} objective(s) ({names}) were answered no and cannot be carried "
            "as conditions with a date: signing would mean an obligation is already being "
            "breached. This is a statement about the engagement as described, not a "
            "judgement on the vendor — changing how they will be used may well clear it.",
        )

    blockers = [q for q in questions if q.blocks_decision]
    if blockers:
        return (
            Decision.MORE_INFORMATION_NEEDED,
            f"{len(blockers)} question(s) material to the outcome are unanswered by the "
            "evidence supplied. This is not a rejection and it is not a finding against "
            "the vendor — nothing in the pack settles these either way, and the honest "
            "response is to send the questions rather than to guess. The list is below.",
        )

    outstanding = len([g for g in gaps if g.attestation.is_absent]) + sum(
        1 for s in finding_severities if s.rank >= Severity.MEDIUM.rank
    )
    if outstanding:
        worst = max(
            [g.severity for g in gaps if g.attestation.is_absent]
            + [max(finding_severities, default=Severity.INFO)],
            default=Severity.INFO,
        )
        return (
            Decision.APPROVE_WITH_CONDITIONS,
            f"{outstanding} item(s) to settle before signature, the most serious rated "
            f"{worst.value}. The engagement is sound enough to proceed provided the "
            "conditions below are met on the timeline agreed with the security team.",
        )

    return (
        Decision.APPROVE,
        "Every applicable objective is evidenced by the pack supplied, and no additional "
        "risk was identified. This rests on the accuracy of the intake and on documents "
        "the vendor wrote about themselves; a material change to how the vendor will be "
        "used warrants a re-review.",
    )


def assess_confidence(intake: VendorIntake, dropped_findings: int = 0) -> tuple[Confidence, str]:
    """How much the review itself should be trusted.

    Surfaced because a review built on a third of a form and no documents, and
    one built on a complete intake plus a current Type II, should not look
    identical on the page. The reader is entitled to know which they are holding,
    and in third-party review that difference is most of the story.
    """
    answered = len(intake.facts)
    total = answered + len(intake.unanswered)
    ratio = answered / total if total else 0.0
    documents = intake.evidence.supplied()

    reasons: list[str] = []
    if ratio < 0.6:
        reasons.append(f"only {answered} of {total} intake questions were answered")
    if not documents:
        reasons.append("no vendor evidence was supplied, so every objective rests on the form")
    elif len(documents) == 1:
        reasons.append(f"one evidence document was supplied ({documents[0]})")
    if intake.evidence.unreadable:
        reasons.append(f"{len(intake.evidence.unreadable)} supplied document(s) could not be read")
    if dropped_findings:
        reasons.append(f"{dropped_findings} proposed finding(s) failed validation")

    if ratio < 0.5 or not documents or dropped_findings > 2:
        level = Confidence.LOW
    elif ratio < 0.8 or len(documents) < 2 or intake.evidence.unreadable:
        level = Confidence.MEDIUM
    else:
        level = Confidence.HIGH

    if not reasons:
        return (
            level,
            "The intake was substantially complete and more than one piece of vendor "
            "evidence was read.",
        )
    return level, "Based on: " + "; ".join(reasons) + "."


def unanswered_questions(intake: VendorIntake) -> list[Question]:
    """Turn blank intake fields into questions.

    Separate from the objective evaluation because these are gaps in *your* form
    rather than in the vendor's evidence. A requester who left a field blank has
    not done anything wrong; they have left something for somebody to go and find
    out, and it is usually a five-minute email.
    """
    # An answer the parser could not place comes first. It is the one item here a
    # requester can settle in a sentence, and until they do, every objective that
    # depends on it never fired at all. Marked untrusted because it quotes what
    # they typed, where the blanks below quote the form.
    questions = [
        Question(
            text=note,
            why_it_matters="An answer was given but could not be mapped onto the taxonomy.",
            blocks_decision=False,
            trusted=False,
        )
        for note in intake.vocabulary_notes[:_MAX_LISTED_BLANKS]
    ]

    listed = intake.unanswered[:_MAX_LISTED_BLANKS]
    questions += [
        Question(
            text=text,
            why_it_matters="Left blank on the intake form.",
            blocks_decision=False,
        )
        for text in listed
    ]
    remaining = len(intake.unanswered) - len(listed)
    if remaining > 0:
        questions.append(
            Question(
                text=f"{remaining} further intake question(s) were left blank.",
                why_it_matters=(
                    "Not listed individually to keep this section readable. Run "
                    "`vendorreview questions` for the full form."
                ),
                blocks_decision=False,
            )
        )
    return questions
