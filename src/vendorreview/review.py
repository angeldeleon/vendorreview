"""Assembles one review from the deterministic and reasoned halves.

Kept separate from both so the ordering is visible in one place: objectives are
evaluated first, the decision is computed from their results, and the model runs
afterwards over a picture that is already settled. The reasoning layer can add
findings and raise the severity floor; it cannot overturn a blocking result or
talk the decision into an approval.

That ordering is the point. A vendor review's verdict has to be defensible a year
later to somebody who was not in the room and is now looking at a breach
notification, and "the model decided" is not a defence.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from .analyze.engine import Analyzer
from .controls.evaluate import assess_confidence, decide, evaluate, unanswered_questions
from .models import Note, Question, Review, Severity, VendorIntake


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check(intake: VendorIntake, *, tool_version: str = "") -> Review:
    """The deterministic half: applicability, evidence results, questions, decision.

    No API key, no network. Exposed as its own command because a security team
    should be able to see what the rules concluded before deciding whether to send
    a vendor's SOC 2 to a third-party API — and because it is genuinely useful on
    its own for teams that would rather not send one at all.
    """
    gaps, control_questions, applicable, attested, conflicts = evaluate(intake)
    questions = control_questions + unanswered_questions(intake)
    decision, rationale = decide(gaps, questions, [])
    confidence, confidence_reason = assess_confidence(intake)

    review = Review(
        intake=intake,
        decision=decision,
        decision_rationale=rationale,
        confidence=confidence,
        gaps=gaps,
        questions=questions,
        applicable_controls=applicable,
        attested_controls=attested,
        conflicts=conflicts,
        tool_version=tool_version,
        reviewed_at=_now(),
    )
    review.notes.append(Note(confidence_reason))
    _evidence_notes(review)
    return review


def full(intake: VendorIntake, analyzer: Analyzer, *, tool_version: str = "") -> Review:
    """The complete review: objective evaluation plus reasoned findings.

    The decision is recomputed after the model returns, because a finding rated
    HIGH is a reason to attach conditions even when every objective was evidenced.
    It is recomputed by the same function on the same rules — not adjusted by the
    model, which never sees the decision at all.
    """
    review = check(intake, tool_version=tool_version)

    findings, model_questions, rejections, model_id = analyzer.analyze(
        intake, review.gaps, review.applicable_controls
    )
    review.findings = findings
    review.model_id = model_id
    review.dropped_findings = len(rejections)
    review.rejections = [(r.title, r.reason) for r in rejections]
    review.questions = _merge_questions(review.questions, model_questions)

    decision, rationale = decide(review.gaps, review.questions, [f.severity for f in findings])
    review.decision = decision
    review.decision_rationale = rationale

    confidence, confidence_reason = assess_confidence(intake, dropped_findings=len(rejections))
    review.confidence = confidence
    review.notes = [Note(confidence_reason)]
    _evidence_notes(review)

    if rejections:
        # Surfaced rather than swallowed. A review where several proposed
        # findings failed validation is one whose survivors deserve more
        # scepticism, and the reader should be the one deciding that.
        review.notes.append(
            Note(
                f"{len(rejections)} proposed finding(s) were rejected before reaching this "
                "review, for citing facts or control identifiers that do not exist."
            )
        )
    if not findings:
        review.notes.append(
            Note(
                "The analysis added no findings beyond the objective evaluation. For a "
                "thin pack that is a reasonable outcome; read the questions above rather "
                "than reading this as a clean result."
            )
        )
    return review


def _evidence_notes(review: Review) -> None:
    """Record what could not be read, and what that costs the review.

    Written here rather than in the evidence loader because it is a statement
    about the review as a whole. An unreadable SOC 2 does not make anything
    false; it makes a set of objectives unknown, and the reader needs to be told
    which document that was.
    """
    evidence = review.intake.evidence
    for entry in evidence.unreadable[:6]:
        # The entry goes in `quoted`, not in the sentence. It names the file and
        # says why it could not be read, and for a questionnaire response file
        # that reason is the YAML parser's account of the vendor's own file --
        # so it is text the vendor wrote, reaching a Markdown document that gets
        # forwarded back to them.
        review.notes.append(
            Note(
                "A supplied document could not be read. Everything it would have settled "
                "is recorded as not evidenced rather than as absent:",
                quoted=entry,
            )
        )
    if review.conflicts:
        review.notes.append(
            Note(
                f"{len(review.conflicts)} objective(s) have sources that disagree with "
                "each other. Listed below — a questionnaire answered by a sales engineer "
                "and a report signed by an auditor are not equally considered claims."
            )
        )


def _merge_questions(existing: list[Question], incoming: list[Question]) -> list[Question]:
    """Add questions from the analysis layer, skipping anything already asked.

    Matched on a normalised prefix rather than exact text, because the model will
    reliably reword a question the objectives already asked, and a review that
    asks the same thing twice in different words reads as though nobody proof-read
    it before sending it to a vendor.

    Nothing arriving here blocks. A blocking question is what turns an approval
    into more-information-needed and what makes the exit code 1, so it is part of
    the verdict — and the verdict is computed from the evidence, which is the
    claim this tool rests on. This is the boundary where analysis-layer questions
    enter a review, so it is where that is enforced rather than in the code that
    happens to produce them today.
    """
    seen = {q.text.casefold()[:60] for q in existing}
    merged = list(existing)
    for question in incoming:
        key = question.text.casefold()[:60]
        if key in seen:
            continue
        seen.add(key)
        merged.append(replace(question, blocks_decision=False))
    merged.sort(key=lambda q: (not q.blocks_decision, q.text))
    return merged


def exit_code(review: Review, fail_on: str) -> int:
    """Map a review onto the exit-code contract.

    0 clean, 1 findings at or above the threshold, 2 could-not-run. A blocking
    result or an unanswered material question is always at least 1 regardless of
    severity: the whole point of blocking is that it does not pass, and the whole
    point of a material unknown is that nobody should sign against it yet.
    """
    if review.blocking_gaps() or review.blocking_questions():
        return 1
    threshold = Severity(fail_on)
    worst = review.worst_severity()
    return 1 if worst is not None and worst.rank >= threshold.rank else 0
