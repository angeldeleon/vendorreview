"""The catalog, its applicability, and the tri-state that runs through it."""

from __future__ import annotations

import re

import pytest

from conftest import document, intake
from vendorreview.controls.catalog import BUILTIN_CONTROLS, CONTROLS_BY_ID, combine
from vendorreview.controls.evaluate import (
    applicable_controls,
    assess_confidence,
    decide,
    evaluate,
    unanswered_questions,
)
from vendorreview.evidence.responses import KNOWN_KEYS, parse_responses
from vendorreview.models import Attestation, Confidence, Decision, EvidenceSet, Severity

# The published identifier formats. Regex-checked here and again in CI, because
# these reach GRC trackers and renewal conversations where somebody looks them
# up, and a malformed identifier is worse than none.
FRAMEWORK_PATTERNS = {
    "NIST CSF 2.0": re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}$"),
    "ISO 27001:2022": re.compile(r"^A\.[5-8]\.\d{1,2}$"),
    "SOC 2 TSC": re.compile(r"^(CC[1-9]\.\d|A\d\.\d|C\d\.\d|P\d\.\d|PI\d\.\d)$"),
    "CIS v8": re.compile(r"^Control (1[0-8]|[1-9])$"),
}


# --------------------------------------------------------------------------
# Catalog shape
# --------------------------------------------------------------------------


def test_control_ids_are_unique() -> None:
    ids = [c.id for c in BUILTIN_CONTROLS]
    assert len(ids) == len(set(ids))
    assert len(CONTROLS_BY_ID) == len(BUILTIN_CONTROLS)


@pytest.mark.parametrize("control", BUILTIN_CONTROLS, ids=lambda c: c.id)
def test_every_control_maps_to_all_four_frameworks(control) -> None:
    assert {f.name for f in control.frameworks} == set(FRAMEWORK_PATTERNS)


@pytest.mark.parametrize("control", BUILTIN_CONTROLS, ids=lambda c: c.id)
def test_every_framework_identifier_is_well_formed(control) -> None:
    for reference in control.frameworks:
        pattern = FRAMEWORK_PATTERNS[reference.name]
        assert pattern.match(reference.identifier), (
            f"{control.id}: malformed {reference.name} identifier {reference.identifier!r}"
        )
        assert reference.title, f"{control.id}: {reference.identifier} has no title"


@pytest.mark.parametrize("control", BUILTIN_CONTROLS, ids=lambda c: c.id)
def test_every_control_has_a_question_and_an_applicability_sentence(control) -> None:
    # The question is the deliverable most vendor reviews actually need, so an
    # objective without one has nothing to say when it is unevidenced -- which is
    # the state it will be in most of the time.
    assert control.question
    assert control.why_template
    assert control.objective


@pytest.mark.parametrize("control", BUILTIN_CONTROLS, ids=lambda c: c.id)
def test_a_blocking_control_states_a_condition(control) -> None:
    # Blocking means the engagement cannot proceed. A blocking objective with no
    # condition tells the reader they are stuck and not how to get unstuck.
    if control.blocking:
        assert control.condition


def test_response_keys_referenced_by_the_catalog_exist() -> None:
    # A typo in a response key is silent: the objective simply never gets an
    # answer, and the review reports "not evidenced" against a vendor who
    # answered the question.
    import inspect

    source = inspect.getsource(__import__("vendorreview.controls.catalog", fromlist=["catalog"]))
    for key in re.findall(r'_response\(i, "([a-z0-9_]+)"\)', source):
        assert key in KNOWN_KEYS, f"catalog references unknown response key {key!r}"


# --------------------------------------------------------------------------
# combine
# --------------------------------------------------------------------------


def test_attested_beats_absent_beats_silence() -> None:
    assert combine((("a", Attestation.ATTESTED), ("b", Attestation.ABSENT)))[0] is (
        Attestation.ATTESTED
    )
    assert combine((("a", Attestation.ABSENT), ("b", Attestation.NOT_EVIDENCED)))[0] is (
        Attestation.ABSENT
    )
    assert combine((("a", Attestation.NOT_EVIDENCED),))[0] is Attestation.NOT_EVIDENCED
    assert combine(())[0] is Attestation.NOT_EVIDENCED


def test_a_disagreement_is_reported_rather_than_discarded() -> None:
    _, conflict = combine((("soc2", Attestation.ATTESTED), ("questionnaire", Attestation.ABSENT)))
    assert conflict is not None
    assert "soc2" in conflict and "questionnaire" in conflict


def test_agreement_reports_no_conflict() -> None:
    assert combine((("a", Attestation.ATTESTED), ("b", Attestation.ATTESTED)))[1] is None


# --------------------------------------------------------------------------
# Tri-state. The top false-positive class in third-party review.
# --------------------------------------------------------------------------


def test_a_blank_answer_is_a_question_not_a_gap() -> None:
    parsed = intake()  # scim_available left blank
    gaps, questions, _, _, _ = evaluate(parsed)
    scim = [g for g in gaps if g.control_id == "IAM-02"]
    assert scim and scim[0].attestation is Attestation.NOT_EVIDENCED
    assert not scim[0].blocking
    assert any("SCIM" in q.text for q in questions)


def test_an_explicit_no_is_a_gap() -> None:
    parsed = intake(scim_available="no")
    gaps, _, _, _, _ = evaluate(parsed)
    scim = [g for g in gaps if g.control_id == "IAM-02"]
    assert scim and scim[0].attestation is Attestation.ABSENT


def test_silence_in_a_document_is_never_read_as_a_no() -> None:
    # A SOC 2 scoped to Security says nothing about key management because it did
    # not have to. Reading that silence as a control failure is the fastest way
    # to have a review disputed and then ignored.
    parsed = intake()
    parsed.evidence = EvidenceSet(responses=parse_responses({"sso_saml_oidc": "yes"}))
    gaps, _, _, _, _ = evaluate(parsed)
    keys = [g for g in gaps if g.control_id == "CRY-03"]
    assert keys and keys[0].attestation is Attestation.NOT_EVIDENCED


def test_a_partial_answer_is_not_evidenced_in_the_review_too() -> None:
    parsed = intake()
    parsed.evidence = EvidenceSet(responses=parse_responses({"encryption_at_rest": "partial"}))
    gaps, _, _, _, _ = evaluate(parsed)
    rest = [g for g in gaps if g.control_id == "CRY-02"]
    assert rest and rest[0].attestation is Attestation.NOT_EVIDENCED


def test_only_an_absent_result_can_block() -> None:
    unknown = intake()  # dpa_status blank
    blocking_unknown = [g for g in evaluate(unknown)[0] if g.control_id == "DAT-05"]
    assert blocking_unknown and not blocking_unknown[0].blocking

    absent = intake(dpa_status="no")
    blocking_absent = [g for g in evaluate(absent)[0] if g.control_id == "DAT-05"]
    assert blocking_absent and blocking_absent[0].blocking


def test_an_unevidenced_gap_carries_the_question_and_an_absent_one_the_condition() -> None:
    unknown = next(g for g in evaluate(intake())[0] if g.control_id == "DAT-05")
    absent = next(g for g in evaluate(intake(dpa_status="no"))[0] if g.control_id == "DAT-05")
    assert unknown.question and absent.condition
    assert unknown.question != absent.condition


# --------------------------------------------------------------------------
# Applicability
# --------------------------------------------------------------------------


def test_tenant_isolation_does_not_fire_on_self_hosted_software() -> None:
    saas = {c.id for c in applicable_controls(intake(hosting="saas"))}
    self_hosted = {c.id for c in applicable_controls(intake(hosting="self_hosted"))}
    assert "TEN-01" in saas
    assert "TEN-01" not in self_hosted


def test_self_hosted_software_pulls_in_the_exposure_objective() -> None:
    assert "NET-01" in {c.id for c in applicable_controls(intake(hosting="self_hosted"))}


def test_privacy_objectives_do_not_fire_without_personal_data() -> None:
    ids = {c.id for c in applicable_controls(intake(data_classes=["internal"]))}
    assert "DAT-05" not in ids
    assert "SUB-02" not in ids


def test_soc2_objectives_only_fire_when_a_report_was_supplied() -> None:
    without = {c.id for c in applicable_controls(intake())}
    assert "ATT-03" not in without

    with_report = intake()
    from vendorreview.models import Soc2Report

    with_report.evidence = EvidenceSet(soc2=Soc2Report(source_name="r.txt"))
    assert "ATT-03" in {c.id for c in applicable_controls(with_report)}


def test_scope_creep_does_not_apply_every_objective_to_every_vendor() -> None:
    minimal = intake(data_classes=["public"], hosting="self_hosted", integrations=["none"])
    assert len(applicable_controls(minimal)) < len(BUILTIN_CONTROLS)


def test_a_predicate_that_raises_costs_one_objective_not_the_review() -> None:
    parsed = intake()
    parsed.data_classes = None  # type: ignore[assignment]
    # Several predicates iterate data_classes; the rest must still evaluate.
    assert applicable_controls(parsed)


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------


def test_a_blocking_absence_means_do_not_proceed() -> None:
    gaps, questions, _, _, _ = evaluate(intake(dpa_status="no"))
    decision, rationale = decide(gaps, questions, [])
    assert decision is Decision.DO_NOT_PROCEED
    assert "DAT-05" in rationale


def test_a_material_unknown_means_more_information_needed() -> None:
    gaps, questions, _, _, _ = evaluate(intake())
    decision, _ = decide(gaps, questions, [])
    assert decision is Decision.MORE_INFORMATION_NEEDED


def test_the_decision_is_reproducible() -> None:
    parsed = intake(dpa_status="no")
    gaps, questions, _, _, _ = evaluate(parsed)
    assert decide(gaps, questions, []) == decide(gaps, questions, [])


def test_findings_can_attach_conditions_but_only_at_medium_or_worse() -> None:
    assert decide([], [], [Severity.LOW])[0] is Decision.APPROVE
    assert decide([], [], [Severity.MEDIUM])[0] is Decision.APPROVE_WITH_CONDITIONS


def test_nothing_outstanding_is_an_approval() -> None:
    decision, rationale = decide([], [], [])
    assert decision is Decision.APPROVE
    assert "re-review" in rationale


def test_an_unevidenced_gap_alone_does_not_produce_conditions() -> None:
    # Conditions come from established absences. Listing an unknown as a
    # condition is the same false accusation in a different section.
    gaps, _, _, _, _ = evaluate(intake())
    decision, _ = decide(gaps, [], [])
    assert decision is Decision.APPROVE


# --------------------------------------------------------------------------
# Confidence and blank-field questions
# --------------------------------------------------------------------------


def test_confidence_is_low_without_evidence() -> None:
    level, reason = assess_confidence(intake())
    assert level is Confidence.LOW
    assert "no vendor evidence" in reason


def test_confidence_notes_an_unreadable_document() -> None:
    parsed = intake()
    parsed.evidence = EvidenceSet(responses=parse_responses({"mfa_enforced": "yes"}))
    parsed.evidence.unreadable.append("SOC 2 (r.txt): not a regular file")
    _, reason = assess_confidence(parsed)
    assert "could not be read" in reason


def test_blank_intake_questions_are_listed_and_then_counted() -> None:
    questions = unanswered_questions(intake())
    assert questions
    assert any("further intake question" in q.text for q in questions)
    assert not any(q.blocks_decision for q in questions)


def test_a_vocabulary_note_is_marked_untrusted() -> None:
    parsed = intake(data_classes=["biometric templates"])
    notes = [q for q in unanswered_questions(parsed) if not q.trusted]
    assert notes


# --------------------------------------------------------------------------
# What a document can and cannot settle
# --------------------------------------------------------------------------


def test_a_scope_statement_is_not_evidence_that_it_covers_the_service() -> None:
    """The classic miss in ISO diligence, and it was in the tool that catches it.

    ATT-07 read ``iso.scope_stated``, which is ATTESTED whenever a certificate
    carries a scope line at all. So a certificate scoped to reception services at
    a head office attested that the certified scope covered the SaaS product
    being bought, and the objective disappeared from the review into the attested
    count.
    """
    from datetime import date

    from vendorreview.evidence.iso27001 import parse_iso

    certificate = parse_iso(
        document(
            "ISO/IEC 27001:2022 Certificate\n"
            "Scope: The provision of facilities management and reception services\n"
            "at the Dublin head office.\n"
            "Expiry: 2029-01-01\n"
        ),
        as_of=date(2026, 6, 1),
    )
    assert certificate.scope_stated is Attestation.ATTESTED  # the statement exists

    parsed = intake()
    parsed.evidence = EvidenceSet(iso=certificate)
    gaps, questions, _, attested, _ = evaluate(parsed)
    assert "ATT-07" not in attested
    gap = next(g for g in gaps if g.control_id == "ATT-07")
    assert gap.attestation is Attestation.NOT_EVIDENCED
    assert any(g.blocks_decision and "certified scope" in g.text for g in questions)


def test_the_vendor_can_settle_the_certified_scope() -> None:
    from datetime import date

    from vendorreview.evidence.iso27001 import parse_iso

    parsed = intake()
    parsed.evidence = EvidenceSet(
        iso=parse_iso(
            document("ISO/IEC 27001:2022\nScope: the platform.\nExpiry: 2029-01-01"),
            as_of=date(2026, 6, 1),
        ),
        responses=parse_responses({"iso_scope_covers_service": "yes"}),
    )
    assert "ATT-07" in evaluate(parsed)[3]


def test_an_unanswered_stage_does_not_attest_the_review_was_early() -> None:
    """A display default is not an answer.

    The parser applies "evaluating" when the field is blank and records the
    question as unanswered. GOV-02 read that default and attested that the review
    happened before commitment, against a form on which nobody said so -- silence
    recorded as evidence, in the direction that flatters rather than accuses.
    """
    blank = intake(stage=None)
    assert "GOV-02" not in evaluate(blank)[3]
    gap = next(g for g in evaluate(blank)[0] if g.control_id == "GOV-02")
    assert gap.attestation is Attestation.NOT_EVIDENCED

    stated = intake(stage="negotiating")
    assert "GOV-02" in evaluate(stated)[3]

    signed = intake(stage="in_use")
    assert next(g for g in evaluate(signed)[0] if g.control_id == "GOV-02").attestation.is_absent


def test_a_gap_records_why_it_scored_what_it_did() -> None:
    # Printed beside the rating, so a reader who thinks an item is overblown can
    # name the input they disagree with. It was computed and never used.
    gap = next(g for g in evaluate(intake(dpa_status="no"))[0] if g.control_id == "DAT-05")
    assert "catalog rating critical" in gap.severity_reason
