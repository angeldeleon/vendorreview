"""Deterministic extraction from the documents the vendor supplied.

Every test here is about what a document literally says. Nothing in this module
is about what any of it means -- that is the catalog's job, and keeping the two
apart is why the tool can be argued with.
"""

from __future__ import annotations

from pathlib import Path

from conftest import TODAY, document, read, write
from vendorreview.evidence import evidence_facts, load_evidence
from vendorreview.evidence.iso27001 import parse_iso
from vendorreview.evidence.pentest import parse_pentest
from vendorreview.evidence.reader import (
    has_ambiguous_date,
    load_document,
    months_between,
    parse_date,
    parse_dates,
)
from vendorreview.evidence.responses import load_responses, parse_responses
from vendorreview.evidence.soc2 import parse_soc2
from vendorreview.models import Attestation

# --------------------------------------------------------------------------
# The reader
# --------------------------------------------------------------------------


def test_a_pdf_is_refused_with_an_explanation(tmp_path) -> None:
    path = tmp_path / "report.pdf"
    path.write_bytes(b"%PDF-1.7\n stream binary")
    doc = load_document(path)
    assert not doc.readable
    assert "pdftotext" in " ".join(doc.problems)


def test_an_unreadable_document_is_a_document_not_an_exception(tmp_path) -> None:
    doc = load_document(tmp_path / "missing.txt")
    assert not doc.readable
    assert doc.problems


def test_page_breaks_are_counted(tmp_path) -> None:
    doc = read(tmp_path, "r.txt", "page one\fpage two\fpage three")
    assert doc.pages == 3


def test_document_lines_are_sanitised_on_the_way_in(tmp_path) -> None:
    doc = read(tmp_path, "r.txt", "key AKIA​IOSFODNN7EXAMPLE in the appendix")
    assert "AKIAIOSFODNN7EXAMPLE" not in "\n".join(doc.lines)


def test_an_empty_document_is_unreadable(tmp_path) -> None:
    assert not read(tmp_path, "r.txt", "   \n  \n").readable


def test_search_returns_the_line_number(tmp_path) -> None:
    import re

    doc = read(tmp_path, "r.txt", "alpha\nbeta\ngamma")
    hit = doc.search(re.compile("beta"))
    assert hit == ("beta", 2)


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------


def test_three_date_spellings_are_read() -> None:
    assert parse_date("dated 2025-03-04") is not None
    assert parse_date("dated March 4, 2025") is not None
    assert parse_date("dated 4 March 2025") is not None


def test_ambiguous_numeric_dates_are_refused_rather_than_guessed() -> None:
    # 03/04/2025 is 3 April in most of the world and 4 March in the United
    # States. Guessing gets a period end wrong by a month, which is exactly how a
    # stale attestation looks current.
    assert parse_date("dated 03/04/2025") is None
    assert has_ambiguous_date("dated 03/04/2025")


def test_dates_come_back_in_the_order_they_appear() -> None:
    found = parse_dates("for the period 1 October 2024 to 2025-09-30")
    assert [d.isoformat() for d in found] == ["2024-10-01", "2025-09-30"]


def test_months_between_does_not_round_up_a_partial_month() -> None:
    from datetime import date

    assert months_between(date(2025, 1, 31), date(2025, 2, 1)) == 0
    assert months_between(date(2025, 1, 1), date(2026, 1, 1)) == 12


# --------------------------------------------------------------------------
# SOC 2
# --------------------------------------------------------------------------

TYPE_TWO = """
SOC 2 Type II Report
A Type I report describes controls at a point in time.
We examined the description for the period from 2026-01-01 to 2026-03-31.
The trust services criteria in scope of this report are Security and Confidentiality.
In our opinion this is an unqualified opinion.
No exceptions noted.
"""


def test_type_two_beats_a_passing_mention_of_type_one() -> None:
    # Every Type II explains what a Type I is in its introduction. Matching the
    # first occurrence classified most Type II reports as Type I.
    report = parse_soc2(document(TYPE_TWO), as_of=TODAY)
    assert report.report_type == "Type II"
    assert report.type_two is Attestation.ATTESTED


def test_a_type_one_is_an_absence_not_a_silence() -> None:
    report = parse_soc2(document("SOC 2 Type I report"), as_of=TODAY)
    assert report.type_two is Attestation.ABSENT


def test_a_report_that_says_neither_is_not_evidenced() -> None:
    report = parse_soc2(document("SOC 2 report for Acme"), as_of=TODAY)
    assert report.type_two is Attestation.NOT_EVIDENCED


def test_a_current_period_is_attested() -> None:
    report = parse_soc2(document(TYPE_TWO), as_of=TODAY)
    assert report.period_start == "2026-01-01"
    assert report.period_end == "2026-03-31"
    assert report.period_current is Attestation.ATTESTED


def test_a_stale_period_is_absent_not_unknown() -> None:
    # A report about a period that ended two years ago is genuinely absent
    # evidence of anything current.
    stale = "SOC 2 Type II for the period from 2022-01-01 to 2022-12-31"
    report = parse_soc2(document(stale), as_of=TODAY)
    assert report.period_current is Attestation.ABSENT
    assert any("bridge letter" in p for p in report.problems)


def test_no_period_is_not_evidenced() -> None:
    report = parse_soc2(document("SOC 2 Type II report"), as_of=TODAY)
    assert report.period_current is Attestation.NOT_EVIDENCED


def test_criteria_are_read_only_from_lines_about_scope() -> None:
    # A report mentions "availability" in a hundred sentences that have nothing
    # to do with what was examined.
    text = (
        "The trust services criteria in scope are Security and Confidentiality.\n"
        "We discussed availability of the service with management at length.\n"
    )
    report = parse_soc2(document(text), as_of=TODAY)
    assert "security" in report.criteria
    assert "availability" not in report.criteria


def test_exceptions_noted_outranks_no_exceptions_noted() -> None:
    # Both phrases appear in a report that has exceptions: the summary says one
    # and the individual test results say the other.
    text = "No exceptions noted.\nCC6.3 — exceptions were noted for 2 of 25 samples."
    report = parse_soc2(document(text), as_of=TODAY)
    assert report.exceptions is Attestation.ATTESTED
    assert report.exception_notes


def test_a_clean_report_records_the_negative_statement() -> None:
    report = parse_soc2(document("No exceptions noted."), as_of=TODAY)
    assert report.exceptions is Attestation.ABSENT


def test_a_carve_out_is_only_read_where_a_subservice_is_discussed() -> None:
    # "Carve-out" appears in glossaries and in the auditor's description of the
    # two methods. Reporting a carve-out against a vendor who has none is a
    # serious claim to make on a word in a definitions section.
    glossary = "Glossary: carve-out method — see the AICPA guide."
    assert parse_soc2(document(glossary), as_of=TODAY).subservice_treatment == ""

    real = (
        "Brightwave uses a subservice organisation for hosting.\n"
        "The description excludes those controls using the carve-out method."
    )
    assert parse_soc2(document(real), as_of=TODAY).subservice_treatment == "carve-out"


def test_opinion_is_read() -> None:
    assert parse_soc2(document("a qualified opinion"), as_of=TODAY).opinion == "qualified"
    assert (
        parse_soc2(document("an adverse opinion"), as_of=TODAY).opinion == "adverse or disclaimed"
    )


def test_an_unreadable_report_claims_nothing_in_either_direction(tmp_path) -> None:
    report = parse_soc2(load_document(tmp_path / "gone.txt"), as_of=TODAY)
    assert report.type_two is Attestation.NOT_EVIDENCED
    assert report.period_current is Attestation.NOT_EVIDENCED
    assert report.problems


# --------------------------------------------------------------------------
# ISO 27001
# --------------------------------------------------------------------------

CERT = """
Certificate of Registration
ISO/IEC 27001:2022
Certificate Number: GB2024/12345
Scope: The provision of the Brightwave webinar platform
from the Dublin and Frankfurt data centres.
Date of expiry: 2027-05-01
"""


def test_a_valid_certificate_is_read(tmp_path) -> None:
    cert = parse_iso(document(CERT), as_of=TODAY)
    assert cert.standard == "ISO/IEC 27001:2022"
    assert cert.certificate_number.startswith("GB2024")
    assert cert.valid is Attestation.ATTESTED
    assert cert.scope_stated is Attestation.ATTESTED
    # Continuation lines are joined: half a scope statement is worse than none.
    assert "Frankfurt" in cert.scope_statement


def test_an_expired_certificate_is_absent() -> None:
    expired = CERT.replace("2027-05-01", "2024-05-01")
    cert = parse_iso(document(expired), as_of=TODAY)
    assert cert.valid is Attestation.ABSENT
    assert any("expired" in p for p in cert.problems)


def test_the_withdrawn_revision_is_reported_without_being_a_failure() -> None:
    cert = parse_iso(document(CERT.replace(":2022", ":2013")), as_of=TODAY)
    assert cert.standard == "ISO/IEC 27001:2013"
    assert cert.valid is Attestation.ATTESTED
    assert any("2013" in p for p in cert.problems)


def test_a_missing_expiry_is_not_evidenced() -> None:
    cert = parse_iso(document("ISO/IEC 27001:2022\nIssue date: 2025-01-01"), as_of=TODAY)
    assert cert.valid is Attestation.NOT_EVIDENCED
    assert any("surveillance" in p for p in cert.problems)


# --------------------------------------------------------------------------
# Penetration test
# --------------------------------------------------------------------------

PENTEST = """
Penetration Test Summary — Brightwave Webinar Platform
Testing was conducted between 2026-02-02 and 2026-02-13.
Scope: the customer-facing web application and its public API.
Findings: 1 critical, 3 high, 6 medium, 4 low.
All findings were retested and verified as closed on 2026-03-20.
"""


def test_a_current_test_is_read() -> None:
    test = parse_pentest(document(PENTEST), as_of=TODAY)
    assert test.tested_on == "2026-02-02"
    assert test.current is Attestation.ATTESTED
    assert test.retested is Attestation.ATTESTED
    assert test.findings["critical"] == 1
    assert test.open_high() == 4


def test_an_explicit_no_retest_outranks_boilerplate_about_retesting() -> None:
    text = PENTEST.replace(
        "All findings were retested and verified as closed on 2026-03-20.",
        "Our methodology includes a retest. No retest was performed for this engagement.",
    )
    assert parse_pentest(document(text), as_of=TODAY).retested is Attestation.ABSENT


def test_counts_need_two_severities_on_one_line() -> None:
    # "3 high risk areas were discussed" in an executive summary is not a
    # finding count.
    text = "Testing was conducted on 2026-02-02.\n3 high risk areas were discussed."
    test = parse_pentest(document(text), as_of=TODAY)
    assert test.counts_stated is Attestation.NOT_EVIDENCED


def test_a_stale_test_is_absent() -> None:
    text = PENTEST.replace("2026-02-02 and 2026-02-13", "2023-02-02 and 2023-02-13")
    assert parse_pentest(document(text), as_of=TODAY).current is Attestation.ABSENT


# --------------------------------------------------------------------------
# Questionnaire responses
# --------------------------------------------------------------------------


def test_yes_no_and_partial_map_to_three_states() -> None:
    parsed = parse_responses(
        {"sso_saml_oidc": "yes", "scim_deprovisioning": "no", "mfa_enforced": "partial"}
    )
    assert parsed.get("sso_saml_oidc") is Attestation.ATTESTED
    assert parsed.get("scim_deprovisioning") is Attestation.ABSENT
    assert parsed.get("mfa_enforced") is Attestation.NOT_EVIDENCED


def test_a_comment_travels_with_its_answer() -> None:
    parsed = parse_responses(
        {"mfa_enforced": {"answer": "partial", "comment": "Not for our support staff."}}
    )
    assert "support staff" in parsed.comments["mfa_enforced"]


def test_free_prose_is_never_a_yes() -> None:
    parsed = parse_responses({"patch_sla": "We aim to fix things promptly."})
    assert parsed.get("patch_sla") is Attestation.NOT_EVIDENCED
    assert parsed.comments["patch_sla"]


def test_unknown_keys_are_reported_not_rejected() -> None:
    # A vendor's export carries their own keys. Refusing the file over one of
    # them means the reviewer hand-edits vendor evidence before reading it.
    parsed = parse_responses({"sso_saml_oidc": "yes", "physical_badge_logs": "yes"})
    assert parsed.unknown_keys == ("physical_badge_logs",)
    assert parsed.get("sso_saml_oidc") is Attestation.ATTESTED


def test_a_missing_key_is_not_evidenced() -> None:
    assert parse_responses({}).get("mfa_enforced") is Attestation.NOT_EVIDENCED


def test_a_malformed_response_file_degrades_rather_than_raising(tmp_path) -> None:
    path = write(tmp_path, "answers.yml", "just a string")
    parsed = load_responses(path)
    assert parsed.problems
    assert parsed.get("mfa_enforced") is Attestation.NOT_EVIDENCED


# --------------------------------------------------------------------------
# The evidence set and its facts
# --------------------------------------------------------------------------


def test_load_evidence_records_an_unreadable_document(tmp_path) -> None:
    evidence = load_evidence(soc2_path=tmp_path / "nope.txt", as_of=TODAY)
    assert evidence.soc2 is not None  # the record exists, saying nothing
    assert evidence.unreadable


def test_load_evidence_reads_what_it_was_given(tmp_path) -> None:
    evidence = load_evidence(
        soc2_path=write(tmp_path, "soc2.txt", TYPE_TWO),
        iso_path=write(tmp_path, "iso.txt", CERT),
        pentest_path=write(tmp_path, "pt.txt", PENTEST),
        responses_path=write(tmp_path, "a.yml", "mfa_enforced: yes\n"),
        as_of=TODAY,
    )
    assert evidence.supplied() == [
        "SOC 2",
        "ISO 27001",
        "penetration test",
        "questionnaire responses",
    ]
    assert not evidence.unreadable


def test_evidence_facts_are_namespaced_by_document(tmp_path) -> None:
    evidence = load_evidence(soc2_path=write(tmp_path, "soc2.txt", TYPE_TWO), as_of=TODAY)
    ids = {f.id for f in evidence_facts(evidence)}
    assert "soc2.type" in ids
    assert "soc2.period" in ids
    assert all(i.startswith("soc2.") for i in ids)


def test_response_facts_are_bounded(tmp_path) -> None:
    many = "\n".join(f"{k}: yes" for k in _all_response_keys())
    evidence = load_evidence(responses_path=write(tmp_path, "a.yml", many), as_of=TODAY)
    facts = [f for f in evidence_facts(evidence) if f.id.startswith("response.")]
    assert 0 < len(facts) <= 40


def _all_response_keys() -> list[str]:
    from vendorreview.evidence.responses import KNOWN_KEYS

    return list(KNOWN_KEYS)


# --------------------------------------------------------------------------
# Truncation, and the opinion
# --------------------------------------------------------------------------


def test_a_truncated_report_naming_type_i_is_not_a_type_i(tmp_path) -> None:
    """A size cap must not manufacture a definitive failure.

    Every other absence this parser records comes from something it found. This
    one comes from not having found "Type II", and on a document cut at a cap
    "not found" means "not read" -- so a report whose introduction explains what
    a Type I is and whose own designation sits past the cut came out as
    answered-no on ATT-02.
    """
    from vendorreview.evidence.reader import MAX_LINES

    body = "A Type I report opines on design at a point in time.\n" + ("filler\n" * MAX_LINES)
    report = parse_soc2(read(tmp_path, "soc2.txt", body), as_of=TODAY)
    assert report.report_type == "Type I"
    assert report.type_two is Attestation.NOT_EVIDENCED


def test_an_untruncated_type_i_is_still_an_absence() -> None:
    report = parse_soc2(document("SOC 2 Type I report on design as at 1 March 2026"), as_of=TODAY)
    assert report.type_two is Attestation.ABSENT


def test_except_for_away_from_the_opinion_is_not_a_qualification() -> None:
    """A false qualified opinion is disproved by opening the report.

    "Except for" is how a qualification is worded and also how a scope sentence
    is worded. Matched anywhere in ninety pages, and tested before the explicit
    wording, it turned a clean report into a citable fact saying the auditor
    qualified their opinion.
    """
    report = parse_soc2(
        document(
            "In our opinion the controls operated effectively throughout the period.\n"
            "This is an unqualified opinion.\n"
            "The system serves all customers except for legacy tenants on the 2019 platform."
        ),
        as_of=TODAY,
    )
    assert report.opinion == "unqualified"


def test_an_explicitly_qualified_opinion_is_still_read() -> None:
    assert (
        parse_soc2(document("We express a qualified opinion on the description."), as_of=TODAY)
    ).opinion == "qualified"


def test_a_qualification_worded_only_as_except_for_is_still_caught() -> None:
    report = parse_soc2(
        document("Except for the matters described below, in our opinion the controls operated."),
        as_of=TODAY,
    )
    assert report.opinion == "qualified"


def test_the_yaml_error_does_not_quote_the_vendors_file_back() -> None:
    """The reason travels into the review notes and out to the vendor.

    ``str(YAMLError)`` embeds the offending line, so a response file whose first
    line was a Markdown image tag put that image in a report. The position and
    the parser's own description are what somebody needs to fix the file.
    """
    import tempfile

    directory = Path(tempfile.mkdtemp())
    path = write(directory, "answers.yml", "![](https://evil.example/px.png): [unclosed\n")
    responses = load_responses(path)
    assert responses.problems
    joined = " ".join(responses.problems)
    assert "evil.example" not in joined
    assert "line 2" in joined
