"""End to end: the CLI, the exit-code contract, config and the review history."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest
import yaml

from conftest import write
from vendorreview.baseline import BaselineStore, StateError, apply_baseline, state_scope
from vendorreview.cli import main
from vendorreview.config import Config, load_config, parse_config
from vendorreview.intake import blank_form, load_intake, parse_intake
from vendorreview.models import Decision, Finding, Review, Severity
from vendorreview.review import check, exit_code
from vendorreview.validation import ValidationError

EXAMPLE = Path(__file__).resolve().parents[1] / "vendor.example.yml"
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

MINIMAL = """
vendor: Brightwave Inc
service: Runs our customer webinars and holds the attendee list.
requesting_team: Marketing
owner: Priya Raman
stage: negotiating
hosting: saas
data_classes: [personal data]
data_subjects: [customers]
criticality: important
"""


# --------------------------------------------------------------------------
# Intake parsing
# --------------------------------------------------------------------------


def test_the_shipped_example_parses_and_reviews() -> None:
    result = check(load_intake(EXAMPLE), tool_version="test")
    assert result.intake.vendor == "Brightwave Inc"
    assert result.decision is Decision.DO_NOT_PROCEED  # the DPA is answered no
    assert result.applicable_controls


def test_the_blank_form_covers_every_question() -> None:
    from vendorreview.intake import QUESTIONS

    form = blank_form()
    for key in QUESTIONS:
        assert f"{key}:" in form


def test_the_blank_form_round_trips_through_the_parser() -> None:
    # A form that does not parse is a form nobody can start from.
    parsed = parse_intake(yaml.safe_load(blank_form()) or {})
    assert parsed.is_empty()  # no vendor named yet
    assert parsed.unanswered


def test_an_unknown_intake_key_is_rejected() -> None:
    # A misspelled scim_avail: silently doing nothing would produce a review
    # saying SCIM was never mentioned, against a team that answered.
    with pytest.raises(ValidationError, match="unknown key"):
        parse_intake({"vendor": "v", "scim_avail": "yes"})


def test_a_non_mapping_intake_is_rejected() -> None:
    with pytest.raises(ValidationError):
        parse_intake(["a", "list"])


def test_yaml_is_loaded_safely(tmp_path) -> None:
    path = write(tmp_path, "bad.yml", "vendor: !!python/object/apply:os.system ['echo hi']\n")
    with pytest.raises(ValidationError):
        load_intake(path)


def test_a_tri_state_boolean_keeps_its_unknown() -> None:
    parsed = parse_intake({"vendor": "v", "sso_available": "on their roadmap for Q3"})
    assert parsed.sso_available is None
    assert any("SAML" in q for q in parsed.unanswered)


def test_an_unanswered_stage_is_defaulted_but_recorded_as_unanswered() -> None:
    parsed = parse_intake({"vendor": "v"})
    assert parsed.stage == "evaluating"
    assert any("evaluating" in q for q in parsed.unanswered)


def test_the_fingerprint_ignores_prose_and_tracks_structure() -> None:
    one = parse_intake(yaml.safe_load(MINIMAL))
    reworded = yaml.safe_load(MINIMAL)
    reworded["service"] = "A completely different description of the same thing."
    assert parse_intake(reworded).fingerprint() == one.fingerprint()

    changed = yaml.safe_load(MINIMAL)
    changed["data_classes"] = ["regulated"]
    assert parse_intake(changed).fingerprint() != one.fingerprint()


# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------


def test_exit_codes_are_the_contract(tmp_path) -> None:
    intake_path = write(tmp_path, "v.yml", MINIMAL)
    assert main(["check", "-i", str(intake_path), "-o", str(tmp_path / "out.md"), "-q"]) == 1


def test_an_empty_intake_exits_two_not_zero(tmp_path) -> None:
    # A review of a form nobody filled in that returns nothing is a clean bill of
    # health for a vendor nobody looked at.
    path = write(tmp_path, "empty.yml", 'vendor: ""\n')
    assert main(["check", "-i", str(path), "-o", str(tmp_path / "o.md"), "-q"]) == 2


def test_a_missing_intake_file_exits_two(tmp_path) -> None:
    assert main(["check", "-i", str(tmp_path / "nope.yml"), "-q"]) == 2


def test_a_blocking_item_always_exits_one_whatever_the_threshold(tmp_path) -> None:
    result = check(parse_intake({**yaml.safe_load(MINIMAL), "dpa_status": "no"}))
    assert result.blocking_gaps()
    assert exit_code(result, "critical") == 1
    assert exit_code(result, "info") == 1


def test_a_clean_review_exits_zero() -> None:
    from test_gate import _fully_evidenced

    assert exit_code(check(_fully_evidenced()), "high") == 0


def test_the_fail_on_threshold_is_honoured() -> None:
    result = Review(intake=parse_intake(yaml.safe_load(MINIMAL)))
    result.findings = [
        Finding(
            id="F-01",
            title="t",
            chain=("a",),
            severity=Severity.LOW,
            data_at_risk=result.intake.max_data_class(),
            blast=result.intake.max_blast(),
        )
    ]
    assert exit_code(result, "high") == 0
    assert exit_code(result, "low") == 1


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------


def test_questions_prints_the_form_and_the_vendor_template(tmp_path, capsys) -> None:
    assert main(["questions", "-q"]) == 0
    out = capsys.readouterr().out
    assert "vendorreview intake" in out
    assert "Vendor response template" in out
    assert "scim_deprovisioning:" in out


def test_controls_prints_the_catalog_with_both_sentences(tmp_path, capsys) -> None:
    assert main(["controls", "-q"]) == 0
    out = capsys.readouterr().out
    assert "control catalog" in out
    assert "**If answered no:**" in out
    assert "**If not evidenced:**" in out
    assert "NIST CSF 2.0" in out


def test_check_runs_with_no_api_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "review.md"
    code = main(["check", "-i", str(EXAMPLE), "-o", str(out), "-q"])
    assert code == 1
    assert "Do not proceed" in out.read_text(encoding="utf-8")


def test_check_reads_the_supplied_evidence(tmp_path) -> None:
    out = tmp_path / "review.md"
    code = main(
        [
            "check",
            "-i",
            str(EXAMPLE),
            "--soc2",
            str(EXAMPLES / "brightwave-soc2.txt"),
            "--responses",
            str(EXAMPLES / "brightwave-responses.yml"),
            "-o",
            str(out),
            "-q",
        ]
    )
    text = out.read_text(encoding="utf-8")
    assert code == 1
    assert "Evidence read: SOC 2, questionnaire responses" in text
    # The carve-out is the single most missed line in the discipline.
    assert "ATT-05" in text


def test_a_requester_view_can_be_asked_for(tmp_path) -> None:
    out = tmp_path / "r.md"
    main(["check", "-i", str(EXAMPLE), "--audience", "requester", "-o", str(out), "-q"])
    text = out.read_text(encoding="utf-8")
    assert "requester view" in text
    assert "Not evidenced" not in text


def test_an_unreadable_evidence_document_costs_that_document_not_the_review(tmp_path) -> None:
    out = tmp_path / "r.md"
    code = main(
        ["check", "-i", str(EXAMPLE), "--soc2", str(tmp_path / "gone.txt"), "-o", str(out), "-q"]
    )
    assert code == 1
    assert "could not be read" in out.read_text(encoding="utf-8")


def test_an_attached_document_is_scrubbed_before_it_reaches_anything(tmp_path) -> None:
    doc = write(tmp_path, "dpa.txt", "Processor contact key AKIAIOSFODNN7EXAMPLE\n")
    intake = load_intake(EXAMPLE)
    from argparse import Namespace

    from vendorreview.cli import _attach_evidence

    _attach_evidence(intake, Namespace(document=str(doc)))
    assert intake.document_lines
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(intake.document_lines)


def test_review_without_a_key_exits_two_not_one(tmp_path, monkeypatch) -> None:
    # "We could not look" must never share an exit code with "we looked and it
    # was fine".
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code = main(["review", "-i", str(EXAMPLE), "--no-save", "-o", str(tmp_path / "o.md"), "-q"])
    assert code == 2


def test_rereview_without_a_baseline_exits_two(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code = main(
        [
            "rereview",
            "-i",
            str(EXAMPLE),
            "--state",
            str(tmp_path / "state.db"),
            "-o",
            str(tmp_path / "o.md"),
            "-q",
        ]
    )
    assert code == 2


def test_json_output_from_the_cli_parses(tmp_path) -> None:
    out = tmp_path / "r.json"
    main(["check", "-i", str(EXAMPLE), "-f", "json", "-o", str(out), "-q"])
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["decision"]
    assert payload["intake"]["vendor"] == "Brightwave Inc"


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_config_defaults_are_safe() -> None:
    config = Config()
    assert config.analysis.verify_tls is True
    assert config.analysis.allow_internal is False
    assert config.analysis.temperature == 0.0


def test_a_quoted_no_is_not_a_boolean() -> None:
    # bool("no") is True, and every non-empty string does this.
    with pytest.raises(ValidationError, match="true or false"):
        parse_config({"analysis": {"allow_internal": "no"}})


def test_unknown_config_keys_are_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown key"):
        parse_config({"analysis": {"api_ke_env": "X"}})
    with pytest.raises(ValidationError, match="unknown key"):
        parse_config({"nonsense": 1})


def test_a_secret_in_the_config_is_refused() -> None:
    with pytest.raises(ValidationError):
        parse_config({"analysis": {"api_key_env": "sk-live-abcdefghij"}})


def test_bounds_are_enforced() -> None:
    for bad in ({"retain": 1}, {"analysis": {"timeout": 9000}}, {"analysis": {"temperature": 5}}):
        with pytest.raises(ValidationError):
            parse_config(bad)


def test_config_round_trips_through_a_file(tmp_path) -> None:
    path = write(tmp_path, "c.yml", "fail_on: medium\noutput_format: json\n")
    config = load_config(path)
    assert config.fail_on == "medium"
    assert config.output_format == "json"


def test_an_invalid_fail_on_is_rejected() -> None:
    with pytest.raises(ValidationError):
        parse_config({"fail_on": "catastrophic"})


# --------------------------------------------------------------------------
# Review history
# --------------------------------------------------------------------------


def _review(vendor: str = "Brightwave Inc") -> Review:
    raw = yaml.safe_load(MINIMAL)
    raw["vendor"] = vendor
    result = check(parse_intake(raw), tool_version="test")
    result.findings = [
        Finding(
            id="F-01",
            title="one",
            chain=("a",),
            severity=Severity.MEDIUM,
            data_at_risk=result.intake.max_data_class(),
            blast=result.intake.max_blast(),
            fact_ids=("vendor",),
            control_ids=("IAM-04",),
        )
    ]
    return result


def test_the_first_review_marks_nothing_as_new(tmp_path) -> None:
    store = BaselineStore(tmp_path / "s.db", scope="a")
    result = _review()
    apply_baseline(result, store)
    assert not result.baseline_available
    assert not result.new_finding_keys


def test_a_second_review_marks_only_what_is_new(tmp_path) -> None:
    store = BaselineStore(tmp_path / "s.db", scope="a")
    first = _review()
    store.save(first)

    second = _review()
    second.findings = [
        *second.findings,
        Finding(
            id="F-02",
            title="two",
            chain=("b",),
            severity=Severity.LOW,
            data_at_risk=second.intake.max_data_class(),
            blast=second.intake.max_blast(),
            fact_ids=("service",),
            control_ids=("LOG-01",),
        ),
    ]
    apply_baseline(second, store)
    assert len(second.new_findings()) == 1
    assert second.new_findings()[0].title == "two"


def test_findings_are_compared_structurally_not_by_wording(tmp_path) -> None:
    store = BaselineStore(tmp_path / "s.db", scope="a")
    first = _review()
    store.save(first)

    reworded = _review()
    reworded.findings = [
        Finding(
            id="F-01",
            title="a completely different sentence about the same thing",
            chain=("a",),
            severity=Severity.MEDIUM,
            data_at_risk=reworded.intake.max_data_class(),
            blast=reworded.intake.max_blast(),
            fact_ids=("vendor",),
            control_ids=("IAM-04",),
        )
    ]
    apply_baseline(reworded, store)
    assert not reworded.new_findings()


def test_two_vendors_get_separate_histories(tmp_path) -> None:
    path = tmp_path / "s.db"
    one = _review("Alpha Ltd")
    two = _review("Beta Ltd")
    assert state_scope(one.intake) != state_scope(two.intake)

    BaselineStore(path, scope=state_scope(one.intake)).save(one)
    assert BaselineStore(path, scope=state_scope(two.intake)).previous() is None


def test_the_history_is_pruned_to_the_retention_window(tmp_path) -> None:
    path = tmp_path / "s.db"
    store = BaselineStore(path, scope="a", retain=2)
    for _ in range(6):
        store.save(_review())
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] <= 3


def test_the_history_file_is_created_private(tmp_path) -> None:
    path = tmp_path / "s.db"
    BaselineStore(path, scope="a").save(_review())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_schema_from_the_future_is_refused(tmp_path) -> None:
    path = tmp_path / "s.db"
    BaselineStore(path, scope="a").save(_review())
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    with pytest.raises(StateError, match="schema version"):
        BaselineStore(path, scope="a").previous()


def test_an_attached_pdf_is_refused_rather_than_sent(tmp_path) -> None:
    """`--document` bypassed the reader entirely.

    No binary check, no line cap, no page cap: a PDF was decoded lossily and its
    compressed streams went to the analysis API in full, while the README says in
    terms that this tool does not parse PDF. It is now recorded as unreadable
    like any other document, which costs that document rather than the review.
    """
    from argparse import Namespace

    from vendorreview.cli import _attach_evidence

    path = tmp_path / "dpa.pdf"
    path.write_bytes(b"%PDF-1.7\n1 0 obj\nstream\n\x00\x01binary\n")
    parsed = load_intake(EXAMPLE)
    _attach_evidence(parsed, Namespace(document=str(path)))

    assert not parsed.document_lines
    assert any("pdftotext" in entry for entry in parsed.evidence.unreadable)
    assert any("could not be read" in str(n) for n in check(parsed).notes)


def test_an_attached_document_is_line_capped_like_every_other(tmp_path) -> None:
    # Read directly, this path carried no line cap and no page cap either.
    from argparse import Namespace

    from vendorreview.cli import _attach_evidence
    from vendorreview.evidence.reader import MAX_LINES

    path = write(tmp_path, "dpa.txt", "x\n" * (MAX_LINES + 50))
    parsed = load_intake(EXAMPLE)
    _attach_evidence(parsed, Namespace(document=str(path)))
    assert parsed.document_lines
    assert len(parsed.document_lines) <= MAX_LINES


def test_list_answers_are_bounded_before_they_reach_the_payload() -> None:
    """An unbounded list answer was amplified on the way out.

    Every unrecognised data type becomes a sentence of its own, and every one of
    these lists is serialised whole into the API request and the JSON report. A
    quarter-megabyte answer -- inside the intake file budget, and free to write --
    produced twenty thousand vocabulary notes and a 2.5 MB request.
    """
    from vendorreview.analyze.prompt import build_user_message

    parsed = parse_intake(
        {
            "vendor": "V",
            "service": "holds the attendee list",
            "data_classes": ",".join(f"weirdtype{n}" for n in range(20_000)),
            "data_subjects": ",".join(f"subject{n}" for n in range(20_000)),
            "regulated_regimes": ",".join(f"regime{n}" for n in range(5_000)),
            "evidence_supplied": ",".join(f"document{n}" for n in range(5_000)),
        }
    )
    assert len(parsed.vocabulary_notes) <= 40
    assert len(parsed.data_subjects) <= 40
    assert len(parsed.regulated_regimes) <= 40
    assert len(parsed.evidence_supplied) <= 40
    assert len(build_user_message(parsed, [], [])) < 100_000
