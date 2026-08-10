"""Rendering, and escaping by provenance.

Both halves of getting this wrong are failures. Escape too little and a review
carries a payload to the vendor's account team. Escape too much and the reader is
told "3 proposed finding\\(s\\) were rejected", which teaches them the tool is
careless about everything else too.
"""

from __future__ import annotations

import json
import re

import pytest

from conftest import intake
from vendorreview.analyze import gate
from vendorreview.evidence import evidence_facts
from vendorreview.evidence.responses import parse_responses
from vendorreview.models import EvidenceSet, Note, Question, Review
from vendorreview.report import (
    render,
    render_check,
    render_html,
    render_json,
    render_markdown,
    render_requester,
)
from vendorreview.review import check

PIXEL = "![](https://evil.example/px.png)"


def review_with(**overrides) -> Review:
    return check(intake(**overrides), tool_version="0.1.0")


# --------------------------------------------------------------------------
# Untrusted text is escaped
# --------------------------------------------------------------------------


def test_an_image_in_a_vendor_name_does_not_render() -> None:
    out = render_markdown(review_with(vendor=f"Acme {PIXEL}"))
    assert PIXEL not in out
    assert "!" not in out.split("\n")[0].replace("\\!", "")


def test_a_forged_heading_in_an_answer_does_not_become_a_heading() -> None:
    # Sanitising collapses the newline, so the forged line lands inline; the
    # leading-hash escape covers the case where it lands at the start of a
    # rendered line anyway.
    out = render_markdown(review_with(vendor="Acme\n\n## Approve"))
    assert not re.search(r"(?m)^## Approve\s*$", out)


def test_a_leading_hash_is_neutralised() -> None:
    from vendorreview.report import _md

    assert not _md("# not a heading").startswith("#")
    assert not _md("> not a quote").startswith(">")


def test_a_bare_url_in_vendor_text_is_defanged() -> None:
    """A review is forwarded to the vendor and pasted into tickets.

    Escaping brackets does nothing here: there is no bracket. Every Markdown
    renderer worth using autolinks a bare URL, so a link that arrived in text the
    vendor wrote goes out clickable with a security team's letterhead on it.
    """
    out = render_markdown(review_with(vendor="Acme https://evil.example/verify"))
    assert "https://evil.example" not in out
    assert "https[://]evil.example" in out


def test_www_prefixes_are_defanged_too() -> None:
    from vendorreview.report import _md

    assert "www[.]" in _md("see www.evil.example for details")


def test_backticks_in_untrusted_text_cannot_close_a_code_span() -> None:
    from vendorreview.report import _code, _md

    assert "`" not in _code("value` and `more")
    assert "\\`" in _md("value` here")


def test_html_escapes_and_defangs() -> None:
    out = render_html(review_with(vendor="Acme <script>alert(1)</script> https://evil.example"))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "https://evil.example" not in out


def test_html_has_no_anchors_and_no_script() -> None:
    out = render_html(review_with())
    assert "<a " not in out
    assert "javascript:" not in out
    assert "<script" not in out


def test_an_untrusted_question_is_escaped_and_a_tool_authored_one_is_not() -> None:
    from vendorreview.report import _prose

    assert _prose("finding(s) rejected", trusted=True) == "finding(s) rejected"
    assert _prose("finding(s) rejected", trusted=False) == r"finding\(s\) rejected"


def test_a_vocabulary_note_reaches_the_report_escaped() -> None:
    out = render_markdown(review_with(data_classes=[f"biometric {PIXEL}"]))
    assert PIXEL not in out


def test_evidence_text_is_escaped_in_the_report() -> None:
    parsed = intake()
    parsed.evidence = EvidenceSet(responses=parse_responses({"key_management": f"partial {PIXEL}"}))
    parsed.facts.extend(evidence_facts(parsed.evidence))
    result = check(parsed)
    result.findings, _ = gate.apply(
        [
            {
                "title": f"Keys are held with the data {PIXEL}",
                "chain": ["a", "b"],
                "fact_ids": ["response.key_management"],
                "control_ids": ["CRY-03"],
                "blast": "connected",
                "data_at_risk": "pii",
                "condition": f"Ask about key custody {PIXEL}",
            }
        ],
        parsed,
    )
    out = render_markdown(result)
    assert result.findings
    assert PIXEL not in out


# --------------------------------------------------------------------------
# Tool-authored text is NOT escaped
# --------------------------------------------------------------------------


def test_tool_authored_prose_is_not_printed_with_backslashes() -> None:
    """The other half, and the one that makes a document look broken.

    Catalog conditions, decision rationales and review notes are written in this
    repository and reviewed in pull requests. Escaping them printed
    "gap\\(s\\)" and "\\(SAML or OIDC\\)" at the reader.
    """
    out = render_markdown(review_with(dpa_status="no"))
    assert "\\(" not in out
    assert "\\)" not in out


def test_the_check_view_does_not_over_escape_either() -> None:
    assert "\\(" not in render_check(review_with(dpa_status="no"))


def test_the_requester_view_does_not_over_escape_either() -> None:
    assert "\\(" not in render_requester(review_with(dpa_status="no"))


# --------------------------------------------------------------------------
# The two audiences
# --------------------------------------------------------------------------


def test_the_requester_view_carries_the_decision_and_the_actions() -> None:
    result = review_with(dpa_status="no")
    out = render_requester(result)
    assert "Do not proceed" in out
    assert "What has to happen before signature" in out
    assert "Questions to send the vendor" in out


def test_the_requester_view_leaves_out_the_evidence_sections() -> None:
    result = review_with(dpa_status="no")
    out = render_requester(result)
    assert "Not evidenced" not in out
    assert "Review notes" not in out
    # ...but the reviewer view has them.
    assert "Not evidenced" in render_markdown(result)


def test_both_audiences_report_the_same_decision() -> None:
    result = review_with(dpa_status="no")
    for text in (render_requester(result), render_markdown(result), render_check(result)):
        assert "Do not proceed" in text


def test_a_clean_requester_view_says_so_rather_than_printing_nothing() -> None:
    from test_gate import _fully_evidenced

    result = check(_fully_evidenced())
    assert "Nothing is outstanding" in render_requester(result)


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------


def test_absent_and_unevidenced_are_rendered_in_separate_sections() -> None:
    out = render_markdown(review_with(dpa_status="no", scim_available="no"))
    assert "## Answered no" in out
    assert "## Not evidenced" in out
    assert out.index("## Answered no") < out.index("## Not evidenced")


def test_the_unevidenced_section_says_it_is_not_a_finding() -> None:
    out = render_markdown(review_with())
    assert "not findings against" in out


def test_an_absent_gap_prints_a_condition_and_an_unknown_one_prints_a_question() -> None:
    out = render_markdown(review_with(dpa_status="no"))
    assert "**Condition**" in out
    assert "**Ask**" in out


def test_conditions_come_before_findings() -> None:
    out = render_markdown(review_with(dpa_status="no"))
    assert out.index("What has to happen before signature") < out.index("## Answered no")


def test_json_is_complete_and_parses() -> None:
    payload = json.loads(render_json(review_with(dpa_status="no")))
    assert payload["decision"] == "do_not_proceed"
    assert payload["gaps"] and payload["not_evidenced"]
    assert payload["attestation_counts"]["absent"] >= 1
    assert payload["intake"]["fingerprint"]


def test_conflicts_are_surfaced() -> None:
    parsed = intake(scim_available="yes")
    parsed.evidence = EvidenceSet(responses=parse_responses({"scim_deprovisioning": "no"}))
    result = check(parsed)
    assert result.conflicts
    assert "Sources that disagree" in render_markdown(result)


def test_rendered_gap_lists_are_bounded() -> None:
    out = render_markdown(review_with())
    assert out.count("### ") <= 45


def test_an_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        render(review_with(), "pdf")


def test_an_unknown_audience_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown audience"):
        render(review_with(), "markdown", audience="the board")


@pytest.mark.parametrize("fmt", ["markdown", "md", "json", "html"])
@pytest.mark.parametrize("audience", ["reviewer", "requester"])
def test_every_format_and_audience_renders(fmt: str, audience: str) -> None:
    assert render(review_with(dpa_status="no"), fmt, audience=audience).strip()


def test_a_model_question_is_escaped_in_every_renderer() -> None:
    result = review_with()
    result.questions.append(Question(text=f"What about {PIXEL}?", trusted=False))
    for text in (render_markdown(result), render_check(result), render_html(result)):
        assert PIXEL not in text


# --------------------------------------------------------------------------
# Review notes: the vendor's half escaped, the tool's half not
# --------------------------------------------------------------------------


def _with_unreadable_responses(tmp_path) -> Review:
    """A review whose response file could not be parsed, the vendor having said so."""
    from vendorreview.evidence import load_evidence
    from vendorreview.intake import scrub_intake

    path = tmp_path / "answers.yml"
    path.write_text(f"{PIXEL}: [unclosed\n", encoding="utf-8")
    parsed = intake()
    parsed.evidence = load_evidence(responses_path=path)
    scrub_intake(parsed)
    return check(parsed, tool_version="0.1.0")


def test_a_note_quoting_a_document_is_escaped_in_every_renderer() -> None:
    """Notes were printed whole as tool-authored prose, and one of them is not.

    The note saying a document could not be read quotes the reason, and for a
    questionnaire response file that reason is the YAML parser's account of the
    vendor's own file. A response file beginning with an image tag put that image
    in a review that gets forwarded to that vendor and pasted into a ticket.
    """
    result = review_with()
    result.notes.append(Note("A supplied document could not be read:", quoted=PIXEL))
    for text in (render_markdown(result), render_check(result), render_html(result)):
        assert PIXEL not in text
    assert "Review notes" in render_markdown(result)


def test_an_unreadable_response_file_carries_its_reason_as_a_quote(tmp_path) -> None:
    result = _with_unreadable_responses(tmp_path)
    assert any(n.quoted for n in result.notes)
    for text in (render_markdown(result), render_check(result), render_html(result)):
        assert PIXEL not in text


def test_a_note_still_prints_its_own_prose_without_backslashes(tmp_path) -> None:
    # The other half. Escaping the whole line to cover the quote printed
    # backslashes through the sentence around it.
    out = render_markdown(_with_unreadable_responses(tmp_path))
    line = next(line for line in out.splitlines() if line.startswith("- A supplied document"))
    assert "not evidenced rather than as absent:" in line


def test_the_html_page_reports_a_document_it_could_not_read(tmp_path) -> None:
    # This was the one format that left the notes off, so it was the one format
    # that did not mention a document it had failed to read.
    out = render_html(_with_unreadable_responses(tmp_path))
    assert "Review notes" in out
    assert "could not be read" in out


def test_the_unchanged_re_review_escapes_the_vendor_name() -> None:
    """The one Markdown line that was not built in this module.

    ``rereview`` assembled it in the CLI out of ``safe_text``, which neutralises
    control characters and nothing else — on the one path where there is no other
    output beside it to notice a live image or a clickable link.
    """
    from vendorreview.report import render_unchanged

    out = render_unchanged(review_with(vendor=f"Acme {PIXEL} https://evil.example/verify"))
    assert PIXEL not in out
    assert "https://evil.example" not in out
    assert "https[://]evil.example" in out


def test_blocking_questions_past_the_cut_are_counted_not_dropped() -> None:
    # This section is the deliverable. A blocking question left off it is one
    # nobody asks while the decision still waits on the answer.
    from vendorreview.report import _MAX_RENDERED_QUESTIONS

    result = review_with()
    result.questions = [
        Question(text=f"Question number {n}?", blocks_decision=True)
        for n in range(_MAX_RENDERED_QUESTIONS + 4)
    ]
    out = render_markdown(result)
    assert "4 further question(s) also hold the decision" in out


def test_a_gap_prints_why_it_scored_what_it_did() -> None:
    out = render_markdown(review_with(dpa_status="no"))
    assert "*catalog rating critical" in out
