"""Rendering, for two audiences who want different things from one review.

A vendor review lands in front of two readers. The **requester** — whoever wants
the vendor, usually somebody in the business with a date they have promised —
wants to know whether they can sign, what has to happen first, and what to put in
the email to the account team. They will not read an attack chain and they should
not have to. The **security reviewer** who owns the sign-off wants the evidence
state, the control mapping and the framework references, because they are the one
who will defend the decision at the renewal, or after an incident.

Two documents solve that and create a worse problem: they drift, and the
requester acts on the wrong one. So this is one review rendered two ways from one
computation. ``--audience requester`` prints the decision, the conditions and the
questions to send the vendor. The default prints those and then the evidence
underneath.

The ordering is deliberate and slightly unusual: conditions and questions before
findings. Most security reports lead with what is wrong, which is the author's
ordering rather than the reader's. Somebody who has been told to fix something
wants the list first and the justification second.

Escaping: the intake was written by another team and the evidence was written by
the vendor being assessed. Both reach a Markdown document that gets pasted into a
ticket and forwarded to that same vendor. A vendor named
``Acme ![](https://evil.example/px.png)`` must not put a tracking pixel in the
review, and a scope statement carrying ``https://acme-security.example/verify``
must not arrive as a clickable link in a document an executive opens. Each
renderer escapes for its own syntax — Markdown prose, Markdown code spans and
HTML each need different treatment, and using one everywhere either leaves a hole
or prints backslashes at the reader.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .analyze.severity import explain
from .models import Attestation, ControlGap, Decision, Finding, Note, Review, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_DECISION_LABEL = {
    Decision.APPROVE: ("✅", "Approve"),
    Decision.APPROVE_WITH_CONDITIONS: ("🟡", "Approve with conditions"),
    Decision.MORE_INFORMATION_NEEDED: ("⚪", "More information needed"),
    Decision.DO_NOT_PROCEED: ("🔴", "Do not proceed"),
}

_DECISION_COLOR = {
    Decision.APPROVE: "#1a7f37",
    Decision.APPROVE_WITH_CONDITIONS: "#b7791f",
    Decision.MORE_INFORMATION_NEEDED: "#5f6b7a",
    Decision.DO_NOT_PROCEED: "#b3261e",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#1e6fb8",
    Severity.INFO: "#5f6b7a",
}

_ATTESTATION_LABEL = {
    Attestation.ATTESTED: "attested",
    Attestation.ABSENT: "answered no",
    Attestation.NOT_EVIDENCED: "not evidenced",
}

# Bounds on what one document prints. A thin pack legitimately leaves thirty
# objectives unevidenced, and thirty full entries buries the four that matter --
# but nothing is hidden: the count is in the tally, the questions section already
# carries the material ones, and the JSON output is complete.
_MAX_RENDERED_GAPS = 20
_MAX_RENDERED_UNEVIDENCED = 20
_MAX_RENDERED_QUESTIONS = 15
_MAX_RENDERED_NOTES = 12

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Backtick breaks out of a code span; bracket, paren and bang build links and
# images. Hash and greater-than are handled separately because they only matter
# at the start of a line. Emphasis markers are deliberately absent — escaping
# them renders every ``self_hosted`` as ``self\_hosted`` and the worst they
# achieve is bold text.
_MD_ESCAPE_RE = re.compile(r"([`\[\]()!])")

# Bare URLs. Every Markdown renderer worth using autolinks these, and escaping
# the punctuation above does nothing to stop it: there is no bracket to escape.
# A review is forwarded to the vendor's account team and pasted into tickets, so
# a clickable link that arrived in text the vendor wrote is a delivery mechanism
# with a security team's letterhead on it. Defanged rather than removed, because
# the reader still needs to see what the document said.
_URL_SCHEME_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15})://")
_URL_HOST_RE = re.compile(r"(?i)\bwww\.")


def _defang(text: str) -> str:
    r"""Neutralise anything a renderer would turn into a link.

    Applied **after** the syntax escape, never before. The replacement inserts
    square brackets, and running it first meant the escape immediately turned
    them back into ``https\[://\]evil.example`` -- backslashes on the reader's
    page and no defang worth the name. Running it second is safe because by that
    point every bracket, paren and bang the untrusted text itself contained is
    already escaped, so the brackets inserted here have nothing to pair with and
    cannot build a link or an image.
    """
    return _URL_HOST_RE.sub("www[.]", _URL_SCHEME_RE.sub(r"\1[://]", text))


def _md(text: object) -> str:
    r"""Escape UNTRUSTED text for Markdown prose.

    Applied by provenance, not everywhere. Three sources of text end up in a
    review and only two of them are untrusted:

    * **Intake answers** — written by another team, and a vendor named
      ``x ![](https://evil.example/px.png)`` must not put a tracking pixel in a
      document that goes to a ticket. Escaped.
    * **Evidence and model output** — a scope statement quoted off a certificate,
      a finding title derived from it. The evidence was written by the party
      being assessed, which makes it the most obviously worth crafting input this
      tool has. Escaped.
    * **Catalog, decision and note text** — written in this repository and
      reviewed in pull requests. NOT escaped, because escaping it renders every
      ``finding(s)`` as ``finding\(s\)`` and every ``(SAML or OIDC)`` as
      ``\(SAML or OIDC\)``, which makes the document look broken and teaches the
      reader that the tool is careless.

    Getting this backwards in either direction is a real failure: escape too
    little and a review carries a payload to the vendor, escape too much and
    nobody trusts a document that cannot punctuate.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    escaped = _defang(_MD_ESCAPE_RE.sub(r"\\\1", collapsed).replace("<", "&lt;"))
    # Only meaningful at the start, and only these two forge structure: a leading
    # hash is a heading, a leading angle bracket is a block quote. Both were
    # reachable — an answer beginning "## Approved" put a second verdict heading
    # in the review, one line below the real one.
    if escaped.startswith("#"):
        escaped = "&#35;" + escaped[1:]
    elif escaped.startswith(">"):
        escaped = "&gt;" + escaped[1:]
    return escaped


def _prose(text: object, *, trusted: bool) -> str:
    r"""Render one line of prose according to where it came from.

    Provenance is decided once, here, so it reads the same at every call site.
    Both halves of getting it wrong have happened in this file: question text
    went out unescaped for every question in the review, including the ones
    quoting a scope statement off a vendor's certificate, and review notes went
    out escaped even though every one of them is written in this repository, so
    the reader was told "3 proposed finding\(s\) were rejected".
    """
    return str(text) if trusted else _md(text)


def _code(text: object) -> str:
    """Prepare a value for inside a Markdown code span.

    Backslash escapes are inert inside backticks, so :func:`_md` here would print
    them literally. The backtick would close the span and is replaced; ``<`` and
    ``>`` are entity-escaped as a second line of defence for renderers that
    mishandle code spans.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _html(text: object) -> str:
    """Escape UNTRUSTED text for HTML, and defang the same way Markdown does.

    ``html.escape`` alone leaves a bare URL as inert text in this page, which is
    correct here — nothing in the HTML renderer builds an anchor. It does not
    survive the page being copied into an email client, which linkifies on the
    way in, so the defang is applied for the same reason it is applied to
    Markdown.
    """
    return _defang(html.escape(" ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())))


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def _header(review: Review) -> list[str]:
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    lines = [
        f"# Third-party review — {_md(intake.vendor or 'unnamed vendor')}",
        "",
        f"## {emoji} {label}",
        "",
        review.decision_rationale,
        "",
    ]
    meta = [
        f"**Service** {_md(intake.service or 'not described')}",
        f"**Requested by** {_md(intake.requesting_team or 'not stated')}",
        f"**Owner** {_md(intake.owner or 'not named')}",
        f"**Stage** {_md(intake.stage)}",
    ]
    lines += [" · ".join(meta), ""]
    return lines


def _tally(review: Review) -> list[str]:
    counts = review.counts_by_severity()
    tally = " · ".join(f"{counts[s.value]} {s.value}" for s in Severity if counts[s.value])
    supplied = review.intake.evidence.supplied()
    return [
        f"{len(review.applicable_controls)} objectives in scope · "
        f"{len(review.attested_controls)} attested · "
        f"{len(review.absent_gaps())} answered no · "
        f"{len(review.unevidenced())} not evidenced · "
        f"{len(review.findings)} additional findings" + (f" · {tally}" if tally else ""),
        "Evidence read: " + (", ".join(supplied) if supplied else "none supplied"),
        f"Review confidence **{review.confidence.value}** · "
        f"engagement fingerprint `{review.intake.fingerprint()}`"
        + (
            f" (was `{_code(review.baseline_fingerprint)}`)"
            if review.baseline_fingerprint
            and review.baseline_fingerprint != review.intake.fingerprint()
            else ""
        ),
        "",
    ]


def _conditions_block(review: Review) -> list[str]:
    conditions = review.conditions()
    if not conditions:
        return []
    lines = [
        "## What has to happen before signature",
        "",
        "Each item is a condition of this review. If one is impractical, come back to the "
        "security team rather than proceeding around it — most have an alternative that "
        "is cheaper than the one being avoided.",
        "",
    ]
    for index, (action, reason, trusted) in enumerate(conditions, start=1):
        # Escaped only when it came from the model or from vendor text. Catalog
        # conditions are written in this repository, and escaping them printed
        # "\(SAML or OIDC\)" at the reader.
        lines.append(f"{index}. {_prose(action, trusted=trusted)}")
        lines.append(f"   *Why: {_prose(reason, trusted=trusted)}*")
    lines.append("")
    return lines


def _questions_block(review: Review) -> list[str]:
    blocking = review.blocking_questions()
    if not blocking:
        return []
    lines = [
        "## Questions to send the vendor",
        "",
        "The decision above cannot be settled until these are answered. They are "
        "questions rather than findings because nothing in the pack settles them either "
        "way: assuming the best waves through real exposure, assuming the worst accuses "
        "the vendor of something nobody asked them about.",
        "",
    ]
    for question in blocking[:_MAX_RENDERED_QUESTIONS]:
        lines.append(f"- {_prose(question.text, trusted=question.trusted)}")
        if question.why_it_matters:
            lines.append(f"  *{_prose(question.why_it_matters, trusted=question.trusted)}*")
    # Counted rather than silently dropped. This section is the deliverable — the
    # list somebody forwards to the account team — and a blocking question left
    # off it is one nobody asks while the decision still waits on the answer.
    if len(blocking) > _MAX_RENDERED_QUESTIONS:
        lines.append(
            f"- _{len(blocking) - _MAX_RENDERED_QUESTIONS} further question(s) also hold "
            "the decision and are in the JSON output._"
        )
    lines.append("")
    return lines


def _note_line(note: Note) -> str:
    r"""One note: its own sentence unescaped, anything it quotes escaped.

    Both halves of getting this wrong were live here. The sentences are written
    in this repository — the confidence line, the rejection count, the baseline
    comparison — and escaping them printed "3 proposed finding\(s\) were
    rejected" at the reader. But the note naming a document that could not be
    read quotes the reason, and for a questionnaire response file that reason is
    the YAML parser's account of the vendor's own file, so a response file
    beginning ``![](https://evil.example/px.png): [`` put an image in a review
    that is forwarded to that vendor and pasted into a ticket.
    """
    return f"- {note.text} {_md(note.quoted)}" if note.quoted else f"- {note.text}"


def _notes_block(review: Review) -> list[str]:
    if not review.notes:
        return []
    return (
        ["## Review notes", ""] + [_note_line(n) for n in review.notes[:_MAX_RENDERED_NOTES]] + [""]
    )


def _gap_block(gap: ControlGap) -> list[str]:
    marker = " · **BLOCKING**" if gap.blocking else ""
    lines = [
        f"### {gap.control_id} · {_SEVERITY_EMOJI[gap.severity]} "
        f"{gap.severity.value.upper()}{marker} · {gap.title}",
        "",
    ]
    if gap.severity_reason:
        # Written in this repository, so not escaped. Printed beside the rating
        # because a reader who thinks an item is overblown should be able to name
        # the input they disagree with rather than conclude the tool is noisy.
        lines += [f"*{gap.severity_reason}*", ""]
    lines += [f"{gap.what_is_missing} {gap.why_applicable}", ""]
    if gap.attestation.is_absent and gap.condition:
        lines.append(f"**Condition** {gap.condition}")
    else:
        lines.append(f"**Ask** {gap.question}")
    if gap.frameworks:
        refs = " · ".join(f"`{_code(f)}`" for f in gap.frameworks)
        lines.append(f"**Maps to** {refs}")
    lines.append("")
    return lines


def _render_finding(finding: Finding, is_new: bool) -> list[str]:
    marker = " · **NEW**" if is_new else ""
    lines = [
        f"### {finding.id} · {_SEVERITY_EMOJI[finding.severity]} "
        f"{finding.severity.value.upper()}{marker} · {_md(finding.title)}",
        "",
        f"*{explain(finding.blast, finding.data_at_risk, len(finding.assumptions))}*",
        "",
        "```",
        "  →  ".join(_code(step) for step in finding.chain),
        "```",
        "",
    ]
    if finding.assumptions:
        lines.append(f"**Assumes** {' · '.join(_md(a) for a in finding.assumptions)}")
    if finding.condition:
        lines.append(f"**Condition** {_md(finding.condition)}")
    if finding.because:
        lines.append(f"**Because** {_md(finding.because)}")
    if finding.control_ids:
        lines.append(f"**Objectives** {', '.join(f'`{_code(c)}`' for c in finding.control_ids)}")
    if finding.frameworks:
        refs = " · ".join(f"`{_code(f)}`" for f in finding.frameworks[:6])
        lines.append(f"**Maps to** {refs}")
    if finding.fact_ids:
        lines.append(f"**From** {', '.join(f'`{_code(f)}`' for f in finding.fact_ids)}")
    lines.append("")
    return lines


def render_requester(review: Review) -> str:
    """The short version, for whoever wants the vendor.

    Decision, conditions, questions, and nothing else. Not a summary of the
    review: the same computed decision and the same computed conditions, with the
    evidence section left off. Somebody who reads only this has read everything
    they have to act on, which is the property that makes it safe to send.
    """
    lines = _header(review)
    lines += _conditions_block(review)
    lines += _questions_block(review)

    if not review.conditions() and not review.blocking_questions():
        lines += [
            "Nothing is outstanding on the security side. This rests on the intake being "
            "accurate and on documents the vendor wrote about themselves — tell the "
            "security team if how the vendor will be used changes materially.",
            "",
        ]

    lines += [
        "---",
        f"_vendorreview {review.tool_version} · reviewed {review.reviewed_at} · requester view_  ",
        "_The full review, with the evidence behind each item, is the reviewer version of "
        "this document._",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(review: Review) -> str:
    """The full review: the requester's half, then the evidence underneath."""
    lines = _header(review)
    lines += _tally(review)
    lines += _conditions_block(review)
    lines += _questions_block(review)

    absent = review.absent_gaps()
    if absent:
        lines += [
            f"## Answered no ({len(absent)})",
            "",
            "Objectives somebody has definitively said are not met — a questionnaire "
            "answer of no, an expired certificate, a report that is a Type I. These are "
            "the only items stated as failures.",
            "",
        ]
        for gap in absent[:_MAX_RENDERED_GAPS]:
            lines += _gap_block(gap)
        if len(absent) > _MAX_RENDERED_GAPS:
            lines += [
                f"_{len(absent) - _MAX_RENDERED_GAPS} further objective(s) were answered no "
                "and are in the JSON output._",
                "",
            ]

    unevidenced = review.unevidenced()
    if unevidenced:
        lines += [
            f"## Not evidenced ({len(unevidenced)})",
            "",
            "Nothing in the pack settles these either way. They are not findings against "
            "the vendor and must not be sent as though they were: a SOC 2 scoped to "
            "Security is silent on availability because it did not have to be, and "
            "reading that silence as a control failure is how a review gets disputed and "
            "then ignored. Severity is capped accordingly.",
            "",
        ]
        for gap in unevidenced[:_MAX_RENDERED_UNEVIDENCED]:
            lines += _gap_block(gap)
        if len(unevidenced) > _MAX_RENDERED_UNEVIDENCED:
            lines += [
                f"_{len(unevidenced) - _MAX_RENDERED_UNEVIDENCED} further objective(s) are "
                "not evidenced and are in the JSON output. A pack this thin is itself the "
                "finding._",
                "",
            ]

    if review.findings:
        new_keys = review.new_finding_keys
        lines += [
            f"## Additional findings ({len(review.findings)})",
            "",
            "Risks arising from how these facts combine, rather than from any single "
            "objective. Produced by analysis over the extracted evidence, and constrained "
            "to citing facts and objectives that exist.",
            "",
        ]
        for finding in review.findings:
            lines += _render_finding(finding, finding.key() in new_keys)

    if review.conflicts:
        lines += [
            f"## Sources that disagree ({len(review.conflicts)})",
            "",
            "One source says yes and another says no. Worth a sentence in the vendor "
            "conversation: a questionnaire answered by a sales engineer and a report "
            "signed by an auditor are not equally considered claims.",
            "",
        ]
        lines += [f"- {_md(entry)}" for entry in review.conflicts[:20]]
        lines.append("")

    other_questions = [q for q in review.questions if not q.blocks_decision]
    if other_questions:
        lines += [f"## Open questions ({len(other_questions)})", ""]
        lines += [f"- {_prose(q.text, trusted=q.trusted)}" for q in other_questions[:25]]
        lines.append("")

    if review.attested_controls:
        lines += [
            f"## Attested ({len(review.attested_controls)})",
            "",
            "Evidenced by the pack. Attested is not verified — nobody here logged into the "
            "vendor's console — but somebody has stated it, in writing, and that is what a "
            "review of this kind can establish.",
            "",
            "```",
            ", ".join(_code(c) for c in review.attested_controls),
            "```",
            "",
        ]

    if review.dropped_findings:
        lines += [
            f"> {review.dropped_findings} proposed finding(s) failed validation and were "
            "discarded — they cited facts or control identifiers that do not exist. Run "
            "with `--explain-drops` to see them.",
            "",
        ]

    lines += _notes_block(review)

    lines += [
        "---",
        f"_vendorreview {review.tool_version} · reviewed {review.reviewed_at}_  ",
        "_This review reflects the engagement as declared and the documents supplied. It "
        "is not an audit and nothing in it was verified against the vendor's systems._",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_check(review: Review) -> str:
    """The objective evaluation alone, with no reasoning layer.

    Printed by ``vendorreview check``, which needs no API key. Its purpose is to
    let a security team see exactly what the deterministic half concluded before
    anyone decides whether to send a vendor's evidence to a third-party API — and
    to give them something usable when they would rather not send it at all.
    """
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    supplied = intake.evidence.supplied()
    lines = [
        f"# Objective check — {_md(intake.vendor or 'unnamed vendor')}",
        "",
        f"## {emoji} {label}",
        "",
        review.decision_rationale,
        "",
        f"{len(review.applicable_controls)} objectives in scope · "
        f"{len(review.attested_controls)} attested · "
        f"{len(review.absent_gaps())} answered no · "
        f"{len(review.unevidenced())} not evidenced · "
        f"{len(review.blocking_questions())} blocking question(s) of "
        f"{len(review.questions)} open",
        "",
        "Evidence read: " + (", ".join(supplied) if supplied else "none supplied"),
        "",
        "This is the deterministic half of a review: applicability, evidence state and the "
        "decision, computed with no model involved. Run `vendorreview review` to add "
        "analysis of how these facts combine.",
        "",
    ]

    absent = review.absent_gaps()
    if absent:
        lines += ["## Answered no", ""]
        for gap in absent:
            marker = " BLOCKING" if gap.blocking else ""
            lines.append(f"- **{gap.control_id}**{marker} · {gap.severity.value} · {gap.title}")
            lines.append(f"  {gap.condition or gap.question}")
        lines.append("")

    unevidenced = review.unevidenced()
    if unevidenced:
        lines += ["## Not evidenced", ""]
        for gap in unevidenced:
            lines.append(f"- **{gap.control_id}** · {gap.severity.value} · {gap.title}")
        lines.append("")

    blocking = review.blocking_questions()
    if blocking:
        lines += ["## Questions blocking the decision", ""]
        lines += [f"- {_prose(q.text, trusted=q.trusted)}" for q in blocking[:20]]
        lines.append("")

    # The notes carry the confidence sentence and, more importantly, the list of
    # documents that could not be read. Leaving them off this view meant the one
    # command a security team runs first was the one that did not mention an
    # unreadable SOC 2 -- a review quietly built on less than the reader believed,
    # which is the exact failure the tri-state exists to prevent.
    lines += _notes_block(review)

    return "\n".join(lines).rstrip() + "\n"


def render_unchanged(review: Review) -> str:
    """The whole re-review, when nothing about the engagement moved.

    Lives here rather than in the CLI because every other line of Markdown this
    tool emits is built in this module, and the one that was not went out with
    the vendor name unescaped and un-defanged — so a vendor called
    ``Acme ![](https://evil.example/px.png)`` put a tracking pixel in the one
    document a renewal produces, in the one path where nothing else is printed
    to notice it beside.
    """
    fingerprint = review.intake.fingerprint()
    return (
        f"# Re-review — {_md(review.intake.vendor or 'unnamed vendor')}\n\n"
        "The declared engagement is unchanged since the last review and no new findings "
        f"were identified.\n\nFingerprint `{_code(fingerprint)}` (unchanged).\n"
    )


def render_json(review: Review) -> str:
    return json.dumps(review.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_html(review: Review, *, audience: str = "reviewer") -> str:
    """A standalone page. No external assets, no JavaScript, no anchors."""
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    colour = _DECISION_COLOR[review.decision]

    conditions = "".join(
        f"<li><strong>{_html(action)}</strong><br><em>{_html(reason)}</em></li>"
        for action, reason, _ in review.conditions()
    )
    conditions_block = (
        f"<section><h2>What has to happen before signature</h2><ol>{conditions}</ol></section>"
        if conditions
        else ""
    )

    questions = "".join(f"<li>{_html(q.text)}</li>" for q in review.blocking_questions()[:15])
    questions_block = (
        f'<section class="notice"><h2>Questions to send the vendor</h2><ul>{questions}</ul>'
        "<p>Nothing in the pack settles these either way. They are questions, not findings "
        "against the vendor.</p></section>"
        if questions
        else ""
    )

    def gap_article(gap: ControlGap) -> str:
        badge = '<span class="blocking">BLOCKING</span>' if gap.blocking else ""
        action = (
            f"<dt>Condition</dt><dd>{_html(gap.condition)}</dd>"
            if gap.attestation.is_absent and gap.condition
            else f"<dt>Ask</dt><dd>{_html(gap.question)}</dd>"
        )
        refs = (
            "<dt>Maps to</dt><dd><code>"
            + _html(" · ".join(str(f) for f in gap.frameworks))
            + "</code></dd>"
            if gap.frameworks
            else ""
        )
        return (
            f'<article><h3><span class="sev" style="background:{_SEVERITY_COLOR[gap.severity]}">'
            f'{_html(gap.severity.value.upper())}</span> <span class="state">'
            f"{_html(_ATTESTATION_LABEL[gap.attestation])}</span> {_html(gap.control_id)} · "
            f"{_html(gap.title)}{badge}</h3>"
            f"<p>{_html(gap.what_is_missing)} {_html(gap.why_applicable)}</p>"
            f"<dl>{action}{refs}</dl></article>"
        )

    absent_blocks = "".join(gap_article(g) for g in review.absent_gaps()[:_MAX_RENDERED_GAPS])
    unevidenced_blocks = "".join(
        gap_article(g) for g in review.unevidenced()[:_MAX_RENDERED_UNEVIDENCED]
    )
    finding_blocks = "".join(
        f'<article><h3><span class="sev" style="background:{_SEVERITY_COLOR[f.severity]}">'
        f"{_html(f.severity.value.upper())}</span> {_html(f.id)} · {_html(f.title)}</h3>"
        f"<pre>{_html('  →  '.join(f.chain))}</pre>"
        f"<dl><dt>Condition</dt><dd>{_html(f.condition)}</dd></dl></article>"
        for f in review.findings
    )

    # Escaped whole, because html.escape prints backslashes at nobody — the split
    # in Note exists for Markdown. What matters here is that the section is
    # present at all: this page was the one format that left the notes off, so it
    # was the one format that did not mention a SOC 2 it had failed to read — a
    # review quietly built on less than the reader believed, which is the exact
    # failure the tri-state exists to prevent.
    notes_block = (
        "<section><h2>Review notes</h2><ul>"
        + "".join(f"<li>{_html(n)}</li>" for n in review.notes[:_MAX_RENDERED_NOTES])
        + "</ul></section>"
        if review.notes
        else ""
    )

    evidence_sections = (
        ""
        if audience == "requester"
        else (
            (
                f"<h2>Answered no ({len(review.absent_gaps())})</h2>{absent_blocks}"
                if absent_blocks
                else ""
            )
            + (
                f"<h2>Not evidenced ({len(review.unevidenced())})</h2>{unevidenced_blocks}"
                if unevidenced_blocks
                else ""
            )
            + (
                f"<h2>Additional findings ({len(review.findings)})</h2>{finding_blocks}"
                if finding_blocks
                else ""
            )
            + notes_block
        )
    )

    supplied = ", ".join(intake.evidence.supplied()) or "none supplied"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Third-party review — {_html(intake.vendor)}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        margin:0; padding:2rem; max-width:900px; margin-inline:auto; }}
 h1 {{ font-size:1.45rem; margin:0 0 .5rem; }}
 h2 {{ font-size:1.05rem; margin:2rem 0 .75rem; }}
 h3 {{ font-size:.95rem; margin:0 0 .4rem; font-weight:600; }}
 .decision {{ border-left:5px solid {colour}; padding:.8rem 1rem; margin:1rem 0 1.5rem;
             background:#00000008; }}
 .decision b {{ font-size:1.1rem; }}
 .meta {{ color:#6b7280; font-size:.85rem; margin-bottom:1.5rem; }}
 .sev {{ color:#fff; padding:.1rem .45rem; border-radius:4px; font-size:.7rem; font-weight:600; }}
 .state {{ color:#6b7280; font-size:.72rem; text-transform:uppercase; letter-spacing:.03em; }}
 .blocking {{ background:#b3261e; color:#fff; padding:.05rem .35rem; border-radius:3px;
              font-size:.65rem; margin-left:.4rem; }}
 article {{ border:1px solid #d1d5db; border-radius:8px; padding:1rem; margin-bottom:1rem; }}
 pre {{ background:#00000010; padding:.6rem .8rem; border-radius:6px; overflow-x:auto;
        font-size:.82rem; }}
 dl {{ display:grid; grid-template-columns:max-content 1fr; gap:.3rem .9rem; font-size:.88rem; }}
 dt {{ font-weight:600; color:#6b7280; }}
 dd {{ margin:0; }}
 ol li {{ margin-bottom:.6rem; }}
 .notice {{ border-left:3px solid #d97706; padding-left:1rem; }}
 footer {{ margin-top:2rem; color:#6b7280; font-size:.8rem; }}
</style></head><body>
<h1>Third-party review — {_html(intake.vendor)}</h1>
<div class="decision"><b>{emoji} {_html(label)}</b><br>
{_html(review.decision_rationale)}</div>
<p class="meta">{_html(intake.service or "service not described")} ·
 requested by {_html(intake.requesting_team or "not stated")} ·
 owner {_html(intake.owner or "not named")} · stage {_html(intake.stage)} ·
 {len(review.applicable_controls)} objectives in scope,
 {len(review.attested_controls)} attested ·
 evidence read: {_html(supplied)} ·
 confidence {_html(review.confidence.value)} ·
 fingerprint <code>{_html(intake.fingerprint())}</code></p>
{conditions_block}
{questions_block}
{evidence_sections}
<footer>vendorreview {_html(review.tool_version)} · reviewed {_html(review.reviewed_at)}<br>
This review reflects the engagement as declared and the documents supplied. It is not an
audit and nothing in it was verified against the vendor's systems.</footer>
</body></html>
"""


def render(review: Review, fmt: str, *, audience: str = "reviewer") -> str:
    """Render one review in one format, for one audience."""
    if audience not in {"reviewer", "requester"}:
        raise ValueError(f"unknown audience {audience!r}; use reviewer or requester")

    markdown = render_requester if audience == "requester" else render_markdown
    renderers: dict[str, Any] = {
        "markdown": lambda: markdown(review),
        "md": lambda: markdown(review),
        "json": lambda: render_json(review),
        "html": lambda: render_html(review, audience=audience),
    }
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ValueError(f"unknown format {fmt!r}; use markdown, json or html")
    # Called outside the lookup guard: wrapping both would report a KeyError
    # raised inside a renderer as "unknown format 'markdown'".
    return str(renderer())
