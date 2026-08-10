"""Command line interface.

Five commands, and the split between them is deliberate.

``questions`` prints the blank intake form and the vendor response template. It
exists because a security team that publishes what it will ask gets better
answers than one that asks on a call the week before signature — the requester
can go and find out, and the vendor can answer once rather than three times.

``check`` runs the objective evaluation and produces a decision with **no API key
and no network call**. This is the command to run first: it shows exactly what
the rules concluded before anyone decides whether to send a vendor's SOC 2 to a
third-party API, and it is genuinely useful on its own for teams that would
rather not send one at all.

``review`` adds the reasoning layer on top. ``rereview`` reports only what changed
since the last review of the same vendor, which is the shape that makes this
survivable at renewal.

``controls`` prints the catalog. A team should be able to read what it will hold
vendors to before it sends the first questionnaire.

Exit codes are a contract:

* ``0`` — reviewed, nothing at or above ``fail_on``, nothing blocking
* ``1`` — reviewed, conditions or blocking items apply
* ``2`` — could not run

1 and 2 are separate on purpose. A pipeline that treats them alike eventually
goes green because the review broke rather than because the vendor got safer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import report
from . import review as review_module
from .analyze.engine import AnalysisError, Analyzer
from .baseline import BaselineStore, StateError, apply_baseline, state_scope
from .config import Config, load_config
from .controls.catalog import BUILTIN_CONTROLS, frameworks_covered
from .evidence import KNOWN_KEYS, evidence_facts, load_document, load_evidence
from .intake import blank_form, load_intake, scrub_intake
from .models import VendorIntake
from .validation import ValidationError

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_ERROR = 2

log = logging.getLogger("vendorreview")

# A DPA is twenty pages, a security addendum is five, an architecture note is
# two. Anything past this is a whole document set concatenated, and the reasoning
# layer does worse with it rather than better.
_MAX_DOC_BYTES = 400_000


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _write(text: str, destination: str | None) -> None:
    if not destination:
        sys.stdout.write(text)
        return
    Path(destination).expanduser().write_text(text, encoding="utf-8")
    log.info("wrote %s", destination)


def _attach_evidence(intake: VendorIntake, args: argparse.Namespace) -> None:
    """Read whatever the vendor supplied and fold it onto the intake.

    Every path here points at a file the vendor sent. The extraction is
    deterministic and the results are tri-state, so a document that says nothing
    about an objective leaves it not evidenced rather than absent — see
    :mod:`vendorreview.evidence`.

    The scrub runs again afterwards because this is the second way text gets onto
    an intake, and it is the way most likely to carry a real credential: an
    architecture appendix with a connection string in it, a runbook with a
    service-account key. Every line was sanitised on the way through the reader
    as well; the scrub here is the guarantee, and the reader is the discipline.
    """
    intake.evidence = load_evidence(
        soc2_path=getattr(args, "soc2", None),
        iso_path=getattr(args, "iso", None),
        pentest_path=getattr(args, "pentest", None),
        responses_path=getattr(args, "responses", None),
    )
    intake.facts.extend(evidence_facts(intake.evidence))

    document = getattr(args, "document", None)
    if document:
        # Read through the same reader as every other evidence file, and for the
        # same reasons. Reading it directly meant this one path had no binary
        # check, no line cap and no page cap: `--document report.pdf` decoded the
        # compressed streams lossily and sent the result to the API in full,
        # while the README says in terms that this tool does not parse PDF. An
        # unreadable attachment is now recorded and printed like any other rather
        # than aborting a review that would otherwise have run.
        attached = load_document(document, max_bytes=_MAX_DOC_BYTES)
        if attached.readable:
            intake.document_lines = list(attached.lines)
            intake.document_name = attached.name
            log.info(
                "attached %s (%d lines) — its full text is sent to the analysis API, with "
                "credential shapes redacted",
                attached.name,
                len(intake.document_lines),
            )
        else:
            reason = "; ".join(attached.problems) or "unknown reason"
            intake.evidence.unreadable.append(f"attached document ({attached.name}): {reason}")
            log.warning("attached document could not be read: %s", reason)

    scrub_intake(intake)


def _analyzer(config: Config) -> Analyzer:
    if not config.analysis.verify_tls:
        log.warning(
            "TLS verification is disabled: the API key is exposed to anyone on the network "
            "path. This should never be on outside a lab."
        )
    return Analyzer(
        api_key_env=config.analysis.api_key_env,
        model=config.analysis.model,
        api_base=config.analysis.api_base,
        max_tokens=config.analysis.max_tokens,
        timeout=config.analysis.timeout,
        verify_tls=config.analysis.verify_tls,
        allow_internal=config.analysis.allow_internal,
        temperature=config.analysis.temperature,
    )


def _print_drops(result: object, args: argparse.Namespace) -> None:
    """Show what the gate refused, when asked. To stderr, so a redirected report
    is never contaminated."""
    if not getattr(args, "explain_drops", False):
        return
    rejections = getattr(result, "rejections", [])
    if not rejections:
        sys.stderr.write("No proposed findings were rejected on this review.\n")
        return
    sys.stderr.write(f"\n{len(rejections)} finding(s) rejected by the gate:\n")
    for title, reason in rejections:
        sys.stderr.write(f"  - {title}\n    {reason}\n")


def cmd_questions(args: argparse.Namespace) -> int:
    """Print the blank intake form, and the vendor response template beside it."""
    lines = [
        blank_form(),
        "",
        "# ------------------------------------------------------------------",
        "# Vendor response template — send this to the vendor, attach the",
        "# completed file with `--responses`. Answer yes, no, or partial.",
        "# 'partial' is treated as not evidenced, which is what it deserves,",
        "# and the comment is quoted back in the review.",
        "# ------------------------------------------------------------------",
        "",
    ]
    for key, description in KNOWN_KEYS.items():
        lines.append(f"# {description}")
        lines.append(f"{key}:")
        lines.append("")
    _write("\n".join(lines), args.output)
    return EXIT_OK


def cmd_controls(args: argparse.Namespace) -> int:
    """Print the control catalog, with framework mappings."""
    lines = [
        "# vendorreview control catalog",
        "",
        f"{len(BUILTIN_CONTROLS)} control objectives. Each applies only when the engagement "
        "says it should — an objective that is not in scope is absent from the review "
        "entirely rather than listed and marked N/A.",
        "",
        "Each objective is settled by named sources, and the result is one of three "
        "states: attested, answered no, or not evidenced. Silence in a document is never "
        "read as a no.",
        "",
        "Framework references per objective: "
        + ", ".join(f"{name} ({count})" for name, count in sorted(frameworks_covered().items())),
        "",
        "Mapping an objective to a control identifier does not make a vendor certified, "
        "and this is not an audit. The mapping exists so a condition can be traced to an "
        "obligation in the language the rest of the organisation already uses.",
        "",
    ]
    for entry in BUILTIN_CONTROLS:
        marker = " · BLOCKING" if entry.blocking else ""
        lines += [
            f"## {entry.id} · {entry.severity.value}{marker} · {entry.title}",
            "",
            entry.objective,
            "",
            f"*Applies when: {entry.why_template}.*",
            "",
            f"**If answered no:** {entry.condition}"
            if entry.condition
            else "**If answered no:** no source can settle this objective; it is always a "
            "question.",
            "",
            f"**If not evidenced:** {entry.question}",
            "",
            "| Framework | Reference |",
            "|---|---|",
        ]
        lines += [
            f"| {f.name} | {f.identifier}{f' — {f.title}' if f.title else ''} |"
            for f in entry.frameworks
        ]
        lines.append("")
    _write("\n".join(lines).rstrip() + "\n", args.output)
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    """Objective evaluation and decision. No API key, no network call."""
    config = _config(args)
    intake = load_intake(args.intake)
    _attach_evidence(intake, args)
    if intake.is_empty():
        log.error(
            "the intake names no vendor or has no answered questions. Refusing to produce "
            "a review of a form nobody filled in."
        )
        return EXIT_ERROR

    result = review_module.check(intake, tool_version=__version__)
    fmt = "check" if config.output_format in {"markdown", "md"} else config.output_format
    if fmt == "check" and args.audience == "requester":
        fmt = "markdown"
    text = (
        report.render_check(result)
        if fmt == "check"
        else report.render(result, fmt, audience=args.audience)
    )
    _write(text, args.output)
    return review_module.exit_code(result, config.fail_on)


def cmd_review(args: argparse.Namespace) -> int:
    """The full review: objective evaluation plus reasoned findings."""
    config = _config(args)
    intake = load_intake(args.intake)
    _attach_evidence(intake, args)
    if intake.is_empty():
        log.error("the intake names no vendor or has no answered questions; cannot review.")
        return EXIT_ERROR

    result = review_module.full(intake, _analyzer(config), tool_version=__version__)

    store = BaselineStore(config.state_path, scope=state_scope(intake), retain=config.retain)
    apply_baseline(result, store)
    if not args.no_save:
        store.save(result)

    _write(report.render(result, config.output_format, audience=args.audience), args.output)
    _print_drops(result, args)
    return review_module.exit_code(result, config.fail_on)


def cmd_rereview(args: argparse.Namespace) -> int:
    """Report only what changed since the last review of this vendor."""
    config = _config(args)
    intake = load_intake(args.intake)
    _attach_evidence(intake, args)
    if intake.is_empty():
        log.error("the intake names no vendor or has no answered questions; cannot review.")
        return EXIT_ERROR

    store = BaselineStore(config.state_path, scope=state_scope(intake), retain=config.retain)
    previous = store.previous()
    if previous is None:
        log.error(
            "no previous review of %r. Run `vendorreview review` once to establish the "
            "baseline, then re-review. Without one there is nothing to compare against, "
            "and reporting everything as new would be useless.",
            intake.vendor,
        )
        return EXIT_ERROR

    result = review_module.full(intake, _analyzer(config), tool_version=__version__)
    apply_baseline(result, store)

    # Save the FULL result before narrowing. Narrowing first and then saving
    # would write a baseline containing only the deltas, erasing every standing
    # item and re-reporting the whole backlog on the next pass.
    if not args.no_save:
        store.save(result)

    if result.baseline_fingerprint == intake.fingerprint() and not result.new_findings():
        # Rendered by report.py like every other line of Markdown this tool
        # emits. Assembled here it was the one that escaped nothing, so a vendor
        # name carrying an image tag or a bare URL went out live on the one path
        # where there is no other output beside it to notice.
        _write(report.render_unchanged(result), args.output)
        return EXIT_OK

    _write(report.render(result, config.output_format, audience=args.audience), args.output)
    _print_drops(result, args)
    return review_module.exit_code(result, config.fail_on)


def _config(args: argparse.Namespace) -> Config:
    config = load_config(args.config) if getattr(args, "config", None) else Config()
    if getattr(args, "format", None):
        config.output_format = args.format
    if getattr(args, "state", None):
        config.state_path = args.state
    if getattr(args, "fail_on", None):
        config.fail_on = args.fail_on
    return config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vendorreview",
        description=(
            "Third-party security review: what a vendor attests to, what is missing, "
            "and what to ask before signing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vendorreview {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser, *, needs_intake: bool = True) -> None:
        if needs_intake:
            sub.add_argument("-i", "--intake", required=True, help="path to the intake YAML")
        sub.add_argument("-o", "--output", help="write here instead of stdout")
        sub.add_argument("-v", "--verbose", action="store_true")
        sub.add_argument("-q", "--quiet", action="store_true")

    def evidence_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--soc2", help="SOC 2 report, as text (pdftotext -layout output)")
        sub.add_argument("--iso", help="ISO 27001 certificate, as text")
        sub.add_argument("--pentest", help="penetration test summary, as text")
        sub.add_argument("--responses", help="the vendor's completed questionnaire, as YAML")
        sub.add_argument(
            "-d",
            "--document",
            help=(
                "any other document as text — a DPA, a security addendum, an "
                "architecture note. Sent to the analysis API in full"
            ),
        )
        sub.add_argument(
            "--audience",
            choices=["reviewer", "requester"],
            default="reviewer",
            help="reviewer gets the evidence, requester gets the decision and the actions",
        )

    def analysis_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("-c", "--config", help="path to a config file")
        sub.add_argument("-f", "--format", choices=["markdown", "md", "json", "html"])
        sub.add_argument("--state", help="path to the review history database")
        sub.add_argument(
            "--fail-on",
            choices=["critical", "high", "medium", "low", "info"],
            help="exit 1 at or above this severity",
        )
        sub.add_argument("--no-save", action="store_true", help="do not record this review")
        sub.add_argument(
            "--explain-drops",
            action="store_true",
            help="show the findings the gate rejected, and why",
        )

    questions = subparsers.add_parser(
        "questions", help="print the blank intake form and the vendor response template"
    )
    common(questions, needs_intake=False)
    questions.set_defaults(func=cmd_questions)

    controls = subparsers.add_parser(
        "controls", help="print the control catalog and its framework mappings"
    )
    common(controls, needs_intake=False)
    controls.set_defaults(func=cmd_controls)

    check = subparsers.add_parser(
        "check", help="objective evaluation and decision (no API key, no network)"
    )
    common(check)
    evidence_args(check)
    check.add_argument("-c", "--config")
    check.add_argument("-f", "--format", choices=["markdown", "md", "json", "html"])
    check.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"])
    check.set_defaults(func=cmd_check)

    review_parser = subparsers.add_parser("review", help="full third-party review")
    common(review_parser)
    evidence_args(review_parser)
    analysis_args(review_parser)
    review_parser.set_defaults(func=cmd_review)

    rereview = subparsers.add_parser(
        "rereview", help="report what changed since the last review of this vendor"
    )
    common(rereview)
    evidence_args(rereview)
    analysis_args(rereview)
    rereview.set_defaults(func=cmd_rereview)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False), getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except (ValidationError, StateError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except AnalysisError as exc:
        # Exit 2, not 1. The analysis did not run, so we know nothing about the
        # vendor beyond the objective evaluation — and "we know nothing" must
        # never share an exit code with "we looked and it was fine".
        log.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except Exception as exc:
        log.error("vendorreview failed unexpectedly: %s: %s", type(exc).__name__, exc)
        log.debug("traceback", exc_info=True)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
