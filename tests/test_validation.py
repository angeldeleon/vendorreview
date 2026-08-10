"""The trust boundary: sanitising, redaction, the scrub, and bounded file reads."""

from __future__ import annotations

import os
import time
from dataclasses import fields

import pytest

from conftest import intake, write
from vendorreview.evidence import evidence_facts
from vendorreview.evidence.responses import parse_responses
from vendorreview.intake import clean, parse_intake, scrub_intake
from vendorreview.models import Attestation, EvidenceSet, Soc2Report, VendorIntake
from vendorreview.validation import (
    ValidationError,
    read_text_file,
    redact,
    safe_text,
    sanitise,
    validate_env_var_name,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a" * 36


# --------------------------------------------------------------------------
# safe_text
# --------------------------------------------------------------------------


def test_control_characters_become_spaces() -> None:
    assert safe_text("a\x00b\x1fc\x7fd") == "a b c d"


def test_invisible_and_bidi_characters_are_dropped() -> None:
    # A bidi override renders a report as text that differs from what the
    # document contains. Trojan Source, pointed at the person signing off.
    assert safe_text("Acme\u202eevil\u202c Ltd") == "Acmeevil Ltd"
    assert safe_text("AKIA\u200bIOSFODNN7EXAMPLE") == AWS_KEY


def test_unpaired_surrogates_are_replaced() -> None:
    assert "\ud800" not in safe_text("bad \ud800 byte")
    safe_text("bad \ud800 byte").encode("utf-8")  # must not raise


def test_length_cap_is_applied() -> None:
    assert len(safe_text("x" * 900, limit=40)) == 40


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        AWS_KEY,
        GITHUB_TOKEN,
        "xoxb-1234567890-abcdefghij",
        "AIza" + "b" * 35,
        "-----BEGIN RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM.SflKxwRJSMeKKF2QT4",
        "Authorization: Bearer abcdefghijklmnop",
        "Token abcdefghijklmnopqrst",
        "postgres://svc:hunter2pass@db.internal:5432/app",
        "redis://:hunter2pass@cache.internal",
        'api_key: "sk_live_abcdefghijklmn"',
        "password=notagoodpassword",
    ],
)
def test_credential_shapes_are_redacted(text: str) -> None:
    assert "redacted" in redact(text)


def test_password_containing_at_sign_is_fully_redacted() -> None:
    # The non-greedy form stopped at the first @ and printed most of the
    # password in the clear.
    out = redact("redis://:P@ssw0rdLong@cache.internal/0")
    assert "ssw0rdLong" not in out


def test_redaction_placeholder_keeps_the_line_readable() -> None:
    assert redact("api_key = abcdefghijkl").startswith("api_key = ")


def test_sanitise_orders_normalisation_before_redaction() -> None:
    # The bug this ordering exists for: redact first and the zero-width space
    # defeats every pattern, then the normalising step deletes the space and
    # reassembles a live key in the stored value.
    assert AWS_KEY not in sanitise("AKIA\u200bIOSFODNN7EXAMPLE")


def test_sanitise_is_idempotent() -> None:
    once = sanitise(f"api_key: {AWS_KEY}")
    assert sanitise(once) == once


# --------------------------------------------------------------------------
# The scrub. One walk over the finished model, and the only guarantee.
# --------------------------------------------------------------------------


def test_every_string_field_on_the_intake_is_scrubbed() -> None:
    """The choke-point test.

    Written over ``fields(VendorIntake)`` rather than over a list of names, so a
    field added next year fails this test until it is covered by the walk. Three
    fields reached the API with credentials in them because a per-site call was
    missing; this is what makes the guarantee structural.
    """
    dirty = VendorIntake()
    for spec in fields(VendorIntake):
        if spec.name in {"evidence", "facts", "integrations"}:
            continue
        current = getattr(dirty, spec.name)
        if isinstance(current, str):
            setattr(dirty, spec.name, f"x {AWS_KEY}")
        elif isinstance(current, tuple):
            setattr(dirty, spec.name, (f"x {AWS_KEY}",))
        elif isinstance(current, list):
            setattr(dirty, spec.name, [f"x {AWS_KEY}"])

    scrubbed = scrub_intake(dirty)
    for spec in fields(VendorIntake):
        value = getattr(scrubbed, spec.name)
        assert AWS_KEY not in repr(value), f"{spec.name} was not scrubbed"


def test_the_scrub_reaches_nested_evidence_records() -> None:
    # The evidence never goes through the intake parser, which is how it was
    # missed the first time.
    dirty = VendorIntake(vendor="v")
    dirty.evidence = EvidenceSet(
        soc2=Soc2Report(source_name="r.txt", opinion=f"unqualified {AWS_KEY}")
    )
    scrubbed = scrub_intake(dirty)
    assert scrubbed.evidence.soc2 is not None
    assert AWS_KEY not in scrubbed.evidence.soc2.opinion


def test_the_scrub_reaches_attached_document_lines() -> None:
    dirty = VendorIntake(vendor="v", document_lines=[f"deploy key {GITHUB_TOKEN}"])
    assert GITHUB_TOKEN not in repr(scrub_intake(dirty).document_lines)


def test_the_scrub_leaves_enum_members_comparable() -> None:
    # Enums subclass str. Cleaning one would return a plain string that no longer
    # compares equal to the member, silently breaking every applicability rule.
    parsed = intake()
    scrubbed = scrub_intake(parsed)
    from vendorreview.models import DataClass

    assert DataClass.PII in scrubbed.data_classes


def test_a_bare_integration_entry_is_redacted_like_any_other() -> None:
    parsed = parse_intake(
        {"vendor": "v", "integrations": [f"api_key {AWS_KEY}"]},
    )
    assert AWS_KEY not in repr(parsed.integrations)


def test_unmapped_vocabulary_is_quoted_back_redacted() -> None:
    parsed = parse_intake({"vendor": "v", "data_classes": [f"biometric {AWS_KEY}"]})
    assert parsed.vocabulary_notes
    assert AWS_KEY not in repr(parsed.vocabulary_notes)


def test_evidence_facts_carry_no_credentials() -> None:
    responses = parse_responses({"key_management": f"partial, key at {AWS_KEY}"})
    facts = evidence_facts(EvidenceSet(responses=responses))
    assert facts
    assert AWS_KEY not in repr(facts)


def test_clean_caps_to_the_requested_budget() -> None:
    assert len(clean("y" * 900, limit=100)) == 100


# --------------------------------------------------------------------------
# Cost. Every pattern is one linear scan.
# --------------------------------------------------------------------------


def test_redaction_is_linear_on_hostile_input() -> None:
    """A vendor supplies the documents this scans.

    One pattern was not linear: a tail that ran to the end of the field looking
    for a character that was not there made ``check`` -- the local, no-network,
    supposedly cheap command -- spend tens of seconds of CPU on a file that took
    a second to produce.
    """
    small = "a://" * 2_000
    large = "a://" * 8_000

    start = time.perf_counter()
    redact(small)
    small_seconds = time.perf_counter() - start

    start = time.perf_counter()
    redact(large)
    large_seconds = time.perf_counter() - start

    # Quadratic would be ~16x. A generous ceiling, because this has to pass on a
    # loaded CI runner; it still fails by orders of magnitude on a backtracking
    # pattern.
    assert large_seconds < max(small_seconds * 8, 0.5) + 1.0


def test_sanitise_bounds_what_it_will_scan() -> None:
    start = time.perf_counter()
    sanitise("b://" * 200_000, limit=200)
    assert time.perf_counter() - start < 5.0


# --------------------------------------------------------------------------
# validate_env_var_name
# --------------------------------------------------------------------------


def test_env_var_name_rejects_a_url_or_path() -> None:
    for bad in ("https://example.test/key", "/etc/secret", "not a name"):
        with pytest.raises(ValidationError):
            validate_env_var_name(bad, where="analysis.api_key_env")


def test_env_var_name_accepts_a_name() -> None:
    assert validate_env_var_name("VENDOR_API_KEY", where="x") == "VENDOR_API_KEY"


# --------------------------------------------------------------------------
# read_text_file
# --------------------------------------------------------------------------


def test_read_text_file_reads_a_regular_file(tmp_path) -> None:
    path = write(tmp_path, "a.txt", "hello")
    assert read_text_file(path, max_bytes=1000) == "hello"


def test_read_text_file_refuses_a_symlink(tmp_path) -> None:
    secret = write(tmp_path, "secret.txt", "top secret")
    link = tmp_path / "link.txt"
    link.symlink_to(secret)
    with pytest.raises(ValidationError):
        read_text_file(link, max_bytes=1000)


def test_read_text_file_refuses_a_directory(tmp_path) -> None:
    with pytest.raises(ValidationError):
        read_text_file(tmp_path, max_bytes=1000)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_read_text_file_refuses_a_fifo_without_hanging(tmp_path) -> None:
    # O_NONBLOCK is why this returns at all: os.open on a FIFO with no writer
    # blocks before the regular-file check can refuse it.
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValidationError):
        read_text_file(fifo, max_bytes=1000)


def test_read_text_file_enforces_the_size_cap(tmp_path) -> None:
    path = write(tmp_path, "big.txt", "z" * 5000)
    with pytest.raises(ValidationError):
        read_text_file(path, max_bytes=100)


def test_read_text_file_decodes_lossily(tmp_path) -> None:
    path = tmp_path / "b.txt"
    path.write_bytes(b"caf\xe9 report")
    assert "report" in read_text_file(path, max_bytes=1000)


def test_missing_file_is_a_validation_error(tmp_path) -> None:
    with pytest.raises(ValidationError):
        read_text_file(tmp_path / "nope.txt", max_bytes=1000)


def test_response_answers_never_become_a_yes_by_accident() -> None:
    parsed = parse_responses({"mfa_enforced": "partial"})
    assert parsed.answers["mfa_enforced"] is Attestation.NOT_EVIDENCED


# --------------------------------------------------------------------------
# Invisible characters inside a credential
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("codepoint", "name"),
    [
        (0x200B, "zero width space"),
        (0xFEFF, "zero width no-break space"),
        (0xFE00, "variation selector-1"),
        (0xFE0F, "variation selector-16"),
        (0xE0041, "tag latin capital letter a"),
        (0xE0100, "variation selector-17"),
        (0x180E, "mongolian vowel separator"),
        (0x034F, "combining grapheme joiner"),
        (0x17B4, "khmer vowel inherent aq"),
        (0x3164, "hangul filler"),
        (0xFFA0, "halfwidth hangul filler"),
        (0xFFF9, "interlinear annotation anchor"),
    ],
)
def test_no_zero_width_character_can_split_a_credential(codepoint: int, name: str) -> None:
    """The redaction defeat, reached through a character nobody had listed.

    Only the zero-width space and the bidi controls were stripped, so
    ``AKIA<variation selector-1>IOSFODNN7EXAMPLE`` matched no pattern, reached the
    API payload and the JSON report, and rendered to a human as the intact key.
    Every one of these occupies no width and every one of them did it.
    """
    split = AWS_KEY[:4] + chr(codepoint) + AWS_KEY[4:]
    cleaned = sanitise(f"service account {split}")
    assert "redacted" in cleaned, f"{name} defeated redaction"
    assert AWS_KEY not in cleaned.replace(chr(codepoint), "")


def test_a_visible_gap_is_left_alone() -> None:
    # A no-break space is collapsed by str.split rather than deleted, and a
    # braille blank occupies a cell. Neither reassembles into a key a reader
    # would copy, and deleting them would corrupt legitimate text.
    assert safe_text("Acme\u00a0Ltd") == "Acme Ltd"
    assert "\u2800" in safe_text("a\u2800b")


def test_redaction_is_linear_on_an_unterminated_userinfo_run() -> None:
    """The shape the previous timing test did not reach.

    ``"a://" * n`` gives every scheme its own slash to stop at, so it never
    exercised the backtracking. A single scheme followed by a long run of
    characters that are none of slash, space or at-sign does: there were as many
    places to put the user/password colon as there were colons, and the tail
    rescanned to the end of the run for each. 64 KB of colons -- one line of a
    text file, free to write -- cost eight seconds inside `check`, and an 8 MB
    document of them cost a quarter of an hour.
    """
    small = "a://" + ":" * 16_000
    large = "a://" + ":" * 64_000

    start = time.perf_counter()
    redact(small)
    small_seconds = time.perf_counter() - start

    start = time.perf_counter()
    redact(large)
    large_seconds = time.perf_counter() - start

    # Quadratic would be ~16x. Generous, because this has to pass on a loaded CI
    # runner; the quadratic form failed it by three orders of magnitude.
    assert large_seconds < max(small_seconds * 8, 0.5) + 1.0


def test_a_hostile_document_line_does_not_stall_the_local_command() -> None:
    assert sanitise("a://" + ":" * 200_000, limit=200)


def test_a_password_containing_a_colon_free_username_is_still_redacted() -> None:
    # The linear form excludes ":" from the user half, which is what RFC 3986
    # says userinfo is. The password half keeps every character it had.
    assert "hunter2" not in redact("postgres://svc:hunter2pass@db.internal:5432/app")
    assert "hunter2" not in redact("redis://:hunter2:pass@cache.internal")
