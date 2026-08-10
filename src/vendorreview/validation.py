"""The trust boundary: untrusted text in, safe text out, and bounded file reads.

Everything this tool reads was written by somebody else, and two of the three
sources were written by the party being assessed.

1. **Intake answers carry secrets.** Requesters paste API keys into "how does it
   authenticate" and tenant admin credentials into "who has admin access",
   routinely, because the form asks a technical question and they answer it with
   the technical detail.

2. **Evidence documents are supplied by the vendor.** A SOC 2 report, a
   certificate, a pen test summary and a questionnaire response file all arrive
   from the organisation whose controls are being questioned. They are the input
   most likely to hold a real credential -- an architecture appendix with a
   connection string in it -- and the input most obviously worth crafting if you
   wanted the review to say something particular.

3. **All of it reaches a Markdown document that gets pasted into a ticket.** A
   vendor named ``Acme ![](https://evil.example/px.png)`` is free to type into a
   procurement system and ends up in a report an executive opens.

:func:`sanitise` is the single ordered entry point for the first two -- sanitise
then redact, and the order is the whole point; see its docstring. :func:`read_text_file`
is the entry point for the third, and refuses to follow a symlink, refuses a
FIFO, and caps what it will read.

Prompt framing is not a control, so the defence against instructions inside a
document is structural rather than textual: the model only ever sees extracted
facts, its output is schema-constrained, and every claim is checked back against
facts that exist. See :mod:`vendorreview.analyze.gate`.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

__all__ = [
    "ValidationError",
    "read_text_file",
    "redact",
    "safe_text",
    "sanitise",
    "validate_env_var_name",
]

_MAX_FIELD_LENGTH = 400

# The widest string redaction will ever be asked to scan. Every caller caps its
# own output far below this; the bound exists so that one enormous answer, or one
# 40 MB line in a vendor PDF export, cannot turn a local no-network command into
# minutes of CPU. Cutting here can leave a fragment of a credential rather than a
# whole one -- a fragment is not a usable secret, and no field on the model comes
# anywhere near this long.
_MAX_SCANNED_LENGTH = 64 * 1024

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Invisible and direction-changing characters. A bidi override in a scope
# statement renders a report as text that differs from what the certificate
# contains, which is the Trojan Source trick pointed at the person signing off
# the vendor. Written as escapes so this file is not itself an example of the
# problem.
#
# The class has to cover every character that occupies no width, not the handful
# everybody thinks of first. Zero-width space and the bidi controls were here;
# the variation selectors, the Unicode tag block, the Mongolian and Khmer format
# characters, the combining grapheme joiner and the Hangul fillers were not --
# and each of them splits a credential exactly the way a zero-width space does.
# ``AKIA<variation selector-1>IOSFODNN7EXAMPLE`` in a vendor's document matched
# no redaction pattern, reached the API payload and the JSON report, and rendered
# to a human as the intact key: the same defeat this ordering exists to prevent,
# reached through a character nobody had listed.
#
# Deliberately absent: NO-BREAK SPACE and the other Zs separators, which
# ``str.split`` below already collapses to an ordinary space, and BRAILLE PATTERN
# BLANK, which occupies a visible cell. Both leave a gap a reader can see, so a
# credential split by one is not a credential anybody copies out of the report.
_INVISIBLE_RE = re.compile(
    "[\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f"
    "\\u200b-\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u206f"
    "\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0\\ufff9-\\ufffb"
    "\\U000e0000-\\U000e0fff]"
)

_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


class ValidationError(ValueError):
    """Raised when untrusted input fails validation."""


def safe_text(value: object, *, limit: int = _MAX_FIELD_LENGTH) -> str:
    """Neutralise one string read from a form, a document or a model response.

    Collapses control characters, drops invisible and bidi-override characters,
    replaces unpaired surrogates so nothing downstream fails to encode, and caps
    length.
    """
    text = _SURROGATE_RE.sub("\ufffd", str(value))
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = _INVISIBLE_RE.sub("", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


# Credential shapes. Deliberately broad: a false redaction costs a reader some
# context, a missed one puts a live key in a report that gets forwarded to a
# vendor's account manager.
#
# Every pattern here is linear on hostile input. That is a requirement, not a
# nicety: `vendorreview check` makes no network call and is supposed to be the
# cheap command, and a vendor supplies the documents it reads.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    # Any auth scheme, not only Bearer: "Token abc..." and "Basic ..." are at
    # least as common in a vendor integration guide and were sailing through.
    (
        "auth-header",
        re.compile(r"(?i)\b(?:bearer|token|basic|apikey)\s+[A-Za-z0-9._\-/+=]{12,}"),
    ),
    # Four subtleties, all of which cost something before they were fixed.
    #   * The username may be empty: redis://:password@host is the canonical
    #     form, and requiring a character before the colon missed it entirely.
    #   * The password may itself contain "@". A non-greedy [^/\s@]+ stopped at
    #     the FIRST @, so redis://:P@ssw0rd@host redacted "redis://:P@" and
    #     printed "ssw0rd@host" -- most of the password, in the clear. Running
    #     greedily to the last @ over-redacts a second URL on the same line,
    #     which is the acceptable direction to fail.
    #   * The greedy run must exclude "/" as well as whitespace, and that is a
    #     performance property rather than a correctness one. With [^\s]* the
    #     tail scanned to the end of the field looking for an @ that was not
    #     there, once per candidate scheme, so a document containing "a://"
    #     repeated cost time quadratic in its length. Userinfo cannot contain
    #     "/" anyway, so excluding it costs no match and bounds each scan to the
    #     distance to the next slash.
    #   * The user half must exclude ":" as well, and that is the same property
    #     one level down. With [^/\s@]* before the colon there were as many
    #     places to put the separator as there were colons, and the tail rescanned
    #     to the end of the run for each of them -- so "a://" followed by 64 KB of
    #     colons, which is one line of a text file anybody can write, cost eight
    #     seconds of CPU inside `check`, the local no-network command, and an 8 MB
    #     document of such lines cost a quarter of an hour. Userinfo is
    #     user ":" password, so the user half cannot contain a colon either;
    #     excluding it makes that run deterministic and the whole pattern one
    #     forward scan. There is a timing test, and it now uses this shape.
    ("basic-auth-url", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s@:]*:[^/\s]*@")),
    (
        "assigned-secret",
        re.compile(
            r"""(?ix)
            # The key may itself be quoted -- "api_key": "..." is how it appears
            # in every JSON and YAML file, and requiring a bare word missed all
            # of them.
            ['"]?\b(?:pass(?:wd|word)?|secret|token|api[_-]?key|apikey|
               access[_-]?key|private[_-]?key|client[_-]?secret|auth)\b['"]?
            \s*[:=]\s*
            # A quoted value runs to its closing quote; an unquoted one stops at
            # whitespace or a comment. Terminating on , ) ; truncated
            # password=a,bcdefghij to one character, dropping it below the
            # length floor and leaving the secret in the clear.
            (?:
              "(?P<dq>[^"\n]{8,})"
            | '(?P<sq>[^'\n]{8,})'
            | (?P<val>[^\s'"#]{8,})
            )
            """
        ),
    ),
)


def redact(text: str) -> str:
    """Replace anything credential-shaped with a labelled placeholder.

    The placeholder keeps the shape of the line intact so it still reads as
    evidence -- ``api_key = <redacted:assigned-secret>`` tells a reviewer what
    was in the document without reproducing it.

    Call :func:`sanitise` rather than this. Redaction on its own is pattern
    matching against whatever bytes it is handed, and text can be written so that
    those bytes do not look like a credential until something downstream tidies
    them up.
    """
    result = str(text)
    for label, pattern in _SECRET_PATTERNS:
        if label == "assigned-secret":

            def _sub(match: re.Match[str]) -> str:
                secret = match.group("dq") or match.group("sq") or match.group("val")
                return match.group(0).replace(secret, "<redacted:assigned-secret>")

            result = pattern.sub(_sub, result)
        else:
            result = pattern.sub(f"<redacted:{label}>", result)
    return result


def sanitise(value: object, *, limit: int = _MAX_FIELD_LENGTH) -> str:
    """Make one piece of untrusted text safe to store, render and transmit.

    Sanitise **then** redact, and the order is the whole point. The other way
    round -- redact the raw string, then strip invisible characters -- hands
    redaction bytes that do not match a credential shape and then removes the
    reason they did not match: ``AKIA<zero-width space>IOSFODNN7EXAMPLE``
    survives redaction untouched, and the next step deletes the zero-width space
    and reassembles a live access key in the stored value, which then goes to the
    API and into the report. Every pattern above can be defeated that way, by
    anyone who can type into the form or edit the document they send you.

    So: normalise first, so redaction sees the string the reader will see; then
    redact; then cap to the field's own budget. The final cap cannot re-expose
    anything, because by then the credential shapes have already been replaced.
    """
    normalised = safe_text(value, limit=_MAX_SCANNED_LENGTH)
    return safe_text(redact(normalised), limit=limit)


def validate_env_var_name(name: str, *, where: str) -> str:
    """Confirm a config field holds an environment variable *name*, not a secret."""
    text = str(name).strip()
    if "://" in text or "/" in text:
        raise ValidationError(
            f"{where} must be the NAME of an environment variable, not a URL or path"
        )
    if not text or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        raise ValidationError(f"{where} is not a valid environment variable name: {name!r}")
    return text


_READ_CHUNK = 1024 * 1024


def read_text_file(path: str | Path, *, max_bytes: int) -> str:
    """Read one file through a descriptor, refusing anything that is not a regular file.

    Used for every file this tool opens, and the evidence documents are the
    reason it is written this way rather than as ``Path.read_text()``.

    * ``O_NOFOLLOW`` because an evidence folder is usually a shared drop
      directory -- somebody in procurement saves the attachments there -- and
      following a symlink out of it would let whoever can write to that directory
      aim this reader at any file the running account can open. ELOOP surfaces as
      a refusal.
    * ``O_NONBLOCK`` because a FIFO at the path blocks inside ``os.open``, before
      the regular-file check can refuse it, and would hang the run with no
      timeout and nothing in the log. Cleared once the descriptor is known to be
      a regular file.
    * The size is checked from ``fstat`` before reading and again while reading:
      the first tells the truth about a regular file, the second catches one that
      grows underneath us.

    Decoding is lossy on purpose. A SOC 2 report exported from a PDF is full of
    ligatures and stray bytes, and refusing to read it over one undecodable
    character would turn "the report is unusual" into "the review did not run".
    """
    file_path = Path(path).expanduser()
    try:
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {file_path}") from exc
    except OSError as exc:
        raise ValidationError(f"cannot open {file_path}: {exc}") from exc

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f"{file_path} is not a regular file; refusing to read it")
        if info.st_size > max_bytes:
            raise ValidationError(
                f"{file_path} is {info.st_size} bytes, above the {max_bytes} byte limit"
            )
        os.set_blocking(fd, True)

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValidationError(
                    f"{file_path} exceeds the {max_bytes} byte limit while reading"
                )
            chunks.append(chunk)
    except OSError as exc:
        raise ValidationError(f"cannot read {file_path}: {exc}") from exc
    finally:
        os.close(fd)

    return b"".join(chunks).decode("utf-8", "replace")
