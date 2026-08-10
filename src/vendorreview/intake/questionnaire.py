"""The intake questionnaire: how this vendor is going to be used.

Deliberately not a security questionnaire. The vendor answers one of those, and
their answers arrive as evidence (:mod:`vendorreview.evidence.responses`). This
form is about *your* side of the engagement -- what data goes in, how it
connects, what breaks if it stops -- and it is the half nobody writes down.

Two constraints pulled against each other, and both mattered.

**It has to be answerable in ten minutes by someone who is not in security.**
A form that takes an afternoon does not get filled in; the contract gets signed
without a review, and the tool has made things worse than the wiki page it
replaced. So the fields are short, the vocabulary is procurement's rather than
the framework's, and free text is accepted where a taxonomy would force a guess.

**Blank has to mean blank.** Every unanswered field is recorded rather than
defaulted, because the difference between "there is no SCIM" and "nobody asked
about SCIM" is the difference between a finding and a question, and this tool
exists to keep those apart.

The parser is strict about structure and forgiving about content: unknown keys
are rejected outright, but a field it cannot interpret becomes an unanswered
question rather than an error, so one odd answer never blocks a whole review.

Everything typed here leaves this module sanitised and redacted, and
:func:`scrub_intake` is where that is guaranteed rather than intended -- see its
docstring for why the guarantee is made over the finished model rather than at
each of the forty places that build one.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from ..models import (
    Connection,
    Criticality,
    DataClass,
    Exposure,
    Fact,
    Hosting,
    Integration,
    VendorIntake,
)
from ..validation import ValidationError, read_text_file, sanitise

_MAX_INTAKE_BYTES = 512 * 1024

# The questions, in the order they appear on the form. Kept here rather than
# scattered through the parser so `vendorreview questions` can print the blank
# form and a requester can see the whole ask before they start.
QUESTIONS: dict[str, str] = {
    "vendor": "Which company is this?",
    "service": "What does the service actually do for us?",
    "requesting_team": "Which team is asking for it?",
    "owner": "Who owns this relationship once it is signed?",
    "stage": "Where are we: evaluating, negotiating, renewing, or already in_use?",
    "hosting": "How does it run: saas, self_hosted, or hybrid?",
    "data_classes": "What kinds of data will the vendor process?",
    "data_subjects": "Whose data is it (employees, customers, partners, public)?",
    "record_volume": "Roughly how many records or people?",
    "data_residency": "Which countries will the data be stored and processed in?",
    "cross_border": "Will data leave that region for support, backup or analytics?",
    "subprocessors": "Which other companies does the vendor pass the data to?",
    "retention": "How long does the vendor keep the data?",
    "deletion_on_termination": "Is deletion on termination contractually committed?",
    "integrations": "How does it connect to our systems?",
    "oauth_scopes": "If OAuth or an app grant is involved, which scopes exactly?",
    "exposure": "How is the service reachable: internet, restricted, or private?",
    "sso_available": "Does it support SAML or OIDC against our identity provider?",
    "scim_available": "Does it support SCIM provisioning and deprovisioning?",
    "mfa_enforced": "Can MFA be enforced for every account, including vendor support?",
    "admin_roles": "What administrative roles exist, and who will hold them?",
    "audit_log_export": "Can we export the audit log into our own SIEM?",
    "criticality": "How critical is it: critical, important, or routine?",
    "outage_impact": "What happens to the business if it is unavailable for a week?",
    "contract_status": "Where is the contract: draft, in negotiation, signed?",
    "dpa_status": "Is a data processing agreement executed?",
    "breach_notification": "What breach notification timeline does the contract commit to?",
    "right_to_audit": "Does the contract give us a right to audit or reassess?",
    "regulated_regimes": "Does any regulation apply (GDPR, HIPAA, PCI DSS, other)?",
    "evidence_supplied": "What has the vendor sent us?",
}

_ALLOWED_KEYS = set(QUESTIONS)

_STAGES = ("evaluating", "negotiating", "renewing", "in_use")

# Synonyms a requester will plausibly type. Accepting these is not laxity: the
# alternative is a validation error on a form that a procurement analyst filled
# in correctly in every way that matters, and that error is how a review does not
# happen.
_DATA_SYNONYMS: dict[str, DataClass] = {
    "pii": DataClass.PII,
    "personal": DataClass.PII,
    "personal data": DataClass.PII,
    "customer data": DataClass.PII,
    "employee data": DataClass.PII,
    "hr data": DataClass.PII,
    "regulated": DataClass.REGULATED,
    "health": DataClass.REGULATED,
    "phi": DataClass.REGULATED,
    "medical": DataClass.REGULATED,
    "payment": DataClass.REGULATED,
    "card": DataClass.REGULATED,
    "pci": DataClass.REGULATED,
    "financial": DataClass.REGULATED,
    "credentials": DataClass.CREDENTIALS,
    "secrets": DataClass.CREDENTIALS,
    "passwords": DataClass.CREDENTIALS,
    "keys": DataClass.CREDENTIALS,
    "tokens": DataClass.CREDENTIALS,
    "confidential": DataClass.CONFIDENTIAL,
    "commercial": DataClass.CONFIDENTIAL,
    "contracts": DataClass.CONFIDENTIAL,
    "source code": DataClass.CONFIDENTIAL,
    "ip": DataClass.CONFIDENTIAL,
    "internal": DataClass.INTERNAL,
    "public": DataClass.PUBLIC,
    "none": DataClass.PUBLIC,
}

_HOSTING_SYNONYMS: dict[str, Hosting] = {
    "saas": Hosting.SAAS,
    "cloud": Hosting.SAAS,
    "vendor hosted": Hosting.SAAS,
    "multi-tenant": Hosting.SAAS,
    "self_hosted": Hosting.SELF_HOSTED,
    "self hosted": Hosting.SELF_HOSTED,
    "on prem": Hosting.SELF_HOSTED,
    "on_prem": Hosting.SELF_HOSTED,
    "on-premise": Hosting.SELF_HOSTED,
    "our tenancy": Hosting.SELF_HOSTED,
    "hybrid": Hosting.HYBRID,
    "connector": Hosting.HYBRID,
    "agent": Hosting.HYBRID,
}

_INTEGRATION_SYNONYMS: dict[str, Integration] = {
    "sso": Integration.SSO,
    "saml": Integration.SSO,
    "oidc": Integration.SSO,
    "scim": Integration.SCIM,
    "provisioning": Integration.SCIM,
    "api key": Integration.API_KEY,
    "api_key": Integration.API_KEY,
    "apikey": Integration.API_KEY,
    "token": Integration.API_KEY,
    "oauth": Integration.OAUTH,
    "app grant": Integration.OAUTH,
    "graph": Integration.OAUTH,
    "webhook": Integration.WEBHOOK,
    "callback": Integration.WEBHOOK,
    "agent": Integration.AGENT,
    "endpoint agent": Integration.AGENT,
    "installed": Integration.AGENT,
    "none": Integration.NONE,
}

_EXPOSURE_SYNONYMS: dict[str, Exposure] = {
    "internet": Exposure.INTERNET,
    "public": Exposure.INTERNET,
    "internet facing": Exposure.INTERNET,
    "restricted": Exposure.RESTRICTED,
    "vpn": Exposure.RESTRICTED,
    "allowlist": Exposure.RESTRICTED,
    "ip allowlist": Exposure.RESTRICTED,
    "zero trust": Exposure.RESTRICTED,
    "private": Exposure.PRIVATE,
    "private link": Exposure.PRIVATE,
    "no inbound": Exposure.PRIVATE,
}

_CRITICALITY_SYNONYMS: dict[str, Criticality] = {
    "critical": Criticality.CRITICAL,
    "tier 1": Criticality.CRITICAL,
    "business critical": Criticality.CRITICAL,
    "important": Criticality.IMPORTANT,
    "tier 2": Criticality.IMPORTANT,
    "routine": Criticality.ROUTINE,
    "tier 3": Criticality.ROUTINE,
    "low": Criticality.ROUTINE,
}

_TRUE = {"yes", "y", "true", "1", "required", "enforced", "enabled", "signed", "executed"}
_FALSE = {"no", "n", "false", "0", "none", "not required", "disabled", "unsigned"}

# Free-text fields, and the budget each gets. A cap per field rather than one
# global cap, because a 60 KB "what does it do" answer is a paste accident and a
# 60 KB subprocessor list is a real one.
_TEXT_FIELDS: tuple[str, ...] = (
    "vendor",
    "service",
    "requesting_team",
    "owner",
    "record_volume",
    "data_residency",
    "subprocessors",
    "retention",
    "oauth_scopes",
    "admin_roles",
    "outage_impact",
    "contract_status",
    "breach_notification",
)

_TRI_BOOL_FIELDS: tuple[str, ...] = (
    "cross_border",
    "deletion_on_termination",
    "sso_available",
    "scim_available",
    "mfa_enforced",
    "audit_log_export",
    "dpa_status",
    "right_to_audit",
)


def clean(value: object, *, limit: int = 600) -> str:
    """Sanitise and redact one answer.

    Every free-text field goes through this, not just the ones that look risky.
    Requesters paste API keys into "which scopes exactly", tenant admin
    credentials into "who will hold them", and a whole connection string into
    "how does it connect" -- routinely, and without thinking, because the form
    asks a technical question and they answer it with the technical detail.

    Redaction happens here rather than at the renderers because there are four
    sinks -- the API payload, the Markdown report, the HTML report, the review
    history -- and doing it at each means eventually forgetting one. Doing it
    once, at the boundary where untrusted text enters, means no downstream code
    has to know.

    Calling this at every parse site is still a discipline rather than a
    guarantee, which is what :func:`scrub_intake` is for.
    """
    return sanitise(value, limit=limit)


def _tri_bool(value: Any) -> bool | None:
    """Parse a yes/no answer, returning None for anything unrecognised.

    None is a first-class result, not a fallback. A requester who wrote "on their
    roadmap for Q3" has not said yes and has not said no, and forcing that into a
    boolean would either invent a finding or hide one.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().casefold()
    if not text:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


# The most entries any list answer contributes, matching the cap the integration
# list already carried. Nobody names more than a handful of data types, data
# subjects, regimes or documents, and the cap is not about tidiness: every one of
# these lands in the JSON report and in the API request whole, and an
# unrecognised entry is amplified into a sentence of its own on the way. A
# quarter-megabyte `data_classes` answer -- comfortably inside the intake file
# budget, and free to write -- turned into twenty thousand vocabulary notes, a
# 2.5 MB API request and a 2.6 MB report.
_MAX_LIST_ENTRIES = 40


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    elif isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        return []
    return parts[:_MAX_LIST_ENTRIES]


def _map_terms(values: list[str], synonyms: dict[str, Any]) -> tuple[list[Any], list[str]]:
    """Map free-text answers onto the taxonomy, reporting what did not map."""
    mapped: list[Any] = []
    unmapped: list[str] = []
    for raw in values:
        key = raw.strip().casefold()
        hit = synonyms.get(key)
        if hit is None:
            hit = next((value for term, value in synonyms.items() if term in key), None)
        if hit is None:
            unmapped.append(raw)
        elif hit not in mapped:
            mapped.append(hit)
    return mapped, unmapped


def _parse_integrations(value: Any) -> tuple[list[Connection], list[str]]:
    """Parse the integration list. A bare string is a pattern name."""
    connections: list[Connection] = []
    problems: list[str] = []

    if value is None:
        return connections, problems
    entries: list[Any]
    if isinstance(value, str):
        entries = list(_as_list(value))
    elif isinstance(value, list):
        entries = list(value)
    else:
        problems.append("integrations should be a list; the value given was ignored")
        return connections, problems

    for entry in entries[:40]:
        if isinstance(entry, str):
            # Bare pattern name. Everything else about it is unknown, which the
            # controls layer will notice -- better than dropping the connection.
            #
            # Cleaned like every other answer. This branch sanitised without
            # redacting for a while, and `integrations: [api_key sk_live_...]` --
            # the obvious way to answer "how does it connect" -- put the key in
            # the API payload and the JSON report while the same string written
            # as a mapping was redacted. One field clear and its neighbour
            # redacted is worse than either alone: it reads as deliberate.
            text = clean(entry, limit=160)
            mapped, _ = _map_terms([text], _INTEGRATION_SYNONYMS)
            pattern = mapped[0] if mapped else Integration.NONE
            connections.append(Connection(pattern=pattern, name=text))
            continue
        if not isinstance(entry, dict):
            problems.append("an integration entry was not a name or a mapping and was ignored")
            continue
        raw_pattern = clean(entry.get("pattern") or entry.get("type") or "", limit=80)
        mapped, _ = _map_terms([raw_pattern], _INTEGRATION_SYNONYMS)
        pattern = mapped[0] if mapped else Integration.NONE
        name = clean(entry.get("name") or raw_pattern, limit=160)
        if not name and pattern is Integration.NONE:
            problems.append("an integration entry named neither a pattern nor a system")
            continue
        direction = str(entry.get("direction") or "unknown").strip().casefold()
        if direction not in {"inbound", "outbound", "bidirectional", "unknown"}:
            direction = "unknown"
        connections.append(
            Connection(
                pattern=pattern,
                name=name,
                scopes=clean(entry.get("scopes") or "", limit=300),
                direction=direction,
                notes=clean(entry.get("notes") or "", limit=300),
            )
        )
    return connections, problems


def parse_intake(raw: Any, *, source: str = "intake") -> VendorIntake:
    """Build a :class:`VendorIntake` from parsed YAML.

    Unknown keys are rejected. A misspelled ``scim_avail:`` silently doing
    nothing would produce a review saying SCIM was never mentioned, against a
    team that answered the question.
    """
    if not isinstance(raw, dict):
        raise ValidationError("the intake file must be a mapping of question keys to answers")

    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in the intake: {', '.join(unknown)}. "
            f"Run `vendorreview questions` for the blank form. Valid keys: "
            f"{', '.join(sorted(_ALLOWED_KEYS))}"
        )

    intake = VendorIntake(source_name=source)
    facts: list[Fact] = []
    unanswered: list[str] = []

    def record(key: str, value: object, *, present: bool) -> None:
        if present:
            facts.append(
                Fact(id=key, question=QUESTIONS[key], value=clean(value, limit=400), source=source)
            )
        else:
            unanswered.append(QUESTIONS[key])

    # -- plain text -------------------------------------------------------
    for key in _TEXT_FIELDS:
        text = clean(raw.get(key) or "", limit=600)
        setattr(intake, key, text)
        record(key, text, present=bool(text))

    # -- stage ------------------------------------------------------------
    stage = str(raw.get("stage") or "").strip().casefold().replace(" ", "_").replace("-", "_")
    if stage in _STAGES:
        intake.stage = stage
        record("stage", stage, present=True)
    else:
        intake.stage = "evaluating"
        # Recorded as unanswered even though a default was applied, so the review
        # never claims the requester told us where the deal stands.
        unanswered.append(QUESTIONS["stage"])

    # -- taxonomies -------------------------------------------------------
    data_classes, unmapped_data = _map_terms(_as_list(raw.get("data_classes")), _DATA_SYNONYMS)
    intake.data_classes = tuple(data_classes)
    record("data_classes", ", ".join(d.value for d in data_classes), present=bool(data_classes))

    subjects = [clean(s, limit=80) for s in _as_list(raw.get("data_subjects"))]
    intake.data_subjects = tuple(subjects)
    record("data_subjects", ", ".join(subjects), present=bool(subjects))

    hostings, _ = _map_terms(_as_list(raw.get("hosting")), _HOSTING_SYNONYMS)
    intake.hosting = hostings[0] if hostings else None
    record("hosting", intake.hosting.value if intake.hosting else "", present=bool(hostings))

    exposures, _ = _map_terms(_as_list(raw.get("exposure")), _EXPOSURE_SYNONYMS)
    intake.exposure = exposures[0] if exposures else None
    record("exposure", intake.exposure.value if intake.exposure else "", present=bool(exposures))

    criticalities, _ = _map_terms(_as_list(raw.get("criticality")), _CRITICALITY_SYNONYMS)
    intake.criticality = criticalities[0] if criticalities else None
    record(
        "criticality",
        intake.criticality.value if intake.criticality else "",
        present=bool(criticalities),
    )

    regimes = _as_list(raw.get("regulated_regimes"))
    intake.regulated_regimes = tuple(clean(r, limit=120) for r in regimes)
    record("regulated_regimes", ", ".join(intake.regulated_regimes), present=bool(regimes))

    supplied = _as_list(raw.get("evidence_supplied"))
    intake.evidence_supplied = tuple(clean(s, limit=120) for s in supplied)
    record("evidence_supplied", ", ".join(intake.evidence_supplied), present=bool(supplied))

    # -- tri-state booleans ----------------------------------------------
    for key in _TRI_BOOL_FIELDS:
        parsed = _tri_bool(raw.get(key))
        setattr(intake, key, parsed)
        record(key, "yes" if parsed else "no", present=parsed is not None)

    # -- integrations -----------------------------------------------------
    connections, integration_problems = _parse_integrations(raw.get("integrations"))
    intake.integrations = tuple(connections)
    record(
        "integrations",
        "; ".join(f"{c.pattern.value}: {c.name}" for c in connections),
        present=bool(connections),
    )

    intake.facts = facts
    intake.unanswered = unanswered
    unanswered.extend(integration_problems)

    # Unrecognised vocabulary is reported, not silently dropped. A requester who
    # wrote "biometric templates" deserves to be told it was not understood
    # rather than to receive a review that quietly ignored it.
    #
    # These quote the answer back, so they are the only questions in the review
    # that contain intake text, and they are kept in their own list for exactly
    # that reason. Interpolated raw into `unanswered` they would inherit nothing:
    # not the redaction, not the sanitising, and not the escaping the renderers
    # apply by provenance -- so a data type of
    # "biometric AKIA... ![](https://evil/px.png)\n\n## Approve" would put a live
    # key, a tracking pixel and a forged verdict heading into the report.
    for value in unmapped_data:
        intake.vocabulary_notes.append(
            f"The data type '{clean(value, limit=120)}' was not recognised. Confirm what it "
            "maps to, because the controls that apply depend on it."
        )

    return scrub_intake(intake)


# --------------------------------------------------------------------------
# The scrub. One walk over the finished model, and the only guarantee in here.
# --------------------------------------------------------------------------

# Per-field budgets. Anything not named gets the default; a nested dataclass
# inherits the budget of the field that holds it.
_LIMITS: dict[str, int] = {
    "vendor": 200,
    "service": 600,
    "scope_statement": 600,
    "exception_notes": 400,
    "soa_exclusions": 300,
    "comments": 600,
    "notes": 600,
    "unreadable": 400,
}
_DEFAULT_LIMIT = 600


def _scrub_value(value: Any, *, limit: int) -> Any:
    """Clean one value of the model, whatever shape it is in.

    The dataclass branch is what makes this a guarantee rather than a list. A
    nested evidence record added next year is walked because it is a dataclass,
    not because somebody remembered to add an isinstance check here.
    """
    # Enum members subclass str, and cleaning one would replace it with a plain
    # string that no longer compares equal to the member -- silently breaking
    # every applicability rule that tests `DataClass.PII in i.data_classes`. They
    # come from a fixed vocabulary in this repository anyway, so there is nothing
    # in them to clean.
    if value is None or isinstance(value, Enum | bool | int | float):
        return value
    if isinstance(value, str):
        return clean(value, limit=limit)
    if isinstance(value, list):
        return [_scrub_value(item, limit=limit) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(item, limit=limit) for item in value)
    if isinstance(value, dict):
        return {
            clean(key, limit=120): _scrub_value(item, limit=_LIMITS.get(str(key), limit))
            for key, item in value.items()
        }
    if is_dataclass(value) and not isinstance(value, type):
        changes = {
            spec.name: _scrub_value(
                getattr(value, spec.name), limit=_LIMITS.get(spec.name, _DEFAULT_LIMIT)
            )
            for spec in fields(value)
        }
        return replace(value, **changes)
    return value


def scrub_intake(intake: VendorIntake) -> VendorIntake:
    """Sanitise and redact every string on a finished intake. The choke point.

    Calling :func:`clean` at each parse site is a discipline, and disciplines
    fail quietly. Three fields reached the API with credentials in them because
    of exactly that: a bare-string integration entry that took a different
    branch, the unrecognised-vocabulary note that was built by interpolation
    after parsing, and the vendor's own evidence documents, which never went
    through the intake parser at all. Each was one missing call, each looked fine
    in review, and each was found only by grepping a payload for a key that
    should not have been in it.

    So the guarantee is made here instead, over the finished model: walk every
    field, clean every string, recurse into nested dataclasses, lists, tuples and
    dicts, and a field added next year is covered by the walk whether or not
    whoever adds it reads this file. It runs at the end of :func:`parse_intake`
    and again every time an evidence document is attached, which is the only
    other way text gets onto an intake.

    Idempotent by construction -- ``<redacted:...>`` is not credential-shaped --
    so running it twice costs a pass over a few kilobytes and nothing else.
    """
    for spec in fields(VendorIntake):
        limit = _LIMITS.get(spec.name, _DEFAULT_LIMIT)
        setattr(intake, spec.name, _scrub_value(getattr(intake, spec.name), limit=limit))
    return intake


def load_intake(path: str | Path) -> VendorIntake:
    """Read and validate an intake file."""
    file_path = Path(path).expanduser()
    text = read_text_file(file_path, max_bytes=_MAX_INTAKE_BYTES)
    try:
        # safe_load only: full load constructs arbitrary Python objects, which
        # would turn a form somebody emailed into procurement into code execution
        # on the reviewer's machine.
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationError(f"the intake file is not valid YAML: {exc}") from exc
    return parse_intake(raw or {}, source=file_path.name)


def blank_form() -> str:
    """The empty questionnaire, printed by ``vendorreview questions``.

    Handing this to whoever wants the vendor is the point. A security team that
    publishes what it will ask gets better answers than one that asks in a
    meeting the week before signature, because the requester can go and find out
    rather than guess in the room.
    """
    lines = [
        "# vendorreview intake — third-party security review",
        "#",
        "# This is about how WE will use the vendor, not about the vendor's own",
        "# controls — they answer that separately and you attach their answers.",
        "#",
        "# Leave anything you do not know blank rather than guessing. A blank",
        "# becomes a question we put to the vendor; a wrong answer becomes a",
        "# conclusion we get wrong.",
        "",
    ]
    hints = {
        "stage": "  # evaluating | negotiating | renewing | in_use",
        "hosting": "  # saas | self_hosted | hybrid",
        "data_classes": "  # e.g. personal data, confidential, credentials, internal, public",
        "data_subjects": "  # e.g. employees, customers, partners, public",
        "exposure": "  # internet | restricted | private",
        "criticality": "  # critical | important | routine",
        "cross_border": "  # yes | no",
        "deletion_on_termination": "  # yes | no",
        "sso_available": "  # yes | no",
        "scim_available": "  # yes | no",
        "mfa_enforced": "  # yes | no",
        "audit_log_export": "  # yes | no",
        "dpa_status": "  # yes | no",
        "right_to_audit": "  # yes | no",
        "regulated_regimes": "  # e.g. GDPR, HIPAA, PCI DSS",
        "evidence_supplied": "  # e.g. SOC 2 Type II, ISO 27001 certificate, pen test summary",
    }
    for key, question in QUESTIONS.items():
        lines.append(f"# {question}")
        if key == "integrations":
            lines += [
                "integrations:",
                "  - pattern:      # sso | scim | api_key | oauth | webhook | agent | none",
                "    name:         # which of our systems, or what it installs on",
                "    direction:    # inbound | outbound | bidirectional",
                "    scopes:       # the exact scopes or permissions, if any",
                "",
            ]
            continue
        lines.append(f"{key}:{hints.get(key, '')}")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "QUESTIONS",
    "blank_form",
    "clean",
    "load_intake",
    "parse_intake",
    "scrub_intake",
]
