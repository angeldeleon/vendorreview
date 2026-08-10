"""The review model: what the vendor attests to, what is missing, what was decided.

A third-party review has a shape a code review does not. There is no repository
to read and no system to connect to. What there is, is a form somebody in
procurement filled in and a folder of documents the vendor sent over: a SOC 2
report, maybe a penetration test summary, a DPA, a completed security
questionnaire. The whole exercise is reading those against how the vendor is
actually going to be used.

That makes one distinction load-bearing, and it runs through every type in this
file:

**Attested, definitively absent, and not evidenced are three different things.**
"The SOC 2 does not mention SCIM" is not "the vendor has no SCIM". It is
*unknown*, and the honest response is a question rather than a finding. Merging
the two is this tool's worst available failure mode: it puts a false accusation
in front of a vendor's account team, the vendor's security lead disproves it in
ten minutes, and the next review this tool produces is not read. See
:class:`Attestation`, which exists so that merging them is something a
contributor has to type on purpose.

Three layers, in decreasing order of how much you should trust them:

1. **Declared and extracted facts** (:class:`VendorIntake`, :class:`EvidenceSet`)
   -- what the requesting team said and what the documents literally contain.
   Extraction is deterministic; no model decides whether a report says "Type II".
2. **Computed control results** (:mod:`vendorreview.controls`) -- which control
   objectives are in scope given the intake, and what the evidence settles about
   each. Pure functions; run it twice and get the same answer.
3. **Reasoned findings** (:class:`Finding`) -- how these particular facts combine
   into something worth raising. The model's contribution, constrained to citing
   facts and controls that exist.

The decision is computed from 2. It is never the model's to make.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class _RankOrdered:
    """Comparison by ``rank`` for the ordered enums below.

    These are ``str`` enums, so without explicit operators they order
    alphabetically -- ``CRITICAL < HIGH`` would be True because "critical" sorts
    first, and ``max()`` over severities would return the wrong one.
    ``functools.total_ordering`` cannot help: it only fills in operators a class
    lacks, and ``str`` supplies all four, so it silently adds nothing.
    """

    @property
    def rank(self) -> int:  # pragma: no cover - overridden by each enum
        raise NotImplementedError

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank


class Attestation(str, Enum):
    """Attested, definitively absent, or not evidenced. The tool's core type.

    The third value is why this is not a ``bool``, and not a ``bool | None``
    either. ``bool | None`` invites ``if not attested:`` and silently merges the
    last two, which is exactly the merge that must not happen. Naming the state
    makes it something you have to write deliberately.

    * ``ATTESTED`` -- a document or a signed questionnaire response says so.
      Not verified: attested. Nobody here logged into the vendor's console.
    * ``ABSENT`` -- somebody said no. The questionnaire answer was "no", the
      certificate is expired, the report is a Type I when a Type II was needed.
      This is the only state that becomes a gap.
    * ``NOT_EVIDENCED`` -- nothing in the pack settles it. Becomes a question,
      and caps at :data:`vendorreview.analyze.severity.UNKNOWN_CAP` if it becomes
      anything at all.

    The failure mode: a SOC 2 report is scoped to Security and says nothing about
    encryption key management, because it did not have to. Reading that silence
    as "the vendor does not manage keys" is wrong, unfair, and the fastest way to
    have a review ignored.
    """

    ATTESTED = "attested"
    ABSENT = "absent"
    NOT_EVIDENCED = "not_evidenced"

    @property
    def is_attested(self) -> bool:
        return self is Attestation.ATTESTED

    @property
    def is_absent(self) -> bool:
        return self is Attestation.ABSENT

    @property
    def is_unknown(self) -> bool:
        return self is Attestation.NOT_EVIDENCED

    @classmethod
    def from_optional(cls, value: bool | None) -> Attestation:
        """Map a tri-state boolean. ``None`` is unknown, never false."""
        if value is None:
            return cls.NOT_EVIDENCED
        return cls.ATTESTED if value else cls.ABSENT

    @property
    def label(self) -> str:
        return {
            Attestation.ATTESTED: "attested",
            Attestation.ABSENT: "absent",
            Attestation.NOT_EVIDENCED: "not evidenced",
        }[self]


def strongest(*values: Attestation) -> Attestation:
    """Combine evidence for one objective from several sources.

    Attested wins over absent, and both win over silence. That order is not
    optimism: a "no" on a generic questionnaire and a "yes" in an audited SOC 2
    report are not equal claims, and the report is the one somebody signed an
    opinion on. Where they genuinely conflict the review still shows both,
    because :func:`Review.conflicts` lists them.
    """
    if any(v.is_attested for v in values):
        return Attestation.ATTESTED
    if any(v.is_absent for v in values):
        return Attestation.ABSENT
    return Attestation.NOT_EVIDENCED


class Severity(_RankOrdered, str, Enum):
    """How much a gap matters. Computed, never chosen by the model."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DataClass(_RankOrdered, str, Enum):
    """What the vendor will process. The biggest driver of what applies.

    Ordered by consequence of loss, not by how procurement talks about it.
    """

    REGULATED = "regulated"
    """Health, payment card, or anything under a named regime. Brings
    obligations a review cannot waive."""

    PII = "pii"
    """Identifies a person. Employee data counts, and teams forget that
    constantly when the data subjects are their own colleagues."""

    CREDENTIALS = "credentials"
    """Secrets, keys, tokens, session material. A vendor holding these turns one
    vendor incident into an incident on everything they can reach."""

    CONFIDENTIAL = "confidential"
    """Commercially sensitive: contracts, pricing, roadmap, source."""

    INTERNAL = "internal"
    PUBLIC = "public"

    @property
    def rank(self) -> int:
        return _DATA_RANK[self]


_DATA_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.CREDENTIALS: 3,
    DataClass.PII: 3,
    DataClass.REGULATED: 4,
}


class Blast(_RankOrdered, str, Enum):
    """How far a compromise of this vendor reaches. The other half of severity.

    Two vendors holding identical data are not the same review if one of them
    also installs an agent on every laptop. What decides this is the integration
    pattern, not the vendor's own security posture -- which is why it is derived
    from the intake and clamped, rather than left to prose.

    Ordered by how much of your estate is reachable from the vendor's side of the
    connection.
    """

    CONTAINED = "contained"
    """Only the data the vendor holds. No live connection back."""

    CONNECTED = "connected"
    """One or more internal systems, through an API key, OAuth grant or
    webhook."""

    IDENTITY = "identity"
    """The corporate identity plane. A vendor with SCIM write or an SSO admin
    role can create accounts, which reaches everything SSO reaches."""

    FLEET = "fleet"
    """Employee endpoints, because the vendor ships an agent that runs as root
    on them and updates itself."""

    CUSTOMER = "customer"
    """Your customers. The only category where a vendor incident becomes your
    breach notification obligation and your customers' problem at once."""

    @property
    def rank(self) -> int:
        return _BLAST_RANK[self]


_BLAST_RANK = {
    Blast.CONTAINED: 0,
    Blast.CONNECTED: 1,
    Blast.IDENTITY: 2,
    Blast.FLEET: 3,
    Blast.CUSTOMER: 4,
}


class Hosting(str, Enum):
    """Where the software runs, which decides whose controls apply."""

    SAAS = "saas"
    """The vendor runs it. Most of your controls become contract terms and
    tenant configuration rather than engineering."""

    SELF_HOSTED = "self_hosted"
    """You run their software in your environment. Their SOC 2 covers their
    corporate controls and says nothing about your deployment."""

    HYBRID = "hybrid"
    """A hosted control plane with a component in your environment -- an agent,
    a connector, a data plane. The pattern that surprises people, because the
    attestation covers one half."""


class Integration(str, Enum):
    """How the vendor connects. Where third-party risk actually concentrates."""

    SSO = "sso"
    SCIM = "scim"
    API_KEY = "api_key"
    OAUTH = "oauth"
    WEBHOOK = "webhook"
    AGENT = "agent"
    NONE = "none"


class Exposure(str, Enum):
    """How the vendor's service is reachable on the network."""

    INTERNET = "internet"
    RESTRICTED = "restricted"
    """IP allow-listed, VPN, or behind a zero-trust proxy."""

    PRIVATE = "private"
    """Private link or no inbound path at all."""


class Criticality(_RankOrdered, str, Enum):
    """What the business loses when the vendor is unavailable."""

    CRITICAL = "critical"
    IMPORTANT = "important"
    ROUTINE = "routine"

    @property
    def rank(self) -> int:
        return {Criticality.ROUTINE: 0, Criticality.IMPORTANT: 1, Criticality.CRITICAL: 2}[self]


class Decision(str, Enum):
    """The output of a vendor review.

    A findings list is not a review. Somebody has to say whether this vendor can
    be signed, and under what conditions -- otherwise procurement reads a
    document, learns nothing they can act on, and signs anyway on the date they
    were always going to sign.
    """

    APPROVE = "approve"
    APPROVE_WITH_CONDITIONS = "approve_with_conditions"
    MORE_INFORMATION_NEEDED = "more_information_needed"
    """Not a rejection. Something material is not evidenced, and answering it
    changes the outcome -- so the honest response is to ask rather than to guess
    in either direction. The commonest verdict on a first pass, and the reason
    the tool exists: the questions come out in an hour instead of a week."""

    DO_NOT_PROCEED = "do_not_proceed"
    """This cannot be signed as described."""


class Confidence(str, Enum):
    """How much the review itself should be trusted.

    Surfaced because a review built on a half-filled form and no documents, and
    one built on a complete intake plus a current Type II, should not look
    identical on the page.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Framework:
    """A control reference in one framework.

    Identifier and title are stored separately so the report can print
    ``ISO 27001:2022 A.5.20 — Addressing information security within supplier
    agreements`` without anyone typing a control number into a sentence and
    getting it wrong.
    """

    name: str
    identifier: str
    title: str = ""

    def __str__(self) -> str:
        return f"{self.name} {self.identifier}" + (f" — {self.title}" if self.title else "")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "identifier": self.identifier, "title": self.title}


@dataclass(frozen=True, slots=True)
class Fact:
    """One declared answer, or one thing a document literally said.

    The unit the analysis is allowed to cite. ``source`` records where it came
    from -- the intake form, the SOC 2, the pen test -- and ``line`` where in the
    document, because a review whose conclusions cannot be traced back to a page
    number is a review the vendor's security lead will dispute and win.
    """

    id: str
    question: str
    value: str
    source: str = "intake"
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "value": self.value,
            "source": self.source,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class Connection:
    """One declared integration between the vendor and your estate."""

    pattern: Integration = Integration.NONE
    name: str = ""
    scopes: str = ""
    """OAuth scopes or API permissions, verbatim. ``mail.read`` and
    ``mail.readwrite`` are one character apart and a different review."""

    direction: str = "unknown"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern.value,
            "name": self.name,
            "scopes": self.scopes,
            "direction": self.direction,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------
# Evidence. Everything below is extracted deterministically -- no model decides
# whether a report says "Type II" -- and every string is sanitised on the way in
# because the party being assessed supplied the document.
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Soc2Report:
    """What a SOC 2 report literally says, and what it conspicuously does not.

    Every field is a tri-state or a quoted string, because the interesting
    outcome of reading a SOC 2 is usually an absence: criteria that were not in
    scope, a subservice organisation carved out, a period that ended fourteen
    months ago. None of those are stated as problems in the report. They are
    stated as facts, in the middle of ninety pages, and skimming misses them.
    """

    source_name: str = ""
    report_type: str = ""
    """"Type II", "Type I", or empty when the report does not say."""

    type_two: Attestation = Attestation.NOT_EVIDENCED
    period_start: str = ""
    period_end: str = ""
    period_current: Attestation = Attestation.NOT_EVIDENCED
    """ATTESTED when the period ended inside the staleness window, ABSENT when it
    ended before it, NOT_EVIDENCED when no period was found. A stale report is
    genuinely absent evidence of anything current, which is why it is ABSENT and
    not merely unknown."""

    criteria: tuple[str, ...] = ()
    """Trust services criteria in scope. Security is always in scope; the other
    four are optional, and a report covering Security alone says nothing about
    availability or privacy however thick it is."""

    exceptions: Attestation = Attestation.NOT_EVIDENCED
    """ATTESTED means exceptions or deviations were noted -- i.e. there ARE
    exceptions. Read the field name as "exceptions were reported", not as "this
    is good"."""

    exception_notes: tuple[str, ...] = ()
    opinion: str = ""
    subservice_treatment: str = ""
    """"carve-out" or "inclusive". A carve-out means the report covers none of
    the controls at the subservice organisation -- routinely the cloud provider,
    routinely where the customer data actually sits. It is stated once, in a
    sentence, and it is the single most missed line in third-party review."""

    lines_read: int = 0
    pages: int = 0
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "report_type": self.report_type,
            "type_two": self.type_two.value,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "period_current": self.period_current.value,
            "criteria": list(self.criteria),
            "exceptions": self.exceptions.value,
            "exception_notes": list(self.exception_notes),
            "opinion": self.opinion,
            "subservice_treatment": self.subservice_treatment,
            "lines_read": self.lines_read,
            "pages": self.pages,
            "problems": list(self.problems),
        }


@dataclass(slots=True)
class IsoCertificate:
    """An ISO/IEC 27001 certificate, read for the two things that matter.

    A certificate is a page. The two facts on it that decide anything are the
    scope statement -- which is frequently narrower than the service being bought
    -- and the expiry date. The Statement of Applicability exclusions are the
    third, and are usually not on the certificate at all, which is itself worth
    reporting.
    """

    source_name: str = ""
    standard: str = ""
    """"ISO/IEC 27001:2022" or ":2013". The 2013 version was withdrawn; a
    certificate against it is not wrong, it is old."""

    certificate_number: str = ""
    scope_statement: str = ""
    scope_stated: Attestation = Attestation.NOT_EVIDENCED
    expiry: str = ""
    valid: Attestation = Attestation.NOT_EVIDENCED
    soa_exclusions: tuple[str, ...] = ()
    exclusions_stated: Attestation = Attestation.NOT_EVIDENCED
    lines_read: int = 0
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "standard": self.standard,
            "certificate_number": self.certificate_number,
            "scope_statement": self.scope_statement,
            "scope_stated": self.scope_stated.value,
            "expiry": self.expiry,
            "valid": self.valid.value,
            "soa_exclusions": list(self.soa_exclusions),
            "exclusions_stated": self.exclusions_stated.value,
            "lines_read": self.lines_read,
            "problems": list(self.problems),
        }


@dataclass(slots=True)
class PenTest:
    """A penetration test summary, read for date, scope, retest and counts.

    The retest is the field people skip. A test that found four highs and was
    never retested is a list of four highs, not a clean bill; a vendor that
    supplies the original report and no retest letter is usually telling you
    something without meaning to.
    """

    source_name: str = ""
    tested_on: str = ""
    current: Attestation = Attestation.NOT_EVIDENCED
    scope_statement: str = ""
    scope_stated: Attestation = Attestation.NOT_EVIDENCED
    retested: Attestation = Attestation.NOT_EVIDENCED
    findings: dict[str, int] = field(default_factory=dict)
    counts_stated: Attestation = Attestation.NOT_EVIDENCED
    lines_read: int = 0
    problems: tuple[str, ...] = ()

    def open_high(self) -> int:
        return int(self.findings.get("critical", 0)) + int(self.findings.get("high", 0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "tested_on": self.tested_on,
            "current": self.current.value,
            "scope_statement": self.scope_statement,
            "scope_stated": self.scope_stated.value,
            "retested": self.retested.value,
            "findings": dict(self.findings),
            "counts_stated": self.counts_stated.value,
            "lines_read": self.lines_read,
            "problems": list(self.problems),
        }


@dataclass(slots=True)
class Responses:
    """A completed security questionnaire, supplied as YAML.

    Structured because the alternative is a spreadsheet, and a spreadsheet is
    where third-party review goes to become unauditable. Each answer is a
    tri-state and carries the vendor's own words alongside it, so a "yes" with a
    caveat in the comment does not read as an unqualified yes.
    """

    source_name: str = ""
    answers: dict[str, Attestation] = field(default_factory=dict)
    comments: dict[str, str] = field(default_factory=dict)
    unknown_keys: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    def get(self, key: str) -> Attestation:
        return self.answers.get(key, Attestation.NOT_EVIDENCED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "answers": {k: v.value for k, v in sorted(self.answers.items())},
            "comments": dict(sorted(self.comments.items())),
            "unknown_keys": list(self.unknown_keys),
            "problems": list(self.problems),
        }


@dataclass(slots=True)
class EvidenceSet:
    """Everything the vendor supplied, after deterministic extraction.

    ``unreadable`` is not an error list. A document that could not be parsed is
    treated as **not evidenced** -- the objectives it would have settled stay
    unknown, and the review says which document it could not read. Crashing on a
    vendor-supplied file would be worse; silently skipping it would be much
    worse, because the review would then be quietly built on less than the reader
    believes.
    """

    soc2: Soc2Report | None = None
    iso: IsoCertificate | None = None
    pentest: PenTest | None = None
    responses: Responses | None = None
    unreadable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def supplied(self) -> list[str]:
        names = []
        if self.soc2 is not None:
            names.append("SOC 2")
        if self.iso is not None:
            names.append("ISO 27001")
        if self.pentest is not None:
            names.append("penetration test")
        if self.responses is not None:
            names.append("questionnaire responses")
        return names

    def response(self, key: str) -> Attestation:
        return self.responses.get(key) if self.responses else Attestation.NOT_EVIDENCED

    def to_dict(self) -> dict[str, Any]:
        return {
            "supplied": self.supplied(),
            "soc2": self.soc2.to_dict() if self.soc2 else None,
            "iso": self.iso.to_dict() if self.iso else None,
            "pentest": self.pentest.to_dict() if self.pentest else None,
            "responses": self.responses.to_dict() if self.responses else None,
            "unreadable": self.unreadable,
            "notes": self.notes,
        }


@dataclass(slots=True)
class VendorIntake:
    """Everything the requesting team declared, plus what the evidence contains.

    Deliberately shallow and answerable. A form nobody completes produces no
    reviews at all, which is worse than a form that misses a nuance -- and the
    unanswered fields are themselves an output, because "nobody could tell us
    which regions the data sits in" is the finding.
    """

    vendor: str = ""
    service: str = ""
    requesting_team: str = ""
    owner: str = ""
    stage: str = "evaluating"

    hosting: Hosting | None = None
    data_classes: tuple[DataClass, ...] = ()
    data_subjects: tuple[str, ...] = ()
    record_volume: str = ""
    data_residency: str = ""
    cross_border: bool | None = None
    subprocessors: str = ""
    retention: str = ""
    deletion_on_termination: bool | None = None

    integrations: tuple[Connection, ...] = ()
    oauth_scopes: str = ""
    exposure: Exposure | None = None

    sso_available: bool | None = None
    scim_available: bool | None = None
    mfa_enforced: bool | None = None
    admin_roles: str = ""
    audit_log_export: bool | None = None

    criticality: Criticality | None = None
    outage_impact: str = ""

    contract_status: str = ""
    dpa_status: bool | None = None
    breach_notification: str = ""
    right_to_audit: bool | None = None
    regulated_regimes: tuple[str, ...] = ()
    evidence_supplied: tuple[str, ...] = ()

    evidence: EvidenceSet = field(default_factory=EvidenceSet)

    facts: list[Fact] = field(default_factory=list)
    unanswered: list[str] = field(default_factory=list)
    """Questions left blank. Each becomes a candidate question, because on a
    vendor review an unanswered field is a real gap and not a formatting problem
    -- somebody has to go and ask the vendor.

    Written in this repository: these are the questions from the form, quoted
    back. Nothing the requester or the vendor typed appears here."""

    vocabulary_notes: list[str] = field(default_factory=list)
    """Answers the parser could not map onto the taxonomy, quoted back so the
    requester can say what they meant.

    Kept apart from :attr:`unanswered` because these carry text somebody else
    wrote and those do not, and a renderer has to know which it is holding.
    Escape the quoted answer or a data type named ``![](https://evil/px.png)``
    puts an image in the review; escape the form's own wording and
    ``(GDPR, HIPAA, PCI DSS, other)`` reaches the reader with backslashes in
    it."""

    document_lines: list[str] = field(default_factory=list)
    """Free text from a document with no parser of its own -- a DPA, a security
    addendum, an architecture note, the deck. Attached with ``--document`` and
    sent to the analysis layer verbatim, because prose cannot be summarised
    without losing what makes it useful.

    Not parsed into facts. Nothing here can settle a control objective, and that
    is deliberate: a claim extracted from prose by pattern matching would be
    indistinguishable in the report from one read off a certificate, and the two
    deserve different confidence. It is context for the reasoning layer and
    nothing else."""

    document_name: str = ""

    source_name: str = ""

    # -- derived -------------------------------------------------------

    def fact_ids(self) -> set[str]:
        return {f.id for f in self.facts}

    def max_data_class(self) -> DataClass:
        return max(self.data_classes, default=DataClass.INTERNAL)

    def patterns(self) -> set[Integration]:
        return {c.pattern for c in self.integrations if c.pattern is not Integration.NONE}

    def max_blast(self) -> Blast:
        """How far a compromise of this vendor reaches, from the declared design.

        The ceiling the gate clamps model claims to. Derived rather than asked,
        because "how bad would it be" is not a question a requesting team can
        answer and every one of them answers it optimistically.
        """
        reach = Blast.CONTAINED
        patterns = self.patterns()
        if patterns - {Integration.NONE}:
            reach = Blast.CONNECTED
        if Integration.SCIM in patterns or Integration.SSO in patterns:
            reach = max(reach, Blast.IDENTITY)
        if Integration.AGENT in patterns or self.hosting is Hosting.HYBRID:
            reach = max(reach, Blast.FLEET)
        if any(subject.casefold().startswith("customer") for subject in self.data_subjects):
            reach = max(reach, Blast.CUSTOMER)
        return reach

    def is_empty(self) -> bool:
        """True when there is not enough here to review.

        Callers must treat this as could-not-run. A review of an empty form that
        returns no findings is a clean bill of health for a vendor nobody looked
        at, which is the most dangerous document this tool could produce.
        """
        return not self.vendor or not self.facts

    def fingerprint(self) -> str:
        """Stable hash of the declared engagement.

        Prose is excluded on purpose: rewording what the service does is not a
        change to the risk, and treating it as one would make every re-review
        look like a new vendor and train the reader to ignore the diff.
        """
        parts = [
            f"vendor={self.vendor.casefold()}",
            f"stage={self.stage}",
            f"hosting={self.hosting.value if self.hosting else ''}",
            f"data={','.join(sorted(d.value for d in self.data_classes))}",
            f"subjects={','.join(sorted(s.casefold() for s in self.data_subjects))}",
            f"exposure={self.exposure.value if self.exposure else ''}",
            f"criticality={self.criticality.value if self.criticality else ''}",
            f"sso={self.sso_available}",
            f"scim={self.scim_available}",
            f"mfa={self.mfa_enforced}",
            f"dpa={self.dpa_status}",
            f"cross_border={self.cross_border}",
            f"regimes={','.join(sorted(self.regulated_regimes))}",
        ]
        parts += sorted(
            f"integration={c.pattern.value}|{c.name.casefold()}|{c.direction}"
            for c in self.integrations
        )
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "service": self.service,
            "requesting_team": self.requesting_team,
            "owner": self.owner,
            "stage": self.stage,
            "fingerprint": self.fingerprint(),
            "hosting": self.hosting.value if self.hosting else None,
            "data_classes": [d.value for d in self.data_classes],
            "data_subjects": list(self.data_subjects),
            "record_volume": self.record_volume,
            "data_residency": self.data_residency,
            "cross_border": self.cross_border,
            "subprocessors": self.subprocessors,
            "retention": self.retention,
            "deletion_on_termination": self.deletion_on_termination,
            "integrations": [c.to_dict() for c in self.integrations],
            "oauth_scopes": self.oauth_scopes,
            "exposure": self.exposure.value if self.exposure else None,
            "blast_radius": self.max_blast().value,
            "sso_available": self.sso_available,
            "scim_available": self.scim_available,
            "mfa_enforced": self.mfa_enforced,
            "admin_roles": self.admin_roles,
            "audit_log_export": self.audit_log_export,
            "criticality": self.criticality.value if self.criticality else None,
            "outage_impact": self.outage_impact,
            "contract_status": self.contract_status,
            "dpa_status": self.dpa_status,
            "breach_notification": self.breach_notification,
            "right_to_audit": self.right_to_audit,
            "regulated_regimes": list(self.regulated_regimes),
            "evidence_supplied": list(self.evidence_supplied),
            "evidence": self.evidence.to_dict(),
            "document_name": self.document_name,
            "facts": [f.to_dict() for f in self.facts],
            "unanswered": self.unanswered,
            "vocabulary_notes": self.vocabulary_notes,
        }


@dataclass(frozen=True, slots=True)
class ControlGap:
    """One applicable control objective the evidence did not satisfy.

    Carries its own :class:`Attestation`, and that field is the difference
    between "the vendor told us there is no SCIM" and "nothing in the pack
    mentions SCIM". Both belong in the review. Only the first is a finding
    against the vendor, and printing them the same way is how a review gets
    disputed line by line.
    """

    control_id: str
    title: str
    attestation: Attestation
    why_applicable: str
    what_is_missing: str
    severity: Severity
    severity_reason: str = ""
    """One line stating why this scored what it did -- the catalog rating, the
    engagement adjustment, the unknown cap.

    Printed beside the rating so a reader who thinks it is overblown can name the
    input they disagree with rather than concluding the tool is noisy. Written in
    this repository, so the renderers do not escape it."""

    frameworks: tuple[Framework, ...] = ()
    evidence_facts: tuple[str, ...] = ()
    condition: str = ""
    """What must be true before signing. Concrete and testable: "SCIM
    deprovisioning enabled in the tenant before production access", not "improve
    access management"."""

    question: str = ""
    """What to ask the vendor when this is unknown rather than absent."""

    blocking: bool = False
    """Cannot be carried as a condition with a date. Only ever set on an ABSENT
    gap: an unknown cannot block, because we do not know there is anything
    wrong."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "attestation": self.attestation.value,
            "why_applicable": self.why_applicable,
            "what_is_missing": self.what_is_missing,
            "severity": self.severity.value,
            "severity_reason": self.severity_reason,
            "frameworks": [f.to_dict() for f in self.frameworks],
            "evidence_facts": list(self.evidence_facts),
            "condition": self.condition,
            "question": self.question,
            "blocking": self.blocking,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A reasoned risk the control checks did not already state.

    The model's contribution, and deliberately the smaller half of the report.
    Anything a rule can decide is decided by a rule; this is for what only
    emerges from how a particular set of facts fit together -- "the SOC 2 carves
    out the cloud provider, the DPA names no subprocessors, and the data is
    replicated to a region nobody has named" is not one control gap, it is a
    chain.
    """

    id: str
    title: str
    chain: tuple[str, ...]
    """The path, one link per entry. A chain a reviewer can break at one link
    beats a category label they have read a hundred times."""

    severity: Severity
    data_at_risk: DataClass
    blast: Blast
    fact_ids: tuple[str, ...] = ()
    control_ids: tuple[str, ...] = ()
    frameworks: tuple[Framework, ...] = ()
    assumptions: tuple[str, ...] = ()
    """What has to be true for this to matter, and is not evidenced."""

    condition: str = ""
    because: str = ""

    def key(self) -> str:
        """Identity for re-review comparison.

        Structural -- which facts, which controls, what is at risk -- and blind
        to the title, because model wording varies between runs and a reworded
        description of a known risk must not resurface as newly introduced.
        """
        material = "|".join(
            [
                ",".join(sorted(self.fact_ids)),
                ",".join(sorted(self.control_ids)),
                self.data_at_risk.value,
                self.blast.value,
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def dedup_key(self) -> str:
        """Identity for collapsing duplicates within one review.

        Looser than :meth:`key`, and deliberately so: two genuinely different
        risks can rest on the same facts and controls, and de-duplicating on
        structure alone would silently drop one of them from the report.
        """
        words = sorted(set(re.findall(r"[a-z0-9]{4,}", self.title.casefold())))
        return hashlib.sha256(f"{self.key()}|{','.join(words)}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key(),
            "title": self.title,
            "chain": list(self.chain),
            "severity": self.severity.value,
            "data_at_risk": self.data_at_risk.value,
            "blast": self.blast.value,
            "fact_ids": list(self.fact_ids),
            "control_ids": list(self.control_ids),
            "frameworks": [f.to_dict() for f in self.frameworks],
            "assumptions": list(self.assumptions),
            "condition": self.condition,
            "because": self.because,
        }


@dataclass(frozen=True, slots=True)
class Question:
    """Something to ask the vendor before signing.

    Distinct from a gap. A gap says what is wrong; this says what nobody knows
    yet. Keeping them apart is what stops a review reading as more certain than
    it is, and it is the deliverable most reviews actually need: a short list of
    specific questions the account team can forward, rather than a document.
    """

    text: str
    why_it_matters: str = ""
    blocks_decision: bool = False
    """True when the answer would change the outcome. These are why the decision
    can come back as more-information-needed rather than a guess.

    Only the control evaluation sets this. A question arriving from the analysis
    layer is displayed and never blocks, because blocking moves the decision and
    the decision is not the model's to move."""

    trusted: bool = True
    """False when the text quotes something the vendor, the requester or the
    model wrote.

    Provenance rather than a safety switch, and it has to travel with the
    question for the same reason it travels with a condition: the renderer
    escapes untrusted text and leaves the tool's own wording alone, and it
    cannot tell them apart by looking."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "why_it_matters": self.why_it_matters,
            "blocks_decision": self.blocks_decision,
        }


@dataclass(frozen=True, slots=True)
class Note:
    r"""One line in the review notes, split by who wrote which half.

    Almost every note is written in this repository -- the confidence sentence,
    the count of rejected findings, the baseline comparison -- and escaping those
    tells the reader "3 proposed finding\(s\) were rejected", which teaches them
    the tool is careless about everything else too.

    But not all of a note is. The one saying a document could not be read carries
    the reason it could not be read, and for a questionnaire response file that
    reason is the YAML parser's account of the vendor's own file. The whole note
    went out unescaped, so a response file beginning
    ``![](https://evil.example/px.png): [`` put an image in a review that is
    forwarded to that same vendor and pasted into a ticket.

    A flag on the whole line would only move the damage: escaping all of it to
    cover the quote prints backslashes through the sentence around it. So the two
    are separate fields instead. :attr:`text` is written here and is never
    escaped; :attr:`quoted` holds whatever came from a document, a form or a
    model and is always escaped. Putting untrusted text in the first is something
    a contributor has to do on purpose, which is the same reason
    :class:`Attestation` is not a ``bool``.
    """

    text: str
    quoted: str = ""

    def __str__(self) -> str:
        return f"{self.text} {self.quoted}".rstrip() if self.quoted else self.text


@dataclass(slots=True)
class Review:
    """One completed vendor review."""

    intake: VendorIntake
    decision: Decision = Decision.MORE_INFORMATION_NEEDED
    decision_rationale: str = ""
    confidence: Confidence = Confidence.MEDIUM

    gaps: list[ControlGap] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    applicable_controls: list[str] = field(default_factory=list)
    attested_controls: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    new_finding_keys: set[str] = field(default_factory=set)
    baseline_available: bool = False
    baseline_fingerprint: str = ""

    dropped_findings: int = 0
    rejections: list[tuple[str, str]] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)

    tool_version: str = ""
    model_id: str = ""
    reviewed_at: str = ""

    # -- views ---------------------------------------------------------

    def absent_gaps(self) -> list[ControlGap]:
        """Objectives somebody said no to. The only ones stated as failures."""
        return [g for g in self.gaps if g.attestation.is_absent]

    def unevidenced(self) -> list[ControlGap]:
        """Objectives nothing in the pack settles. Never stated as failures."""
        return [g for g in self.gaps if g.attestation.is_unknown]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for gap in self.gaps:
            counts[gap.severity.value] += 1
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def counts_by_attestation(self) -> dict[str, int]:
        counts = {a.value: 0 for a in Attestation}
        counts[Attestation.ATTESTED.value] = len(self.attested_controls)
        for gap in self.gaps:
            counts[gap.attestation.value] += 1
        return counts

    def worst_severity(self) -> Severity | None:
        severities = [g.severity for g in self.gaps] + [f.severity for f in self.findings]
        return max(severities, default=None)

    def blocking_gaps(self) -> list[ControlGap]:
        return [g for g in self.gaps if g.blocking]

    def blocking_questions(self) -> list[Question]:
        return [q for q in self.questions if q.blocks_decision]

    def conditions(self) -> list[tuple[str, str, bool]]:
        r"""Everything that has to be true before signing, as (what, why, trusted).

        Gaps and findings merged into one list on purpose: the person who has to
        take this to the vendor does not care which of the two internal machines
        produced an item, they care what is on the call agenda.

        ``trusted`` carries provenance through the merge, and it has to. Gap
        conditions are written in this repository and reviewed in pull requests;
        finding conditions come from the model and are derived from text the
        vendor wrote. Escaping both renders every ``(SAML or OIDC)`` as
        ``\(SAML or OIDC\)``, which makes the document look broken; escaping
        neither lets vendor-supplied text carry a link into a ticket.
        """
        items: list[tuple[str, str, bool]] = []
        for gap in sorted(self.absent_gaps(), key=lambda g: -g.severity.rank):
            if gap.condition:
                items.append((gap.condition, gap.title, True))
        for finding in sorted(self.findings, key=lambda f: -f.severity.rank):
            if finding.condition:
                items.append((finding.condition, finding.title, False))
        return items

    def new_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.key() in self.new_finding_keys]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "model_id": self.model_id,
            "reviewed_at": self.reviewed_at,
            "decision": self.decision.value,
            "decision_rationale": self.decision_rationale,
            "confidence": self.confidence.value,
            "intake": self.intake.to_dict(),
            "counts": self.counts_by_severity(),
            "attestation_counts": self.counts_by_attestation(),
            "applicable_controls": self.applicable_controls,
            "attested_controls": self.attested_controls,
            "gaps": [g.to_dict() for g in self.absent_gaps()],
            "not_evidenced": [g.to_dict() for g in self.unevidenced()],
            "findings": [f.to_dict() for f in self.findings],
            "questions": [q.to_dict() for q in self.questions],
            "conditions": [{"do": d, "for": w} for d, w, _ in self.conditions()],
            "conflicts": self.conflicts,
            "baseline_available": self.baseline_available,
            "baseline_fingerprint": self.baseline_fingerprint,
            "new_finding_keys": sorted(self.new_finding_keys),
            "dropped_findings": self.dropped_findings,
            "rejections": [{"title": t, "reason": r} for t, r in self.rejections],
            "notes": [str(n) for n in self.notes],
        }
