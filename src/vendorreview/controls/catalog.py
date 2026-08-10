"""The control catalog: what a third-party review checks, and why it applies.

One reviewable table, in one file, printed in full by ``vendorreview controls``.
A security team adopting this needs to read what it will hold vendors to before
it sends the first questionnaire, and "read the code" is not an acceptable
answer to that.

Four properties make this different from the spreadsheet it replaces:

**Applicability is computed, not assumed.** Every entry carries an ``applies``
predicate over the declared engagement. A tenant-isolation objective does not
fire on software you self-host. A cross-border transfer objective does not fire
on a vendor holding no personal data. A questionnaire that asks every question of
every vendor is the reason nobody reads the answers.

**Evidence is tri-state, and it comes from named sources.** Every entry carries
an ``evidence`` function returning one ``(source, attestation)`` pair per place
the answer could come from -- the intake, the questionnaire response, the SOC 2,
the certificate. Attested, absent, or not evidenced. Silence in a document is
never absence: a SOC 2 scoped to Security says nothing about availability, and
reading that silence as a control failure is the fastest way to have a review
disputed and then ignored.

**Conditions and questions are different fields.** When an objective is *absent*
the catalog states the condition that would make it approvable. When it is *not
evidenced* the catalog states the question to send the vendor. Printing the same
sentence for both is how a review ends up accusing a vendor of something nobody
asked them about.

**Framework references are data, not prose.** Each entry carries its NIST CSF
2.0, ISO 27001:2022 Annex A, SOC 2 TSC and CIS v8 references, so a condition can
cite them without anyone typing a control number into a sentence and getting it
wrong. Control identifiers are taken from the published frameworks; the mapping
between them is editorial judgement and is meant to be argued with.

A word on what this is not. Mapping an objective to ISO A.5.20 does not make a
vendor certified, and this tool is not an audit. The mapping exists so that a
condition traces to an obligation in the language the rest of the organisation
already uses.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import (
    Attestation,
    Criticality,
    DataClass,
    Exposure,
    Framework,
    Hosting,
    Integration,
    Severity,
    VendorIntake,
    strongest,
)

# Framework names, spelled once. A typo in a framework label reaching a report
# that goes to GRC is a small embarrassment with a long half-life.
NIST = "NIST CSF 2.0"
ISO = "ISO 27001:2022"
SOC2 = "SOC 2 TSC"
CIS = "CIS v8"


def _nist(identifier: str, title: str) -> Framework:
    return Framework(NIST, identifier, title)


def _iso(identifier: str, title: str) -> Framework:
    return Framework(ISO, f"A.{identifier}", title)


def _soc2(identifier: str, title: str) -> Framework:
    return Framework(SOC2, identifier, title)


def _cis(identifier: str, title: str) -> Framework:
    return Framework(CIS, f"Control {identifier}", title)


Sources = tuple[tuple[str, Attestation], ...]


@dataclass(frozen=True, slots=True)
class Control:
    """One control objective, with the conditions under which it is in scope."""

    id: str
    title: str
    objective: str
    """What good looks like, in one sentence somebody in procurement can act on."""

    applies: Callable[[VendorIntake], bool]
    """Pure predicate over the declared engagement. Returning False removes the
    objective from the review entirely -- not asked, not reported, not counted."""

    evidence: Callable[[VendorIntake], Sources]
    """Every place this objective could be settled, as ``(source, attestation)``.

    More than one entry is normal and is the point: the questionnaire says one
    thing, the SOC 2 says another, and a review that silently picks one has
    thrown away the most interesting fact in the pack. :func:`combine` resolves
    them and reports the disagreement."""

    severity: Severity
    """The catalog's own rating, before the engagement adjusts it. See
    :mod:`vendorreview.analyze.severity` for the table and its bounds."""

    condition: str
    """What must be true before signing, when the objective is definitively
    absent. Written as something somebody can put on a call agenda, not as a
    principle they have to interpret."""

    question: str
    """What to ask the vendor, when nothing settles the objective. A different
    sentence from the condition on purpose: one is an instruction, the other is
    a question, and the tri-state is worth nothing if the report prints them the
    same way."""

    frameworks: tuple[Framework, ...]
    evidence_facts: tuple[str, ...] = ()
    blocking: bool = False
    """Cannot be carried as a condition with a date. Only ever honoured on an
    ABSENT result: an unknown cannot block, because nobody has established that
    anything is wrong. Reserved for cases where signing means an obligation is
    already being breached."""

    why_template: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# Reading the engagement. Small named helpers so the table below reads as
# English rather than as attribute access.
# --------------------------------------------------------------------------


def _tri(value: bool | None) -> Attestation:
    return Attestation.from_optional(value)


def _has_data(intake: VendorIntake, *classes: DataClass) -> bool:
    return any(c in intake.data_classes for c in classes)


def _personal_data(intake: VendorIntake) -> bool:
    return _has_data(intake, DataClass.PII, DataClass.REGULATED)


def _sensitive(intake: VendorIntake) -> bool:
    return intake.max_data_class().rank >= DataClass.CONFIDENTIAL.rank


def _connected(intake: VendorIntake) -> bool:
    return bool(intake.patterns())


def _always(_: VendorIntake) -> bool:
    return True


def _nothing(_: VendorIntake) -> Sources:
    """No source can settle this objective. It is a question by construction.

    Used for the objectives no document this tool reads will ever answer --
    insurance, breach history, tenant isolation architecture. Naming them is
    still worth doing: an unasked question is the one that gets missed, and the
    output of this tool is meant to be the list of questions.
    """
    return ()


def _answered(text: str) -> Attestation:
    """A substantive free-text answer is an attestation, a blank is silence.

    Never absent. A short answer might be inadequate, but this layer cannot judge
    that, and inventing a failure out of brevity would put a finding against a
    team that answered the question honestly.
    """
    return Attestation.ATTESTED if text and len(text.strip()) >= 12 else Attestation.NOT_EVIDENCED


def _response(intake: VendorIntake, key: str) -> tuple[str, Attestation]:
    return (f"questionnaire:{key}", intake.evidence.response(key))


def _soc2_current(intake: VendorIntake) -> Attestation:
    report = intake.evidence.soc2
    return report.period_current if report else Attestation.NOT_EVIDENCED


def _iso_valid(intake: VendorIntake) -> Attestation:
    certificate = intake.evidence.iso
    return certificate.valid if certificate else Attestation.NOT_EVIDENCED


BUILTIN_CONTROLS: tuple[Control, ...] = (
    # ------------------------------------------------------ attestation: SOC 2
    Control(
        id="ATT-01",
        title="An independent attestation exists at all",
        objective=(
            "Somebody outside the vendor has examined their controls and written "
            "an opinion you can read."
        ),
        applies=_always,
        evidence=lambda i: (
            ("soc2 report", Attestation.ATTESTED if i.evidence.soc2 else Attestation.NOT_EVIDENCED),
            (
                "iso certificate",
                Attestation.ATTESTED if i.evidence.iso else Attestation.NOT_EVIDENCED,
            ),
            ("intake:evidence_supplied", _answered(", ".join(i.evidence_supplied))),
        ),
        severity=Severity.HIGH,
        condition=(
            "Obtain a current SOC 2 Type II or ISO 27001 certificate before signature. "
            "Absence is not automatically disqualifying for a twelve-person vendor, but "
            "it moves the entire assurance burden onto contract terms and onto you, and "
            "that trade needs to be made deliberately rather than by default."
        ),
        question=(
            "Which independent security attestations do you hold, and can you send the "
            "full report rather than the certificate page?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.19", "Information security in supplier relationships"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("evidence_supplied",),
        why_template="every vendor review starts with what independent assurance exists",
        tags=("attestation",),
    ),
    Control(
        id="ATT-02",
        title="The SOC 2 is a Type II, not a Type I",
        objective=(
            "The report says the controls operated over a period, not that they were "
            "suitably designed on one day."
        ),
        applies=lambda i: i.evidence.soc2 is not None,
        evidence=lambda i: (
            (
                "soc2:type",
                i.evidence.soc2.type_two if i.evidence.soc2 else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Ask for the Type II. A Type I is a design opinion on a single date and is "
            "routinely sent when a Type II was asked for — a vendor in their first year "
            "may legitimately have only a Type I, in which case ask when the Type II "
            "period closes and diarise it."
        ),
        question=(
            "Is the report a Type I or a Type II? The cover page did not say in terms "
            "this tool could read."
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC4.1", "Evaluations of internal control"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("soc2.type",),
        why_template="a SOC 2 report was supplied",
        tags=("attestation",),
    ),
    Control(
        id="ATT-03",
        title="The attestation period has not run out",
        objective=(
            "The report covers a period recent enough to say something about the "
            "vendor as they are now."
        ),
        applies=lambda i: i.evidence.soc2 is not None,
        evidence=lambda i: (("soc2:period", _soc2_current(i)),),
        severity=Severity.HIGH,
        condition=(
            "Ask for the current report, or a bridge letter from the auditor covering "
            "the gap. This is the commonest real finding in third-party review and it "
            "is not a control failure: the cover page of a stale report looks exactly "
            "like the cover page of a fresh one, so nobody notices."
        ),
        question=(
            "What period does the report cover, and is there a bridge letter covering "
            "the time since it ended?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC4.1", "Evaluations of internal control"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("soc2.period",),
        why_template="a SOC 2 report was supplied and an attestation is worth its date",
        tags=("attestation",),
    ),
    Control(
        id="ATT-04",
        title="Exceptions in the report have been read",
        objective=(
            "Somebody has read the testing exceptions and the opinion, rather than the cover page."
        ),
        applies=lambda i: i.evidence.soc2 is not None,
        evidence=lambda i: (
            (
                "soc2:exceptions",
                # Inverted on purpose: the field records whether exceptions were
                # reported, and exceptions being reported is the thing that has
                # to be looked at. ATTESTED there is ABSENT here.
                Attestation.ABSENT
                if i.evidence.soc2 and i.evidence.soc2.exceptions.is_attested
                else Attestation.ATTESTED
                if i.evidence.soc2 and i.evidence.soc2.exceptions.is_absent
                else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Read the exceptions the report lists and decide, per exception, whether it "
            "touches the way you will use this vendor. Most do not. The point is to have "
            "made that judgement rather than to have skipped the section — an exception "
            "on change management at a vendor holding your customer records is a "
            "conversation, and one on physical badge logs is usually not."
        ),
        question=(
            "Does the report note any testing exceptions or deviations, and what is the "
            "remediation status of each?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC4.1", "Evaluations of internal control"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("soc2.exceptions", "soc2.opinion"),
        why_template="a SOC 2 report was supplied and its exceptions are the part worth reading",
        tags=("attestation",),
    ),
    Control(
        id="ATT-05",
        title="Subservice organisations are not silently carved out",
        objective=(
            "You know whether the report covers the infrastructure your data will "
            "actually sit on, or excludes it."
        ),
        applies=lambda i: i.evidence.soc2 is not None,
        evidence=lambda i: (
            (
                "soc2:subservice",
                Attestation.ABSENT
                if i.evidence.soc2 and i.evidence.soc2.subservice_treatment == "carve-out"
                else Attestation.ATTESTED
                if i.evidence.soc2 and i.evidence.soc2.subservice_treatment == "inclusive"
                else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "The report uses the carve-out method, so it covers none of the controls at "
            "the subservice organisation — routinely the cloud provider, routinely where "
            "your data actually sits. Get that provider's own attestation, and confirm "
            "which complementary subservice controls the report assumes are in place."
        ),
        question=(
            "Does the report use the carve-out or the inclusive method, and which "
            "subservice organisations are named?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.21", "Managing information security in the ICT supply chain"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("soc2.subservice",),
        why_template=(
            "a SOC 2 report was supplied and a carve-out is the single most missed line in it"
        ),
        tags=("attestation", "supply-chain"),
    ),
    # -------------------------------------------------------- attestation: ISO
    Control(
        id="ATT-06",
        title="The ISO 27001 certificate is in date",
        objective="The certificate has not expired.",
        applies=lambda i: i.evidence.iso is not None,
        evidence=lambda i: (("iso:expiry", _iso_valid(i)),),
        severity=Severity.MEDIUM,
        condition=(
            "Ask for the current certificate. A lapsed certificate is not evidence of a "
            "current information security management system, and certification bodies "
            "publish a register you can check independently."
        ),
        question=(
            "When does the certificate expire, and what was the outcome of the most "
            "recent surveillance audit?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC4.1", "Evaluations of internal control"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("iso.expiry",),
        why_template="an ISO 27001 certificate was supplied",
        tags=("attestation",),
    ),
    Control(
        id="ATT-07",
        title="The certified scope covers the service being bought",
        objective=(
            "The scope statement on the certificate includes the product and the "
            "location you are actually buying."
        ),
        applies=lambda i: i.evidence.iso is not None,
        # Whether a scope statement EXISTS is not whether it COVERS the service,
        # and this objective is about the second. `iso.scope_stated` answers the
        # first: it is ATTESTED whenever the certificate carries a scope line
        # longer than thirty characters, which every certificate does. Reading it
        # here meant a certificate scoped to "facilities management and reception
        # services at the Dublin head office" attested that the certified scope
        # covered the SaaS product being bought, and the objective then vanished
        # from the review into the attested count -- the single classic miss in
        # ISO diligence, produced by the tool that exists to catch it. The parser
        # says so itself: it quotes the statement and refuses to judge coverage,
        # because that is a judgement about your service and a regex has no
        # business making it.
        #
        # So the certificate cannot settle this and does not try. The vendor can,
        # and that is a question worth asking in terms; the statement itself is
        # still quoted in the review as the `iso.scope` fact, which is what the
        # reviewer reads it against.
        evidence=lambda i: (_response(i, "iso_scope_covers_service"),),
        severity=Severity.HIGH,
        condition=(
            "Read the scope statement against what you are buying. Certificates are "
            "routinely scoped to a head-office ISMS, or to one product line, or to one "
            "data centre, and the certificate looks identical either way — the scope is "
            "one sentence in small type on the back."
        ),
        question=(
            "What exactly is the certified scope — which entities, which products, which "
            "locations — and can you send the Statement of Applicability?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.19", "Information security in supplier relationships"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("iso.scope", "iso.exclusions"),
        why_template="an ISO 27001 certificate was supplied and its scope decides what it covers",
        tags=("attestation",),
    ),
    # --------------------------------------------------- attestation: pen test
    Control(
        id="ATT-08",
        title="An independent penetration test within the last year",
        objective="Somebody outside the vendor has attacked the product recently.",
        applies=lambda i: _sensitive(i) or _personal_data(i) or _connected(i),
        evidence=lambda i: (
            (
                "pentest:date",
                i.evidence.pentest.current if i.evidence.pentest else Attestation.NOT_EVIDENCED,
            ),
            _response(i, "penetration_test_annual"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Ask when the next test is scheduled and require an annual cadence in the "
            "contract. A test from three years ago describes a product that no longer "
            "exists in the form that was tested."
        ),
        question=(
            "When was the product last penetration tested, by whom, and can you send the "
            "summary letter?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("8.29", "Security testing in development and acceptance"),
            _soc2("CC4.1", "Evaluations of internal control"),
            _cis("18", "Penetration Testing"),
        ),
        evidence_facts=("pentest.date",),
        why_template="the vendor will hold sensitive data or connect to your systems",
        tags=("attestation", "assurance"),
    ),
    Control(
        id="ATT-09",
        title="Penetration test findings were retested",
        objective="Somebody went back and confirmed the findings were actually closed.",
        applies=lambda i: i.evidence.pentest is not None,
        evidence=lambda i: (
            (
                "pentest:retest",
                i.evidence.pentest.retested if i.evidence.pentest else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Ask for the retest letter. A report that found four highs and was never "
            "retested is a list of four highs, not a clean bill — and a vendor who sends "
            "the original and no retest is usually telling you something without "
            "meaning to."
        ),
        question=(
            "Were the findings retested and verified closed, and can you send the retest "
            "letter or the current status of each finding?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("8.8", "Management of technical vulnerabilities"),
            _soc2("CC7.1", "Detection of configuration changes and vulnerabilities"),
            _cis("18", "Penetration Testing"),
        ),
        evidence_facts=("pentest.retest", "pentest.findings"),
        why_template="a penetration test summary was supplied",
        tags=("attestation", "assurance"),
    ),
    # -------------------------------------------------------------- supply chain
    Control(
        id="SUB-01",
        title="The subprocessor list is disclosed",
        objective="You know which other companies your data reaches behind the vendor.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=lambda i: (
            ("intake:subprocessors", _answered(i.subprocessors)),
            _response(i, "subprocessor_list_published"),
        ),
        severity=Severity.HIGH,
        condition=(
            "Obtain the current subprocessor list and attach it to the contract "
            "schedule. Your data reaches every name on it, and a vendor who will not "
            "produce one is telling you they do not maintain one."
        ),
        question=(
            "Which subprocessors handle customer data, in which countries, and where is "
            "the list published?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.21", "Managing information security in the ICT supply chain"),
            _soc2("P6.1", "Privacy — disclosure to third parties"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("subprocessors",),
        why_template="the vendor will process personal or confidential data",
        tags=("supply-chain",),
    ),
    Control(
        id="SUB-02",
        title="Subprocessor changes come with notice and flow-down",
        objective=(
            "New subprocessors are notified in advance, and are held to the same terms "
            "the vendor accepted."
        ),
        applies=lambda i: _personal_data(i),
        evidence=lambda i: (_response(i, "subprocessor_change_notice"),),
        severity=Severity.MEDIUM,
        condition=(
            "Require advance written notice of new subprocessors with a right to object, "
            "and flow-down of the security and privacy terms. Without it the list you "
            "just obtained is accurate for exactly as long as it takes to change, and "
            "nobody will tell you when it does."
        ),
        question=(
            "What notice do you give before adding a subprocessor, and do your "
            "subprocessor contracts carry the same obligations as ours with you?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.20", "Addressing information security within supplier agreements"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("subprocessors",),
        why_template="the vendor will process personal data",
        tags=("supply-chain", "contract"),
    ),
    # --------------------------------------------------------------------- data
    Control(
        id="DAT-01",
        title="Data residency is known",
        objective="You can say which countries the data is stored and processed in.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=lambda i: (
            ("intake:data_residency", _answered(i.data_residency)),
            _response(i, "data_residency_controlled"),
        ),
        severity=Severity.HIGH,
        condition=(
            "Get the storage and processing regions in writing, including where support "
            "staff access the data from. Support access from a third region is the part "
            "that gets missed, and it is processing."
        ),
        question=(
            "In which countries is customer data stored, processed, and accessed from by "
            "your support and engineering staff?"
        ),
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.34", "Privacy and protection of PII"),
            _soc2("P6.1", "Privacy — disclosure to third parties"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("data_residency", "data_classes"),
        why_template="the vendor will hold personal or confidential data",
        tags=("data", "privacy"),
    ),
    Control(
        id="DAT-02",
        title="A transfer mechanism covers the cross-border flow",
        objective=(
            "Personal data leaving its region does so under a named legal mechanism, "
            "not by accident."
        ),
        applies=lambda i: _personal_data(i) and i.cross_border is not False,
        # No source settles this. The intake asks whether data leaves the region;
        # nothing on the form or in any document this tool reads names the
        # mechanism that would make it lawful, so the honest output is the
        # question. Deriving an answer from the yes/no would report an absent
        # transfer mechanism against a vendor operating under clauses nobody
        # asked about.
        evidence=_nothing,
        severity=Severity.HIGH,
        condition="",
        question=(
            "Does data leave its stated region for support, backup or analytics, and if "
            "so under which transfer mechanism?"
        ),
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.14", "Information transfer"),
            _soc2("P6.1", "Privacy — disclosure to third parties"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("cross_border", "data_residency"),
        why_template="personal data may leave the region it is stored in",
        tags=("data", "privacy"),
    ),
    Control(
        id="DAT-03",
        title="A retention period is defined",
        objective="The vendor deletes data when it is no longer needed, on a stated schedule.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=lambda i: (
            ("intake:retention", _answered(i.retention)),
            _response(i, "retention_policy"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Agree the retention period in the contract, including backups. "
            "'Indefinitely' is an answer, but it is one that grows the consequence of "
            "every future breach at this vendor for as long as the relationship lasts."
        ),
        question="How long do you retain customer data, including in backups?",
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.10", "Information deletion"),
            _soc2("P4.2", "Privacy — retention of personal information"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("retention",),
        why_template="the vendor will hold personal or confidential data",
        tags=("data", "privacy"),
    ),
    Control(
        id="DAT-04",
        title="Deletion on termination is committed",
        objective="When the contract ends, the data goes, and you get evidence that it did.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=lambda i: (
            ("intake:deletion_on_termination", _tri(i.deletion_on_termination)),
            _response(i, "deletion_on_termination"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Put deletion on termination in the contract with a deadline and a "
            "certificate of destruction, and state what happens to backups. Cheapest to "
            "negotiate before signature and hardest to obtain at the point you actually "
            "want it, which is usually the point the relationship has soured."
        ),
        question=(
            "On termination, within what period is customer data deleted, does that "
            "include backups, and do you provide evidence of deletion?"
        ),
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.10", "Information deletion"),
            _soc2("P4.3", "Privacy — disposal of personal information"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("deletion_on_termination",),
        why_template="the vendor will hold personal or confidential data",
        tags=("data", "exit"),
    ),
    Control(
        id="DAT-05",
        title="A data processing agreement is executed",
        objective="The contract says what the vendor may and may not do with the data.",
        applies=lambda i: _personal_data(i),
        evidence=lambda i: (("intake:dpa_status", _tri(i.dpa_status)),),
        severity=Severity.CRITICAL,
        condition=(
            "Execute the data processing agreement before any personal data is sent. It "
            "has to cover purpose limitation, subprocessors, breach notification, "
            "international transfer and deletion on termination. Sending personal data "
            "to a processor without one is not a risk to be accepted with a date on it."
        ),
        question="Is a data processing agreement in place, and which version of it?",
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.20", "Addressing information security within supplier agreements"),
            _soc2("P6.1", "Privacy — disclosure to third parties"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("dpa_status", "data_classes"),
        blocking=True,
        why_template="the vendor will process personal data",
        tags=("data", "privacy", "contract"),
    ),
    Control(
        id="DAT-06",
        title="The applicable regime is named",
        objective="A named regulation brings requirements the review cannot waive.",
        applies=lambda i: DataClass.REGULATED in i.data_classes or bool(i.regulated_regimes),
        evidence=lambda i: (
            (
                "intake:regulated_regimes",
                Attestation.ATTESTED if i.regulated_regimes else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.HIGH,
        condition=(
            "Name the regime — GDPR, HIPAA, PCI DSS or other — and bring compliance or "
            "legal into this review before signature. A security review cannot sign off "
            "regulated data on its own authority, and a BAA or an AOC is a different "
            "document from a DPA."
        ),
        question=(
            "Which regulatory regime applies to this data, and does the vendor hold the "
            "corresponding attestation — a BAA, a PCI attestation of compliance?"
        ),
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.31", "Legal, statutory, regulatory and contractual requirements"),
            _soc2("CC2.3", "Communication with external parties"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("regulated_regimes", "data_classes"),
        why_template="regulated data is in scope",
        tags=("data", "compliance"),
    ),
    # ----------------------------------------------------------------- crypto
    Control(
        id="CRY-01",
        title="Encryption in transit on every path",
        objective="Customer data is encrypted on every network path, not only the front door.",
        applies=_always,
        evidence=lambda i: (_response(i, "encryption_in_transit"),),
        severity=Severity.HIGH,
        condition=(
            "Require current TLS on every path carrying customer data, including the "
            "vendor's internal and subprocessor hops. The public endpoint is rarely the "
            "gap; the batch export to an analytics provider is."
        ),
        question=(
            "Which TLS versions do you support on customer-facing and internal paths, "
            "and is anything still permitted below TLS 1.2?"
        ),
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.24", "Use of cryptography"),
            _soc2("CC6.7", "Transmission and movement of information"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("response.encryption_in_transit",),
        why_template="any vendor holding your data moves it over a network",
        tags=("crypto",),
    ),
    Control(
        id="CRY-02",
        title="Encryption at rest",
        objective="Stored customer data is encrypted, including backups.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=lambda i: (_response(i, "encryption_at_rest"),),
        severity=Severity.MEDIUM,
        condition=(
            "Require encryption at rest for stored data and backups. On its own it "
            "defends against a narrow set of failures — a lost disk, a mis-shipped "
            "backup — so treat it as table stakes rather than as an answer to anything "
            "about access control."
        ),
        question="Is customer data encrypted at rest, and does that include backups and exports?",
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.24", "Use of cryptography"),
            _soc2("CC6.1", "Logical access security software and infrastructure"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("response.encryption_at_rest",),
        why_template="the vendor will store personal or confidential data",
        tags=("crypto",),
    ),
    Control(
        id="CRY-03",
        title="Key custody is stated",
        objective="You know who holds the keys and who can decrypt the data.",
        applies=lambda i: (
            _has_data(i, DataClass.REGULATED, DataClass.CREDENTIALS)
            or i.max_data_class().rank >= DataClass.PII.rank
        ),
        evidence=lambda i: (_response(i, "key_management"),),
        severity=Severity.MEDIUM,
        condition=(
            "Establish who holds the keys, where they are held, and whether the vendor's "
            "own staff can decrypt the data. Encryption at rest with the vendor holding "
            "the keys in the same account as the data protects against a stolen disk and "
            "nothing else — which is fine, provided nobody believes otherwise."
        ),
        question=(
            "Who holds the encryption keys, are they held in a separate service from the "
            "data, and is customer-managed or bring-your-own key available?"
        ),
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.24", "Use of cryptography"),
            _soc2("CC6.1", "Logical access security software and infrastructure"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("response.key_management",),
        why_template="the vendor will hold personal, regulated or credential data",
        tags=("crypto",),
    ),
    # ------------------------------------------------------------- isolation
    Control(
        id="TEN-01",
        title="Tenant isolation is described",
        objective=(
            "You know how one customer's data is kept away from another's in a shared platform."
        ),
        applies=lambda i: i.hosting is Hosting.SAAS and (_personal_data(i) or _sensitive(i)),
        evidence=_nothing,
        severity=Severity.MEDIUM,
        condition="",
        question=(
            "How is tenant data isolated — separate databases, separate schemas, or a "
            "tenant identifier on shared tables — and what enforces that boundary at the "
            "application layer?"
        ),
        frameworks=(
            _nist("PR.IR", "Technology Infrastructure Resilience"),
            _iso("8.22", "Segregation of networks"),
            _soc2("CC6.1", "Logical access security software and infrastructure"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("hosting", "data_classes"),
        why_template="the service is multi-tenant SaaS holding personal or confidential data",
        tags=("isolation",),
    ),
    # ------------------------------------------------------------------ access
    Control(
        id="IAM-01",
        title="Single sign-on against your identity provider",
        objective=(
            "Staff sign in with their corporate account, so joiners and leavers are "
            "handled centrally rather than in one more admin console."
        ),
        applies=lambda i: i.hosting is not Hosting.SELF_HOSTED,
        evidence=lambda i: (
            ("intake:sso_available", _tri(i.sso_available)),
            _response(i, "sso_saml_oidc"),
        ),
        severity=Severity.HIGH,
        condition=(
            "Require SAML or OIDC against the corporate identity provider before "
            "production access. Where the vendor charges for it, price that against the "
            "cost of maintaining a separate account list for the life of the contract — "
            "it is usually not close."
        ),
        question="Do you support SAML or OIDC single sign-on, and is it included in this tier?",
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.16", "Identity management"),
            _soc2("CC6.1", "Logical access security software and infrastructure"),
            _cis("5", "Account Management"),
        ),
        evidence_facts=("sso_available",),
        why_template="the vendor operates the service and your staff will hold accounts on it",
        tags=("identity",),
    ),
    Control(
        id="IAM-02",
        title="SCIM deprovisioning",
        objective="An account is removed at the vendor when somebody leaves, without a ticket.",
        applies=lambda i: (
            i.hosting is not Hosting.SELF_HOSTED and (_personal_data(i) or _sensitive(i))
        ),
        evidence=lambda i: (
            ("intake:scim_available", _tri(i.scim_available)),
            _response(i, "scim_deprovisioning"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Where SCIM is unavailable, name who removes accounts manually and how that "
            "is evidenced each quarter. Orphaned accounts at a vendor on people who left "
            "eighteen months ago are among the most common real findings in an "
            "assessment, and nobody ever intends them."
        ),
        question=(
            "Do you support SCIM provisioning and deprovisioning, and does deprovisioning "
            "revoke active sessions and API tokens as well as the account?"
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.18", "Access rights"),
            _soc2("CC6.2", "Registration and authorisation of users"),
            _cis("5", "Account Management"),
        ),
        evidence_facts=("scim_available",),
        why_template="the vendor holds accounts reaching personal or confidential data",
        tags=("identity",),
    ),
    Control(
        id="IAM-03",
        title="MFA can be enforced for every account",
        objective=(
            "Every account, including the vendor's own support staff, needs more than a password."
        ),
        applies=_always,
        evidence=lambda i: (
            ("intake:mfa_enforced", _tri(i.mfa_enforced)),
            _response(i, "mfa_enforced"),
        ),
        severity=Severity.HIGH,
        condition=(
            "Enforce MFA on every account before production data is loaded. Ask "
            "specifically whether it applies to the vendor's own support and engineering "
            "staff, not only to yours — the answer is different often enough to be worth "
            "the question, and their accounts reach every tenant."
        ),
        question=(
            "Can MFA be enforced for all accounts, is it enforced for your own support "
            "and engineering staff, and which factors are supported?"
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.17", "Authentication information"),
            _soc2("CC6.1", "Logical access security software and infrastructure"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("mfa_enforced",),
        why_template="every vendor account is reachable by whoever holds its password",
        tags=("identity",),
    ),
    Control(
        id="IAM-04",
        title="Vendor-side privileged access is separated and reviewed",
        objective=(
            "The vendor's staff cannot reach your data as a matter of routine, and "
            "when they do it is logged and approved."
        ),
        applies=lambda i: (
            i.hosting is not Hosting.SELF_HOSTED and (_personal_data(i) or _sensitive(i))
        ),
        evidence=lambda i: (_response(i, "admin_role_separation"),),
        severity=Severity.HIGH,
        condition=(
            "Establish which vendor roles can read customer data in production, how that "
            "access is approved, and whether you can see it in your own audit log. "
            "Standing production access for a support organisation is the single most "
            "common way a vendor incident becomes your incident."
        ),
        question=(
            "Which of your staff can access customer data in production, is that access "
            "just-in-time or standing, and is it visible in our audit log?"
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("8.2", "Privileged access rights"),
            _soc2("CC6.3", "Role-based access and segregation of duties"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("response.admin_role_separation", "admin_roles"),
        why_template="the vendor operates the platform holding your personal or confidential data",
        tags=("identity", "vendor-access"),
    ),
    Control(
        id="IAM-05",
        title="Integration credentials are scoped to what the use case needs",
        objective=(
            "The API token, OAuth grant or agent has the narrowest permission set that "
            "makes the integration work."
        ),
        applies=lambda i: bool(
            i.patterns() & {Integration.API_KEY, Integration.OAUTH, Integration.AGENT}
        ),
        evidence=lambda i: (("intake:oauth_scopes", _answered(i.oauth_scopes)),),
        severity=Severity.HIGH,
        condition=(
            "Write down the exact scopes granted and have the data owner confirm each "
            "one is needed. Integrations get scoped by what the vendor's setup guide "
            "makes easy, and the guide asks for read-write on everything because that is "
            "what never generates a support ticket."
        ),
        question=(
            "Exactly which scopes or API permissions does the integration require, and "
            "which of them are optional?"
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("8.3", "Information access restriction"),
            _soc2("CC6.3", "Role-based access and segregation of duties"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("oauth_scopes", "integrations"),
        why_template="the vendor holds a token, grant or agent reaching into your estate",
        tags=("identity", "integration"),
    ),
    # ----------------------------------------------------------------- logging
    Control(
        id="LOG-01",
        title="A customer-visible audit trail you can export",
        objective=(
            "You can see who did what at this vendor, in your own tooling, without asking them."
        ),
        applies=lambda i: _personal_data(i) or _sensitive(i) or _connected(i),
        evidence=lambda i: (
            ("intake:audit_log_export", _tri(i.audit_log_export)),
            _response(i, "audit_log_export"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Require an exportable audit log covering sign-in, administrative action and "
            "access to records, and route it into the SIEM at onboarding rather than "
            "during an incident. A log you have to request from the vendor during an "
            "incident is a log you get after the week that mattered."
        ),
        question=(
            "What audit events are available to us, how far back are they retained, and "
            "can they be streamed or exported to our SIEM?"
        ),
        frameworks=(
            _nist("DE.CM", "Continuous Monitoring"),
            _iso("8.15", "Logging"),
            _soc2("CC7.2", "System monitoring for anomalies"),
            _cis("8", "Audit Log Management"),
        ),
        evidence_facts=("audit_log_export",),
        why_template=(
            "the vendor will hold sensitive data or hold a live connection to your systems"
        ),
        tags=("logging",),
    ),
    # --------------------------------------------------------------- incidents
    Control(
        id="INC-01",
        title="A contractual breach notification timeline",
        objective="The contract says how quickly the vendor has to tell you.",
        applies=_always,
        evidence=lambda i: (
            ("intake:breach_notification", _answered(i.breach_notification)),
            _response(i, "incident_notification"),
        ),
        severity=Severity.HIGH,
        condition=(
            "Put a notification deadline in the contract, measured in hours from the "
            "vendor becoming aware, and say what the notification has to contain. "
            "'Without undue delay' is not a deadline, and it is what the vendor's "
            "template says."
        ),
        question=(
            "Within how many hours of becoming aware of a security incident affecting "
            "our data will you notify us, and what will that notification contain?"
        ),
        frameworks=(
            _nist("RS.CO", "Incident Response Reporting and Communication"),
            _iso("5.20", "Addressing information security within supplier agreements"),
            _soc2("P6.5", "Privacy — notification of unauthorised disclosure"),
            _cis("17", "Incident Response Management"),
        ),
        evidence_facts=("breach_notification",),
        why_template="every vendor relationship needs a stated notification obligation",
        tags=("incident", "contract"),
    ),
    Control(
        id="INC-02",
        title="Notification is fast enough for your own regulatory clock",
        objective=(
            "The vendor's deadline leaves you time to meet the one your regulator gives you."
        ),
        applies=lambda i: _personal_data(i) or bool(i.regulated_regimes),
        evidence=_nothing,
        # MEDIUM, and deliberately below the threshold that holds the decision.
        # Nothing this tool reads can settle whether a deadline is fast enough --
        # that is a judgement the reviewer makes against the answer INC-01
        # collects. Rating it HIGH made it permanently blocking for every vendor
        # touching personal data, with no answer that could ever clear it, which
        # is a review that always says more-information-needed and therefore says
        # nothing.
        severity=Severity.MEDIUM,
        condition="",
        question=(
            "Our own notification obligation runs from the point we become aware. Does "
            "your contractual deadline leave us time inside it, and will you notify us of "
            "incidents at your subprocessors on the same clock?"
        ),
        frameworks=(
            _nist("RS.CO", "Incident Response Reporting and Communication"),
            _iso("5.31", "Legal, statutory, regulatory and contractual requirements"),
            _soc2("P6.5", "Privacy — notification of unauthorised disclosure"),
            _cis("17", "Incident Response Management"),
        ),
        evidence_facts=("breach_notification", "regulated_regimes"),
        why_template=(
            "personal or regulated data means you carry a notification deadline of your own"
        ),
        tags=("incident", "compliance"),
    ),
    Control(
        id="INC-03",
        title="The incident response plan is tested",
        objective="The vendor has rehearsed the plan rather than only written it.",
        applies=lambda i: i.criticality is Criticality.CRITICAL or _personal_data(i),
        evidence=lambda i: (_response(i, "incident_response_plan"),),
        severity=Severity.MEDIUM,
        condition=(
            "Ask for the date of the last exercise and who took part. A plan nobody has "
            "run is a document, and the gap between the two shows up at three in the "
            "morning on the day it matters."
        ),
        question=(
            "When did you last exercise the incident response plan, and does the exercise "
            "include notifying customers?"
        ),
        frameworks=(
            _nist("RS.MA", "Incident Management"),
            _iso("5.24", "Information security incident management planning and preparation"),
            _soc2("CC7.4", "Incident response programme"),
            _cis("17", "Incident Response Management"),
        ),
        evidence_facts=("response.incident_response_plan",),
        why_template="the vendor is business-critical or will hold personal data",
        tags=("incident",),
    ),
    Control(
        id="HIS-01",
        title="Breach history is disclosed",
        objective="You have asked about past incidents rather than discovering them later.",
        applies=_always,
        evidence=_nothing,
        severity=Severity.LOW,
        condition="",
        question=(
            "Have you had a security incident affecting customer data in the last three "
            "years? If so, what happened, what changed as a result, and were customers "
            "notified?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("5.7", "Threat intelligence"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("17", "Incident Response Management"),
        ),
        evidence_facts=("vendor",),
        why_template="a vendor's history is the cheapest predictor of their next few years",
        tags=("incident", "diligence"),
    ),
    # ---------------------------------------------------------- vulnerabilities
    Control(
        id="VUL-01",
        title="A documented vulnerability management programme",
        objective="Vulnerabilities are found and fixed on a process rather than on request.",
        applies=_always,
        evidence=lambda i: (_response(i, "vulnerability_management"),),
        severity=Severity.MEDIUM,
        condition=(
            "Ask how vulnerabilities are discovered, triaged and tracked to closure, and "
            "who owns that. A vendor without an answer is not necessarily insecure, but "
            "they are finding out about vulnerabilities the same way you would."
        ),
        question=(
            "How do you discover and track vulnerabilities in your product and your "
            "infrastructure, and who owns remediation?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("8.8", "Management of technical vulnerabilities"),
            _soc2("CC7.1", "Detection of configuration changes and vulnerabilities"),
            _cis("7", "Continuous Vulnerability Management"),
        ),
        evidence_facts=("response.vulnerability_management",),
        why_template="every vendor runs software with vulnerabilities in it",
        tags=("vulnerability",),
    ),
    Control(
        id="VUL-02",
        title="Published remediation timescales",
        objective="There is a stated deadline per severity, not a best-efforts sentence.",
        applies=lambda i: _personal_data(i) or _sensitive(i) or _connected(i),
        evidence=lambda i: (_response(i, "patch_sla"),),
        severity=Severity.MEDIUM,
        condition=(
            "Get the remediation timescales by severity into the contract, and ask what "
            "the current compliance against them is. An SLA nobody measures is a "
            "sentence; the interesting number is the percentage of criticals closed "
            "inside it last quarter."
        ),
        question=(
            "What are your remediation timescales by severity, and what proportion of "
            "critical and high findings were closed inside them last quarter?"
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("8.8", "Management of technical vulnerabilities"),
            _soc2("CC7.1", "Detection of configuration changes and vulnerabilities"),
            _cis("7", "Continuous Vulnerability Management"),
        ),
        evidence_facts=("response.patch_sla",),
        why_template="the vendor holds sensitive data or connects to your systems",
        tags=("vulnerability",),
    ),
    Control(
        id="SDL-01",
        title="A documented secure development lifecycle",
        objective=(
            "Security review, code review and dependency scanning happen before a "
            "release, as part of the process."
        ),
        applies=lambda i: (
            i.hosting is not Hosting.SELF_HOSTED and (_personal_data(i) or _sensitive(i))
        ),
        evidence=lambda i: (
            _response(i, "secure_development_lifecycle"),
            _response(i, "dependency_scanning"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Ask what happens between a developer's commit and production: peer review, "
            "static analysis, dependency scanning, and who can push without them. The "
            "exceptions are the interesting part."
        ),
        question=(
            "What does your release process require before code reaches production, and "
            "are third-party dependencies scanned for known vulnerabilities?"
        ),
        frameworks=(
            _nist("PR.PS", "Platform Security"),
            _iso("8.25", "Secure development life cycle"),
            _soc2("CC8.1", "Change management"),
            _cis("16", "Application Software Security"),
        ),
        evidence_facts=("response.secure_development_lifecycle",),
        why_template="the vendor builds and operates the software holding your data",
        tags=("development",),
    ),
    # -------------------------------------------------------------- resilience
    Control(
        id="BCP-01",
        title="Business continuity with a tested recovery",
        objective=(
            "There is a stated recovery objective and somebody has restored from "
            "backup to prove it."
        ),
        applies=lambda i: (
            i.criticality is not None and i.criticality.rank >= Criticality.IMPORTANT.rank
        ),
        evidence=lambda i: (
            _response(i, "business_continuity_plan"),
            _response(i, "backup_tested"),
        ),
        severity=Severity.MEDIUM,
        condition=(
            "Get the recovery time and recovery point objectives in writing, with the "
            "date of the last restoration test, and check they are compatible with what "
            "breaks on your side. An untested backup is a hypothesis."
        ),
        question=(
            "What are your RTO and RPO for this service, when did you last test a "
            "restoration, and what was the result?"
        ),
        frameworks=(
            _nist("RC.RP", "Incident Recovery Plan Execution"),
            _iso("5.30", "ICT readiness for business continuity"),
            _soc2("A1.2", "Availability — backup and recovery"),
            _cis("11", "Data Recovery"),
        ),
        evidence_facts=("criticality", "outage_impact"),
        why_template="the business has said it depends on this vendor being available",
        tags=("resilience",),
    ),
    Control(
        id="EXT-01",
        title="You can get the data out",
        objective="There is a documented export in a format you could actually use.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        evidence=_nothing,
        severity=Severity.LOW,
        condition="",
        question=(
            "How do we export our data, in what format, and is there an API or is it a "
            "support request? What does it cost after termination?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("data_classes",),
        why_template="the vendor will hold data you would need back",
        tags=("exit",),
    ),
    Control(
        id="EXT-02",
        title="A right to reassess during the term",
        objective=(
            "The contract lets you ask for current evidence, rather than the evidence "
            "that existed at signature."
        ),
        applies=lambda i: i.criticality is Criticality.CRITICAL or _personal_data(i),
        evidence=lambda i: (
            ("intake:right_to_audit", _tri(i.right_to_audit)),
            _response(i, "right_to_audit"),
        ),
        severity=Severity.LOW,
        condition=(
            "Include a right to receive the current attestation annually and to request "
            "a reassessment on material change. A full audit right is rarely granted and "
            "rarely exercised; an annual evidence right is granted routinely and is the "
            "one that gets used."
        ),
        question=(
            "Will you provide your current attestation annually for the life of the "
            "contract, and notify us of material changes to the service or its hosting?"
        ),
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC9.2", "Vendor and business partner risk management"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("right_to_audit",),
        why_template="the vendor is business-critical or will process personal data",
        tags=("contract", "assurance"),
    ),
    Control(
        id="INS-01",
        title="Cyber insurance appropriate to the exposure",
        objective="The vendor carries cover that would matter if the worst happened.",
        applies=lambda i: (
            i.criticality is Criticality.CRITICAL
            or _personal_data(i)
            or _has_data(i, DataClass.CREDENTIALS)
        ),
        evidence=_nothing,
        severity=Severity.LOW,
        condition="",
        question=(
            "What cyber and technology errors-and-omissions cover do you carry, at what "
            "limit, and can you provide the certificate of insurance?"
        ),
        frameworks=(
            _nist("GV.RM", "Risk Management Strategy"),
            _iso("5.20", "Addressing information security within supplier agreements"),
            _soc2("CC9.1", "Risk mitigation for business disruptions"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("criticality", "data_classes"),
        why_template="the engagement is business-critical or involves personal or credential data",
        tags=("contract", "diligence"),
    ),
    Control(
        id="NET-01",
        title="Exposure of a self-hosted or hybrid component is deliberate",
        objective=(
            "Anything the vendor installs in your environment is reachable only by "
            "what needs to reach it."
        ),
        applies=lambda i: (
            i.hosting in {Hosting.SELF_HOSTED, Hosting.HYBRID} or Integration.AGENT in i.patterns()
        ),
        evidence=lambda i: (
            (
                "intake:exposure",
                Attestation.ATTESTED
                if i.exposure in {Exposure.RESTRICTED, Exposure.PRIVATE}
                else Attestation.ABSENT
                if i.exposure is Exposure.INTERNET
                else Attestation.NOT_EVIDENCED,
            ),
        ),
        severity=Severity.HIGH,
        condition=(
            "Put the component behind the VPN, an IP allow-list or a private link, and "
            "confirm who patches it. Software you run in your own environment carries "
            "none of the vendor's operational controls with it, and their attestation "
            "says nothing about your deployment of it."
        ),
        question=(
            "How is the self-hosted or agent component reachable, who patches it, and "
            "what privileges does it hold on the host?"
        ),
        frameworks=(
            _nist("PR.IR", "Technology Infrastructure Resilience"),
            _iso("8.20", "Networks security"),
            _soc2("CC6.6", "Protection against external threats"),
            _cis("12", "Network Infrastructure Management"),
        ),
        evidence_facts=("exposure", "hosting", "integrations"),
        why_template="the vendor's software or agent runs inside your environment",
        tags=("exposure",),
    ),
    Control(
        id="GOV-01",
        title="A named owner for the relationship",
        objective="Somebody is accountable for this vendor after the project ends.",
        applies=_always,
        evidence=lambda i: (
            ("intake:owner", Attestation.ATTESTED if i.owner else Attestation.NOT_EVIDENCED),
        ),
        severity=Severity.LOW,
        condition=(
            "Name the individual accountable for this vendor once it is signed. "
            "Unowned vendors are the ones that renew automatically, miss their "
            "reassessment, and surface in an audit three years later with an expired "
            "attestation nobody chased."
        ),
        question="Who on our side owns this relationship after signature?",
        frameworks=(
            _nist("GV.RR", "Roles, Responsibilities, and Authorities"),
            _iso("5.9", "Inventory of information and other associated assets"),
            _soc2("CC1.5", "Accountability for internal control responsibilities"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("owner",),
        why_template="every vendor needs somebody accountable for it",
        tags=("governance",),
    ),
    Control(
        id="GOV-02",
        title="The review happened before commitment",
        objective="The engagement can still change when the review lands.",
        applies=_always,
        # Nobody having said where the deal stands is not the same as the deal
        # being early. The parser applies "evaluating" as a display default when
        # the field is blank and records the question as unanswered; reading that
        # default here attested "the review happened before commitment" against a
        # form where nobody answered, which is silence recorded as evidence -- the
        # same merge as reading an absence out of one, in the direction that
        # flatters rather than accuses. The fact list is the honest test of
        # whether the requester actually answered.
        evidence=lambda i: (
            (
                "intake:stage",
                Attestation.NOT_EVIDENCED
                if "stage" not in i.fact_ids()
                else Attestation.ATTESTED
                if i.stage in {"evaluating", "negotiating"}
                else Attestation.ABSENT,
            ),
        ),
        severity=Severity.LOW,
        condition=(
            "Note that the contract is already signed or the service already in use, so "
            "findings become remediation and renegotiation rather than conditions. Worth "
            "recording — a pattern of reviews arriving after signature is a process "
            "problem, not a vendor one."
        ),
        question="Where is this in the buying cycle?",
        frameworks=(
            _nist("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            _iso("5.19", "Information security in supplier relationships"),
            _soc2("CC3.2", "Identification and analysis of risk"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("stage", "contract_status"),
        why_template="a review is worth more before the contract is signed than after",
        tags=("governance", "process"),
    ),
)


CONTROLS_BY_ID: dict[str, Control] = {c.id: c for c in BUILTIN_CONTROLS}


def known_control_ids() -> set[str]:
    """Every valid control id. The gate discards a finding citing anything else."""
    return set(CONTROLS_BY_ID)


def frameworks_covered() -> dict[str, int]:
    """How many objectives reference each framework. Printed by ``vendorreview controls``."""
    counts: dict[str, int] = {}
    for entry in BUILTIN_CONTROLS:
        for reference in entry.frameworks:
            counts[reference.name] = counts.get(reference.name, 0) + 1
    return counts


def combine(sources: Sources) -> tuple[Attestation, str | None]:
    """Resolve several sources into one state, and report a disagreement.

    Attested beats absent, and both beat silence -- see
    :func:`vendorreview.models.strongest` for why that order is not optimism.
    Where one source says yes and another says no, the disagreement is returned
    alongside the resolved state rather than discarded, because it is frequently
    the most interesting thing in the pack: a questionnaire answered by the sales
    engineer and a SOC 2 signed by an auditor are not equally considered claims,
    and the gap between them is worth a sentence in the review.
    """
    resolved = strongest(*(state for _, state in sources))

    yes = [name for name, state in sources if state.is_attested]
    no = [name for name, state in sources if state.is_absent]
    if yes and no:
        return resolved, f"{', '.join(yes)} says yes; {', '.join(no)} says no"
    return resolved, None
