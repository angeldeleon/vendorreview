# vendorreview

Third-party security review. A pile of documents the vendor sent you goes in; what they actually attest to, what is missing, what the gaps mean for how you will use them, and the questions worth sending back come out.

[![CI](https://github.com/angeldeleon/vendorreview/actions/workflows/ci.yml/badge.svg)](https://github.com/angeldeleon/vendorreview/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## The problem

Somebody in the business wants a vendor. On your desk: a ninety-page SOC 2, a pen test summary, a DPA in track changes, a completed questionnaire, and a sales deck. Signature is Thursday. You have an hour.

There are two ways this usually goes. Either the review is a rubber stamp — somebody checks the SOC 2 exists, notes the logo on the cover page, and approves — or it is a two-hundred-row questionnaire that takes three weeks, produces a spreadsheet of green cells, and contains no judgement anybody can act on. Both end the same way: the contract gets signed on the date it was always going to be signed, and nobody has learned anything about the vendor.

The reason is not laziness. It is that the interesting content of a vendor pack is *absences*, and absences do not announce themselves. The report period ended fourteen months ago and the cover page looks identical to a fresh one. The trust services criteria cover Security and nothing else. The subservice organisation — the cloud provider where your data will actually sit — is carved out in one sentence in the management assertion that nobody reads. The pen test found four highs and there is no retest letter. Every one of those is a five-word finding buried on a page you skimmed.

vendorreview reads the pack for those lines, works out which control objectives are in scope given how this vendor will actually be used, and produces a short memo with a decision on it. It runs in seconds. Run it on every vendor, then spend your hour on the three things it flagged.

## What it produces

A decision, then the conditions, then the questions, then the evidence underneath:

```
# Third-party review — Brightwave Inc

## 🔴 Do not proceed

1 objective(s) (DAT-05) were answered no and cannot be carried as conditions with a
date: signing would mean an obligation is already being breached.

37 objectives in scope · 21 attested · 8 answered no · 8 not evidenced · 3 blocking questions
Evidence read: SOC 2, questionnaire responses

## What has to happen before signature

1. Execute the data processing agreement before any personal data is sent.
2. The report uses the carve-out method, so it covers none of the controls at the
   subservice organisation — routinely the cloud provider, routinely where your data
   actually sits. Get that provider's own attestation.
3. Ask for the current report, or a bridge letter covering the gap.

## Questions to send the vendor

- Can MFA be enforced for all accounts, is it enforced for your own support and
  engineering staff, and which factors are supported?
- Which of your staff can access customer data in production, is that access
  just-in-time or standing, and is it visible in our audit log?
```

Two audiences, one computation. `--audience requester` prints exactly the above and stops — the decision, the actions, the questions — because the person who wants the vendor needs a thing to do and an email to send. The default keeps going into the evidence state per objective, the control mapping and the framework references, because the reviewer is the one who has to defend the decision at the renewal.

## Attested, absent, not evidenced

This is the whole tool, and it is why it can be sent to a vendor without embarrassment.

**"The SOC 2 does not mention SCIM" is not "the vendor has no SCIM."** It is unknown. Conflating the two is the top false-positive class in third-party review, and it costs more than a wrong line in a report: the vendor's security lead disproves it in ten minutes, forwards the correction to your requesting team, and the next review you produce is not read by either of them.

So every objective resolves to one of three states, and they are printed differently, rated differently, and only one of them can block:

| State | What it means | How it appears |
|---|---|---|
| **Attested** | A document or a signed questionnaire answer says so. Not verified — nobody logged into the vendor's console | Counted, not listed |
| **Answered no** | Somebody said no, or the certificate is expired, or the report is a Type I when a Type II was asked for | A gap, with a condition. The only state that can be blocking |
| **Not evidenced** | Nothing in the pack settles it | A question to send the vendor. Severity capped at medium |

The three states have to hold in both directions, and the second one is easier to get wrong. A form field nobody filled in is not an attestation because the parser applied a display default to it, and a certificate that states *a* scope is not a certificate stating that its scope covers the thing you are buying — which is the classic miss in ISO diligence, and something the tool has to refuse to conclude rather than quietly conclude for you.

A "partial" on a questionnaire is not evidenced, and the vendor's own comment is quoted alongside it — because "partial" is the honest answer to half these questions and usually means "for customers, not for our support staff", which is a different conversation from either yes or no.

## Why you can trust the output

A language model asked to review a vendor will warn about a subprocessor nobody named, cite a control identifier that does not exist, and write both in the same confident register as its correct findings. And the documents it reads were written by the party being assessed — a SOC 2 is a document about a vendor, produced for that vendor, with a footer they control.

So the model is not in charge of anything that matters.

**The decision is computed, not reasoned.** Which objectives apply, what the evidence settles about each, and whether this can be signed — all of it is a pure function of the intake and the extracted evidence. Run it twice, get the same answer. Disagree with the answer and you can point at the line that produced it. `vendorreview check` runs this half with **no API key and no network call**.

**Extraction is deterministic.** No model decides whether a report says "Type II", whether a period has ended, or whether a subservice organisation is carved out. Those are facts about the document, read by code you can go and look at, quoted with a line number.

**The model may only cite what exists.** Findings must reference facts that were declared on the intake or extracted from a document, and control identifiers that are in the catalog. Anything else is dropped before you see it, and the drop is counted. An invented control reference is the most damaging error available here: it survives into a questionnaire sent to the vendor, into a GRC tracker, and into a renewal conversation where somebody looks it up.

**Claims are clamped to the declared engagement, in both directions.** A finding cannot claim a wider blast radius than the integration pattern supports, or more sensitive data than the intake declares — and it cannot claim much less either. Understatement is the half nobody notices: severity is computed from blast radius and data class, so a real risk described as contained to the vendor is a real risk nobody acts on, and the report looks clean. A claim may sit at most two bands below the declared engagement.

**Severity is arithmetic, bounded in both directions.** Catalog rating, moved by at most one band for this engagement, capped at medium when nothing is evidenced. A requester who writes "routine" and "internal" on the form to get a signature this week cannot talk a critical finding down to low.

## Install

```bash
pip install vendorreview
```

## Usage

```bash
vendorreview questions                    # the blank intake form, and the template to send the vendor
vendorreview controls                     # what you will hold vendors to, and its framework mappings
vendorreview check  -i vendor.yml         # objectives + decision. No API key, no network.
vendorreview check  -i vendor.yml --soc2 soc2.txt --responses answers.yml --pentest pt.txt
vendorreview review -i vendor.yml --soc2 soc2.txt -o review.md
vendorreview review -i vendor.yml --audience requester -o for-marketing.md
vendorreview rereview -i vendor.yml       # only what changed since the last review
```

Set `ANTHROPIC_API_KEY` for `review` and `rereview`.

Start with `vendorreview questions`. It prints two things: the intake form, which is about how *you* will use the vendor, and the response template to send *them*. A security team that publishes what it will ask gets better answers than one that asks on a call the week before signature.

### Documents

The reports arrive as PDFs. This does not parse PDF, on purpose — a PDF parser is a large attack surface for a security tool to carry, and the extraction step should be one command you can run and inspect:

```bash
pdftotext -layout brightwave-soc2.pdf brightwave-soc2.txt
vendorreview check -i vendor.yml --soc2 brightwave-soc2.txt
```

`--soc2`, `--iso`, `--pentest` and `--responses` are parsed for the specific things that decide a review. `--document` takes anything else — a DPA, a security addendum, an architecture note — and passes it to the reasoning layer as context. It is read through the same bounded reader as everything else, so a PDF is refused there too. Nothing from `--document` settles a control objective, deliberately: a claim pattern-matched out of prose would look identical in the report to one read off a certificate, and the two deserve different confidence.

## The control catalog

41 objectives across attestation currency and scope, sub-processor disclosure and flow-down, data residency and transfer mechanism, encryption and key custody, tenant isolation, access control including the vendor's own privileged access, customer-visible audit trail, incident notification against both contractual and regulatory clocks, vulnerability management and patch SLAs, secure development, business continuity and tested recovery, exit and data return, insurance, and breach history.

Each carries an applicability predicate, so a tenant-isolation objective does not fire on software you self-host and a cross-border objective does not fire on a vendor holding no personal data. Each carries two sentences rather than one: the condition when the answer is no, and the question when nothing settles it. `vendorreview controls` prints the lot.

| Framework | Used for |
|---|---|
| **NIST CSF 2.0** | Function and category references — broad, and readable by people outside security |
| **ISO 27001:2022 Annex A** | What an ISO auditor expects a supplier review to cite |
| **SOC 2 TSC** | The common language for SaaS assessment, and what the report you are reading is written against |
| **CIS Controls v8** | The most prescriptive — good for conditions that go into a contract schedule |

Control identifiers are taken from the published frameworks and regex-checked in CI. The mapping *between* them is editorial judgement and is meant to be argued with — [`controls/catalog.py`](src/vendorreview/controls/catalog.py) is one reviewable table for exactly that reason.

Mapping an objective to ISO A.5.20 does not make a vendor certified, and this is not an audit. See Limitations.

## Renewal

The second review of the same vendor reports only what changed. Vendors come back — the product adds an agent, a new subprocessor appears, the SOC 2 is a year newer — and re-reading a full review each time is how the reassessment gets skipped and the renewal goes through on the strength of a review from three years ago.

Comparison is on the *structure* of the declared engagement, not its wording, so rephrasing what the service does is not a change and does not resurface anything.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Reviewed, nothing at or above `fail_on`, nothing blocking |
| 1 | Reviewed, conditions or blocking items apply |
| 2 | Could not run |

1 and 2 are separate on purpose. A pipeline that treats them alike eventually goes green because the review broke rather than because the vendor got safer.

## What leaves your infrastructure

`check`, `questions` and `controls` send nothing. They are local and need no key.

`review` and `rereview` send the intake answers, the facts extracted from the evidence, and — if you attach one with `--document` — that document's text, up to the first 1,200 lines. Credential-shaped strings are redacted in all of it, at one boundary, before anything is sent. If a vendor's pack is too sensitive to leave your network, run `check`: the objective evaluation and the decision are identical either way.

The review history is a list of every vendor assessed and every gap each one had — a shortlist of which of your suppliers to attack, and through what. It is created `0600` and gitignored by default.

## Limitations

Worth knowing before you rely on it:

- **It reviews documents, not systems.** Nothing here connects to the vendor. Attested means somebody wrote it down, not that it is true. Every well-known vendor breach of the last decade happened to a company holding a current, clean SOC 2.
- **This is not an audit and not a certification.** Framework references exist to place a condition in familiar language. An auditor wants evidence of operating effectiveness over a period, which is a different exercise entirely — and is, in fact, what the SOC 2 you are reading already is.
- **Extraction is pattern matching over text.** It reads what a report literally says, and it will miss things a report says unusually. Everything it misses stays *not evidenced* rather than becoming a false absence, which is the safe direction, but a thin extraction and a thin vendor look similar on the page. The confidence line says which one you are holding. The same applies to a document cut at a size cap: an absence has to come from something the parser found, never from something it did not reach.
- **It does not parse PDF.** Run `pdftotext -layout` first. This is a deliberate trade of convenience for attack surface.
- **The catalog is a starting point, not your policy.** Forty-one objectives. Your organisation has requirements that are not here, and some of these will not fit how you buy. Fork it — it is one file and it is meant to be edited.
- **The model is in the trust path for findings, though not for the decision.** A plausible-but-wrong finding that cites real facts and real objectives will get through. Treat the findings section as a strong prompt for a human reviewer. The evidence state and the decision do not have this property, which is why they are computed.

## Security design

Full detail in [SECURITY.md](SECURITY.md). The short version: every document is supplied by the party being assessed and is treated that way — read through a descriptor with `O_NOFOLLOW` and `O_NONBLOCK`, size- line- and page-capped, sanitised then redacted at one ordered entry point, and guaranteed by one walk over the finished model rather than by a call at each of forty parse sites. Text is escaped per renderer and by provenance, so a scope statement somebody wrote cannot forge a heading or carry a clickable link into a ticket, and the tool's own prose is not printed with backslashes in it. The API base is SSRF-guarded and redirects are refused. Review history is SQLite at `0600`.

CI runs ruff, mypy, bandit and pip-audit, and asserts the invariants a review would miss — that no framework identifier in the catalog is malformed, that the decision is never read from model output, that silence is recorded as neither an absence nor an attestation, that severity is clamped in both directions, and that nothing credential-shaped reaches the API payload or any of the three report formats, including a key split by an invisible character.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contribution is a control objective: one entry, its applicability rule, its evidence sources, the condition, the question, and its four framework references. The second most useful is a line a SOC 2 states in a phrasing the extractor does not recognise.

Security issues: [private reporting](https://github.com/angeldeleon/vendorreview/security/advisories/new), not a public issue.

## License

Apache 2.0.
