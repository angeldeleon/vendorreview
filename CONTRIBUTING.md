# Contributing

## The most useful contributions

**A control objective.** [`src/vendorreview/controls/catalog.py`](src/vendorreview/controls/catalog.py) is one reviewable table of what a vendor review checks. One entry is real value for about thirty lines, and it is the file most worth reviewing — a wrong applicability rule fires on vendors it should not, and that is how a security process loses its audience.

Every entry needs five things:

1. **An applicability rule** — a pure predicate over the declared engagement. If it returns True for every vendor, it is not a rule, it is a checklist row, and it will be ignored along with the rest of the questionnaire it came from.
2. **Evidence sources**, as `(source, attestation)` pairs. More than one is normal, and the disagreement between them is frequently the most interesting thing in the pack.
3. **A condition**, for when the answer is no. Concrete enough to put on a call agenda. "Improve access management" is a sentence.
4. **A question**, for when nothing settles it. A different sentence from the condition, and this is not a formality — printing the same words for both is how a review ends up accusing a vendor of something nobody asked them about.
5. **All four framework references**, taken from the published frameworks rather than from memory. CI regex-checks every identifier and requires all four.

**A phrasing the extractor misses.** SOC 2 reports say the same six things in a hundred ways. If your vendor's report states its period, its criteria, its exceptions or its subservice method in wording [`evidence/soc2.py`](src/vendorreview/evidence/soc2.py) does not recognise, that is a good issue and a better pull request. Include the phrasing, redacted; nobody needs the vendor's name.

## Before opening a pull request

```bash
pip install -e ".[dev]"
ruff format . && ruff check . && mypy src && bandit -q -r src -c pyproject.toml && pytest
```

## What will be pushed back on

- **Turning silence into an absence.** An objective whose evidence function returns `ABSENT` because a document did not mention something. This is the failure this tool exists to avoid, and one false accusation is enough for a vendor's security lead to stop reading anything it produces.
- **An objective that applies to every vendor.** The reason two-hundred-row questionnaires go unread.
- **Letting the model decide anything the gate cannot check.** The decision, applicability and severity are computed deliberately. A new field on the analysis schema needs to argue why the gate can validate it.
- **A new regex that can backtrack.** Every pattern here runs over documents supplied by the party being assessed. Keep them linear and anchored; there is a timing test, and it exists because one of them was not.
- **Adding intake questions without removing any.** The form has a budget: roughly ten minutes of a non-security person's attention. Past that it does not get filled in, and a review that does not happen is worse than one that missed a nuance.
- **Parsing PDF.** Not a convenience worth the attack surface. `pdftotext -layout` is one command, and it is the only place anybody gets to see exactly what the tool will read.
- **Longer reports.** Two audiences, a page each. A pull request that adds a section needs to argue why it earns the space.

## Security issues

Do not open a public issue. Use [private reporting](https://github.com/angeldeleon/vendorreview/security/advisories/new).
