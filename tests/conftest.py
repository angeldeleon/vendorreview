"""Fixtures shared across the suite.

The helpers here build intakes and evidence rather than reading files, because
almost every test is about what the tool concludes rather than about YAML
parsing — and the handful that are about parsing say so by reading a file.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from vendorreview.evidence.reader import Document, load_document
from vendorreview.intake import parse_intake
from vendorreview.models import VendorIntake

# Fixed so a staleness verdict does not change with the calendar. Every parser
# takes ``as_of`` for this reason.
TODAY = date(2026, 6, 1)

BASE_INTAKE: dict[str, Any] = {
    "vendor": "Brightwave Inc",
    "service": "Runs our customer webinars and holds the attendee list.",
    "requesting_team": "Marketing",
    "owner": "Priya Raman",
    "stage": "negotiating",
    "hosting": "saas",
    "data_classes": ["personal data"],
    "data_subjects": ["customers"],
    "criticality": "important",
    "exposure": "internet",
}


@pytest.fixture
def base() -> dict[str, Any]:
    return dict(BASE_INTAKE)


def intake(**overrides: Any) -> VendorIntake:
    """A parsed intake with the base engagement plus overrides."""
    raw = dict(BASE_INTAKE)
    raw.update(overrides)
    return parse_intake({k: v for k, v in raw.items() if v is not None})


def document(text: str, name: str = "evidence.txt") -> Document:
    """A Document built from a string, without touching the filesystem."""
    from vendorreview.validation import sanitise

    lines = tuple(sanitise(line, limit=1000) for line in text.splitlines())
    return Document(name=name, lines=lines, pages=1, readable=True)


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def read(tmp_path: Path, name: str, text: str) -> Document:
    """Round-trip through the real reader, so path handling is exercised too."""
    return load_document(write(tmp_path, name, text))


CLEAN_RESPONSES = """
sso_saml_oidc: yes
scim_deprovisioning: yes
mfa_enforced: yes
admin_role_separation: yes
encryption_in_transit: yes
encryption_at_rest: yes
key_management: yes
data_residency_controlled: yes
retention_policy: yes
deletion_on_termination: yes
subprocessor_list_published: yes
subprocessor_change_notice: yes
vulnerability_management: yes
patch_sla: yes
penetration_test_annual: yes
secure_development_lifecycle: yes
dependency_scanning: yes
audit_log_export: yes
incident_notification: yes
incident_response_plan: yes
business_continuity_plan: yes
backup_tested: yes
background_checks: yes
security_training: yes
iso_scope_covers_service: yes
right_to_audit: yes
vulnerability_disclosure: yes
"""
