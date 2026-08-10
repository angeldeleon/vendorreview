"""Severity: the table, and the bounds in both directions.

Suppression is the half nobody notices. An exaggerated rating is visible to
anyone reading the report; a real risk described as contained and rated
informational looks exactly like a review that found nothing.
"""

from __future__ import annotations

import pytest

from conftest import intake
from vendorreview.analyze.severity import (
    MAX_ADJUSTMENT,
    UNKNOWN_CAP,
    engagement_adjustment,
    explain,
    explain_gap,
    gap_severity,
    rate,
    score,
)
from vendorreview.models import Attestation, Blast, DataClass, Severity

# --------------------------------------------------------------------------
# Finding severity
# --------------------------------------------------------------------------


def test_data_outranks_reach() -> None:
    # A vendor holding health records for two hundred people is a worse day than
    # a webhook into the press-release system.
    contained_regulated = score(Blast.CONTAINED, DataClass.REGULATED)
    customer_public = score(Blast.CUSTOMER, DataClass.PUBLIC)
    assert contained_regulated > customer_public


def test_the_bands_are_monotonic_in_both_inputs() -> None:
    assert (
        rate(Blast.CUSTOMER, DataClass.REGULATED).rank
        >= rate(Blast.CONNECTED, DataClass.REGULATED).rank
    )
    assert (
        rate(Blast.CUSTOMER, DataClass.REGULATED).rank
        >= rate(Blast.CUSTOMER, DataClass.INTERNAL).rank
    )


def test_public_data_is_capped_at_low_however_far_it_reaches() -> None:
    assert rate(Blast.CUSTOMER, DataClass.PUBLIC) is Severity.LOW
    assert "capped at low" in explain(Blast.CUSTOMER, DataClass.PUBLIC)


def test_assumptions_lower_the_band() -> None:
    assert rate(Blast.CUSTOMER, DataClass.PII, 0).rank > rate(Blast.CUSTOMER, DataClass.PII, 3).rank


def test_the_assumption_penalty_is_capped() -> None:
    # Uncapped, a model sets its own band by choosing how many assumptions to
    # list, and every individual claim still passes the gate. That is the
    # suppression half of prompt injection, and a vendor writes the documents.
    assert score(Blast.CUSTOMER, DataClass.REGULATED, 3) == score(
        Blast.CUSTOMER, DataClass.REGULATED, 20
    )
    assert "(3 counted)" in explain(Blast.CUSTOMER, DataClass.REGULATED, 9)


def test_score_never_goes_negative() -> None:
    assert score(Blast.CONTAINED, DataClass.PUBLIC, 3) == 0.0
    assert rate(Blast.CONTAINED, DataClass.PUBLIC, 3) is Severity.INFO


# --------------------------------------------------------------------------
# Gap severity, bounded in both directions
# --------------------------------------------------------------------------


def test_sensitive_data_raises_a_rating_by_exactly_one_band() -> None:
    parsed = intake(data_classes=["personal data"])
    assert engagement_adjustment(parsed) == 1
    assert gap_severity(Severity.MEDIUM, Attestation.ABSENT, parsed) is Severity.HIGH


def test_a_routine_internal_engagement_lowers_a_rating_by_exactly_one_band() -> None:
    parsed = intake(data_classes=["internal"], criticality="routine")
    assert engagement_adjustment(parsed) == -1
    assert gap_severity(Severity.HIGH, Attestation.ABSENT, parsed) is Severity.MEDIUM


def test_the_adjustment_cannot_move_more_than_one_band_in_either_direction() -> None:
    """A requester cannot talk a finding down, and the tool cannot inflate one.

    The downward half is the one that matters. "Routine" and "internal" are free
    to type into a form by somebody who wants a signature this week, and an
    unbounded adjustment would take an absent DPA from critical to low and the
    exit code from 1 to 0.
    """
    worst = intake(data_classes=["regulated", "credentials"], criticality="critical")
    best = intake(data_classes=["public"], criticality="routine")
    for parsed in (worst, best):
        assert abs(engagement_adjustment(parsed)) <= MAX_ADJUSTMENT

    assert gap_severity(Severity.CRITICAL, Attestation.ABSENT, best).rank >= Severity.HIGH.rank
    assert gap_severity(Severity.MEDIUM, Attestation.ABSENT, worst).rank <= Severity.HIGH.rank


def test_ratings_are_clamped_to_the_ends_of_the_scale() -> None:
    hot = intake(data_classes=["regulated"], criticality="critical")
    cold = intake(data_classes=["public"], criticality="routine")
    assert gap_severity(Severity.CRITICAL, Attestation.ABSENT, hot) is Severity.CRITICAL
    assert gap_severity(Severity.INFO, Attestation.ABSENT, cold) is Severity.INFO


def test_an_unevidenced_objective_is_capped() -> None:
    parsed = intake(data_classes=["regulated"], criticality="critical")
    rated = gap_severity(Severity.CRITICAL, Attestation.NOT_EVIDENCED, parsed)
    assert rated is UNKNOWN_CAP
    assert "not evidenced" in explain_gap(Severity.CRITICAL, Attestation.NOT_EVIDENCED, parsed)


def test_the_unknown_cap_is_a_ceiling_and_never_a_floor() -> None:
    # A LOW objective does not become MEDIUM because nobody answered it.
    parsed = intake(data_classes=["internal"], criticality="routine")
    assert gap_severity(Severity.LOW, Attestation.NOT_EVIDENCED, parsed).rank <= Severity.LOW.rank


def test_an_absent_objective_is_not_capped() -> None:
    parsed = intake(data_classes=["regulated"])
    assert gap_severity(Severity.CRITICAL, Attestation.ABSENT, parsed) is Severity.CRITICAL


@pytest.mark.parametrize("base", list(Severity))
def test_explain_names_the_inputs_a_reader_could_disagree_with(base) -> None:
    parsed = intake()
    text = explain_gap(base, Attestation.ABSENT, parsed)
    assert base.value in text
