"""Orchestrates the reasoning layer: evidence in, validated findings out.

The sequence is fixed, and each step narrows what the next one can do:

    intake + extracted evidence + computed results
      -> forced tool call (schema-constrained)
      -> gate (facts must exist, control ids must exist, claims clamped)
      -> computed severity

Nothing downstream trusts the model's judgement about what exists or how bad it
is. The decision never comes near here -- it is computed in
:mod:`vendorreview.controls.evaluate` from the control results, and findings only
influence it through their computed severity.

If the API is unreachable this raises rather than returning an empty result. A
vendor review that silently degrades to "no additional risks found" because a
network call failed looks exactly like good news, and would be signed against as
such.
"""

from __future__ import annotations

import os
from typing import Any

from ..httpclient import HTTPError, post_json
from ..models import ControlGap, Finding, Question, VendorIntake
from ..validation import ValidationError, safe_text, sanitise
from . import gate
from .prompt import ANALYSIS_TOOL, SYSTEM_PROMPT, build_user_message

DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_API_BASE = "https://api.anthropic.com/v1/messages"
DEFAULT_MAX_TOKENS = 8000
_API_VERSION = "2023-06-01"
_MAX_MODEL_QUESTIONS = 6


class AnalysisError(Exception):
    """The analysis could not run. Never a substitute for 'no risks found'."""


class Analyzer:
    """Runs the model over an engagement and returns validated findings."""

    def __init__(
        self,
        *,
        api_key_env: str = "ANTHROPIC_API_KEY",
        model: str = DEFAULT_MODEL,
        api_base: str = DEFAULT_API_BASE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = 120.0,
        verify_tls: bool = True,
        allow_internal: bool = False,
        temperature: float = 0.0,
    ) -> None:
        self.api_key_env = api_key_env
        self.model = model
        self.api_base = api_base
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.allow_internal = allow_internal
        # Zero by default. Two reviews of an unchanged pack must reach the same
        # conclusion, or "new since the last review" becomes a coin toss and the
        # renewal signal stops meaning anything.
        self.temperature = temperature

    def api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            raise AnalysisError(
                f"{self.api_key_env} is not set. vendorreview needs an API key for the "
                "reasoning layer; `vendorreview check` runs the objective evaluation and "
                "the decision without one."
            )
        return key

    def analyze(
        self, intake: VendorIntake, gaps: list[ControlGap], applicable: list[str]
    ) -> tuple[list[Finding], list[Question], list[gate.Rejection], str]:
        """Analyse the engagement. Raises rather than degrading to a clean result."""
        if intake.is_empty():
            raise AnalysisError(
                "the intake is empty: no vendor named or no answered questions. This is an "
                "incomplete form, not a clean review. Run `vendorreview questions` for the "
                "blank form."
            )

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": SYSTEM_PROMPT,
            "tools": [ANALYSIS_TOOL],
            # Forced, not suggested. Otherwise the model may answer in prose,
            # which would need parsing -- the fragile step the schema removes.
            "tool_choice": {"type": "tool", "name": ANALYSIS_TOOL["name"]},
            "messages": [{"role": "user", "content": build_user_message(intake, gaps, applicable)}],
        }

        try:
            response = post_json(
                self.api_base,
                payload,
                headers={
                    "x-api-key": self.api_key(),
                    "anthropic-version": _API_VERSION,
                },
                timeout=self.timeout,
                verify_tls=self.verify_tls,
                allow_internal=self.allow_internal,
            )
        except (HTTPError, ValidationError) as exc:
            raise AnalysisError(f"analysis request failed: {exc}") from exc

        raw = _extract_tool_input(response)
        findings, rejections = gate.apply(raw.get("findings"), intake)
        questions = _questions(raw)
        model_id = safe_text(response.get("model") or self.model, limit=80)
        return findings, questions, rejections, model_id


def _extract_tool_input(response: dict[str, Any]) -> dict[str, Any]:
    content = response.get("content")
    if not isinstance(content, list):
        raise AnalysisError("the API response had no content block")

    for block in content:
        if (
            isinstance(block, dict)
            and block.get("type") == "tool_use"
            and block.get("name") == ANALYSIS_TOOL["name"]
        ):
            tool_input = block.get("input")
            if isinstance(tool_input, dict):
                return tool_input

    stop_reason = response.get("stop_reason")
    if stop_reason == "max_tokens":
        raise AnalysisError(
            "the analysis was cut off at the token limit. Raise analysis.max_tokens, or "
            "attach a shorter document."
        )
    raise AnalysisError(
        f"the API did not return the expected tool call (stop_reason={stop_reason})"
    )


def _questions(raw: dict[str, Any]) -> list[Question]:
    """Questions the model would ask. Displayed, never load-bearing.

    ``blocks_decision`` is set here rather than read. A blocking question is what
    turns a review from approve into more-information-needed and fails the exit
    code, so a model marking its own questions as blocking would be moving the
    decision -- the one thing the split in this tool exists to prevent, and the
    one claim in the README that has to hold literally. Closing it cost nothing:
    the question still appears, under open questions rather than blocking ones.

    ``trusted`` is False because the text is written by the model out of an
    engagement somebody else described and documents a vendor wrote, and it lands
    in a report that goes into a ticket.
    """
    questions: list[Question] = []
    items = raw.get("questions")
    if not isinstance(items, list):
        return questions
    for item in items[:_MAX_MODEL_QUESTIONS]:
        if not isinstance(item, dict):
            continue
        text = sanitise(item.get("text") or "", limit=400)
        if not text:
            continue
        questions.append(
            Question(
                text=text,
                why_it_matters=sanitise(item.get("why_it_matters") or "", limit=400),
                blocks_decision=False,
                trusted=False,
            )
        )
    return questions


__all__ = ["AnalysisError", "Analyzer"]
