"""Role and display-name normalization for spawned agents."""

from __future__ import annotations

from strix.tools.agents_graph.tools import _normalize_agent_role, _short_agent_name


def test_hypothesis_role_is_accepted_and_inferred() -> None:
    assert (
        _normalize_agent_role("hypothesis", name="Hypothesis Explorer", skills=[])
        == "hypothesis"
    )
    assert (
        _normalize_agent_role("hypothesis_explorer", name="Explorer", skills=[])
        == "hypothesis"
    )
    assert (
        _normalize_agent_role(None, name="Hypothesis Explorer — Upload", skills=[])
        == "hypothesis"
    )
    assert (
        _normalize_agent_role(
            None,
            name="Upload explorer",
            skills=["hypothesis_driven_security_testing"],
        )
        == "hypothesis"
    )


def test_short_agent_name_replaces_prompt_sized_labels() -> None:
    long_name = "Chain and impact review: Target (single, in scope): https://example.test " * 4

    assert (
        _short_agent_name(
            long_name,
            role="chain_reviewer",
            component="Upload",
            risk_area="",
        )
        == "Chain Reviewer: Upload"
    )
    assert (
        _short_agent_name(
            "XSS Specialist",
            role="specialist",
            component="Search",
            risk_area="XSS",
        )
        == "XSS Specialist"
    )

    without_focus = _short_agent_name(
        long_name,
        role="chain_reviewer",
        component="",
        risk_area="",
    )
    assert without_focus.startswith("Chain Reviewer ")
    assert len(without_focus) <= 80
