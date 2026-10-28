from __future__ import annotations

from strix.agents.prompt import render_system_prompt
from strix.skills import load_skills, validate_requested_skills


def test_portswigger_methodology_and_desync_skills_are_loadable() -> None:
    requested = [
        "custom/portswigger_web_security_methodology",
        "vulnerabilities/advanced_http_desync",
    ]
    assert validate_requested_skills(requested) is None

    loaded = load_skills(requested)
    assert "portswigger_web_security_methodology" in loaded
    assert "advanced_http_desync" in loaded
    assert "PortSwigger Topic Routing Matrix" in loaded["portswigger_web_security_methodology"]
    assert "Browser-powered" in loaded["advanced_http_desync"]


def test_cache_and_websocket_skills_include_validation_workflows() -> None:
    loaded = load_skills(["cache_poisoning", "websocket"])
    assert "Establish a Cache Oracle" in loaded["cache_poisoning"]
    assert "Controlled Identity Matrix" in loaded["websocket"]


def test_hacktricks_recognition_overlay_is_loadable() -> None:
    requested = ["custom/hacktricks_recognition_and_validation"]
    assert validate_requested_skills(requested) is None

    loaded = load_skills(requested)
    overlay = loaded["hacktricks_recognition_and_validation"]
    assert "The Five-Step Route" in overlay
    assert "Environment, Cloud, CI/CD, and Directory Services" in overlay
    assert "## Routing Table" in overlay


def test_hypothesis_testing_skill_and_root_prompt_require_creative_pass() -> None:
    requested = ["custom/hypothesis_driven_security_testing"]
    assert validate_requested_skills(requested) is None

    loaded = load_skills(requested)
    body = loaded["hypothesis_driven_security_testing"]
    assert "Skills are a memory aid and routing catalogue" in body
    assert "## Hypothesis Contract" in body
    assert "## Negative-Space Controls" in body

    deep_root_prompt = render_system_prompt(scan_mode="deep", is_root=True)
    assert "MANDATORY CREATIVE HYPOTHESIS PASS" in deep_root_prompt
    assert "hypothesis_driven_security_testing" in deep_root_prompt
    assert "A generic brainstorming agent" in deep_root_prompt
