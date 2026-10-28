from collections.abc import Iterator
from pathlib import Path

import pytest

import strix.skills as skills_mod
from strix.agents.prompt import _resolve_skills, render_system_prompt
from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    register_skill_dir,
    registered_skill_dirs,
    skill_search_dirs,
    validate_requested_skills,
)
from strix.utils.resource_paths import get_strix_resource_path


@pytest.fixture(autouse=True)
def _clear_extra_dirs() -> Iterator[None]:
    original = list(skills_mod._EXTRA_SKILL_DIRS)
    skills_mod._EXTRA_SKILL_DIRS.clear()
    try:
        yield
    finally:
        skills_mod._EXTRA_SKILL_DIRS[:] = original


def _write_skill(root: Path, category: str, name: str, body: str) -> None:
    category_dir = root / category
    category_dir.mkdir(parents=True, exist_ok=True)
    (category_dir / f"{name}.md").write_text(body, encoding="utf-8")


def _write_root_skill(root: Path, name: str, body: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{name}.md").write_text(body, encoding="utf-8")


def test_no_registration_leaves_builtin_only() -> None:
    assert registered_skill_dirs() == ()
    builtin = get_strix_resource_path("skills")
    assert skill_search_dirs() == (builtin,)
    assert {"nmap", "subfinder"}.issubset(
        {skill["name"] for skill in get_available_skills()["tooling"]}
    )
    assert "default_credentials" in {
        skill["name"] for skill in get_available_skills()["vulnerabilities"]
    }


def test_register_is_idempotent_and_ordered(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()

    register_skill_dir(a)
    register_skill_dir(b)
    register_skill_dir(a)

    # Most recently registered wins → highest precedence first.
    assert registered_skill_dirs() == (b, a)


def test_registered_dir_adds_new_skill(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "widget body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["extra"] == [{"name": "widget", "description": ""}]
    assert load_skills(["widget"]) == {"widget": "widget body"}


def test_available_skill_includes_frontmatter_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        "---\nname: widget\ndescription: Useful widget guidance\n---\nwidget body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful widget guidance"}
    ]


def test_available_skill_supports_colon_in_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        '---\nname: widget\ndescription: "Useful widget: handles YAML"\n---\nwidget body',
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful widget: handles YAML"}
    ]


def test_available_skill_normalizes_quoted_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        '---\nname: widget\ndescription: "Useful: widget guidance"\n---\nwidget body',
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful: widget guidance"}
    ]


def test_available_skill_normalizes_multiline_descriptions(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "block",
        "---\nname: block\n\ndescription: |\n"
        "  First paragraph\n\n  Second paragraph\n\n---\nblock body",
    )
    _write_skill(
        tmp_path,
        "extra",
        "plain",
        "---\nname: plain\n\ndescription: First line\n  Second line\n\n---\nplain body",
    )
    register_skill_dir(tmp_path)

    available = {skill["name"]: skill["description"] for skill in get_available_skills()["extra"]}
    assert available == {
        "block": "First paragraph Second paragraph",
        "plain": "First line Second line",
    }


def test_available_skill_supports_block_scalar_trailing_comment(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "commented",
        "---\nname: commented\ndescription: | # paragraph\n"
        "  First line\n  Second line\n---\ncommented body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "commented", "description": "First line Second line"}
    ]


def test_malformed_frontmatter_keeps_skill_body(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "broken",
        "---\nname: [broken\ndescription: should be empty\n---\nbroken body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [{"name": "broken", "description": ""}]
    assert load_skills(["extra/broken"]) == {"broken": "broken body"}


def test_system_prompt_renders_skill_descriptions() -> None:
    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "- technologies/firebase: Firebase security testing covering" in prompt
    assert "default-login test" in prompt


def test_system_prompt_omits_empty_skill_description(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "---\nname: widget\ndescription:\n---\nwidget body")
    register_skill_dir(tmp_path)

    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "- extra/widget\n" in prompt
    assert "- extra/widget: " not in prompt


def test_registered_root_skill_is_discoverable_and_valid(tmp_path: Path) -> None:
    _write_root_skill(tmp_path, "widget", "widget body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["root"] == [{"name": "widget", "description": ""}]
    assert validate_requested_skills(["widget"]) is None
    assert validate_requested_skills(["root/widget"]) is None
    assert load_skills(["widget"]) == {"widget": "widget body"}
    assert load_skills(["root/widget"]) == {"widget": "widget body"}


def test_ambiguous_bare_skill_requires_qualified_name(tmp_path: Path) -> None:
    _write_skill(tmp_path, "alpha", "widget", "alpha body")
    _write_skill(tmp_path, "beta", "widget", "beta body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["alpha"] == [{"name": "widget", "description": ""}]
    assert get_available_skills()["beta"] == [{"name": "widget", "description": ""}]
    assert validate_requested_skills(["alpha/widget"]) is None
    assert validate_requested_skills(["beta/widget"]) is None

    error = validate_requested_skills(["widget"])
    assert error is not None
    assert "Ambiguous skill name" in error
    assert "alpha/widget" in error
    assert "beta/widget" in error

    assert load_skills(["widget"]) == {}
    assert load_skills(["alpha/widget"]) == {"widget": "alpha body"}
    assert load_skills(["beta/widget"]) == {"widget": "beta body"}


def test_registered_dir_overrides_builtin_skill(tmp_path: Path) -> None:
    _write_skill(tmp_path, "coordination", "root_agent", "overridden root agent")
    register_skill_dir(tmp_path)

    loaded = load_skills(["coordination/root_agent"])
    assert loaded["root_agent"] == "overridden root agent"


def test_builtin_skill_still_loads_when_not_overridden(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "widget body")
    register_skill_dir(tmp_path)

    # A packaged skill the registered dir does not shadow still resolves.
    assert load_skills(["scan_modes/deep"]).get("deep")


def test_missing_skill_is_skipped(tmp_path: Path) -> None:
    register_skill_dir(tmp_path)
    assert load_skills(["does_not_exist"]) == {}


def test_resolve_skills_always_includes_analysis_baseline() -> None:
    resolved = _resolve_skills(requested=None)

    assert "analysis/counterevidence" in resolved
    assert "analysis/severity_calibration" in resolved
    assert "analysis/triage_validation" in resolved
    assert "tooling/hexstrike" in resolved


def test_default_credentials_skill_is_loadable_by_qualified_name() -> None:
    loaded = load_skills(["vulnerabilities/default_credentials"])

    assert "default_credentials" in loaded
    assert "one controlled attempt" in loaded["default_credentials"]


def test_cve_exploit_validation_skill_is_loadable_by_qualified_name() -> None:
    loaded = load_skills(["vulnerabilities/cve_exploit_validation"])

    body = loaded["cve_exploit_validation"]
    assert "confirmed" in body
    assert "ruled_out" in body
    assert "inconclusive" in body
    assert "needs_follow_up" in body
    assert "related_report_ids" in body
    assert "at most two" in body
    assert "create_dependency_report" in body
    assert "create_vulnerability_report" in body


def test_bypass_specialist_skills_cover_auth_waf_and_filters() -> None:
    loaded = load_skills(
        [
            "vulnerabilities/authentication_bypass",
            "vulnerabilities/waf_evasion",
            "vulnerabilities/input_filter_bypass",
        ]
    )

    assert "protected consequence" in loaded["authentication_bypass"]
    assert "Fingerprint Before Evasion" in loaded["waf_evasion"]
    assert "same semantic security-relevant input" in loaded["waf_evasion"]
    assert "canonicalization" in loaded["input_filter_bypass"]
    assert "needs_follow_up" in loaded["input_filter_bypass"]


def test_deep_prompt_routes_bypass_signals() -> None:
    prompt = render_system_prompt(scan_mode="deep", is_root=True)

    assert "authentication_bypass" in prompt
    assert "waf_evasion" in prompt
    assert "input_filter_bypass" in prompt


def test_source_artifact_skill_includes_discovered_source_pivot() -> None:
    loaded = load_skills(["vulnerabilities/source_artifact_leakage"])

    body = loaded["source_artifact_leakage"]
    assert "Discovered Source Pivot" in body
    assert "Local Code Review - Discovered Source" in body
    assert "source_review=True" in body
    assert "do not execute" in body.lower()
    assert "create_vulnerability_report" in body
    assert "current_target_confirmed" in body
    assert "out_of_scope_target" in body


def test_system_prompt_routes_blackbox_source_leaks_to_source_pivot() -> None:
    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "Discovered Source Pivot" in prompt
    assert "create_agent(source_review=true" in prompt
    assert "report that disclosure against the current endpoint" in prompt


def test_root_prompt_requires_recon_results_to_drive_vulnerability_dispatch() -> None:
    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "RECON-TO-VULNERABILITY HANDOFF GATE" in prompt
    assert "vulnerability dispatch matrix" in prompt
    assert "recon-only completion is invalid" in prompt
    assert "object IDs/roles/tenants" in prompt
    assert "cve_exploit_validation" in prompt


def test_deep_mode_requires_cve_poc_validation() -> None:
    prompt = render_system_prompt(scan_mode="deep", is_root=True)

    assert "Deep CVE PoC Validation" in prompt
    assert "A deep scan must not leave a CVE candidate" in prompt
    assert "cve_exploit_validation" in prompt
    assert "needs_follow_up" in prompt


def test_recon_handoff_requires_structured_downstream_candidates() -> None:
    prompt = render_system_prompt(scan_mode="quick", is_root=False)

    assert "surface → observed signal → likely risk area → recommended skill(s)" in prompt
    assert "ROOT AGENT: after recon results arrive" not in prompt


def test_resolve_skills_adds_scope_triage_for_root_only() -> None:
    assert "reconnaissance/scope_triage" not in _resolve_skills(requested=None)
    assert "reconnaissance/scope_triage" in _resolve_skills(requested=None, is_root=True)


def test_resolve_skills_adds_diff_mode_only_when_diff_scoped() -> None:
    assert "scan_modes/diff" not in _resolve_skills(requested=None)
    diff_scoped = _resolve_skills(requested=None, is_diff_scoped=True)
    assert "scan_modes/diff" in diff_scoped
    # Diff scope overlays the depth mode rather than replacing it.
    assert "scan_modes/deep" in diff_scoped


def test_resolve_skills_gates_source_aware_skills_on_whitebox() -> None:
    blackbox = _resolve_skills(requested=None)
    assert "analysis/fix_verification" not in blackbox
    assert "analysis/source_aware_discovery" not in blackbox
    assert "coordination/verified_whitebox_audit" not in blackbox

    whitebox = _resolve_skills(requested=None, is_whitebox=True)
    assert "analysis/fix_verification" in whitebox
    assert "analysis/source_aware_discovery" in whitebox
    assert "coordination/verified_whitebox_audit" in whitebox


def test_verified_whitebox_protocol_requires_independent_verification() -> None:
    loaded = load_skills(["coordination/verified_whitebox_audit"])

    body = loaded["verified_whitebox_audit"]
    assert "Whitebox Coverage Critic" in body
    assert "Only a verifier may call `create_vulnerability_report`" in body
    assert "needs_validation" in body
    assert "no external network" in body


def test_verified_whitebox_protocol_is_rendered_only_for_whitebox() -> None:
    blackbox = render_system_prompt(scan_mode="quick", is_root=True)
    whitebox = render_system_prompt(scan_mode="quick", is_root=True, is_whitebox=True)

    assert "Verified White-Box Audit Protocol" not in blackbox
    assert "Verified White-Box Audit Protocol" in whitebox
    assert "Only a verifier may call `create_vulnerability_report`" in whitebox


def test_new_skill_files_load() -> None:
    names = [
        "analysis/counterevidence",
        "analysis/severity_calibration",
        "analysis/triage_validation",
        "analysis/evidence_hygiene",
        "analysis/fix_verification",
        "analysis/source_aware_discovery",
        "coordination/verified_whitebox_audit",
        "reconnaissance/scope_triage",
        "reconnaissance/web_attack_surface",
        "tooling/recon_enrichment",
        "tooling/hexstrike",
        "vulnerabilities/second_order_sqli",
        "vulnerabilities/shadow_api",
        "vulnerabilities/account_takeover",
        "vulnerabilities/api_misconfiguration",
        "vulnerabilities/cache_poisoning",
        "vulnerabilities/clickjacking",
        "vulnerabilities/cors_misconfiguration",
        "vulnerabilities/exceptional_conditions",
        "vulnerabilities/forgot_password",
        "vulnerabilities/host_header_injection",
        "vulnerabilities/html_injection",
        "vulnerabilities/ldap_xpath_injection",
        "vulnerabilities/mfa_bypass",
        "vulnerabilities/session_management",
        "vulnerabilities/anti_automation_controls",
        "vulnerabilities/source_artifact_leakage",
        "vulnerabilities/cve_exploit_validation",
        "vulnerabilities/authentication_bypass",
        "vulnerabilities/waf_evasion",
        "vulnerabilities/input_filter_bypass",
        "vulnerabilities/spa_api_discovery",
        "protocols/grpc",
        "protocols/saml",
        "protocols/websocket",
        "frameworks/aspnet",
        "frameworks/laravel",
        "frameworks/nodejs",
        "frameworks/springboot",
        "custom/ci_cd_security",
        "scan_modes/diff",
    ]
    loaded = load_skills(names)
    for name in names:
        key = name.split("/")[-1]
        assert loaded.get(key), f"{name} failed to load"
