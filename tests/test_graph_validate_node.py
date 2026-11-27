from __future__ import annotations

from pentest_agent.graph import validate_input_node


def test_validate_input_node_blocks_unauthorized(valid_target_dict):
    data = dict(valid_target_dict)
    data["authorization_confirmed"] = False
    state = {"session_id": data["session_id"], "target": data}

    cmd = validate_input_node(state)

    assert cmd.goto == "audit"  # refused runs still get an audit record
    assert cmd.update["phase"] == "blocked"
    assert "authorization_confirmed" in cmd.update["error"]


def test_validate_input_node_proceeds_when_authorized(valid_target_dict):
    state = {"session_id": valid_target_dict["session_id"], "target": valid_target_dict}

    cmd = validate_input_node(state)

    assert cmd.goto == "choose_scope"  # what to test: website + code, website only, code only
    assert cmd.update["phase"] == "validated"
    assert "example.com" in cmd.update["allowed_domains"]
    assert "www.example.com" in cmd.update["allowed_domains"]
    assert cmd.update["profile"] == "quick"
    assert "started_at" in cmd.update


def test_validate_input_node_carries_additional_allowed_domains(valid_target_dict):
    data = dict(valid_target_dict)
    data["additional_allowed_domains"] = ["cdn.example.net"]
    state = {"session_id": data["session_id"], "target": data}

    cmd = validate_input_node(state)

    assert "cdn.example.net" in cmd.update["allowed_domains"]
