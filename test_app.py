import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

VALID_PREVIEW_PAYLOAD = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature-branch",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {
                "owner": "docker",
                "name": "build-push-action",
                "ref": "4f58e73531d09ec423978a7c1b7743d60077b441"
            }
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}

VALID_PRODUCTION_PAYLOAD = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "environmentApproval": True,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {
                "owner": "docker",
                "name": "build-push-action",
                "ref": "4f58e73531d09ec423978a7c1b7743d60077b441"
            }
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}


def test_valid_preview_promote():
    response = client.post("/release-gate", json=VALID_PREVIEW_PAYLOAD)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "promote"
    assert data["violations"] == []


def test_valid_production_promote():
    response = client.post("/release-gate", json=VALID_PRODUCTION_PAYLOAD)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "promote"
    assert data["violations"] == []


def test_excess_permission():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["workflow"] = dict(VALID_PREVIEW_PAYLOAD["workflow"])
    # Adding extra permission scope
    payload["workflow"]["permissions"] = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
        "issues": "write"
    }
    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "EXCESS_PERMISSION" in data["violations"]


def test_unsafe_pr_trigger():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["workflow"] = dict(VALID_PREVIEW_PAYLOAD["workflow"])
    payload["workflow"]["trigger"] = "pull_request_target"

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in data["violations"]


def test_tests_incomplete():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["workflow"] = dict(VALID_PREVIEW_PAYLOAD["workflow"])
    payload["workflow"]["testsPassed"] = False

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "TESTS_INCOMPLETE" in data["violations"]


def test_mutable_action():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["workflow"] = dict(VALID_PREVIEW_PAYLOAD["workflow"])
    # Third party action using tag instead of full commit SHA
    payload["workflow"]["actions"] = [
        {"owner": "actions", "name": "checkout", "ref": "v4"},
        {"owner": "third-party", "name": "custom-action", "ref": "v1.0.0"}
    ]

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "MUTABLE_ACTION" in data["violations"]


def test_single_stage_image():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["image"] = dict(VALID_PREVIEW_PAYLOAD["image"])
    payload["image"]["multiStage"] = False

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "SINGLE_STAGE_IMAGE" in data["violations"]


def test_root_runtime():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["image"] = dict(VALID_PREVIEW_PAYLOAD["image"])
    payload["image"]["runsAsRoot"] = True

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "ROOT_RUNTIME" in data["violations"]


def test_secret_in_layer():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["image"] = dict(VALID_PREVIEW_PAYLOAD["image"])
    payload["image"]["secretMode"] = "copy"

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "SECRET_IN_LAYER" in data["violations"]


def test_critical_cve():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["image"] = dict(VALID_PREVIEW_PAYLOAD["image"])
    payload["image"]["criticalVulnerabilities"] = 3

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "CRITICAL_CVE" in data["violations"]


def test_unpinned_image():
    payload = dict(VALID_PREVIEW_PAYLOAD)
    payload["image"] = dict(VALID_PREVIEW_PAYLOAD["image"])
    payload["image"]["digestPinned"] = False

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "UNPINNED_IMAGE" in data["violations"]


def test_invalid_production_ref():
    payload = dict(VALID_PRODUCTION_PAYLOAD)
    payload["ref"] = "refs/heads/feature"

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in data["violations"]


def test_approval_required():
    payload = dict(VALID_PRODUCTION_PAYLOAD)
    payload["workflow"] = dict(VALID_PRODUCTION_PAYLOAD["workflow"])
    payload["workflow"]["environmentApproval"] = False

    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    assert "APPROVAL_REQUIRED" in data["violations"]


def test_multiple_violations():
    payload = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {"contents": "read"},
            "testsPassed": False,
            "matrixComplete": True,
            "failFast": True,
            "actions": [{"owner": "custom", "name": "act", "ref": "main"}]
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "copy",
            "criticalVulnerabilities": 1,
            "digestPinned": False
        }
    }
    response = client.post("/release-gate", json=payload)
    data = response.json()
    assert data["decision"] == "block"
    expected_violations = {
        "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
        "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
        "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"
    }
    assert set(data["violations"]) == expected_violations
