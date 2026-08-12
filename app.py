import re
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="CI/CD Release Gate Policy Endpoint")

SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
async def release_gate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"decision": "block", "violations": ["INVALID_JSON"]}
        )

    violations = []

    target = payload.get("target", "")
    event = payload.get("event", "")
    ref = payload.get("ref", "")
    workflow = payload.get("workflow", {})
    if not isinstance(workflow, dict):
        workflow = {}
    image = payload.get("image", {})
    if not isinstance(image, dict):
        image = {}

    # 1. PERMISSIONS CHECK: EXCESS_PERMISSION
    # "Permissions must be exactly least privilege for a release: contents: read, packages: write, and id-token: none. No additional scopes may be present."
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }
    actual_permissions = workflow.get("permissions")
    if not isinstance(actual_permissions, dict) or actual_permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. UNSAFE_PR_TRIGGER
    # "A pull request must use pull_request, never pull_request_target."
    trigger = workflow.get("trigger", "")
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. TESTS_INCOMPLETE
    # "Tests must pass, the whole matrix must finish, and failFast must be false."
    tests_passed = workflow.get("testsPassed") is True
    matrix_complete = workflow.get("matrixComplete") is True
    fail_fast = workflow.get("failFast") is False
    if not (tests_passed and matrix_complete and fail_fast):
        violations.append("TESTS_INCOMPLETE")

    # 4. MUTABLE_ACTION
    # "Actions owned by actions may use a version tag. Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA."
    actions = workflow.get("actions", [])
    if isinstance(actions, list):
        has_mutable = False
        for act in actions:
            if not isinstance(act, dict):
                has_mutable = True
                break
            owner = act.get("owner", "")
            action_ref = act.get("ref", "")
            if owner != "actions":
                if not isinstance(action_ref, str) or not SHA_REGEX.match(action_ref):
                    has_mutable = True
                    break
        if has_mutable:
            violations.append("MUTABLE_ACTION")
    else:
        violations.append("MUTABLE_ACTION")

    # 5. SINGLE_STAGE_IMAGE
    # "The image must be multi-stage..."
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. ROOT_RUNTIME
    # "...run as non-root..."
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. SECRET_IN_LAYER
    # "...use either no build secret or a BuildKit secret mount..."
    secret_mode = image.get("secretMode", "")
    if secret_mode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. CRITICAL_CVE
    # "...have zero critical vulnerabilities..."
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. UNPINNED_IMAGE
    # "...and be referenced by digest."
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production requirements
    # "Production additionally requires a push on refs/heads/main and an environmentApproval: true field on workflow."
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }
