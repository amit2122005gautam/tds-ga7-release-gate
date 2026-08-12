export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    let payload;
    try {
      payload = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ decision: "block", violations: ["INVALID_JSON"] }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const violations = [];

    const target = payload.target || "";
    const event = payload.event || "";
    const ref = payload.ref || "";
    const workflow = (typeof payload.workflow === "object" && payload.workflow !== null) ? payload.workflow : {};
    const image = (typeof payload.image === "object" && payload.image !== null) ? payload.image : {};

    // 1. EXCESS_PERMISSION
    const expectedPermissions = {
      contents: "read",
      packages: "write",
      "id-token": "none"
    };
    const actualPermissions = workflow.permissions || {};
    const keysMatch = Object.keys(actualPermissions).length === 3 &&
      actualPermissions.contents === "read" &&
      actualPermissions.packages === "write" &&
      actualPermissions["id-token"] === "none";

    if (!keysMatch) {
      violations.push("EXCESS_PERMISSION");
    }

    // 2. UNSAFE_PR_TRIGGER
    const trigger = workflow.trigger || "";
    if (trigger === "pull_request_target" || (event === "pull_request" && trigger !== "pull_request")) {
      violations.push("UNSAFE_PR_TRIGGER");
    }

    // 3. TESTS_INCOMPLETE
    const testsPassed = workflow.testsPassed === true;
    const matrixComplete = workflow.matrixComplete === true;
    const failFast = workflow.failFast === false;
    if (!(testsPassed && matrixComplete && failFast)) {
      violations.push("TESTS_INCOMPLETE");
    }

    // 4. MUTABLE_ACTION
    const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
    const shaRegex = /^[0-9a-f]{40}$/;
    let hasMutable = false;
    for (const act of actions) {
      if (typeof act !== "object" || act === null) {
        hasMutable = true;
        break;
      }
      const owner = act.owner || "";
      const actionRef = act.ref || "";
      if (owner !== "actions") {
        if (typeof actionRef !== "string" || !shaRegex.test(actionRef)) {
          hasMutable = true;
          break;
        }
      }
    }
    if (hasMutable) {
      violations.push("MUTABLE_ACTION");
    }

    // 5. SINGLE_STAGE_IMAGE
    if (image.multiStage !== true) {
      violations.push("SINGLE_STAGE_IMAGE");
    }

    // 6. ROOT_RUNTIME
    if (image.runsAsRoot !== false) {
      violations.push("ROOT_RUNTIME");
    }

    // 7. SECRET_IN_LAYER
    const secretMode = image.secretMode || "";
    if (secretMode !== "none" && secretMode !== "buildkit") {
      violations.push("SECRET_IN_LAYER");
    }

    // 8. CRITICAL_CVE
    if (image.criticalVulnerabilities !== 0) {
      violations.push("CRITICAL_CVE");
    }

    // 9. UNPINNED_IMAGE
    if (image.digestPinned !== true) {
      violations.push("UNPINNED_IMAGE");
    }

    // 10 & 11. Production checks
    if (target === "production") {
      if (event !== "push" || ref !== "refs/heads/main") {
        violations.push("INVALID_PRODUCTION_REF");
      }
      if (workflow.environmentApproval !== true) {
        violations.push("APPROVAL_REQUIRED");
      }
    }

    const decision = violations.length === 0 ? "promote" : "block";

    return new Response(JSON.stringify({ decision, violations }), {
      headers: { "Content-Type": "application/json" }
    });
  }
};
