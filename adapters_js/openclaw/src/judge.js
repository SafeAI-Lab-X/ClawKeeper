/**
 * judge.js — thin HTTP client around clawkeeper-core's /v1/judge endpoint.
 *
 * Pure JS, no openclaw imports. Built so it can be unit-tested without
 * the OpenClaw runtime: just call `judge(payload, options)`.
 */

/**
 * Forward a JS-style judge payload to the Python core.
 *
 * @param {object} payload  - { mode, requestId, forwardedContext, policy }
 * @param {object} options  - { serverUrl, failurePolicy, timeoutMs }
 * @returns {Promise<object>} The parsed Decision dict from the server.
 *   On failure honours options.failurePolicy:
 *     - "fail-closed": returns a synthetic stop decision so the caller blocks.
 *     - "fail-open"  : returns a synthetic continue decision.
 */
export async function judge(payload, options = {}) {
  const serverUrl = options.serverUrl || "http://127.0.0.1:7474";
  const failurePolicy = options.failurePolicy || "fail-closed";
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 2000;

  const url = `${serverUrl.replace(/\/+$/, "")}/v1/judge`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      return _failureDecision(failurePolicy, `server returned ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    clearTimeout(timer);
    return _failureDecision(failurePolicy, err?.message || String(err));
  }
}

/**
 * Build a synthetic Decision for transport failures so the caller has
 * something to act on without a try/catch at the hook boundary.
 */
function _failureDecision(failurePolicy, reason) {
  if (failurePolicy === "fail-open") {
    return {
      decision: "continue",
      stopReason: "transport_failure_fail_open",
      shouldContinue: true,
      needsUserDecision: false,
      summary: `clawkeeper-core unreachable: ${reason}. Letting through per fail-open policy.`,
      riskLevel: "medium",
      evidence: [`transport_error=${reason}`],
      nextAction: "continue_run",
      version: 1,
    };
  }
  return {
    decision: "stop",
    stopReason: "transport_failure_fail_closed",
    shouldContinue: false,
    needsUserDecision: false,
    summary: `clawkeeper-core unreachable: ${reason}. Blocking per fail-closed policy.`,
    riskLevel: "high",
    evidence: [`transport_error=${reason}`],
    nextAction: "stop_run",
    version: 1,
  };
}
