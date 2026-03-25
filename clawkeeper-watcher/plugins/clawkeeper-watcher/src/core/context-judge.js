const DEFAULT_POLICY = {
  maxRiskBeforeStop: "critical",
  requireUserConfirmationFor: ["exec", "bash", "shell", "network", "write"],
  autoContinueAllowed: false,
  maxToolStepsWithoutUserTurn: 3,
  treatCommandExecutionAsHighRisk: true,
};

const RISK_ORDER = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// Avoid \b here so Chinese intent phrases still match while preserving English keywords.
const USER_STOP_RE = /(停止|取消|不要|算了|终止|stop|cancel|abort|don't|do not)/i;
const USER_CONTINUE_RE = /(继续|是|好的|确认|继续做|ok|okay|yes|continue|go ahead)/i;

function normalizePolicy(policy = {}) {
  return {
    ...DEFAULT_POLICY,
    ...policy,
    requireUserConfirmationFor: Array.isArray(policy.requireUserConfirmationFor)
      ? policy.requireUserConfirmationFor
      : DEFAULT_POLICY.requireUserConfirmationFor,
  };
}

function normalizeMessage(message) {
  if (!message || typeof message !== "object") {
    return null;
  }

  return {
    role: typeof message.role === "string" ? message.role : "unknown",
    content: typeof message.content === "string" ? message.content : "",
    toolName:
      typeof message.toolName === "string"
        ? message.toolName
        : typeof message.name === "string"
          ? message.name
          : "",
    raw: typeof message.raw === "string" ? message.raw : "",
    error: typeof message.error === "string" ? message.error : "",
    result: typeof message.result === "string" ? message.result : "",
  };
}

function lastMessageByRole(messages, role) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i]?.role === role) {
      return messages[i];
    }
  }
  return null;
}

function lastMessageIndexByRole(messages, role) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i]?.role === role) {
      return i;
    }
  }
  return -1;
}

function summarizeEvidence(messages) {
  const evidence = [];
  for (const message of messages) {
    if (!message) {
      continue;
    }
    if (message.toolName) {
      evidence.push(`tool=${message.toolName}`);
    }
    if (message.error) {
      evidence.push(`error=${message.error.slice(0, 120)}`);
    }
    if (
      message.result &&
      /CTX_PROBE_|CMD_OUT_|exitCode|signal|stderr|stdout/i.test(message.result)
    ) {
      evidence.push(`result=${message.result.slice(0, 120)}`);
    }
  }
  return evidence.slice(0, 8);
}

function buildBaseDecision(overrides = {}) {
  return {
    version: 1,
    decision: "continue",
    stopReason: "completed",
    shouldContinue: true,
    needsUserDecision: false,
    userQuestion: null,
    summary: "The current context does not require any additional confirmation.",
    riskLevel: "low",
    evidence: [],
    nextAction: "continue_run",
    continueHint: null,
    ...overrides,
  };
}

export function judgeForwardedContext(input = {}) {
  const mode = typeof input.mode === "string" ? input.mode : "local";
  const localEnhanced = mode === "local";

  // Wrap buildBaseDecision to always include mode metadata
  const decide = (overrides = {}) => buildBaseDecision({ localEnhanced, mode, ...overrides });

  const requestId = typeof input.requestId === "string" ? input.requestId : null;
  const forwardedContext =
    input.forwardedContext && typeof input.forwardedContext === "object"
      ? input.forwardedContext
      : null;
  const policy = normalizePolicy(input.policy);

  if (
    !forwardedContext ||
    !Array.isArray(forwardedContext.messages) ||
    forwardedContext.messages.length === 0
  ) {
    return decide({
      decision: "stop",
      stopReason: "missing_input",
      shouldContinue: false,
      summary: "Missing forwardedContext.messages. Context judgment cannot be completed.",
      riskLevel: "medium",
      evidence: requestId ? [`requestId=${requestId}`] : [],
      nextAction: "stop_run",
    });
  }

  const normalizedMessages = forwardedContext.messages.map(normalizeMessage).filter(Boolean);
  const metadata =
    forwardedContext.metadata && typeof forwardedContext.metadata === "object"
      ? forwardedContext.metadata
      : {};

  const lastUserIndex = lastMessageIndexByRole(normalizedMessages, "user");
  const activeMessages =
    lastUserIndex >= 0 ? normalizedMessages.slice(lastUserIndex) : normalizedMessages;
  const lastUser = lastMessageByRole(normalizedMessages, "user");
  const toolMessages = activeMessages.filter(
    (message) =>
      message.toolName &&
      message.toolName !== "clawbands_respond" &&
      message.toolName !== "clawkeeper_bands_respond",
  );
  const toolCount = toolMessages.length;
  const toolNames = new Set(
    toolMessages.map((message) => message.toolName.toLowerCase()).filter(Boolean),
  );
  const hasCommandTool = ["exec", "bash", "shell"].some((name) => toolNames.has(name));
  const hasToolError = activeMessages.some((message) => message.error);
  const lastUserContent = lastUser?.content ?? "";

  const evidence = [
    requestId ? `requestId=${requestId}` : null,
    metadata.sessionKey ? `sessionKey=${metadata.sessionKey}` : null,
    `messageCount=${normalizedMessages.length}`,
    `activeMessageCount=${activeMessages.length}`,
    `toolCount=${toolCount}`,
    ...summarizeEvidence(activeMessages),
  ].filter(Boolean);

  if (USER_STOP_RE.test(lastUserContent)) {
    return decide({
      decision: "stop",
      stopReason: "user_requested_stop",
      shouldContinue: false,
      summary:
        "The latest user message explicitly asks to stop or cancel, so execution should stop.",
      riskLevel: "low",
      evidence,
      nextAction: "stop_run",
    });
  }

  if (hasToolError || metadata.success === false) {
    return decide({
      decision: "stop",
      stopReason: metadata.error ? "upstream_error" : "unknown",
      shouldContinue: false,
      summary: metadata.error
        ? `The upstream run failed: ${String(metadata.error).slice(0, 160)}`
        : "An error context was detected in the upstream run. Stop first and inspect the failure before continuing.",
      riskLevel: "high",
      evidence,
      nextAction: "stop_run",
    });
  }

  if (toolCount > policy.maxToolStepsWithoutUserTurn) {
    return decide({
      decision: "ask_user",
      stopReason: "tool_loop_limit",
      shouldContinue: false,
      needsUserDecision: true,
      userQuestion: `${toolCount} tool calls have already run in this turn. Do you want to continue with the next step?`,
      summary:
        "The consecutive tool-call limit has been reached. Return to the user for confirmation.",
      riskLevel: "high",
      evidence,
      nextAction: "ask_user",
      continueHint:
        "Continue only after explicit user confirmation, and reduce the number of tool calls in the next turn if possible.",
    });
  }

  const needsRiskConfirmation =
    (hasCommandTool && policy.treatCommandExecutionAsHighRisk) ||
    policy.requireUserConfirmationFor.some((keyword) =>
      toolNames.has(String(keyword).toLowerCase()),
    );

  if (needsRiskConfirmation && !policy.autoContinueAllowed) {
    const question = USER_CONTINUE_RE.test(lastUserContent)
      ? "A high-risk action was detected, and the user has already signaled to continue. Please confirm one more time before proceeding."
      : "Command execution or another high-risk tool call was detected. Do you want to continue to the next step?";
    return decide({
      decision: "ask_user",
      stopReason: "waiting_user_confirmation",
      shouldContinue: false,
      needsUserDecision: true,
      userQuestion: question,
      summary:
        "The context contains high-risk actions, and the policy requires explicit user confirmation.",
      riskLevel: "high",
      evidence,
      nextAction: "ask_user",
      continueHint:
        "If the user confirms, execution may continue in the next turn, but avoid asking the same confirmation again.",
    });
  }

  const highestRisk = hasCommandTool ? "medium" : "low";
  const stopAt = String(policy.maxRiskBeforeStop || "critical").toLowerCase();
  if (RISK_ORDER[highestRisk] >= (RISK_ORDER[stopAt] ?? RISK_ORDER.critical)) {
    return decide({
      decision: "stop",
      stopReason: "high_risk_action",
      shouldContinue: false,
      summary: `The risk level ${highestRisk} has reached the policy threshold ${stopAt}. This turn should stop.`,
      riskLevel: highestRisk,
      evidence,
      nextAction: "stop_run",
    });
  }

  return decide({
    decision: "continue",
    stopReason: "completed",
    shouldContinue: true,
    needsUserDecision: false,
    summary: "The current context may continue without additional user confirmation.",
    riskLevel: highestRisk,
    evidence,
    nextAction: "continue_run",
    continueHint: hasCommandTool
      ? "If the next turn continues with command execution, run context-judge again."
      : null,
  });
}
