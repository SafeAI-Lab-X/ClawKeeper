import { clearPendingDecision, getPendingDecision } from "./pending-decision-store";

interface PendingPromptEvent {
  messages?: unknown[];
  prompt?: string;
}

interface PendingPromptContext {
  sessionKey?: string;
}

// Avoid word-boundary matching so Chinese confirmations still match reliably.
const CONTINUE_RE = /(继续|是|好的|确认|继续做|ok|okay|yes|continue|go ahead)/i;
const STOP_RE = /(不要|停止|取消|算了|终止|stop|cancel|abort|don't|do not)/i;

function extractText(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (!Array.isArray(value)) {
    return "";
  }
  return value
    .map((item) =>
      item && typeof item === "object" && typeof (item as { text?: unknown }).text === "string"
        ? String((item as { text?: unknown }).text)
        : "",
    )
    .filter(Boolean)
    .join("\n");
}

function latestUserText(messages: unknown[] | undefined): string {
  if (!Array.isArray(messages)) {
    return "";
  }
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (!message || typeof message !== "object") {
      continue;
    }
    const role = (message as { role?: unknown }).role;
    if (role === "user") {
      return extractText((message as { content?: unknown }).content);
    }
  }
  return "";
}

export function createPendingDecisionPromptHook() {
  return async (event: PendingPromptEvent, ctx: PendingPromptContext) => {
    const pending = await getPendingDecision(ctx.sessionKey);
    if (!pending) {
      return undefined;
    }

    const latestUser = latestUserText(event.messages);

    if (CONTINUE_RE.test(latestUser)) {
      await clearPendingDecision(ctx.sessionKey);
      return {
        prependContext: [
          "系统注记：上一轮安全判定要求用户确认。",
          `用户问题：${pending.question}`,
          "用户现在已明确确认继续，可以继续后续流程。",
          pending.continueHint ? `继续提示：${pending.continueHint}` : "",
        ]
          .filter(Boolean)
          .join("\n"),
      };
    }

    if (STOP_RE.test(latestUser)) {
      await clearPendingDecision(ctx.sessionKey);
      return {
        prependContext: [
          "系统注记：上一轮安全判定要求用户确认。",
          `用户问题：${pending.question}`,
          "用户现在明确拒绝继续执行高风险动作。",
          "不要继续原操作，只需简短确认已停止并等待新的指令。",
        ].join("\n"),
      };
    }

    return {
      prependContext: [
        "系统注记：当前会话仍存在一个未完成的安全确认。",
        `待确认问题：${pending.question}`,
        "如果用户没有明确回答继续或停止，你可以先处理用户的新问题，但不要擅自继续上一轮高风险动作。",
        pending.continueHint ? `继续提示：${pending.continueHint}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  };
}
