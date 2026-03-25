/**
 * 事件日志安全扫描器
 * 分析日志事件以检测安全风险
 */

import fs from "node:fs/promises";
import path from "node:path";
import {
  PROMPT_INJECTION_PATTERNS,
  CREDENTIAL_LEAK_PATTERNS,
  DANGEROUS_COMMAND_PATTERNS,
  HIGH_RISK_TOOLS,
  ANOMALOUS_ACTIVITY_CONFIG,
  DETECTION_DESCRIPTIONS,
} from "./security-rules.js";

/**
 * 扫描日志记录中的安全风险
 *
 * @param {Array} records - 来自特定日期的日志记录数组
 * @returns {Object} 扫描结果，包含风险列表和统计信息
 *
 * 返回对象结构：
 *   - date: 扫描的日期 (YYYY-MM-DD 格式)
 *   - totalEvents: 扫描的总事件数
 *   - risks: 检测到的风险数组
 *   - statistics: 统计信息对象
 *     - byType: 按事件类型统计的计数
 *   - summary: 摘要信息
 *     - riskCount: 检测到的风险总数
 */
export async function scanLogsForSecurityRisks(records) {
  const result = {
    date: records.length > 0 ? extractDateFromRecord(records[0]) : null,
    totalEvents: records.length,
    risks: [],
    statistics: {
      byType: {},
    },
    summary: {
      riskCount: 0,
    },
  };

  if (records.length === 0) {
    return result;
  }

  // 统计每种事件类型的数量
  for (const record of records) {
    result.statistics.byType[record.type] = (result.statistics.byType[record.type] || 0) + 1;
  }

  // 扫描日志记录中的安全风险
  // TODO: 在 checkSecurityRisks 函数中实现具体的安全检测逻辑
  const detectedRisks = checkSecurityRisks(records);

  result.risks = detectedRisks;
  result.summary.riskCount = detectedRisks.length;

  return result;
}

/**
 * 检查日志记录中的安全风险
 *
 * 实现多个安全检测模块，参考 openclaw-safety-guardian 的规则框架：
 * - 提示词注入检测 (Prompt injection detection)
 * - 凭证泄露检测 (Credential leak detection)
 * - 危险命令检测 (Dangerous command patterns)
 * - 可疑工具调用检测 (Suspicious tool calls)
 * - 异常活动频率检测 (Anomalous activity rates)
 *
 * @param {Array} records - 待扫描的日志记录数组
 * @returns {Array} 检测到的风险数组，每个风险对象的结构应为：
 *   {
 *     title: 风险标题 (字符串)
 *     description: 风险描述 (字符串，可选)
 *     timestamp: 检测时间 (可选)
 *     affectedRecords: 相关日志记录的索引数组 (可选)
 *   }
 */
function checkSecurityRisks(records) {
  const risks = [];

  if (records.length === 0) {
    return risks;
  }

  // 执行各项安全检测
  detectPromptInjection(records, risks);
  detectCredentialLeaks(records, risks);
  detectDangerousCommands(records, risks);
  detectSuspiciousToolCalls(records, risks);
  detectAnomalousActivity(records, risks);

  return risks;
}

/**
 * 检测提示词注入风险
 * 参考 openclaw-safety-guardian 的提示词注入模式
 */
function detectPromptInjection(records, risks) {
  const injectionPatterns = PROMPT_INJECTION_PATTERNS;
  const affectedRecords = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    let contentToCheck = "";

    // 检查不同类型的日志记录
    if (record.type === "llm_input") {
      contentToCheck = (record.systemPrompt || "") + " " + (record.prompt || "");
    } else if (record.type === "message_received" || record.type === "message_sending") {
      contentToCheck = record.content || "";
    }

    // 检查是否匹配注入模式
    for (const pattern of injectionPatterns) {
      if (pattern.test(contentToCheck)) {
        affectedRecords.push(i);
        break;
      }
    }
  }

  if (affectedRecords.length > 0) {
    const desc = DETECTION_DESCRIPTIONS.promptInjection;
    risks.push({
      title: desc.title,
      description: desc.description(affectedRecords.length),
      affectedRecords,
    });
  }
}

/**
 * 检测凭证泄露风险
 */
function detectCredentialLeaks(records, risks) {
  const credentialPatterns = CREDENTIAL_LEAK_PATTERNS;
  const affectedRecords = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    let contentToCheck = "";

    // 检查输出阶段（LLM输出、消息发送）
    if (record.type === "llm_output") {
      contentToCheck = record.assistantTexts?.[0] || "";
    } else if (record.type === "message_sending") {
      contentToCheck = record.content || "";
    }

    // 检查是否包含凭证模式
    for (const pattern of credentialPatterns) {
      if (pattern.test(contentToCheck)) {
        affectedRecords.push(i);
        break;
      }
    }
  }

  if (affectedRecords.length > 0) {
    const desc = DETECTION_DESCRIPTIONS.credentialLeak;
    risks.push({
      title: desc.title,
      description: desc.description(affectedRecords.length),
      affectedRecords,
    });
  }
}

/**
 * 检测危险命令风险
 * 参考 openclaw-safety-guardian 的危险命令模式
 * 支持 Linux, macOS 和 Windows 平台
 */
function detectDangerousCommands(records, risks) {
  const dangerousPatterns = DANGEROUS_COMMAND_PATTERNS;
  const affectedRecords = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    // 检查工具调用参数中的危险命令
    if (record.type === "before_tool_call") {
      const toolName = record.toolName || "";
      const isCommandTool = /^(exec|shell|spawn|bash|sh|command)$/i.test(toolName);

      if (isCommandTool && record.params) {
        const paramsStr = JSON.stringify(record.params);

        for (const pattern of dangerousPatterns) {
          if (pattern.test(paramsStr)) {
            affectedRecords.push(i);
            break;
          }
        }
      }
    }
  }

  if (affectedRecords.length > 0) {
    const desc = DETECTION_DESCRIPTIONS.dangerousCommand;
    risks.push({
      title: desc.title,
      description: desc.description(affectedRecords.length),
      affectedRecords,
    });
  }
}

/**
 * 检测可疑的工具调用风险
 * 支持 Linux, macOS 和 Windows 平台的高风险工具检测
 */
function detectSuspiciousToolCalls(records, risks) {
  const highRiskTools = HIGH_RISK_TOOLS;
  const highRiskCalls = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    if (record.type === "before_tool_call") {
      const toolName = (record.toolName || "").toLowerCase();

      if (highRiskTools.has(toolName)) {
        highRiskCalls.push(i);
      }
    }
  }

  // 报告风险工具调用
  if (highRiskCalls.length > 0) {
    const desc = DETECTION_DESCRIPTIONS.suspiciousToolCall;
    risks.push({
      title: desc.title,
      description: desc.description(highRiskCalls.length),
      affectedRecords: highRiskCalls,
    });
  }
}

/**
 * 检测异常活动频率
 */
function detectAnomalousActivity(records, risks) {
  // 统计各类型事件
  const eventCounts = {};
  const toolCounts = {};

  for (const record of records) {
    eventCounts[record.type] = (eventCounts[record.type] || 0) + 1;

    if (record.type === "before_tool_call") {
      const toolName = record.toolName || "unknown";
      toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;
    }
  }

  // 检测异常频率 - 检测特定工具的过度调用
  const toolCallThreshold = ANOMALOUS_ACTIVITY_CONFIG.toolCallThreshold;
  const anomalousTools = [];
  for (const [toolName, count] of Object.entries(toolCounts)) {
    // 如果同一工具在一天内被调用超过阈值，标记为异常
    if (count > toolCallThreshold) {
      anomalousTools.push({ toolName, count });
    }
  }

  if (anomalousTools.length > 0) {
    const affectedRecords = [];
    for (let i = 0; i < records.length; i++) {
      if (records[i].type === "before_tool_call") {
        if (anomalousTools.some((a) => a.toolName === records[i].toolName)) {
          affectedRecords.push(i);
        }
      }
    }

    const desc = DETECTION_DESCRIPTIONS.anomalousActivity;
    risks.push({
      title: desc.title,
      description: desc.description(anomalousTools),
      affectedRecords,
    });
  }
}

/**
 * 从日志记录中提取日期
 *
 * @param {Object} record - 单条日志记录
 * @returns {string|null} 日期字符串 (YYYY-MM-DD 格式)，如果解析失败返回 null
 */
function extractDateFromRecord(record) {
  if (!record.timestamp) {
    return null;
  }

  try {
    const date = new Date(record.timestamp);
    return date.toISOString().split("T")[0];
  } catch {
    return null;
  }
}

/**
 * 格式化扫描结果以输出到控制台
 *
 * @param {Object} scanResult - 来自 scanLogsForSecurityRisks 函数的扫描结果
 * @param {Array} records - 原始的日志记录数组，用于显示具体的风险日志
 * @returns {string} 格式化的输出字符串，包含扫描报告的完整内容
 *
 * 报告内容包括：
 * - 扫描日期和扫描的事件总数
 * - 按事件类型分类的统计
 * - 检测到的安全风险列表以及具体的日志记录
 * - 总体摘要
 */
export function formatScanResults(scanResult, records = []) {
  if (!scanResult || scanResult.totalEvents === 0) {
    return "📭 Scan Result: No log events available for analysis";
  }

  const lines = [];

  lines.push(`\n🔍 Security Scan Report - ${scanResult.date || "Unknown Date"}\n`);
  lines.push(
    `Total Events Scanned: ${scanResult.totalEvents} | ` +
      `Risks Detected: ${scanResult.summary.riskCount}`,
  );

  // Event type statistics
  lines.push("\n📊 Event Type Statistics:");
  for (const [type, count] of Object.entries(scanResult.statistics.byType)) {
    lines.push(`  • ${type}: ${String(count)}`);
  }

  // Detected security risks details
  if (scanResult.summary.riskCount > 0) {
    lines.push("\n⚠️  Detected Security Risks:");
    for (const risk of scanResult.risks) {
      lines.push(`  🔔 ${risk.title}`);
      if (risk.description) {
        lines.push(`      📝 ${risk.description}`);
      }
      if (risk.affectedRecords && risk.affectedRecords.length > 0) {
        lines.push(`      📊 Affected Events: ${risk.affectedRecords.length}`);

        // Print specific log records
        lines.push("      📋 Log Records:");
        for (const recordIdx of risk.affectedRecords) {
          const record = records[recordIdx];
          if (record) {
            lines.push(formatLogRecord(record, recordIdx + 1));
          }
        }
      }
    }
  } else {
    lines.push("\n✅ No security risks detected");
  }

  // Summary information
  lines.push("\n📌 Scan Summary:");
  lines.push(`  Risks Found: ${scanResult.summary.riskCount > 0 ? "⚠️  Yes" : "✅ No"}`);

  return lines.join("\n");
}

/**
 * 格式化单条日志记录用于显示
 *
 * @param {Object} record - 日志记录
 * @param {number} index - 记录的序号（1开始）
 * @returns {string} 格式化的日志字符串
 */
function formatLogRecord(record, index) {
  const lines = [];
  const timestamp = record.timestamp || "Unknown Time";

  lines.push(`        [${index}] ${timestamp} | ${record.type}`);

  // Add detailed information based on log type
  if (record.type === "before_tool_call") {
    lines.push(`            Tool: ${record.toolName || "unknown"}`);
    if (record.params) {
      const paramsStr = JSON.stringify(record.params).substring(0, 100);
      lines.push(
        `            Parameters: ${paramsStr}${JSON.stringify(record.params).length > 100 ? "..." : ""}`,
      );
    }
  } else if (record.type === "llm_input") {
    lines.push(`            Model: ${record.model || "unknown"}`);
    if (record.prompt) {
      const promptStr = record.prompt.substring(0, 100);
      lines.push(`            Prompt: ${promptStr}${record.prompt.length > 100 ? "..." : ""}`);
    }
  } else if (record.type === "llm_output") {
    lines.push(`            Model: ${record.model || "unknown"}`);
    if (record.assistantTexts && Array.isArray(record.assistantTexts)) {
      const responseStr = record.assistantTexts[0]?.substring(0, 100) || "";
      lines.push(
        `            Response: ${responseStr}${record.assistantTexts[0]?.length > 100 ? "..." : ""}`,
      );
    }
  } else if (record.type === "message_received" || record.type === "message_sending") {
    const direction = record.type === "message_received" ? "From" : "To";
    const target = record.type === "message_received" ? record.from : record.to;
    lines.push(`            ${direction}: ${target || "unknown"}`);
    if (record.content) {
      const contentStr = record.content.substring(0, 100);
      lines.push(`            Content: ${contentStr}${record.content.length > 100 ? "..." : ""}`);
    }
  }

  return lines.join("\n");
}

/**
 * 保存安全扫描报告到txt文件
 *
 * @param {Object} scanResult - 来自 scanLogsForSecurityRisks 函数的扫描结果
 * @param {Array} records - 原始的日志记录数组
 * @param {string} stateDir - OpenClaw工作目录
 * @param {string} filename - 日志文件名（用于命名报告）
 * @returns {Promise<string>} 保存的报告文件路径
 */
export async function saveSecurityScanReport(scanResult, records = [], stateDir, filename) {
  // Create report directory: workspace/security-reports
  const reportDir = path.join(stateDir, "workspace", "security-reports");

  // Ensure directory exists
  try {
    await fs.mkdir(reportDir, { recursive: true });
  } catch (error) {
    console.error(`❌ Failed to create report directory ${reportDir}: ${error.message}`);
    throw error;
  }

  // Get date (extracted from scan result or filename)
  const reportDate = scanResult.date || filename.replace(".jsonl", "");
  const reportName = `${reportDate}-security-report.txt`;
  const reportPath = path.join(reportDir, reportName);

  // Generate report content
  const reportContent = formatScanResults(scanResult, records);

  // Save report
  try {
    await fs.writeFile(reportPath, reportContent, "utf-8");
  } catch (error) {
    console.error(`❌ Failed to save report ${reportPath}: ${error.message}`);
    throw error;
  }

  return reportPath;
}
