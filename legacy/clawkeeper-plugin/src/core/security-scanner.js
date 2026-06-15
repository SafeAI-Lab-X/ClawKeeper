/**
 * Event log security scanner
 * Analyzes log events to detect security risks
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  PROMPT_INJECTION_PATTERNS,
  CREDENTIAL_LEAK_PATTERNS,
  DANGEROUS_COMMAND_PATTERNS,
  HIGH_RISK_TOOLS,
  ANOMALOUS_ACTIVITY_CONFIG,
  DETECTION_DESCRIPTIONS,
} from './security-rules.js';

/**
 * Scan log records for security risks
 * 
 * @param {Array} records - Array of log records from a specific date
 * @returns {Object} Scan result containing risks list and statistics
 * 
 * Return object structure:
 *   - date: Date scanned (YYYY-MM-DD format)
 *   - totalEvents: Total events scanned
 *   - risks: Array of detected risks
 *   - statistics: Statistics object
 *     - byType: Count by event type
 *   - summary: Summary information
 *     - riskCount: Total risks detected
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
    }
  };

  if (records.length === 0) {
    return result;
  }

  // Count each event type
  for (const record of records) {
    result.statistics.byType[record.type] = (result.statistics.byType[record.type] || 0) + 1;
  }

  // Scan log records for security risks
  // TODO: Implement specific security detection logic in checkSecurityRisks function
  const detectedRisks = checkSecurityRisks(records);
  
  result.risks = detectedRisks;
  result.summary.riskCount = detectedRisks.length;

  return result;
}

/**
 * Check log records for security risks
 * 
 * Implements multiple security detection modules:
 * - Prompt injection detection
 * - Credential leak detection
 * - Dangerous command patterns
 * - Suspicious tool calls
 * - Anomalous activity rates
 * 
 * @param {Array} records - Array of log records to scan
 * @returns {Array} Array of detected risks, each risk object structure:
 *   {
 *     title: Risk title (string)
 *     description: Risk description (string, optional)
 *     timestamp: Detection time (optional)
 *     affectedRecords: Array of affected log record indices (optional)
 *   }
 */
function checkSecurityRisks(records) {
  const risks = [];
  
  if (records.length === 0) {
    return risks;
  }

  // Execute each security detection module
  detectPromptInjection(records, risks);
  detectCredentialLeaks(records, risks);
  detectDangerousCommands(records, risks);
  detectSuspiciousToolCalls(records, risks);
  detectAnomalousActivity(records, risks);
  
  return risks;
}

/**
 * Detect prompt injection risks
 */
function detectPromptInjection(records, risks) {
  const injectionPatterns = PROMPT_INJECTION_PATTERNS;
  const affectedRecords = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    let contentToCheck = '';

    // Check different types of log records
    if (record.type === 'llm_input') {
      contentToCheck = (record.systemPrompt || '') + ' ' + (record.prompt || '');
    } else if (record.type === 'message_received' || record.type === 'message_sending') {
      contentToCheck = record.content || '';
    }

    // Check if it matches injection patterns
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
    let contentToCheck = '';

    // Check output phase (LLM output, message sending)
    if (record.type === 'llm_output') {
      contentToCheck = (record.assistantTexts?.[0] || '');
    } else if (record.type === 'message_sending') {
      contentToCheck = record.content || '';
    }

    // Check if it contains credential patterns
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
 * Detect dangerous command risks
 * Supports Linux, macOS and Windows platforms
 */
function detectDangerousCommands(records, risks) {
  const dangerousPatterns = DANGEROUS_COMMAND_PATTERNS;
  const affectedRecords = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    // Check for dangerous commands in tool call parameters
    if (record.type === 'before_tool_call') {
      const toolName = record.toolName || '';
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
 * Detect suspicious tool call risks
 * Supports detection of high-risk tools for Linux, macOS and Windows platforms
 */
function detectSuspiciousToolCalls(records, risks) {
  const highRiskTools = HIGH_RISK_TOOLS;
  const highRiskCalls = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    if (record.type === 'before_tool_call') {
      const toolName = (record.toolName || '').toLowerCase();

      if (highRiskTools.has(toolName)) {
        highRiskCalls.push(i);
      }
    }
  }

  // Report suspicious tool calls
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
 * Detect anomalous activity
 */
function detectAnomalousActivity(records, risks) {
  // Count each event type
  const eventCounts = {};
  const toolCounts = {};

  for (const record of records) {
    eventCounts[record.type] = (eventCounts[record.type] || 0) + 1;
    
    if (record.type === 'before_tool_call') {
      const toolName = record.toolName || 'unknown';
      toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;
    }
  }

  // Detect anomalous frequency - detect excessive calls to specific tools
  const toolCallThreshold = ANOMALOUS_ACTIVITY_CONFIG.toolCallThreshold;
  const anomalousTools = [];
  for (const [toolName, count] of Object.entries(toolCounts)) {
    // If the same tool is called more than threshold in a day, mark as anomalous
    if (count > toolCallThreshold) {
      anomalousTools.push({ toolName, count });
    }
  }

  if (anomalousTools.length > 0) {
    const affectedRecords = [];
    for (let i = 0; i < records.length; i++) {
      if (records[i].type === 'before_tool_call') {
        if (anomalousTools.some(a => a.toolName === records[i].toolName)) {
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
 * Extract date from log record
 * 
 * @param {Object} record - Single log record
 * @returns {string|null} Date string (YYYY-MM-DD format), null if parsing fails
 */
function extractDateFromRecord(record) {
  if (!record.timestamp) return null;
  
  try {
    const date = new Date(record.timestamp);
    return date.toISOString().split('T')[0];
  } catch {
    return null;
  }
}

/**
 * Format scan results for output to console
 * 
 * @param {Object} scanResult - Scan result from scanLogsForSecurityRisks function
 * @param {Array} records - Original log records array for showing specific risk logs
 * @returns {string} Formatted output string with complete scan report
 * 
 * Report content includes:
 * - Scan date and total events scanned
 * - Statistics classified by event type
 * - List of detected security risks and specific log records
 * - Overall summary
 */
export function formatScanResults(scanResult, records = []) {
  if (!scanResult || scanResult.totalEvents === 0) {
    return '📭 Scan Result: No log events available for analysis';
  }

  const lines = [];
  
  lines.push(`\n🔍 Security Scan Report - ${scanResult.date || 'Unknown Date'}\n`);
  lines.push(
    `Total Events Scanned: ${scanResult.totalEvents} | ` +
    `Risks Detected: ${scanResult.summary.riskCount}`
  );
  
  // Event type statistics
  lines.push('\n📊 Event Type Statistics:');
  for (const [type, count] of Object.entries(scanResult.statistics.byType)) {
    lines.push(`  • ${type}: ${count}`);
  }

  // Detected security risks details
  if (scanResult.summary.riskCount > 0) {
    lines.push('\n⚠️  Detected Security Risks:');
    for (const risk of scanResult.risks) {
      lines.push(`  🔔 ${risk.title}`);
      if (risk.description) {
        lines.push(`      📝 ${risk.description}`);
      }
      if (risk.affectedRecords && risk.affectedRecords.length > 0) {
        lines.push(`      📊 Affected Events: ${risk.affectedRecords.length}`);
        
        // Print specific log records
        lines.push('      📋 Log Records:');
        for (const recordIdx of risk.affectedRecords) {
          const record = records[recordIdx];
          if (record) {
            lines.push(formatLogRecord(record, recordIdx + 1));
          }
        }
      }
    }
  } else {
    lines.push('\n✅ No security risks detected');
  }

  // Summary information
  lines.push('\n📌 Scan Summary:');
  lines.push(`  Risks Found: ${scanResult.summary.riskCount > 0 ? '⚠️  Yes' : '✅ No'}`);
  
  return lines.join('\n');
}

/**
 * Format a single log record for display
 * 
 * @param {Object} record - Log record
 * @param {number} index - Record index number (starting from 1)
 * @returns {string} Formatted log string
 */
function formatLogRecord(record, index) {
  const lines = [];
  const timestamp = record.timestamp || 'Unknown Time';
  
  lines.push(`        [${index}] ${timestamp} | ${record.type}`);
  
  // Add detailed information based on log type
  if (record.type === 'before_tool_call') {
    lines.push(`            Tool: ${record.toolName || 'unknown'}`);
    if (record.params) {
      const paramsStr = JSON.stringify(record.params).substring(0, 100);
      lines.push(`            Parameters: ${paramsStr}${JSON.stringify(record.params).length > 100 ? '...' : ''}`);
    }
  } else if (record.type === 'llm_input') {
    lines.push(`            Model: ${record.model || 'unknown'}`);
    if (record.prompt) {
      const promptStr = record.prompt.substring(0, 100);
      lines.push(`            Prompt: ${promptStr}${record.prompt.length > 100 ? '...' : ''}`);
    }
  } else if (record.type === 'llm_output') {
    lines.push(`            Model: ${record.model || 'unknown'}`);
    if (record.assistantTexts && Array.isArray(record.assistantTexts)) {
      const responseStr = record.assistantTexts[0]?.substring(0, 100) || '';
      lines.push(`            Response: ${responseStr}${record.assistantTexts[0]?.length > 100 ? '...' : ''}`);
    }
  } else if (record.type === 'message_received' || record.type === 'message_sending') {
    const direction = record.type === 'message_received' ? 'From' : 'To';
    const target = record.type === 'message_received' ? record.from : record.to;
    lines.push(`            ${direction}: ${target || 'unknown'}`);
    if (record.content) {
      const contentStr = record.content.substring(0, 100);
      lines.push(`            Content: ${contentStr}${record.content.length > 100 ? '...' : ''}`);
    }
  }
  
  return lines.join('\n');
}

/**
 * Save security scan report to text file
 * 
 * @param {Object} scanResult - Scan result from scanLogsForSecurityRisks function
 * @param {Array} records - Original log records array
 * @param {string} stateDir - OpenClaw working directory
 * @param {string} filename - Log filename (used for report naming)
 * @returns {Promise<string>} Path to saved report file
 */
export async function saveSecurityScanReport(scanResult, records = [], stateDir, filename) {
  // Create report directory: workspace/security-reports
  const reportDir = path.join(stateDir, 'workspace', 'security-reports');
  
  // Ensure directory exists
  try {
    await fs.mkdir(reportDir, { recursive: true });
  } catch (error) {
    console.error(`❌ Failed to create report directory ${reportDir}: ${error.message}`);
    throw error;
  }

  // Get date (extracted from scan result or filename)
  const reportDate = scanResult.date || filename.replace('.jsonl', '');
  const reportName = `${reportDate}-security-report.txt`;
  const reportPath = path.join(reportDir, reportName);

  // Generate report content
  const reportContent = formatScanResults(scanResult, records);

  // Save report
  try {
    await fs.writeFile(reportPath, reportContent, 'utf-8');
  } catch (error) {
    console.error(`❌ Failed to save report ${reportPath}: ${error.message}`);
    throw error;
  }

  return reportPath;
}

