# ClawKeeper: Plugin-based Protection

<p align="left">
  <a href="https://github.com/openclaw/openclaw">
    <img src="https://img.shields.io/badge/OpenClaw-Compatible-blue.svg" alt="OpenClaw">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
</p>

**A minimal security control plugin for OpenClaw agents.**

ClawKeeper incorporates existing security plugins and integrates relevant security functions to provide robust runtime enforcement against adversarial actions at the runtime level.

![](../fig/plugins.png)

# 💡 Features

To overcome the limitations of isolated defenses, our plugin is designed as a comprehensive security auditor, scanner, and hardening enforcer for the entire agent ecosystem, ensuring system integrity from static configuration to post-execution analysis.

### 🎯 Threat Detection
Comprehensive security threat identification across multiple layers. Cover the majority of security risks outlined in the OWASP Agent Security Initiative (ASI) and OpenClaw Security threat categories:
- **Gateway Security**: Validate network binding, authentication, TLS encryption, and device verification (10 checks)
- **Credentials Management**: Scan for exposed secrets, file permissions, OAuth tokens, and plaintext credentials (8 checks)
- **Execution Controls**: Enforce approval gates, sandbox isolation, and safe execution boundaries (7 checks)
- **Access Control**: Monitor policy enforcement, messaging restrictions, and session isolation (5 checks)
- **Memory Integrity**: Detect prompt injections, obfuscated payloads, and unauthorized file access (5 checks)
- **Cost Exposure**: Track spending limits, logging volume, and API quotas (4 checks)
- **Supply Chain Security**: Scan skills for malicious patterns, unsafe prerequisites, and dependency vulnerabilities (6+ checks)
- **Indicators of Compromise**: Identify suspicious outbound connections and known malicious artifacts (5 checks)
- **Multi-Framework Resilience**: Verify kill switches, control tokens, cognitive integrity, and graceful degradation (4 checks)
- **Cross-Layer Risk Analysis**: Detect compound attack surfaces spanning multiple security domains

### 🔐 Configuration Protection
Protect critical configuration files from tampering:
- **Tamper Prevention**: Guard `openclaw.json` and `AGENTS.md` from unauthorized modifications
- **File Integrity Monitoring**: Real-time detection of configuration changes
- **Automatic Alerts**: Immediate notification on suspicious alterations

### 👁️ Monitoring & Logging
Complete visibility into agent behavior:
- **Event Auditing**: Comprehensive logging of all agent operations (tool calls, messages, LLM activity)
- **Compliance Records**: Structured logs queryable by date, tool type, agent ID, and event type

### 🔍 Behavior Scanning
Analyze agent behavior patterns from execution logs:
- **Log Analysis**: Deep inspection of agent behavior recorded in audit logs
- **Pattern Detection**: Identify suspicious execution patterns and anomalies
- **Behavioral Reporting**: Generate insights from agent decision patterns
- **Event Filtering**: Query logs by date, tool type, agent ID, and event category
- **Risk Scoring**: Quantify detected anomalies with severity levels

### 🛡️ Hardening
Applied security with recovery safeguards:
- **One-Click Hardening**: Apply all available security fixes interactively
- **Auto-Fix Safety**: Deterministic, non-breaking remediation


## Security Boundaries Monitored

Clawkeeper audits:

| Boundary | Purpose |
|----------|---------|
| **Network Gateway** | Restrict binding to localhost, enforce authentication, enable TLS, and verify device identity |
| **Credential Storage** | Protect credentials with proper file permissions, scan for exposed secrets, prevent plaintext storage |
| **Code Execution** | Require human approval for execution, maintain sandbox isolation, restrict Docker capabilities |
| **Access Control** | Enforce decision-maker policies, restrict group messaging, implement rate limiting and session isolation |
| **Agent Memory** | Monitor for prompt injection patterns, obfuscation techniques, and unauthorized file access |
| **Cost Management** | Configure LLM spending limits, API quotas, and monitor logging volume |
| **Supply Chain** | Scan skills for dangerous patterns, validate metadata, pin dependency versions |
| **Security Resilience** | Verify kill switches, control token configuration, and graceful degradation settings |
| **System Indicators** | Monitor for command-and-control connections and known malicious artifacts |
| **Configuration Integrity** | Detect tampering and unauthorized modifications to agent configurations |

# 🚀 Quick Start

## Installation

Linux:
```bash
bash install.sh
```

Windows:
```powershell
./install.ps1
```

---

# 🛠️ Command Reference

### Core Security Auditing
```bash
# Run security audit and threat detection
npx openclaw clawkeeper audit

# Output audit results as JSON for scripting
npx openclaw clawkeeper audit --json

# Show current security score and top threats
npx openclaw clawkeeper status
```

### Security Hardening
```bash
# Apply all available security hardening fixes
npx openclaw clawkeeper harden

# Restore configuration from latest backup
npx openclaw clawkeeper rollback

# Restore from specific backup
npx openclaw clawkeeper rollback <backup-folder-name>
```

### Monitoring
```bash
# Start real-time configuration drift monitoring
npx openclaw clawkeeper monitor
```

### Event Logs & Behavior Scanning
```bash
# View today's event logs
npx openclaw clawkeeper logs

# View logs from specific date
npx openclaw clawkeeper logs --date 2026-03-14

# Filter logs by event type (before_tool_call, message_received, message_sending, llm_input, llm_output)
npx openclaw clawkeeper logs --type before_tool_call

# Filter logs by tool name (only for before_tool_call events)
npx openclaw clawkeeper logs --tool bash

# Scan logs for security risks
npx openclaw clawkeeper logs --scan

# Scan logs and save detailed report to file
npx openclaw clawkeeper logs --scan --save-report

# List all available log files
npx openclaw clawkeeper logs --all

# Show path to today's log file
npx openclaw clawkeeper log-path

# Limit output to specific number of records (default: 20)
npx openclaw clawkeeper logs --limit 50
```

### Skill Security Scanning
```bash
# Scan a skill for security issues and risks
npx openclaw clawkeeper scan-skill ~/path/to/skill

# Output scan results as JSON
npx openclaw clawkeeper scan-skill ~/path/to/skill --json
```


# 🎮 Example Usage

### Identify sensitive information
Before (left) vs. after (right) installing ClawKeeper.
OpenClaw outputs the password directly, whereas ClawKeeper identifies and blocks sensitive information.

![](../fig/plugins_example_1.png)

---

### Threat detection report

Run 
```bash
npx openclaw clawkeeper audit
```

ClawKeeper generates a comprehensive threat detection report for OpenClaw, providing a security score, categorized risks, and identifying a high-severity network misconfiguration. The report also enables automatic remediation by supplying diagnostic evidence and executable hardening commands.

![](../fig/plugins_example_2.png)

---

### Behavior scanning report

Run 
```bash
npx openclaw clawkeeper logs --scan
```

ClawKeeper performs retrospective security auditing by analyzing full-lifecycle logs and successfully detects a prompt injection attack originating from an external messaging platform.

![](../fig/plugins_example_3.png)

---

### Scanning an unsafe skill

Run
```bash
npx openclaw clawkeeper scan-skill ~/path/to/unsafe-skill
```

The skill scan detected a high-risk remote script execution (curl-to-bash) vulnerability in the installation script.

![](../fig/plugins_example_4.png)

---

# 📂 Architecture

Clawkeeper consists of three core layers:

1. **Core Engine** (`src/core/`)
   - `audit-engine.js` — Configuration validation
   - `hardening.js` — Auto-remediation
   - `skill-scanner.js` — Third-party code analysis
   - `drift-monitor.js` — Real-time change detection
   - `security-rules.js` — Declarative security policies

2. **Plugin System** (`src/plugin/`)
   - `sdk.js` — OpenClaw plugin entry point
   - `cli.js` — Command-line interface
   - Hook integration for tool interception

3. **Reporting** (`src/reporters/`)
   - `console-reporter.js` — Human-readable output
   - `json-reporter.js` — Machine-readable export

### File Structure

```
src/
  ├── core/              # Core security logic
  │   ├── audit-engine.js       # Configuration auditing
  │   ├── hardening.js          # Auto-fixes and hardening
  │   ├── skill-scanner.js      # Supply chain scanning
  │   ├── drift-monitor.js      # Configuration drift detection
  │   ├── security-rules.js     # Security policy rules
  │   ├── interceptor.js        # Tool call interception
  │   ├── rollback.js           # Configuration rollback
  │   ├── controls.js           # Security control definitions
  │   └── metadata.js           # Metadata utilities
  ├── plugin/            # OpenClaw integration
  │   ├── sdk.js         # Plugin entry point
  │   └── cli.js         # CLI commands
  └── reporters/         # Output formatting
      ├── console-reporter.js   # Terminal output
      └── json-reporter.js      # JSON export

skill/                   # Clawkeeper skill for OpenClaw
examples/               # Example skills for testing
test/                   # Test suite
```

---

# 📕 Reference

- SecureClaw: [https://github.com/adversa-ai/secureclaw](https://github.com/adversa-ai/secureclaw)
- OpenClaw Safety Guardian: [https://github.com/gulou69/openclaw-safety-guardian](https://github.com/gulou69/openclaw-safety-guardian)
- ClawBands: [https://github.com/SeyZ/clawbands](https://github.com/SeyZ/clawbands)

---

# 📝 License

This project is licensed under [MIT](https://opensource.org/licenses/MIT).