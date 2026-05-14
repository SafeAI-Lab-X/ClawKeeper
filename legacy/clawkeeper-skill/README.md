# ClawKeeper: Skill-based Protection

<p align="left">
  <a href="https://github.com/openclaw/openclaw">
    <img src="https://img.shields.io/badge/OpenClaw-Compatible-blue.svg" alt="OpenClaw">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
</p>

A set of **simple yet effective security skills** for OpenClaw agents.

Unlike traditional security solutions that require **plugins / sandboxes / complex policy systems**, this project explores a simpler and more auditable approach:

> Security rules are defined as structured **Markdown documents** that the agent can directly interpret and enforce, supplemented by corresponding security **scripts**.

OpenClaw can directly read these security guidelines and automatically deploy security policies, significantly reducing user configuration costs. 

![](../fig/skill.png)

Within these security rule definitions, protection is implemented across two complementary dimensions. At the **system level**, we provide **Windows**-specific constraints rather than assuming a **Linux**-only environment, while also ensuring straightforward migration to **macOS**. This enables the agent to align its behavior with real-world execution environments, encompassing filesystem access, privilege boundaries, and local task management. 

At the **software level**, since OpenClaw can be integrated with platforms such as Telegram, Feishu (Lark), and DingTalk, each of which exhibits distinct functional characteristics and therefore distinct security requirements, we adopt **Feishu (Lark)** as a representative case to construct a corresponding security constraint framework, specifying operational norms and considerations for OpenClaw within this software context.

# 💡 Features

This approach is primarily designed to defend against the following **Agent-specific security risks**:

- Prompt Injection
- Destructive system operations
- Skill / plugin supply chain poisoning
- Sensitive information disclosure
- Permission abuse
- ...

## I. Windows Safety Guide

### 🎯 Behavior Security Policy
Enforce red-line and yellow-line behaviors:
- **Destructive Operations**: Block dangerous commands like `rd /s /q C:\`, `format`, `Remove-Item -Recurse -Force`
- **Authentication Tampering**: Prevent unauthorized modifications to `openclaw.json`, SSH configs, and SAM/NTDS.dit
- **Sensitive Data Exfiltration**: Block attempts to send credentials, tokens, private keys via `curl/Invoke-WebRequest` or reverse shells
- **Privilege Persistence**: Detect unauthorized scheduled tasks, user creation, service installation, and registry modifications
- **Code Injection**: Catch Base64-encoded commands, `Invoke-Expression`, and script block creation attacks
- **Supply Chain Protection**: Prohibit blind execution of third-party package installation commands (`npm install`, `pip install`, `winget install`, etc.)
- **Permission Tampering**: Monitor unauthorized permission changes to openclaw core files

### 🔐 Configuration Baseline Protection
- **Hash-Based Baseline**: Generate initial SHA256 baseline of critical configuration files
- **Daily Integrity Check**: Automated verification against baseline to detect unauthorized changes
- **File Integrity Monitoring**: Real-time alerting on configuration drift

### 📋 Operation Logging & Audit
- **Comprehensive Audit Trail**: Log all yellow-line operations with timestamp, full command, reason, and result
- **Compliance Records**: Daily memory file (`YYYY-MM-DD.md`) containing all high-risk operations

### 🌙 Nightly Security Audit
- **Automated Scheduled Checks**: Runs every night at 03:00 (local timezone)
- **Security Scanning**: Comprehensive system vulnerability assessment and hardening recommendations
- **Visibility Reports**: Auto-generated and pushed reports with security findings

## II. Feishu Safety Guide

### 💬 Message Content Protection
- **Pre-Send Filtering**: Block messages containing tokens, passwords, private keys, ID numbers, phone numbers, or bank card information
- **Credential Detection**: Detect and prevent exposure of `$FS_TOKEN` (app_access_token, tenant_access_token, Webhook URLs)
- **Prevent Data Leakage**: Real-time regex scanning to catch sensitive data before external transmission

### 🔑 Credential & Permission Management
- **Credential Protection**: Guard against hardcoded Feishu API tokens in messages, documents, and code
- **Permission Audit**: Monitor unauthorized bulk contact exports, private chat access, and cross-department space access
- **Privilege Escalation Prevention**: Restrict permission changes from org-internal to public internet access
- **Webhook Abuse Prevention**: Verify webhook targets before data transmission

### ⚠️ Behavior Security Policy
Enforce red-line and yellow-line behaviors specific to Feishu:
- **External Data Sharing Risks**: Block unauthorized document sharing with external users or public internet
- **Third-Party Injection Prevention**: Prohibit blind execution of Feishu message instruction/links (e.g., "click to authorize")
- **Approval Forgery Prevention**: Prevent unauthorized OA approval or expense claim submission
- **Social Engineering Defense**: Block fraudulent information in approval notes

### 📊 Audit & Reporting
- **Operation Logging**: Record all yellow-line operations (authorized permission changes, token rotation, document management)
- **Scheduled Security Report**: Auto-generated periodic security audit with compliance findings
- **Timeline-Based Queries**: Review operations by date and action type

---

# 🚀 Quick Start

The core objective of this project is:

> **Let the agent deploy security rules itself.**

No need for:

- Installing security plugins
- Configuring complex policies
- Modifying agent framework code

We provide two installation methods: Skill and Prompt.

## From Skill

### I. Windows Safety Guide

1. Run the Windows safety guide installation script:

    ```powershell
    skills/windows-safety-guide/scripts/install.ps1
    ```

2. Send instruction to OpenClaw to use the skill:
   ```
   Please use the windows-safety-guide skill to enforce behavior security policies, configuration protection, and enable nightly security audits.
   ```

OpenClaw will:
- Generate configuration baseline for integrity monitoring
- Set up file protection and tamper detection
- Configure scheduled nightly security audits (3:00 AM daily)
- Enable operation logging and compliance audit trail

---

### II. Feishu (Lark) Safety Guide

1. Run the Feishu safety guide installation script:

    ```bash
    bash skills/feishu-safety-guide/scripts/install.sh
    ```
    Or on Windows:

    ```powershell
    skills/feishu-safety-guide/scripts/install.ps1
    ```

2. Send instruction to OpenClaw to use the skill:
   ```
   Please use the feishu-safety-guide skill to enforce message protection, credential security, and enable periodic security reporting in Feishu (Lark).
   ```

OpenClaw will:
- Deploy message content filtering and credential protection
- Configure permission audit and logging
- Set up scheduled security reports
- Enable Feishu-specific threat detection

---

## From Prompt

### I. Windows Safety Guide

1. Send the **[security audit script](script/nightly-security-audit-windows.ps1)** to OpenClaw:
   ```
   Please move the nightly-security-audit-windows.ps1 script to openclaw's workspace\scripts\ directory.
   ```

2. Send the **[security guideline document](docs/OpenClaw-Windows-Guide-en.md)** to OpenClaw, and send the deployment instruction:
   ```
   Please completely follow this Windows security guideline document to deploy all security measures for my OpenClaw.
   ```

---

### II. Feishu (Lark) Safety Guide

1. Open Feishu Robot Chat, and send the **[security guideline document](docs/OpenClaw-feishu-Guide-en.md)** to OpenClaw.

3. Send the deployment instruction:
   ```
   Please completely follow this Feishu security guideline document to deploy all security measures for my OpenClaw environment.
   ```

---

# 🎮 Example Effect

### Windows code injection detection

When presented with an obfuscated Base64 payload, the security mechanism intercepts the input, decodes the string for transparency, and successfully identifies the underlying malicious intent (a code injection attempt). 

![](../fig/skill_example_1_1.png)

---

### Windows Daily Security Report

OpenClaw automatically executes a comprehensive daily system security inspection (default 3 o'clock every day).

![](../fig/skill_example_2_1.png)

---

### Feishu (Lark) sensitive behavior detection

The security mechanism detects a direct attempt to transmit sensitive credentials to an external contact. 

![](../fig/skill_example_1_2.png)

---

### Feishu (Lark) regular interaction report

Summarize the latest interaction logs of Feishu (Lark). It categorizes historical events by risk severity—successfully highlighting critical threats such as "Jailbreak attempts" and unauthorized SSH key access requests—while compiling quantitative event statistics (default every 6 hours).

![](../fig/skill_example_2_2.png)

---

# 📂  Project Structure

```
clawkeeper-skill
│
├─ README.md                                    # Project documentation
├─ docs                                         # Security guideline documents
│   ├─ OpenClaw-feishu-Guide-en.md             # Feishu (Lark) security guide (English)
│   ├─ OpenClaw-feishu-Guide-zh.md             # Feishu (Lark) security guide (Chinese)
│   ├─ OpenClaw-Windows-Guide-en.md            # Windows security guide (English)
│   └─ OpenClaw-Windows-Guide-zh.md            # Windows security guide (Chinese)
├─ script                                       # Shared utility scripts
│   └─ nightly-security-audit-windows.ps1      # Daily Windows security audit script
└─ skills                                       # Deployable security skills
    ├─ feishu-safety-guide                     # Feishu (Lark) security skill
    │   ├─ SKILL.md                            # Skill definition and metadata
    │   └─ scripts
    │       ├─ install.ps1                     # Installation script (Windows)
    │       ├─ install.sh                      # Installation script (Linux/macOS)
    │       ├─ uninstall.ps1                   # Uninstallation script (Windows)
    │       └─ uninstall.sh                    # Uninstallation script (Linux/macOS)
    └─ windows-safety-guide                    # Windows security skill
        ├─ SKILL.md                            # Skill definition and metadata
        └─ scripts
            ├─ check-config-baseline.ps1       # Verify config file integrity
            ├─ generate-config-baseline.ps1    # Generate initial baseline
            ├─ install.ps1                     # Installation script
            ├─ nightly-security-audit-windows.ps1  # Scheduled audit task
            └─ uninstall.ps1                   # Uninstallation script
```

---

# 📕 Reference

- OpenClaw Minimal Security Practice Guide
  [https://github.com/slowmist/openclaw-security-practice-guide](https://github.com/slowmist/openclaw-security-practice-guide)

---

# 📝 License

This project is licensed under [MIT](https://opensource.org/licenses/MIT).