"""Pattern catalogue for security detection — prompt injection, credential
leaks, dangerous commands. Ported from
legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/security-rules.js.

All patterns compile with `re.IGNORECASE`. CJK patterns work as-is because
Python regex handles Unicode natively.
"""

from __future__ import annotations

import re


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# ── Prompt-injection patterns (EN + CN + mixed) ────────────────────────────


PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # EN: ignore/forget previous instructions
    _r(r"ignore\s+(all\s+)?(previous|prior|above|earlier|initial)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)"),
    _r(r"disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?|rules?|guidelines?)"),
    _r(r"forget\s+(everything|all|what\s+(?:i|you)\s+said|the\s+above|the\s+previous)"),
    _r(r"don't?\s+(?:follow|obey|respect|honor)\s+(the\s+)?(?:previous|prior|original|above)\s+(instructions?|rules?|prompts?)"),
    _r(r"discard\s+(?:your\s+)?(?:initial\s+)?(?:system\s+)?(?:instructions?|rules?|prompts?)"),

    # EN: override/modify
    _r(r"override\s+(all\s+)?(system|previous|your)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)"),
    _r(r"replace\s+your\s+(?:instructions?|prompts?|rules?|guidelines?)\s+with"),
    _r(r"modify\s+your\s+(?:instructions?|prompts?|rules?|behavior|responses?)"),
    _r(r"change\s+your\s+(?:system\s+)?(?:prompts?|instructions?|guidelines?|behavior)"),
    _r(r"update\s+your\s+(?:system\s+)?(?:prompts?|instructions?|rules?)"),

    # EN: bypass safety
    _r(r"bypass\s+(all\s+)?(safety|security|content\s+(?:policy|filter)|ethical?|moral)\s*(filters?|checks?|restrictions?|guards?|safeguards?)"),
    _r(r"remove\s+(?:the\s+)?(?:safety|security|content)\s*(?:filters?|guards?|restrictions?)"),
    _r(r"disable\s+(?:true|false)?\s*(?:safety|security|content)\s*(?:filters?|guards?|restrictions?|mode)"),
    _r(r"(?:turn\s+)?off\s+(?:your\s+)?(?:safety|security|content\s+(?:policy|filter))\s*(?:features?|guards?)"),
    _r(r"don't?\s+(?:apply|enforce|follow|check|care\s+about)\s+(?:safety|security|content)\s*(?:policies?|guidelines?|filters?)"),

    # EN: role-play / mode switch
    _r(r"you\s+are\s+now\s+(a|an)\s+(?:evil|jailbreak|hack|cracked|unrestricted|unfiltered|uncensored)"),
    _r(r"you\s+(?:are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a|an)?\s*(?:admin|root|developer|hacker|attacker|malicious)"),
    _r(r"switch\s+(?:mode|role)\s+(?:to|into)?\s*(?:developer|admin|root|jailbreak|evil|god)"),
    _r(r"enter\s+(?:developer|admin|god|unrestricted|jailbreak)\s*mode"),
    _r(r"activate\s+(?:developer|admin|god|unrestricted)\s*(?:mode|status|privileges?)"),
    _r(r"pretend\s+(?:i\s+(?:am|was)|you\s+(?:are|were))\s+(?:a\s+)?(?:developer|admin|hacker|god)"),

    # EN: system prompt markers
    _r(r"\[\s*(?:system|admin|root|dev|operator)\s*\]"),
    _r(r"<<<?(?:system|admin|root|dev|SYSTEM|ADMIN)\s*>>?"),
    _r(r"\{\s*(?:system|SYSTEM)\s*:"),
    _r(r"<!--\s*system"),
    _r(r"%system%\s*[:=]"),

    # EN: inject new instructions
    _r(r"(?:new|follow\s+(?:these\s+)?)?(?:instructions?|rules?|guidelines?|directives?)\s*[:=]\s*['\"]"),
    _r(r"(?:my\s+)?(?:instructions?|rules?|prompts?|directives?)\s+(?:are|is|will\s+be)\s*[:=]?"),
    _r(r"(?:from\s+now\s+on|henceforth|starting\s+now)\s*[,:]?\s+(?:ignore|follow|do)\s+(?:this|these)"),
    _r(r"act\s+(?:as\s+)?(?:if\s+)?(?:your\s+top\|only\|primary)\s+(?:instruction|goal|priority)\s+(?:is|was|were)"),

    # CN: ignore/forget instructions
    _r(r"忽略[^。]*(?:之前|之上|之下|上面|下面|所有|一切).*?(?:指令|提示|规则|约束|要求)"),
    _r(r"抛弃[^。]*(?:之前|所有|一切).*?(?:指令|提示|规则|约束|说的).*?话?"),
    _r(r"遗忘[^。]*(?:之前|所有|一切|上面).*?(?:指令|提示|规则|约束|内容)"),
    _r(r"不要[^。]*(?:遵序|遵守|执行|按照).*?(?:之前|之上|原本).*?(?:指令|提示|规则|约束)"),
    _r(r"忘记[^。]*(?:之前|所有|一切).*?(?:指令|提示|规则|约束|内容)"),
    _r(r"摒弃[^。]*(?:之前|原本|所有).*?(?:指令|约束|规则|提示)"),

    # CN: override/modify
    _r(r"覆盖[^。]*(?:系统|原本|之前).*?(?:指令|提示|规则|约束)"),
    _r(r"替换[^。]*(?:你的|原本).*?(?:指令|提示|规则|约束|系统提示)"),
    _r(r"改变[^。]*(?:你的|系统).*?(?:行为|指令|提示|逻辑|功能)"),
    _r(r"修改[^。]*(?:你的|系统).*?(?:指令|提示|规则|约束|行为)"),
    _r(r"现在[^。]*(?:以|按照|按)\s*['\"《「][\s\S]{0,50}['\"》」]\s*(?:作为|为主|为準|指令)"),

    # CN: bypass safety
    _r(r"(?:关闭|禁用|停用|取消|移除)[^。]*(?:安全|审核|检测|限制|过滤|防护|屏障)"),
    _r(r"(?:不要|别)[^。]*(?:检查|审核|计算|限制|屏蔽|过滤|防护|监管|遵守).*?(?:规则|政策|指南|安全)"),
    _r(r"(?:突破|绕过|跳过|无视)[^。]*(?:安全|限制|过滤|屏障|防护|审核|道德|伦理)"),
    _r(r"(?:移除|删除|取消)[^。]*(?:限制|防护|屏障|审核|过滤)"),

    # CN: role-play / mode switch
    _r(r"你\s*(?:现在|已经|是)\s*(?:一个|一名|作为)\s*(?:邪恶|不受限|无约束|黑客|恶意|危险)"),
    _r(r"(?:进入|切换|启动|激活)[^。]*(?:开发者|管理员|管理|完全|不受限|无约束|邪恶|神)\s*(?:模式|状态|身份)"),
    _r(r"(?:模拟|扮演|假设|假如).*?你\s*(?:是|为)\s*(?:开发者|管理员|管理|黑客|神|邪恶的)"),
    _r(r"(?:你要|你必须|你只需要)(?:假装|假如|当成|认为).*?(?:自己|你)[\s$]*(?:没有|没关于|不受).*?(?:限制|约束|规则)"),

    # CN: system markers
    _r(r"【\s*(?:系统|管理|开发|操作者)\s*】"),
    _r(r"\{\{\s*(?:系统提示|系统指令|管理员)\s*\}\}"),
    _r(r"《\s*系统提示\s*》"),
    _r(r"<!-- 系统"),
    _r(r"\[系统[\s\S]{0,20}?\]"),

    # CN: inject new instructions
    _r(r"(?:新|现在的|以下的|接下来的).*?(?:指令|规则|提示|要求).*?(?:是|为|如下)[\s：:]"),
    _r(r"(?:从现在开始|接下来|今后|从此刻起)[^。]*?(?:你的|你应该).*?(?:指令|规则|行为|目标)"),
    _r(r"(?:我的|新的|真实的).*?(?:指令|规则|提示词|约束).*?(?:为|是|如下)[\s：:]"),

    # Mixed CN+EN
    _r(r"(?:ignore|忽略|disregard|遗忘).*?(?:instructions|指令|rules|规则|prompts|提示)[\s\S]{0,30}(?:和|,|，|and|\||；)"),
    _r(r"bypass.*?安全|safety.*?绕过|防护|security"),
    _r(r"你.*?act\s+as|你.*?switch.*?mode|enter.*?你.*?模式"),
]


# ── Credential-leak patterns ───────────────────────────────────────────────


CREDENTIAL_LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),                    # OpenAI keys
    re.compile(r"gh[ps]_[a-zA-Z0-9]{36,}"),                # GitHub tokens
    re.compile(r"AKIA[A-Z0-9]{16}"),                       # AWS access keys
    re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}"),
    re.compile(r"xox[bprs]-[a-zA-Z0-9-]{10,}"),            # Slack tokens
    _r(r"(?:api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)\s*[:=]\s*[\"']?[a-zA-Z0-9+/\-_]{20,}"),
]


# ── Dangerous command patterns ─────────────────────────────────────────────


DANGEROUS_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    # Linux/macOS bulk deletion
    _r(r"rm\s+-r?f?\s+(?:\/|~|\$HOME)"),
    _r(r"rm\s+-rf\s+\*\s*$"),
    _r(r"rmdir\s+-p"),
    # Windows bulk deletion
    _r(r"rmdir\s+\/s\s+\/q\s+(?:C:\\|%SYSTEMROOT%|%USERPROFILE%|\*)"),
    _r(r"del\s+\/s\s+\/q\s+(?:C:\\|%SYSTEMROOT%|%USERPROFILE%|\*)"),
    _r(r"Remove-Item\s+.*-Recurse\s+.*-Force"),
    _r(r"\$null\s*=\s*Remove-Item\s+(?:C:\\|%SYSTEMROOT%)"),
    # Linux/macOS priv escalation
    _r(r"sudo\s+(?:su|bash|sh|chmod\s+777|chown\s+-R\s+root)"),
    _r(r"chmod\s+(?:777|a\+rwx|u\+s)\s+\/"),
    _r(r"chown\s+-R\s+(?:0:0|root:root)"),
    _r(r"chmod\s+u\+s\s+\/(?:bin|usr)"),
    # Windows priv escalation
    _r(r"icacls\s+(?:C:\\|%SYSTEMROOT%)\s+.*\/grant|\/deny"),
    _r(r"takeown\s+\/f\s+(?:C:\\|%SYSTEMROOT%)"),
    _r(r"net\s+(?:user|localgroup|admin)\s+.*\/add"),
    _r(r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)"),
    # Linux/macOS credential collection
    _r(r"cat\s+(?:\/etc\/(?:passwd|shadow|sudoers)|~\/\.ssh\/id_|~\/\.aws\/)"),
    _r(r"grep\s+.*(?:password|key|secret|token|api)"),
    _r(r"find\s+\/\s+(?:-name|.*)\s+(?:\.ssh|\.aws|\.config)"),
    # Windows credential collection
    _r(r"type\s+(?:C:\\|%USERPROFILE%\\).*(?:\.ssh|\.aws|credentials|config)"),
    _r(r"reg\s+query\s+(?:HKLM|HKCU).*(?:Password|Secret|Token|Credential)"),
    _r(r"Get-ChildItem\s+.*-Path\s+(?:C:\\|%USERPROFILE%)\s+.*Recurse"),
    _r(r"net\s+(?:user|accounts)\s+\/domain"),
    _r(r"ver(?:sion)?|systeminfo|whoami"),
    # macOS-specific
    _r(r"pmset\s+(?:hibernatemode|sleepimage|standby)"),
    _r(r"diskutil\s+(?:secureErase|eraseVolume|unmountDisk)"),
    _r(r"launchctl\s+(?:unload|disable).*\/Library\/"),
    # Network exfil / reverse shell
    _r(r"(?:curl|wget|nc|ncat)\s+.*\|\s*(?:bash|sh|python|node|powershell)"),
    _r(r"(?:curl|wget)\s+.*-o\s+(?:\/tmp|\/dev|%TEMP%|%AppData%)"),
    _r(r"\|\s*IEX\s*\("),
    _r(r"DownloadFile.*ExecutionPolicy"),
    # Disk wipe
    _r(r"dd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\/(?:sd|hd|nvme)"),
    _r(r"mkfs(?:\..*)?[\s.]"),
    _r(r"format\s+[A-Z]:\s*\/\w"),
    _r(r"cipher\s+\/w:"),
    _r(r"shred\s+-(?:vfz|u)\s+\/"),
    # Process control
    _r(r"fork\s*\(\s*\)\s*&&\s*fork"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;"),
    _r(r"taskkill\s+\/f\s+\/im\s+(?:explorer|svchost|csrss)"),
    _r(r"Stop-Process\s+-Name\s+(?:explorer|csrss|winlogon)"),
    _r(r"kill\s+-9\s+(?:1|init|systemd|launchd)"),
    _r(r"killall\s+(?:1|init|systemd|launchd|-9)"),
    # Firewall / network
    _r(r"netsh\s+(?:advfirewall|firewall)\s+set"),
    _r(r"iptables\s+(?:-I|-A)\s+(?:INPUT|FORWARD|OUTPUT)"),
    _r(r"ufw\s+(?:disable|reset)"),
    _r(r"ipfw\s+flush"),
    # Log clearing
    _r(r"rm\s+-f\s+\/var\/log\/"),
    _r(r"cat\s+\/dev\/null\s*>\s*\/var\/log\/"),
    _r(r"Get-EventLog\s+-LogName\s+\*\s*\|\s*Remove-EventLog"),
    _r(r"wevtutil\s+cl\s+(?:System|Security|Application)"),
]


# ── High-risk tool taxonomy ────────────────────────────────────────────────


HIGH_RISK_TOOLS: set[str] = {
    # Generic / Linux / macOS
    "gateway", "cron", "exec", "spawn", "shell", "bash", "sh", "zsh", "ksh",
    "fs_delete", "fs_move", "fs_write", "apply_patch", "eval", "system", "popen",
    # Linux/macOS system
    "sudo", "su", "chmod", "chown", "chgrp", "umask", "pkexec", "visudo",
    "setfacl", "getfacl", "usermod", "groupadd", "groupdel", "useradd",
    "userdel", "passwd",
    # macOS
    "launchctl", "launchd", "pmset", "diskutil", "dscl", "security",
    "codesign", "xcode-select",
    # Windows
    "powershell", "powershell_ise", "ps", "cmd", "command", "comspec",
    "cmd.exe", "powershell.exe", "wmic", "wmi", "reg", "regedit", "regsvr32",
    "taskkill", "taskmgr", "sc", "services", "wevtutil", "netsh", "net",
    "ipconfig", "systeminfo", "whoami", "whoami.exe", "ver", "version",
    "schtasks", "at", "rundll32", "msiexec", "icacls", "takeown", "cipher",
    "format", "diskpart", "msconfig", "services.msc", "devmgmt.msc",
    "diskmgmt.msc", "eventvwr.msc", "firewall.cpl", "getadmin",
    # Network
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "ftp",
    "tftp", "ping", "tracert", "nslookup", "net.exe",
}


# ── Anomalous-activity config ──────────────────────────────────────────────


ANOMALOUS_ACTIVITY_CONFIG: dict[str, object] = {
    "toolCallThreshold": 20,
    "monitoredTools": [],
}


# ── Detection descriptions ─────────────────────────────────────────────────


DETECTION_DESCRIPTIONS: dict[str, dict[str, object]] = {
    "promptInjection": {
        "title": "Prompt Injection Risk Detected",
        "describe": lambda count: (
            f"Found {count} log records containing suspicious prompt injection patterns, "
            f"which may indicate system prompts have been tampered with"
        ),
    },
    "credentialLeak": {
        "title": "Credential Leak Risk Detected",
        "describe": lambda count: (
            f"Found {count} log records that may contain API keys, tokens, or other sensitive "
            f"credentials, posing an information disclosure risk"
        ),
    },
    "dangerousCommand": {
        "title": "Dangerous Command Execution Detected",
        "describe": lambda count: (
            f"Found {count} dangerous tool calls (such as file deletion, permission modification, "
            f"command injection, etc.), which may lead to system corruption"
        ),
    },
    "suspiciousToolCall": {
        "title": "Risky Tool Call Detected",
        "describe": lambda count: (
            f"Found {count} risky tool calls, including system commands, file operations, "
            f"permission management, etc. These calls may pose a threat to system security "
            f"(supports Linux, macOS, and Windows platforms)"
        ),
    },
    "anomalousActivity": {
        "title": "Anomalous Activity Frequency Detected",
        "describe": lambda tools: (
            "Found anomalous tool call frequency: "
            + ", ".join(f"{t.get('toolName')}({t.get('count')})" for t in tools)
            + ", which may indicate automated attacks or agent loss of control"
        ),
    },
}
