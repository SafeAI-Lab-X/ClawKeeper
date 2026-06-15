/**
 * Security detection rules library
 * Contains pattern definitions for detecting prompt injection, credential leaks, dangerous commands, etc.
 * Centralized management for easy maintenance and extension
 */

/**
 * Prompt injection detection rules
 * Used to identify inputs that may attempt to tamper with system prompts or bypass security policies
 * Supports multiple injection patterns and variants for both English and Chinese
 */
export const PROMPT_INJECTION_PATTERNS = [
  // ──── English: Ignore/Discard instructions ────
  /ignore\s+(all\s+)?(previous|prior|above|earlier|initial)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)/i,
  /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i,
  /forget\s+(everything|all|what\s+(?:i|you)\s+said|the\s+above|the\s+previous)/i,
  /don't?\s+(?:follow|obey|respect|honor)\s+(the\s+)?(?:previous|prior|original|above)\s+(instructions?|rules?|prompts?)/i,
  /discard\s+(?:your\s+)?(?:initial\s+)?(?:system\s+)?(?:instructions?|rules?|prompts?)/i,
  
  // ──── English: Override/Modify instructions ────
  /override\s+(all\s+)?(system|previous|your)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)/i,
  /replace\s+your\s+(?:instructions?|prompts?|rules?|guidelines?)\s+with/i,
  /modify\s+your\s+(?:instructions?|prompts?|rules?|behavior|responses?)/i,
  /change\s+your\s+(?:system\s+)?(?:prompts?|instructions?|guidelines?|behavior)/i,
  /update\s+your\s+(?:system\s+)?(?:prompts?|instructions?|rules?)/i,
  
  // ──── English: Bypass security mechanisms ────
  /bypass\s+(all\s+)?(safety|security|content\s+(?:policy|filter)|ethical?|moral)\s*(filters?|checks?|restrictions?|guards?|safeguards?)/i,
  /remove\s+(?:the\s+)?(?:safety|security|content)\s*(?:filters?|guards?|restrictions?)/i,
  /disable\s+(?:true|false)?\s*(?:safety|security|content)\s*(?:filters?|guards?|restrictions?|mode)/i,
  /(?:turn\s+)?off\s+(?:your\s+)?(?:safety|security|content\s+(?:policy|filter))\s*(?:features?|guards?)/i,
  /don't?\s+(?:apply|enforce|follow|check|care\s+about)\s+(?:safety|security|content)\s*(?:policies?|guidelines?|filters?)/i,
  
  // ──── English: Role-play/Mode switching ────
  /you\s+are\s+now\s+(a|an)\s+(?:evil|jailbreak|hack|cracked|unrestricted|unfiltered|uncensored)/i,
  /you\s+(?:are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a|an)?\s*(?:admin|root|developer|hacker|attacker|malicious)/i,
  /switch\s+(?:mode|role)\s+(?:to|into)?\s*(?:developer|admin|root|jailbreak|evil|god)/i,
  /enter\s+(?:developer|admin|god|unrestricted|jailbreak)\s*mode/i,
  /activate\s+(?:developer|admin|god|unrestricted)\s*(?:mode|status|privileges?)/i,
  /pretend\s+(?:i\s+(?:am|was)|you\s+(?:are|were))\s+(?:a\s+)?(?:developer|admin|hacker|god)/i,
  
  // ──── English: System prompt markers ────
  /\[\s*(?:system|admin|root|dev|operator)\s*\]/i,
  /<<<?(?:system|admin|root|dev|SYSTEM|ADMIN)\s*>>?/i,
  /\{\s*(?:system|SYSTEM)\s*:/i,
  /<!--\s*system/i,
  /%system%\s*[:=]/i,
  
  // ──── English: Inject new instructions ────
  /(?:new|follow\s+(?:these\s+)?)?(?:instructions?|rules?|guidelines?|directives?)\s*[:=]\s*['"]/i,
  /(?:my\s+)?(?:instructions?|rules?|prompts?|directives?)\s+(?:are|is|will\s+be)\s*[:=]?/i,
  /(?:from\s+now\s+on|henceforth|starting\s+now)\s*[,:]?\s+(?:ignore|follow|do)\s+(?:this|these)/i,
  /act\s+(?:as\s+)?(?:if\s+)?(?:your\s+top\|only\|primary)\s+(?:instruction|goal|priority)\s+(?:is|was|were)/i,
  
  // ──── Chinese: Ignore/Discard instructions ────
  /忽略[^。]*(?:之前|之上|之下|上面|下面|所有|一切).*?(?:指令|提示|规则|约束|要求)/,
  /抛弃[^。]*(?:之前|所有|一切).*?(?:指令|提示|规则|约束|说的).*?话?/,
  /遗忘[^。]*(?:之前|所有|一切|上面).*?(?:指令|提示|规则|约束|内容)/,
  /不要[^。]*(?:遵序|遵守|执行|按照).*?(?:之前|之上|原本).*?(?:指令|提示|规则|约束)/,
  /忘记[^。]*(?:之前|所有|一切).*?(?:指令|提示|规则|约束|内容)/,
  /摒弃[^。]*(?:之前|原本|所有).*?(?:指令|约束|规则|提示)/,
  
  // ──── Chinese: Override/Modify instructions ────
  /覆盖[^。]*(?:系统|原本|之前).*?(?:指令|提示|规则|约束)/,
  /替换[^。]*(?:你的|原本).*?(?:指令|提示|规则|约束|系统提示)/,
  /改变[^。]*(?:你的|系统).*?(?:行为|指令|提示|逻辑|功能)/,
  /修改[^。]*(?:你的|系统).*?(?:指令|提示|规则|约束|行为)/,
  /现在[^。]*(?:以|按照|按)\s*['"《「][\s\S]{0,50}['"》」]\s*(?:作为|为主|为準|指令)/,
  
  // ──── Chinese: Bypass security mechanisms ────
  /(?:关闭|禁用|停用|取消|移除)[^。]*(?:安全|审核|检测|限制|过滤|防护|屏障)/,
  /(?:不要|别)[^。]*(?:检查|审核|计算|限制|屏蔽|过滤|防护|监管|遵守).*?(?:规则|政策|指南|安全)/,
  /(?:突破|绕过|跳过|无视)[^。]*(?:安全|限制|过滤|屏障|防护|审核|道德|伦理)/,
  /(?:移除|删除|取消)[^。]*(?:限制|防护|屏障|审核|过滤)/,
  
  // ──── Chinese: Role-play/Mode switching ────
  /你\s*(?:现在|已经|是)\s*(?:一个|一名|作为)\s*(?:邪恶|不受限|无约束|黑客|恶意|危险)/,
  /(?:进入|切换|启动|激活)[^。]*(?:开发者|管理员|管理|完全|不受限|无约束|邪恶|神)\s*(?:模式|状态|身份)/,
  /(?:模拟|扮演|假设|假如).*?你\s*(?:是|为)\s*(?:开发者|管理员|管理|黑客|神|邪恶的)/,
  /(?:你要|你必须|你只需要)(?:假装|假如|当成|认为).*?(?:自己|你)[\s$]*(?:没有|没关于|不受).*?(?:限制|约束|规则)/,
  
  // ──── Chinese: System prompt markers ────
  /【\s*(?:系统|管理|开发|操作者)\s*】/,
  /\{\{\s*(?:系统提示|系统指令|管理员)\s*\}\}/,
  /《\s*系统提示\s*》/,
  /<!-- 系统/,
  /\[系统[\s\S]{0,20}?\]/,
  
  // ──── Chinese: Inject new instructions ────
  /(?:新|现在的|以下的|接下来的).*?(?:指令|规则|提示|要求).*?(?:是|为|如下)[\s：:]/,
  /(?:从现在开始|接下来|今后|从此刻起)[^。]*?(?:你的|你应该).*?(?:指令|规则|行为|目标)/,
  /(?:我的|新的|真实的).*?(?:指令|规则|提示词|约束).*?(?:为|是|如下)[\s：:]/,
  
  // ──── Mixed attacks: English-Chinese mix ────
  /(?:ignore|忽略|disregard|遗忘).*?(?:instructions|指令|rules|规则|prompts|提示)[\s\S]{0,30}(?:和|,|，|and|\||；)/i,
  /bypass.*?安全|safety.*?绕过|防护|security/i,
  /你.*?act\s+as|你.*?switch.*?mode|enter.*?你.*?模式/i,
];


/**
 * Credential leak detection rules
 * Used to identify potentially exposed API keys, tokens, and other sensitive credentials
 */
export const CREDENTIAL_LEAK_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/,                    // OpenAI API keys
  /gh[ps]_[a-zA-Z0-9]{36,}/,               // GitHub tokens
  /AKIA[A-Z0-9]{16}/,                      // AWS access keys
  /-----BEGIN\s+PRIVATE\s+KEY-----/,       // PEM private keys
  /Bearer\s+[a-zA-Z0-9._\-]{20,}/,         // Bearer tokens
  /xox[bprs]-[a-zA-Z0-9\-]{10,}/,          // Slack tokens
  /(?:api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)\s*[:=]\s*["']?[a-zA-Z0-9+/\-_]{20,}/i,
];

/**
 * Dangerous command detection rules
 * Contains dangerous operation patterns for Linux/macOS/Windows platforms
 * Covers: file deletion, privilege escalation, command injection, system destruction, etc.
 */
export const DANGEROUS_COMMAND_PATTERNS = [
  // ──── Linux/macOS bulk deletion ────
  /rm\s+-r?f?\s+(?:\/|~|\$HOME)/i,
  /rm\s+-rf\s+\*\s*$/i,
  /rmdir\s+-p/i,
  
  // ──── Windows bulk deletion ────
  /rmdir\s+\/s\s+\/q\s+(?:C:\\|%SYSTEMROOT%|%USERPROFILE%|\*)/i,
  /del\s+\/s\s+\/q\s+(?:C:\\|%SYSTEMROOT%|%USERPROFILE%|\*)/i,
  /Remove-Item\s+.*-Recurse\s+.*-Force/i,
  /\$null\s*=\s*Remove-Item\s+(?:C:\\|%SYSTEMROOT%)/i,
  
  // ──── Linux/macOS privilege escalation ────
  /sudo\s+(?:su|bash|sh|chmod\s+777|chown\s+-R\s+root)/i,
  /chmod\s+(?:777|a\+rwx|u\+s)\s+\//i,
  /chown\s+-R\s+(?:0:0|root:root)/i,
  /chmod\s+u\+s\s+\/(?:bin|usr)/i,
  
  // ──── Windows privilege escalation ────
  /icacls\s+(?:C:\\|%SYSTEMROOT%)\s+.*\/grant|\/deny/i,
  /takeown\s+\/f\s+(?:C:\\|%SYSTEMROOT%)/i,
  /net\s+(?:user|localgroup|admin)\s+.*\/add/i,
  /Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)/i,
  
  // ──── Linux/macOS credential and sensitive info collection ────
  /cat\s+(?:\/etc\/(?:passwd|shadow|sudoers)|~\/\.ssh\/id_|~\/\.aws\/)/i,
  /grep\s+.*(?:password|key|secret|token|api)/i,
  /find\s+\/\s+(?:-name|.*)\s+(?:\.ssh|\.aws|\.config)/i,
  
  // ──── Windows credential and sensitive info collection ────
  /type\s+(?:C:\\|%USERPROFILE%\\).*(?:\.ssh|\.aws|credentials|config)/i,
  /reg\s+query\s+(?:HKLM|HKCU).*(?:Password|Secret|Token|Credential)/i,
  /Get-ChildItem\s+.*-Path\s+(?:C:\\|%USERPROFILE%)\s+.*Recurse/i,
  /net\s+(?:user|accounts)\s+\/domain/i,
  /ver(?:sion)?|systeminfo|whoami/i,
  
  // ──── macOS-specific dangerous operations ────
  /pmset\s+(?:hibernatemode|sleepimage|standby)/i,
  /diskutil\s+(?:secureErase|eraseVolume|unmountDisk)/i,
  /launchctl\s+(?:unload|disable).*\/Library\//i,
  
  // ──── Network exfiltration and reverse shells ────
  /(?:curl|wget|nc|ncat)\s+.*\|\s*(?:bash|sh|python|node|powershell)/i,
  /(?:curl|wget)\s+.*-o\s+(?:\/tmp|\/dev|%TEMP%|%AppData%)/i,
  /\|\s*IEX\s*\(/i,  // PowerShell IEX (Invoke-Expression)
  /DownloadFile.*ExecutionPolicy/i,
  
  // ──── 磁盘破坏和覆盖 ────
  /dd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\/(?:sd|hd|nvme)/i,
  /mkfs(?:\..*)?[\s\.]/i,
  /format\s+[A-Z]:\s*\/\w/i,
  /cipher\s+\/w:/i,  // Windows 磁盘覆盖
  /shred\s+-(?:vfz|u)\s+\//i,  // Linux 文件覆盖
  
  // ──── Process and system control ────
  /fork\s*\(\s*\)\s*&&\s*fork/i,  // Fork bomb
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,  // Bash fork bomb
  /taskkill\s+\/f\s+\/im\s+(?:explorer|svchost|csrss)/i,
  /Stop-Process\s+-Name\s+(?:explorer|csrss|winlogon)/i,
  /kill\s+-9\s+(?:1|init|systemd|launchd)/i,
  /killall\s+(?:1|init|systemd|launchd|-9)/i,
  
  // ──── Firewall and network config modification ────
  /netsh\s+(?:advfirewall|firewall)\s+set/i,
  /iptables\s+(?:-I|-A)\s+(?:INPUT|FORWARD|OUTPUT)/i,
  /ufw\s+(?:disable|reset)/i,
  /ipfw\s+flush/i,
  
  // ──── Log clearing ────
  /rm\s+-f\s+\/var\/log\//i,
  /cat\s+\/dev\/null\s*>\s*\/var\/log\//i,
  /Get-EventLog\s+-LogName\s+\*\s*\|\s*Remove-EventLog/i,
  /wevtutil\s+cl\s+(?:System|Security|Application)/i,
];

/**
 * 高风险工具调用列表
 * 包含可能被滥用的系统命令、脚本执行器等
 * 涵盖 Linux、macOS 和 Windows 平台
 */
export const HIGH_RISK_TOOLS = new Set([
  // ──── General/Linux/macOS tools ────
  'gateway',
  'cron',
  'exec',
  'spawn',
  'shell',
  'bash',
  'sh',
  'zsh',
  'ksh',
  'fs_delete',
  'fs_move',
  'fs_write',
  'apply_patch',
  'eval',
  'system',
  'popen',
  
  // ──── Linux/macOS system tools ────
  'sudo',
  'su',
  'chmod',
  'chown',
  'chgrp',
  'umask',
  'pkexec',
  'visudo',
  'setfacl',
  'getfacl',
  'usermod',
  'groupadd',
  'groupdel',
  'useradd',
  'userdel',
  'passwd',
  
  // ──── macOS-specific tools ────
  'launchctl',
  'launchd',
  'pmset',
  'diskutil',
  'dscl',
  'security',
  'codesign',
  'xcode-select',
  
  // ──── Windows system tools ────
  'powershell',
  'powershell_ise',
  'ps',
  'cmd',
  'command',
  'comspec',
  'cmd.exe',
  'powershell.exe',
  'wmic',
  'wmi',
  'reg',
  'regedit',
  'regsvr32',
  'taskkill',
  'taskmgr',
  'sc',
  'services',
  'wevtutil',
  'netsh',
  'net',
  'ipconfig',
  'systeminfo',
  'whoami',
  'whoami.exe',
  'ver',
  'version',
  'schtasks',
  'at',
  'rundll32',
  'msiexec',
  'icacls',
  'takeown',
  'cipher',
  'format',
  'diskpart',
  'msconfig',
  'services.msc',
  'devmgmt.msc',
  'diskmgmt.msc',
  'eventvwr.msc',
  'firewall.cpl',
  'getadmin',
  
  // ──── Network tools ────
  'curl',
  'wget',
  'nc',
  'ncat',
  'netcat',
  'socat',
  'ssh',
  'telnet',
  'ftp',
  'tftp',
  'ping',
  'tracert',
  'nslookup',
  'whoami',
  'net.exe',
]);

/**
 * Anomalous activity detection configuration
 * Used to identify possible automated attacks or agent loss of control
 */
export const ANOMALOUS_ACTIVITY_CONFIG = {
  // Threshold for excessive calls to a single tool within one day
  toolCallThreshold: 20,
  
  // List of tools to monitor for anomalies (empty means check all)
  monitoredTools: [],
};

/**
 * Security detection rule descriptions
 * Used to generate readable detection reports
 */
export const DETECTION_DESCRIPTIONS = {
  promptInjection: {
    title: 'Prompt Injection Risk Detected',
    description: (count) => `Found ${count} log records containing suspicious prompt injection patterns, which may indicate system prompts have been tampered with`,
  },
  credentialLeak: {
    title: 'Credential Leak Risk Detected',
    description: (count) => `Found ${count} log records that may contain API keys, tokens, or other sensitive credentials, posing an information disclosure risk`,
  },
  dangerousCommand: {
    title: 'Dangerous Command Execution Detected',
    description: (count) => `Found ${count} dangerous tool calls (such as file deletion, permission modification, command injection, etc.), which may lead to system corruption`,
  },
  suspiciousToolCall: {
    title: 'Risky Tool Call Detected',
    description: (count) => `Found ${count} risky tool calls, including system commands, file operations, permission management, etc. These calls may pose a threat to system security (supports Linux, macOS, and Windows platforms)`,
  },
  anomalousActivity: {
    title: 'Anomalous Activity Frequency Detected',
    description: (tools) => `Found anomalous tool call frequency: ${tools.map(t => `${t.toolName}(${t.count})`).join(', ')}, which may indicate automated attacks or agent loss of control`,
  },
};
