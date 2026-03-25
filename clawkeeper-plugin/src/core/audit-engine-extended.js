/**
 * audit-engine-extended.js
 * Extended audit engine with advanced security checks across multiple layers
 */

import { fileExists, getConfigPath, getSkillInstallPath, getSoulPath, readJsonIfExists } from './state.js';
import { PLUGIN_NAME, VERSION } from './metadata.js';
import { getControls } from './controls.js';
import {
  PROMPT_INJECTION_PATTERNS,
  CREDENTIAL_LEAK_PATTERNS,
  DANGEROUS_COMMAND_PATTERNS,
  HIGH_RISK_TOOLS,
  ANOMALOUS_ACTIVITY_CONFIG,
  DETECTION_DESCRIPTIONS
} from './security-rules.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const SCORE_BY_SEVERITY = {
  CRITICAL: 20,
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0
};

// ============================================================
// Cross-platform utility functions
// ============================================================

const PLATFORM = os.platform();
const IS_WINDOWS = PLATFORM === 'win32';
const IS_LINUX = PLATFORM === 'linux';
const IS_MACOS = PLATFORM === 'darwin';

/**
 * Check file/directory permissions for excessive permissiveness
 * Windows: Check NTFS ownership and access control
 * Unix: Check permission bits
 */
async function checkFilePermissions(filePath) {
  try {
    const stats = await fs.stat(filePath);
    
    if (IS_WINDOWS) {
      // On Windows, check if file is owned by SYSTEM or current user
      // NTFS permission checks are complex, using simplified approach
      // If file exists and is accessible, permissions are considered configured
      return {
        isExcessivelyPermissive: false,  // Windows NTFS is relatively secure by default
        mode: null,
        message: 'Windows NTFS permissions'
      };
    } else {
      // Unix systems: check permission bits
      const mode = stats.mode & 0o777;
      const otherPerms = mode & 0o077;
      
      return {
        isExcessivelyPermissive: otherPerms !== 0,
        mode,
        otherPerms,
        message: `${mode.toString(8)}`
      };
    }
  } catch (err) {
    return {
      isExcessivelyPermissive: false,
      mode: null,
      error: err.message
    };
  }
}

// ============================================================
// Advanced Gateway Security Audit Checks
// ============================================================

async function auditGatewayExtended(context) {
  const extendedFindings = [];
  const gw = context.config?.gateway || {};

  // GW-001: Gateway bind mode - must be loopback for local access
  if (gw?.bind && gw.bind !== 'loopback' && gw.bind !== '127.0.0.1' && gw.bind !== 'localhost') {
    extendedFindings.push({
      id: 'SC-GW-001',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Gateway not bound to loopback',
      description: `Gateway is bound to "${gw.bind}" instead of loopback. This exposes the gateway to network attacks.`,
      evidence: `gateway.bind = "${gw.bind}"`,
      remediation: 'Set gateway.bind to "loopback" in openclaw.json',
      autoFixable: true,
      threat: 'exposure',
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-002: Gateway authentication mode - must use password or token
  const authMode = gw?.auth?.mode ?? (gw?.authToken ? 'token' : undefined);
  if (authMode !== 'password' && authMode !== 'token') {
    extendedFindings.push({
      id: 'SC-GW-002',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Gateway authentication disabled',
      description: `Gateway authentication mode is "${authMode ?? 'none'}". Anyone with network access can control this instance.`,
      evidence: `gateway.auth.mode = "${authMode ?? 'undefined'}"`,
      remediation: 'Set gateway.auth.mode to "password" or "token" and configure a strong credential',
      autoFixable: true,
      threat: 'authentication-bypass',
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-003: Auth token/password length - must be >= 32 characters
  const token = gw?.auth?.token ?? gw?.auth?.password ?? gw?.authToken ?? '';
  if ((authMode === 'token' || authMode === 'password') && token.length > 0 && token.length < 32) {
    extendedFindings.push({
      id: 'SC-GW-003',
      severity: 'HIGH',
      category: 'gateway',
      title: 'Gateway auth token/password too short',
      description: `Auth credential is only ${token.length} characters. Should be at least 32 characters for adequate entropy.`,
      evidence: `token length = ${token.length} (expected >= 32)`,
      remediation: 'Update gateway.auth.token or gateway.auth.password to a longer value (32+ chars)',
      autoFixable: false,
      threat: 'weak-authentication',
      references: [],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-004: Gateway port accessible from non-localhost (requires deep scan)
  const gatewayPort = gw?.port ?? 18789;
  extendedFindings.push({
    id: 'SC-GW-004',
    severity: 'INFO',
    category: 'gateway',
    title: 'Gateway port accessibility check (requires --deep)',
    description: `Port ${gatewayPort} remote accessibility requires deep scan mode (--deep) for active probing.`,
    evidence: `Port: ${gatewayPort}`,
    remediation: 'Run audit with --deep flag for active network probing',
    autoFixable: false,
    threat: 'reconnaissance',
    references: [],
    owaspAsi: 'ASI05',
    maestroLayer: 'L4',
    nistCategory: 'evasion',
  });

  // GW-005: Browser relay port accessibility
  const browserRelayPort = (gw?.port ?? 18789) - 897;
  extendedFindings.push({
    id: 'SC-GW-005',
    severity: 'INFO',
    category: 'gateway',
    title: 'Browser relay port accessibility check (requires --deep)',
    description: `Browser relay port ${browserRelayPort} accessibility requires deep scan mode (--deep) for active probing.`,
    evidence: `Browser relay port: ${browserRelayPort}`,
    remediation: 'Run audit with --deep flag for active network probing',
    autoFixable: false,
    threat: 'reconnaissance',
    references: [],
    owaspAsi: 'ASI05',
    maestroLayer: 'L4',
    nistCategory: 'evasion',
  });

  // GW-006: TLS must be enabled for secure communication
  if (!gw?.tls?.enabled) {
    extendedFindings.push({
      id: 'SC-GW-006',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'TLS not enabled on gateway',
      description: 'Gateway traffic is unencrypted. Credentials and conversation data are transmitted in plaintext.',
      evidence: 'gateway.tls.enabled is not true',
      remediation: 'Configure gateway.tls with a valid certificate and key',
      autoFixable: false,
      threat: 'eavesdropping',
      references: [],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-007: mDNS mode should be minimal or disabled
  if (gw?.mdns && gw.mdns.mode !== 'minimal' && gw.mdns.mode !== 'disabled' && gw.mdns.mode !== 'off') {
    extendedFindings.push({
      id: 'SC-GW-007',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'mDNS discovery enabled or in full mode',
      description: 'mDNS is broadcasting sensitive instance information on the local network. This widens the attack surface.',
      evidence: `gateway.mdns.mode = "${gw.mdns.mode}"`,
      remediation: 'Set gateway.mdns.mode to "minimal" or "disabled"',
      autoFixable: true,
      threat: 'reconnaissance',
      references: [],
      owaspAsi: 'ASI04',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-008: Reverse proxy without trustedProxies is a critical bypass
  if (gw?.bind && gw.bind !== 'loopback' && gw.bind !== '127.0.0.1' && (!gw?.trustedProxies || gw.trustedProxies.length === 0)) {
    extendedFindings.push({
      id: 'SC-GW-008',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Reverse proxy without trustedProxies configuration',
      description: 'Gateway is network-accessible without trustedProxies set. All connections appear as localhost, bypassing authentication.',
      evidence: `gateway.bind = "${gw.bind}", trustedProxies = ${JSON.stringify(gw.trustedProxies)}`,
      remediation: 'Set gateway.trustedProxies to the IP of your reverse proxy, e.g., ["127.0.0.1"]',
      autoFixable: true,
      threat: 'authorization-bypass',
      references: ['CVE-2026-25253'],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-009: Device authentication bypass on Control UI
  if (gw?.controlUi?.dangerouslyDisableDeviceAuth === true) {
    extendedFindings.push({
      id: 'SC-GW-009',
      severity: 'CRITICAL',
      category: 'gateway',
      title: 'Device authentication disabled on Control UI',
      description: 'dangerouslyDisableDeviceAuth is enabled, bypassing all device-level authentication for the Control UI.',
      evidence: 'gateway.controlUi.dangerouslyDisableDeviceAuth = true',
      remediation: 'Set gateway.controlUi.dangerouslyDisableDeviceAuth to false',
      autoFixable: true,
      threat: 'authentication-bypass',
      references: [],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  // GW-010: Insecure authentication bypass
  if (gw?.controlUi?.allowInsecureAuth === true) {
    extendedFindings.push({
      id: 'SC-GW-010',
      severity: 'MEDIUM',
      category: 'gateway',
      title: 'Insecure authentication allowed on Control UI',
      description: 'allowInsecureAuth is enabled on Control UI, allowing weaker authentication methods.',
      evidence: 'gateway.controlUi.allowInsecureAuth = true',
      remediation: 'Set gateway.controlUi.allowInsecureAuth to false',
      autoFixable: true,
      threat: 'weak-authentication',
      references: [],
      owaspAsi: 'ASI03',
      maestroLayer: 'L4',
      nistCategory: 'evasion',
    });
  }

  return extendedFindings;
}

// ============================================================
// Advanced Credentials Security Audit Checks
// ============================================================

async function auditCredentialsExtended(context) {
  const extendedFindings = [];
  const stateDir = context.stateDir;

  try {
    // CRED-001: State directory permissions check (Unix only)
    if (!IS_WINDOWS) {
      const statDirPerms = await checkFilePermissions(stateDir);
      if (statDirPerms.isExcessivelyPermissive) {
        extendedFindings.push({
          id: 'SC-CRED-001',
          severity: 'HIGH',
          category: 'credentials',
          title: 'State directory has excessive permissions',
          description: `~/.openclaw/ directory is accessible by group/other users (${statDirPerms.message}).`,
          evidence: `Permissions: ${statDirPerms.message} (expected: 700)`,
          remediation: 'Run: chmod 700 ~/.openclaw/',
          autoFixable: true,
          threat: 'unauthorized-access',
          references: [],
          owaspAsi: 'ASI03',
          maestroLayer: 'L4',
          nistCategory: 'privacy',
        });
      }
    } else {
      // Windows: Check if directory is on NTFS
      extendedFindings.push({
        id: 'SC-CRED-001',
        severity: 'INFO',
        category: 'credentials',
        title: 'State directory permissions (Windows)',
        description: 'On Windows NTFS, directory permissions are inherited from parent. Ensure %APPDATA% is only accessible by the current user.',
        evidence: `Platform: Windows`,
        remediation: 'Verify folder permissions in Properties > Security tab',
        autoFixable: false,
        threat: 'unauthorized-access',
        references: [],
        owaspAsi: 'ASI03',
        maestroLayer: 'L4',
        nistCategory: 'privacy',
      });
    }

    // CRED-002: Config file permissions check (Unix only)
    const configPath = getConfigPath(stateDir);
    if (!IS_WINDOWS) {
      if (await fileExists(configPath)) {
        const configPerms = await checkFilePermissions(configPath);
        if (configPerms.isExcessivelyPermissive) {
          extendedFindings.push({
            id: 'SC-CRED-002',
            severity: 'HIGH',
            category: 'credentials',
            title: 'Config file has excessive permissions',
            description: `openclaw.json is readable by group/other users (${configPerms.message}).`,
            evidence: `Permissions: ${configPerms.message} (expected: 600)`,
            remediation: 'Run: chmod 600 ~/.openclaw/openclaw.json',
            autoFixable: true,
            threat: 'unauthorized-access',
            references: [],
            owaspAsi: 'ASI03',
            maestroLayer: 'L4',
            nistCategory: 'privacy',
          });
        }
      }
    } else {
      // Windows: Info about NTFS permissions
      extendedFindings.push({
        id: 'SC-CRED-002',
        severity: 'INFO',
        category: 'credentials',
        title: 'Config file permissions (Windows)',
        description: 'On Windows NTFS, ensure openclaw.json is only readable by the current user.',
        evidence: `Platform: Windows`,
        remediation: 'Right-click file > Properties > Security > Advanced > verify permissions',
        autoFixable: false,
        threat: 'unauthorized-access',
        references: [],
        owaspAsi: 'ASI03',
        maestroLayer: 'L4',
        nistCategory: 'privacy',
      });
    }

    // CRED-003: .env file with plaintext API keys
    const envPath = path.join(stateDir, '.env');
    const envContent = await fs.readFile(envPath, 'utf-8').catch(() => null);
    if (envContent !== null) {
      const apiKeyPatterns = [
        { pattern: CREDENTIAL_LEAK_PATTERNS[0], name: 'OpenAI API key' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[1], name: 'GitHub token' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[2], name: 'AWS access key' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[3], name: 'Private key' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[4], name: 'Bearer token' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[5], name: 'Slack token' },
        { pattern: CREDENTIAL_LEAK_PATTERNS[6], name: 'API/Secret key' },
      ];

      for (const { pattern, name } of apiKeyPatterns) {
        if (pattern.test(envContent)) {
          extendedFindings.push({
            id: 'SC-CRED-003',
            severity: 'CRITICAL',
            category: 'credentials',
            title: `Plaintext ${name} in .env file`,
            description: `.env file contains plaintext ${name}. These should encrypted or passed via secure channels.`,
            evidence: `Found ${name} pattern in .env`,
            remediation: 'Remove from .env and use encrypted environment variables or secret manager',
            autoFixable: false,
            threat: 'credential-exposure',
            references: [],
            owaspAsi: 'ASI03',
            maestroLayer: 'L4',
            nistCategory: 'privacy',
          });
          break;
        }
      }
    }

    // CRED-004: credentials/*.json permissions  
    const credsDir = path.join(stateDir, 'credentials');
    if (await fileExists(credsDir)) {
      try {
        const credFiles = await fs.readdir(credsDir);
        for (const credFile of credFiles) {
          const credPath = path.join(credsDir, credFile);
          try {
            const stat = await fs.stat(credPath);
            if (!stat.isDirectory()) {
              if (!IS_WINDOWS) {
                const perms = await checkFilePermissions(credPath);
                if (perms.isExcessivelyPermissive) {
                  extendedFindings.push({
                    id: 'SC-CRED-004',
                    severity: 'CRITICAL',
                    category: 'credentials',
                    title: `Credential file has excessive permissions: ${credFile}`,
                    description: `${credFile} is readable by group/other users. Contains sensitive credentials.`,
                    evidence: `${credPath}: ${perms.message} (expected: 600)`,
                    remediation: `Run: chmod 600 ${credPath}`,
                    autoFixable: true,
                    threat: 'credential-exposure',
                    references: [],
                    owaspAsi: 'ASI03',
                    maestroLayer: 'L4',
                    nistCategory: 'privacy',
                  });
                }
              }
            }
          } catch (err) {
            // Skip files that can't be accessed
          }
        }
      } catch (err) {
        // credentials directory may not exist
      }
    }

    // CRED-005: auth-profiles.json permissions
    const agentsDir = path.join(stateDir, 'agents');
    if (await fileExists(agentsDir)) {
      try {
        const agentDirs = await fs.readdir(agentsDir);
        for (const agent of agentDirs) {
          const authProfilePath = path.join(agentsDir, agent, 'auth-profiles.json');
          if (await fileExists(authProfilePath)) {
            if (!IS_WINDOWS) {
              const perms = await checkFilePermissions(authProfilePath);
              if (perms.isExcessivelyPermissive) {
                extendedFindings.push({
                  id: 'SC-CRED-005',
                  severity: 'CRITICAL',
                  category: 'credentials',
                  title: `Auth profiles file has excessive permissions: ${agent}`,
                  description: `auth-profiles.json is readable by group/other users. Contains authentication tokens.`,
                  evidence: `${authProfilePath}: ${perms.message} (expected: 600)`,
                  remediation: `Run: chmod 600 ${authProfilePath}`,
                  autoFixable: true,
                  threat: 'credential-exposure',
                  references: [],
                  owaspAsi: 'ASI03',
                  maestroLayer: 'L4',
                  nistCategory: 'privacy',
                });
              }
            }
          }
        }
      } catch (err) {
        // agents directory may not exist
      }
    }

    // CRED-006: OAuth tokens in plaintext files under state dir
    try {
      const credFiles = await fs.readdir(credsDir).catch(() => []);
      for (const credFile of credFiles) {
        if (credFile.endsWith('.json')) {
          const credPath = path.join(credsDir, credFile);
          try {
            const content = await fs.readFile(credPath, 'utf-8');
            if (content.includes('access_token') || content.includes('refresh_token') || content.includes('token')) {
              // Check if token value is in plaintext (not encrypted/hashed)
              const oauthPatterns = /['\"]?(access_token|refresh_token)['\"]?\s*:\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?/g;
              if (oauthPatterns.test(content)) {
                extendedFindings.push({
                  id: 'SC-CRED-006',
                  severity: 'CRITICAL',
                  category: 'credentials',
                  title: `Plaintext OAuth tokens in ${credFile}`,
                  description: 'OAuth tokens are stored in plaintext. These should be encrypted at rest.',
                  evidence: `File: ${credPath}`,
                  remediation: 'Implement token encryption at rest or use token vault service',
                  autoFixable: false,
                  threat: 'credential-exposure',
                  references: [],
                  owaspAsi: 'ASI03',
                  maestroLayer: 'L4',
                  nistCategory: 'privacy',
                });
              }
            }
          } catch (err) {
            // Skip files that can't be read
          }
        }
      }
    } catch (err) {
      // credentials directory operations
    }

    // CRED-007: API keys in memory/soul files
    if (await fileExists(agentsDir)) {
      try {
        const agents = await fs.readdir(agentsDir);
        for (const agent of agents) {
          const agentDir = path.join(agentsDir, agent);
          const memoryFiles = ['soul.md', 'SOUL.md', 'MEMORY.md', 'memory.md', 'soul.json'];
          
          for (const memFile of memoryFiles) {
            const memPath = path.join(agentDir, memFile);
            try {
              if (!await fileExists(memPath)) continue;
              const content = await fs.readFile(memPath, 'utf-8');
              
              const apiKeyPatterns = [
                { pattern: CREDENTIAL_LEAK_PATTERNS[0], name: 'OpenAI key' },
                { pattern: CREDENTIAL_LEAK_PATTERNS[1], name: 'GitHub token' },
                { pattern: CREDENTIAL_LEAK_PATTERNS[5], name: 'Slack token' },
              ];

              for (const { pattern, name } of apiKeyPatterns) {
                if (pattern.test(content)) {
                  extendedFindings.push({
                    id: 'SC-CRED-007',
                    severity: 'CRITICAL',
                    category: 'credentials',
                    title: `Plaintext ${name} in memory file: ${agent}/${memFile}`,
                    description: `API key found in agent memory. Keys should never be stored in memory files.`,
                    evidence: `File: ${memPath}`,
                    remediation: 'Remove all API keys from memory files and use environment variables',
                    autoFixable: false,
                    threat: 'credential-exposure',
                    references: [],
                    owaspAsi: 'ASI03',
                    maestroLayer: 'L4',
                    nistCategory: 'privacy',
                  });
                  break;
                }
              }
            } catch (err) {
              // Skip files that can't be read
            }
          }
        }
      } catch (err) {
        // agents directory operations
      }
    }

    // CRED-008: Scan all .md and .json files for API keys
    async function scanDirForApiKeys(dir, depth = 0, maxDepth = 5) {
      const foundKeys = [];
      if (depth > maxDepth) return foundKeys;
      
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            foundKeys.push(...await scanDirForApiKeys(path.join(dir, entry.name), depth + 1, maxDepth));
          } else if (entry.name.endsWith('.md') || entry.name.endsWith('.json')) {
            try {
              const content = await fs.readFile(path.join(dir, entry.name), 'utf-8');
              // Use patterns from security-rules.js for comprehensive credential detection
              for (const pattern of CREDENTIAL_LEAK_PATTERNS) {
                if (pattern.test(content)) {
                  foundKeys.push({ file: path.join(dir, entry.name), pattern: pattern.toString() });
                  break;
                }
              }
            } catch (err) {
              // Skip files that can't be read
            }
          }
        }
      } catch (err) {
        // Skip directories that can't be accessed
      }
      return foundKeys;
    }

    const apiKeyMatches = await scanDirForApiKeys(stateDir);
    if (apiKeyMatches.length > 0) {
      extendedFindings.push({
        id: 'SC-CRED-008',
        severity: 'CRITICAL',
        category: 'credentials',
        title: `Plaintext API keys found in ${apiKeyMatches.length} file(s)`,
        description: `Found ${apiKeyMatches.length} potential API key exposure(s) in state directory files.`,
        evidence: `Files: ${apiKeyMatches.slice(0, 3).map(m => m.file.replace(stateDir, '')).join(', ')}`,
        remediation: 'Remove all API keys from files and use environment variables or secure secret management',
        autoFixable: false,
        threat: 'credential-exposure',
        references: [],
        owaspAsi: 'ASI03',
        maestroLayer: 'L4',
        nistCategory: 'privacy',
      });
    }

  } catch (err) {
    // If we can't access state dir, skip extended credential checks
    console.debug('Could not perform extended credential audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Advanced Execution Layer Security Audit Checks  
// ============================================================

async function auditExecutionExtended(context) {
  const extendedFindings = [];
  const exec = context.config?.exec || {};

  // EXEC-001: exec.approvals off - whether approval queue is disabled
  if (exec.approvals === 'off') {
    extendedFindings.push({
      id: 'SC-EXEC-001',
      severity: 'CRITICAL',
      category: 'execution',
      title: 'Execution approvals disabled',
      description: 'exec.approvals is set to "off". All tool executions are automatically approved without review.',
      evidence: `exec.approvals = "off"`,
      remediation: 'Set exec.approvals to "on" or "strict" to require approval for risky operations',
      autoFixable: false,
      threat: 'unreviewed-execution',
      references: [],
      owaspAsi: 'ASI02',
      maestroLayer: 'L3',
      nistCategory: 'misuse',
    });
  }

  // EXEC-002: tools.exec.host = gateway - execution host location
  if (context.config?.tools?.exec?.host === 'gateway') {
    extendedFindings.push({
      id: 'SC-EXEC-002',
      severity: 'HIGH',
      category: 'execution',
      title: 'Code execution runs on gateway',
      description: 'tools.exec.host is set to "gateway". Execution runs on the same host as the gateway, increasing attack surface.',
      evidence: `tools.exec.host = "gateway"`,
      remediation: 'Set tools.exec.host to "sandbox"',
      autoFixable: false,
      threat: 'uncontrolled-execution',
      references: [],
      owaspAsi: 'ASI02',
      maestroLayer: 'L3',
      nistCategory: 'misuse',
    });
  }

  // EXEC-003: Sandbox mode check
  const sandbox = context.config?.sandbox || {};
  if (sandbox.mode !== 'all' && sandbox.mode !== 'workspace-write') {
    extendedFindings.push({
      id: 'SC-EXEC-003',
      severity: 'MEDIUM',
      category: 'execution',
      title: 'Sandbox mode not set to "all"',
      description: `Sandbox mode is "${sandbox.mode ?? 'undefined'}". Not all commands run in a sandboxed environment.`,
      evidence: `sandbox.mode = "${sandbox.mode ?? 'undefined'}"`,
      remediation: 'Set sandbox.mode to "all" for maximum protection',
      autoFixable: false,
      threat: 'uncontrolled-execution',
      references: [],
      owaspAsi: 'ASI05',
      maestroLayer: 'L3',
      nistCategory: 'misuse',
    });
  }

  // EXEC-004: Docker read-only filesystem
  if (context.config?.docker) {
    const services = context.config.docker.services || {};
    for (const [serviceName, service] of Object.entries(services)) {
      if (!service.read_only) {
        extendedFindings.push({
          id: 'SC-EXEC-004',
          severity: 'MEDIUM',
          category: 'execution',
          title: `Docker service "${serviceName}" not read-only`,
          description: 'Container filesystem is writable, allowing post-exploitation persistence.',
          evidence: `Service "${serviceName}": read_only is not set`,
          remediation: 'Add read_only: true to the Docker service configuration',
          autoFixable: true,
          threat: 'persistence',
          references: [],
          owaspAsi: 'ASI05',
          maestroLayer: 'L3',
          nistCategory: 'misuse',
        });
      }
    }
  }

  // EXEC-005: Docker capability restrictions (cap_drop)
  if (context.config?.docker?.services) {
    const services = context.config.docker.services;
    let hasCapDropAll = false;
    
    for (const [svcName, svc] of Object.entries(services)) {
      if (svc.cap_drop && svc.cap_drop.includes('ALL')) {
        hasCapDropAll = true;
        break;
      }
    }

    if (!hasCapDropAll) {
      extendedFindings.push({
        id: 'SC-EXEC-005',
        severity: 'INFO',
        category: 'execution',
        title: 'Docker services: Review capability restrictions (cap_drop)',
        description: 'Not all Docker services have cap_drop: ["ALL"] configured.',
        evidence: 'Docker services configuration',
        remediation: 'Add cap_drop: ["ALL"] to each service to drop all Linux capabilities',
        autoFixable: false,
        threat: 'privilege-escalation',
        references: [],
        owaspAsi: 'ASI05',
        maestroLayer: 'L3',
        nistCategory: 'misuse',
      });
    }
  }

  // EXEC-006: Docker privilege escalation restrictions (no-new-privileges)
  if (context.config?.docker?.services) {
    const services = context.config.docker.services;
    let hasNoNewPrivileges = false;
    
    for (const [svcName, svc] of Object.entries(services)) {
      if (svc.security_opt && svc.security_opt.includes('no-new-privileges:true')) {
        hasNoNewPrivileges = true;
        break;
      }
    }

    if (!hasNoNewPrivileges) {
      extendedFindings.push({
        id: 'SC-EXEC-006',
        severity: 'INFO',
        category: 'execution',
        title: 'Docker services: Review privilege escalation restrictions',
        description: 'Not all Docker services have no-new-privileges security option set.',
        evidence: 'Docker services configuration',
        remediation: 'Add security_opt: ["no-new-privileges:true"] to prevent privilege escalation',
        autoFixable: false,
        threat: 'privilege-escalation',
        references: [],
        owaspAsi: 'ASI05',
        maestroLayer: 'L3',
        nistCategory: 'misuse',
      });
    }
  }

  // EXEC-007: Docker host network mode check
  if (context.config?.docker?.services) {
    const services = context.config.docker.services;
    for (const [svcName, svc] of Object.entries(services)) {
      if (svc.network_mode === 'host') {
        extendedFindings.push({
          id: 'SC-EXEC-007',
          severity: 'HIGH',
          category: 'execution',
          title: `Docker service "${svcName}" uses host network mode`,
          description: 'Container shares the host network namespace, bypassing network isolation.',
          evidence: `Service "${svcName}": network_mode = "host"`,
          remediation: 'Remove network_mode: "host" and use bridge networking',
          autoFixable: true,
          threat: 'network-isolation-bypass',
          references: [],
          owaspAsi: 'ASI05',
          maestroLayer: 'L3',
          nistCategory: 'misuse',
        });
      }
    }
  }

  return extendedFindings;
}

// ============================================================
// Access Control Security Audit Checks (AC-001~005)
// ============================================================

async function auditAccessControlExtended(context) {
  const extendedFindings = [];
  
  try {
    // AC-001: DM policy configurability
    const dmPolicy = context.config?.messaging?.dmPolicy;
    if (dmPolicy === 'open') {
      extendedFindings.push({
        id: 'SC-AC-001',
        severity: 'HIGH',
        category: 'access-control',
        title: 'DM policy is completely open',
        description: 'Direct messaging policy allows unrestricted incoming messages from any user.',
        evidence: `messaging.dmPolicy = "open"`,
        remediation: 'Set messaging.dmPolicy to "pairing" or "allowlist" to restrict who can contact the agent',
        autoFixable: false,
        threat: 'unauthorized-access',
        references: [],
        owaspAsi: 'ASI09',
        maestroLayer: 'L3',
        nistCategory: 'evasion',
      });
    }

    // AC-002: Group message policy
    const groupPolicy = context.config?.messaging?.groupPolicy;
    if (groupPolicy === 'open') {
      extendedFindings.push({
        id: 'SC-AC-002',
        severity: 'MEDIUM',
        category: 'access-control',
        title: 'Group message policy is unrestricted',
        description: 'Agent accepts messages from all groups without restriction.',
        evidence: `messaging.groupPolicy = "open"`,
        remediation: 'Restrict group access by setting groupPolicy to "whitelist" or "disabled"',
        autoFixable: false,
        threat: 'unauthorized-access',
        references: [],
        owaspAsi: 'ASI09',
        maestroLayer: 'L3',
        nistCategory: 'evasion',
      });
    }

    // AC-003: Wildcard allowlist check
    const allowlist = context.config?.messaging?.allowlist;
    if (allowlist && allowlist.includes('*')) {
      extendedFindings.push({
        id: 'SC-AC-003',
        severity: 'HIGH',
        category: 'access-control',
        title: 'Wildcard in messaging allowlist',
        description: 'Using "*" in the allowlist defeats the purpose of access control.',
        evidence: `messaging.allowlist contains "*"`,
        remediation: 'Replace wildcard with specific user/group identifiers',
        autoFixable: false,
        threat: 'unauthorized-access',
        references: [],
        owaspAsi: 'ASI09',
        maestroLayer: 'L3',
        nistCategory: 'evasion',
      });
    }

    // AC-004: Session isolation check
    const sessionDmScope = context.config?.session?.dmScope;
    if (!sessionDmScope || sessionDmScope !== 'per-channel-peer') {
      extendedFindings.push({
        id: 'SC-AC-004',
        severity: 'MEDIUM',
        category: 'access-control',
        title: 'Session context not isolated per user',
        description: 'session.dmScope is not "per-channel-peer". Agent context may leak between different users.',
        evidence: `session.dmScope = "${sessionDmScope ?? 'undefined'}"`,
        remediation: 'Set session.dmScope to "per-channel-peer" to isolate context per user',
        autoFixable: true,
        threat: 'context-leakage',
        references: [],
        owaspAsi: 'ASI09',
        maestroLayer: 'L3',
        nistCategory: 'evasion',
      });
    }

    // AC-005: Rate limiting configuration
    const rateLimitConfig = context.config?.messaging?.rateLimit;
    if (!rateLimitConfig) {
      extendedFindings.push({
        id: 'SC-AC-005',
        severity: 'LOW',
        category: 'access-control',
        title: 'No rate limiting configured for messages',
        description: 'Rate limiting is not configured. Agent could be overwhelmed by message floods.',
        evidence: `messaging.rateLimit is not configured`,
        remediation: 'Configure rate limiting: set messaging.rateLimit to { messagesPerMinute: 30, burstsAllowed: 2 }',
        autoFixable: false,
        threat: 'denial-of-service',
        references: [],
        owaspAsi: 'ASI08',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

  } catch (err) {
    console.debug('Could not perform access control audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Memory Integrity Checks (SC-MEM-001~005)
// ============================================================

async function auditMemoryIntegrityExtended(context) {
  const extendedFindings = [];
  
  try {
    const stateDir = context.stateDir;
    const agentsDir = path.join(stateDir, 'agents');

    // MEM-001: Check if agents directory exists
    if (!await fileExists(agentsDir)) {
      extendedFindings.push({
        id: 'SC-MEM-001',
        severity: 'INFO',
        category: 'memory',
        title: 'No agents directory found',
        description: 'No agents directory found. Memory integrity checks skipped.',
        evidence: `Path: ${agentsDir}`,
        remediation: 'No action needed if this is a fresh installation',
        autoFixable: false,
        threat: 'none',
        references: [],
        owaspAsi: 'ASI06',
        maestroLayer: 'L2',
        nistCategory: 'poisoning',
      });
      return extendedFindings;
    }

    // List all agent directories
    let agents = [];
    try {
      agents = await fs.readdir(agentsDir);
    } catch {
      return extendedFindings; 
    }

    const memoryFileNames = ['soul.md', 'SOUL.md', 'soul.json', 'MEMORY.md', 'memory.md'];

    for (const agent of agents) {
      const agentDir = path.join(agentsDir, agent);

      // MEM-002: Check for prompt injection patterns in memory files
      for (const memFile of memoryFileNames) {
        const memPath = path.join(agentDir, memFile);
        
        try {
          if (!await fileExists(memPath)) continue;
          
          const content = await fs.readFile(memPath, 'utf-8');
          
          const injectionPatterns = PROMPT_INJECTION_PATTERNS;

          for (const pattern of injectionPatterns) {
            if (pattern.test(content)) {
              extendedFindings.push({
                id: 'SC-MEM-002',
                severity: 'CRITICAL',
                category: 'memory',
                title: `Potential prompt injection detected in ${memFile} (${agent})`,
                description: `Memory file contains potential prompt injection pattern: "${pattern.source}"`,
                evidence: `File: ${memPath}`,
                remediation: 'Review and clean this file. Check for unauthorized modifications.',
                autoFixable: false,
                threat: 'prompt-injection',
                references: [],
                owaspAsi: 'ASI06',
                maestroLayer: 'L2',
                nistCategory: 'poisoning',
              });
            }
          }

          // MEM-003: Check for large base64 blocks (potential obfuscation)
          const base64BlockPattern = /[A-Za-z0-9+/=]{100,}/g;
          const base64Blocks = content.match(base64BlockPattern) || [];
          
          if (base64Blocks.length > 5) {
            extendedFindings.push({
              id: 'SC-MEM-003',
              severity: 'MEDIUM',
              category: 'memory',
              title: `Multiple base64 blocks in ${memFile} (${agent})`,
              description: `Memory file contains ${base64Blocks.length} large base64 encoded blocks which may hide malicious instructions`,
              evidence: `File: ${memPath}, Found ${base64Blocks.length} blocks`,
              remediation: 'Review and decode the base64 content to verify it is benign',
              autoFixable: false,
              threat: 'obfuscation',
              references: [],
              owaspAsi: 'ASI06',
              maestroLayer: 'L2',
              nistCategory: 'poisoning',
            });
          }

          // MEM-004: Check for non-whitelisted URLs in memory (simplified cross-platform check)
          const urlPattern = /https?:\/\/[^\s"'<>]+/g;
          const urls = content.match(urlPattern) || [];
          const allowedDomains = context.config?.network?.egressAllowlist || [
            'api.anthropic.com',
            'api.openai.com',
            'generativelanguage.googleapis.com',
          ];

          const suspiciousUrls = urls.filter(url => {
            try {
              const urlObj = new URL(url);
              return !allowedDomains.some(domain => urlObj.hostname.includes(domain));
            } catch {
              return false;
            }
          });

          if (suspiciousUrls.length > 0) {
            extendedFindings.push({
              id: 'SC-MEM-004',
              severity: 'MEDIUM',
              category: 'memory',
              title: `Suspicious URLs in ${memFile} (${agent})`,
              description: `Memory file contains URLs not in the egress allowlist: ${suspiciousUrls.slice(0, 3).join(', ')}`,
              evidence: `File: ${memPath}, Found ${suspiciousUrls.length} suspicious URLs`,
              remediation: 'Verify these URLs are legitimate. Add to allowlist if approved.',
              autoFixable: false,
              threat: 'data-exfiltration',
              references: [],
              owaspAsi: 'ASI03',
              maestroLayer: 'L4',
              nistCategory: 'evasion',
            });
          }

        } catch (err) {
          // File read error, continue to next file
          continue;
        }
      }

      // MEM-005: Check memory file permissions (Unix only)
      if (!IS_WINDOWS) {
        for (const memFile of memoryFileNames) {
          const memPath = path.join(agentDir, memFile);
          
          try {
            if (!await fileExists(memPath)) continue;
            
            const perms = await checkFilePermissions(memPath);
            if (perms.isExcessivelyPermissive) {
              extendedFindings.push({
                id: 'SC-MEM-005',
                severity: 'HIGH',
                category: 'memory',
                title: `Memory file has excessive permissions (${agent}/${memFile})`,
                description: `Memory file is readable by group/other users. Unauthorized access possible.`,
                evidence: `${memPath}: ${perms.message} (expected: 600)`,
                remediation: `Run: chmod 600 ${memPath}`,
                autoFixable: true,
                threat: 'unauthorized-access',
                references: [],
                owaspAsi: 'ASI06',
                maestroLayer: 'L2',
                nistCategory: 'privacy',
              });
            }
          } catch (err) {
            continue;
          }
        }
      }
    }

  } catch (err) {
    console.debug('Could not perform memory integrity audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Cost Exposure Checks (SC-COST-001~004)
// ============================================================

async function auditCostExposureExtended(context) {
  const extendedFindings = [];
  
  try {
    const stateDir = context.stateDir;

    // COST-001: LLM spending limits
    const envPath = path.join(stateDir, '.env');
    let envContent = '';
    
    try {
      envContent = await fs.readFile(envPath, 'utf-8');
    } catch {
      // .env file may not exist
    }

    const hasSpendingLimit = 
      envContent.includes('SPENDING_LIMIT') ||
      envContent.includes('MAX_BUDGET') ||
      envContent.includes('COST_LIMIT') ||
      context.config?.cost?.dailyLimitUsd;

    if (!hasSpendingLimit) {
      extendedFindings.push({
        id: 'SC-COST-001',
        severity: 'MEDIUM',
        category: 'cost',
        title: 'No LLM spending limits configured',
        description: 'No spending limit is set. Runaway API calls could result in unexpected costs.',
        evidence: 'No SPENDING_LIMIT, MAX_BUDGET, or COST_LIMIT found in .env',
        remediation: 'Configure daily spending limit via cost.dailyLimitUsd in openclaw.json or set SPENDING_LIMIT env var',
        autoFixable: false,
        threat: 'cost-exposure',
        references: [],
        owaspAsi: 'ASI08',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

    // COST-002: Check for high-volume logging
    const logsDir = path.join(stateDir, 'logs');
    if (await fileExists(logsDir)) {
      try {
        const logFiles = await fs.readdir(logsDir);
        if (logFiles.length > 100) {
          extendedFindings.push({
            id: 'SC-COST-002',
            severity: 'LOW',
            category: 'cost',
            title: 'High volume of log files',
            description: `Found ${logFiles.length} log files. Excessive logging may indicate high API usage.`,
            evidence: `Logs directory: ${logsDir}, Files: ${logFiles.length}`,
            remediation: 'Review recent logs for unusual API activity: review-logs command',
            autoFixable: false,
            threat: 'cost-exposure',
            references: [],
            owaspAsi: 'ASI08',
            maestroLayer: 'L5',
            nistCategory: 'misuse',
          });
        }
      } catch {
        // Can't read logs directory
      }
    }

    // COST-003: API quota configuration
    const apiQuota = context.config?.api?.quotas;
    if (!apiQuota) {
      extendedFindings.push({
        id: 'SC-COST-003',
        severity: 'INFO',
        category: 'cost',
        title: 'No API quotas configured',
        description: 'API quotas are not configured. Per-minute/per-day limits not enforced.',
        evidence: 'api.quotas is not set',
        remediation: 'Set api.quotas to enforce rate limiting: { perMinute: 600, perDay: 10000 }',
        autoFixable: false,
        threat: 'cost-exposure',
        references: [],
        owaspAsi: 'ASI08',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

    // COST-004: Model version control
    const model = context.config?.llm?.model;
    if (!model || !model.includes('gpt-4') && !model.includes('claude-3') && !model.includes('gemini')) {
      extendedFindings.push({
        id: 'SC-COST-004',
        severity: 'INFO',
        category: 'cost',
        title: 'Older LLM model configured',
        description: 'Using an older or unspecified LLM model. Consider using latest cost-optimized models.',
        evidence: `llm.model = "${model ?? 'not specified'}"`,
        remediation: 'Consider upgrading to gpt-4-turbo, claude-3-sonnet or similar cost-effective models',
        autoFixable: false,
        threat: 'cost-exposure',
        references: [],
        owaspAsi: 'ASI08',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

  } catch (err) {
    console.debug('Could not perform cost exposure audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Multi-Framework Security Checks (SC-KILL/TRUST/CTRL/DEGRAD)
// ============================================================

async function auditMultiFrameworkExtended(context) {
  const extendedFindings = [];
  
  try {
    const stateDir = context.stateDir;

    // KILL-001: Kill switch status
    const killSwitchDir = path.join(stateDir, '.secureclaw');
    const killSwitchPath = path.join(killSwitchDir, 'killswitch');
    
    if (await fileExists(killSwitchPath)) {
      extendedFindings.push({
        id: 'SC-KILL-001',
        severity: 'INFO',
        category: 'kill-switch',
        title: 'Kill switch is currently active',
        description: 'The kill switch file exists. Agent operations are suspended.',
        evidence: `Kill switch file: ${killSwitchPath}`,
        remediation: 'To resume operations, remove kill switch file or run: npx openclaw clawkeeper resume',
        autoFixable: false,
        threat: 'none',
        references: [],
        owaspAsi: 'ASI10',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

    // TRUST-001: Check cognitive files for injection
    const cognitiveFiles = ['SOUL.md', 'IDENTITY.md', 'TOOLS.md', 'AGENTS.md', 'SECURITY.md'];
    const injectionPatterns = PROMPT_INJECTION_PATTERNS;

    for (const cogFile of cognitiveFiles) {
      const cogPath = path.join(stateDir, cogFile);
      
      try {
        if (!await fileExists(cogPath)) continue;
        
        const content = await fs.readFile(cogPath, 'utf-8');
        
        for (const pattern of injectionPatterns) {
          if (pattern.test(content)) {
            extendedFindings.push({
              id: 'SC-TRUST-001',
              severity: 'CRITICAL',
              category: 'memory-trust',
              title: `Injected instruction pattern in workspace cognitive file: ${cogFile}`,
              description: `Cognitive file contains prompt injection pattern: "${pattern.source}". Possible context poisoning attack.`,
              evidence: `File: ${cogPath}`,
              remediation: 'Immediately review and clean this file. Check git history for unauthorized changes.',
              autoFixable: false,
              threat: 'context-poisoning',
              references: ['MITRE ATLAS AML.CS0051'],
              owaspAsi: 'ASI06',
              maestroLayer: 'L2',
              nistCategory: 'poisoning',
            });
            break; // Only report first pattern match per file
          }
        }
      } catch (err) {
        continue;
      }
    }

    // CTRL-001: Control token customization
    const configPath = path.join(stateDir, 'openclaw.json');
    try {
      const configContent = await fs.readFile(configPath, 'utf-8');
      
      if (!configContent.includes('controlTokens') && !configContent.includes('control_tokens')) {
        extendedFindings.push({
          id: 'SC-CTRL-001',
          severity: 'MEDIUM',
          category: 'control-tokens',
          title: 'Default control tokens in use',
          description: 'Control tokens have not been customized from defaults. Attackers could spoof model control tokens.',
          evidence: 'No controlTokens key found in openclaw.json',
          remediation: 'Add custom controlTokens to openclaw.json with unique, non-guessable values',
          autoFixable: false,
          threat: 'token-spoofing',
          references: ['MITRE ATLAS AML.CS0051'],
          owaspAsi: 'ASI01',
          maestroLayer: 'L3',
          nistCategory: 'evasion',
        });
      }
    } catch (err) {
      // Config file may not exist or be readable
    }

    // DEGRAD-001: Graceful degradation configuration
    if (!context.config?.secureclaw?.failureMode) {
      extendedFindings.push({
        id: 'SC-DEGRAD-001',
        severity: 'LOW',
        category: 'degradation',
        title: 'No graceful degradation mode configured',
        description: 'No failureMode is set. Agent has no predefined strategy for handling security issues.',
        evidence: 'secureclaw.failureMode is not configured',
        remediation: 'Set secureclaw.failureMode to "block_all", "safe_mode", or "read_only"',
        autoFixable: false,
        threat: 'misconfiguration',
        references: [],
        owaspAsi: 'ASI08',
        maestroLayer: 'L5',
        nistCategory: 'misuse',
      });
    }

  } catch (err) {
    console.debug('Could not perform multi-framework audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Cross-Layer Risk Detection (SC-CROSS-001)
// ============================================================

function auditCrossLayerRisk(findings) {
  const crossFindings = [];
  
  // Collect layers with non-INFO severity findings
  const affectedLayers = new Set();
  const severityCounts = {};

  for (const finding of findings) {
    if (finding.maestroLayer && finding.severity !== 'INFO') {
      affectedLayers.add(finding.maestroLayer);
      severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
    }
  }

  // SC-CROSS-001: Cross-layer compound attack surface
  if (affectedLayers.size >= 3) {
    const layers = Array.from(affectedLayers).sort().join(', ');
    const summary = Object.entries(severityCounts)
      .map(([sev, count]) => `${count} ${sev}`)
      .join(', ');

    crossFindings.push({
      id: 'SC-CROSS-001',
      severity: 'HIGH',
      category: 'cross-layer',
      title: 'Cross-layer compound attack surface detected',
      description: `Findings span ${affectedLayers.size} MAESTRO layers (${layers}). Compound attack surfaces enable chained exploits (e.g., supply chain → credentials → execution).`,
      evidence: `Affected layers: ${layers}, Summary: ${summary}`,
      remediation: 'Address findings by layer priority: first L2 (memory), then L3 (control), then L4+ (infrastructure)',
      autoFixable: false,
      threat: 'compound-attack',
      references: ['https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro'],
      owaspAsi: 'ASI10',
      maestroLayer: 'L6',
      nistCategory: 'evasion',
    });
  }

  return crossFindings;
}

// ============================================================
// Enhanced Supply Chain Checks (SC-SKILL-001+)
// ============================================================

async function auditSupplyChainExtended(context) {
  const extendedFindings = [];
  
  try {
    const skillDir = context.skillDir;
    
    if (!await fileExists(skillDir)) {
      extendedFindings.push({
        id: 'SC-SKILL-001',
        severity: 'INFO',
        category: 'supply-chain',
        title: 'No skills installed',
        description: 'No skills directory found. Skill-based supply chain checks skipped.',
        evidence: `Skill directory: ${skillDir}`,
        remediation: 'No action needed if skills are not used',
        autoFixable: false,
        threat: 'none',
        references: [],
        owaspAsi: 'ASI04',
        maestroLayer: 'L7',
        nistCategory: 'poisoning',
      });
      return extendedFindings;
    }

    let skillDirs = [];
    try {
      skillDirs = await fs.readdir(skillDir);
    } catch {
      return extendedFindings;
    }

    // SC-SKILL-001: Installed skills count
    extendedFindings.push({
      id: 'SC-SKILL-001',
      severity: 'INFO',
      category: 'supply-chain',
      title: `${skillDirs.length} skill(s) installed`,
      description: `Found ${skillDirs.length} installed skills. Each skill has access to agent capabilities.`,
      evidence: `Installed skills: ${skillDirs.length > 0 ? skillDirs.join(', ') : 'none'}`,
      remediation: 'Review each installed skill for necessity and trustworthiness',
      autoFixable: false,
      threat: 'supply-chain-risk',
      references: [],
      owaspAsi: 'ASI04',
      maestroLayer: 'L7',
      nistCategory: 'poisoning',
    });

    if (skillDirs.length === 0) {
      return extendedFindings;
    }

    // SC-SKILL-002~005: Check each skill for dangerous patterns
    const dangerousPatterns = [
      { regex: /child_process|exec\(|spawn\(|shell\s*:\s*true/, name: 'Child process execution' },
      { regex: /eval\(|Function\(|compile\(/, name: 'Dynamic code execution' },
      { regex: /require\s*\(\s*['"].*\W.*['"]/, name: 'Dynamic module loading' },
      { regex: /fs\.(writeFile|unlinkSync|rmSync|unlink|rm)\s*\(/, name: 'Unsafe file operations' },
      { regex: /process\.(exit|kill)|process\.argv/, name: 'Process manipulation' },
    ];

    for (const skillName of skillDirs) {
      const skillPath = path.join(skillDir, skillName);
      
      try {
        // SC-SKILL-002: Check skill.json for dangerous patterns
        const skillJsonPath = path.join(skillPath, 'skill.json');
        if (await fileExists(skillJsonPath)) {
          try {
            const skillJson = await readJsonIfExists(skillJsonPath);
            const executeScript = skillJson?.scripts?.execute || skillJson?.execute || '';

            for (const { regex, name } of dangerousPatterns) {
              if (regex.test(executeScript)) {
                extendedFindings.push({
                  id: 'SC-SKILL-002',
                  severity: 'HIGH',
                  category: 'supply-chain',
                  title: `Dangerous pattern in skill "${skillName}": ${name}`,
                  description: `Skill contains potentially dangerous pattern that could allow code execution.`,
                  evidence: `Skill: ${skillName}, Pattern: ${name}`,
                  remediation: 'Review skill code carefully. Consider sandboxing skill execution.',
                  autoFixable: false,
                  threat: 'arbitrary-code-execution',
                  references: [],
                  owaspAsi: 'ASI04',
                  maestroLayer: 'L3',
                  nistCategory: 'poisoning',
                });
                break;
              }
            }
          } catch (err) {
            // skill.json parse error
          }
        }

        // SC-SKILL-003~004: Check for skillmetadata and prerequisites
        const packageJsonPath = path.join(skillPath, 'package.json');
        if (await fileExists(packageJsonPath)) {
          try {
            const packageJson = await readJsonIfExists(packageJsonPath);
            
            // SC-SKILL-003: Check for required fields
            if (!packageJson.name || !packageJson.version) {
              extendedFindings.push({
                id: 'SC-SKILL-003',
                severity: 'LOW',
                category: 'supply-chain',
                title: `Skill "${skillName}" missing package metadata`,
                description: 'Skill package.json is missing name or version fields.',
                evidence: `Skill: ${skillName}`,
                remediation: 'Add name and version fields to skill package.json',
                autoFixable: false,
                threat: 'metadata-inconsistency',
                references: [],
                owaspAsi: 'ASI04',
                maestroLayer: 'L7',
                nistCategory: 'poisoning',
              });
            }

            // SC-SKILL-004: Check if dependencies are pinned (security best practice)
            const deps = packageJson.dependencies || {};
            const hasFlexibleVersions = Object.values(deps).some(v => 
              typeof v === 'string' && (v.includes('^') || v.includes('~') || v === '*' || v === 'latest')
            );
            
            if (hasFlexibleVersions) {
              extendedFindings.push({
                id: 'SC-SKILL-004',
                severity: 'LOW',
                category: 'supply-chain',
                title: `Skill "${skillName}" uses flexible dependency versions`,
                description: 'Dependencies use flexible version specifiers (^ or ~) instead of fixed pinned versions.',
                evidence: `Skill: ${skillName}`,
                remediation: 'Pin all dependencies to exact versions for reproducibility',
                autoFixable: false,
                threat: 'supply-chain-mutation',
                references: [],
                owaspAsi: 'ASI04',
                maestroLayer: 'L7',
                nistCategory: 'poisoning',
              });
            }

            // SC-SKILL-005: Check for dangerous prerequisites
            const prerequisites = skillJson?.prerequisites || [];
            for (const prereq of prerequisites) {
              if (typeof prereq === 'string' && (prereq.includes('sudo') || prereq.includes('root'))) {
                extendedFindings.push({
                  id: 'SC-SKILL-005',
                  severity: 'MEDIUM',
                  category: 'supply-chain',
                  title: `Skill "${skillName}" requires elevated privileges`,
                  description: 'Skill prerequisites include sudo or root commands.',
                  evidence: `Skill: ${skillName}, Prerequisite: ${prereq}`,
                  remediation: 'Review whether elevated privilege is truly necessary',
                  autoFixable: false,
                  threat: 'privilege-escalation',
                  references: [],
                  owaspAsi: 'ASI05',
                  maestroLayer: 'L3',
                  nistCategory: 'poisoning',
                });
              }
            }
          } catch (err) {
            // package.json parse error
          }
        }

        // SC-SKILL-006: Check for dangerous prerequisites in skill.json metadata
        try {
          const skillJsonPath = path.join(skillPath, 'skill.json');
          if (await fileExists(skillJsonPath)) {
            const skillJson = await readJsonIfExists(skillJsonPath);
            const prerequisites = skillJson?.prerequisites || [];
            
            const dangerousPrereqs = prerequisites.filter(p => 
              typeof p === 'string' && (
                p.includes('curl') || p.includes('wget') || 
                p.includes('sh -c') || p.includes('bash -c') ||
                p.includes('eval') || p.includes('source')
              )
            );

            if (dangerousPrereqs.length > 0) {
              extendedFindings.push({
                id: 'SC-SKILL-006',
                severity: 'HIGH',
                category: 'supply-chain',
                title: `Skill "${skillName}" has dangerous prerequisites`,
                description: `Skill prerequisites contain remote code execution patterns: ${dangerousPrereqs.join(', ')}`,
                evidence: `Skill: ${skillName}`,
                remediation: 'Avoid installing skills with curl|bash patterns. Review source code before installation.',
                autoFixable: false,
                threat: 'supply-chain-injection',
                references: [],
                owaspAsi: 'ASI04',
                maestroLayer: 'L3',
                nistCategory: 'poisoning',
              });
            }
          }
        } catch (err) {
          // skill.json operations
        }

      } catch (err) {
        console.debug(`Error scanning skill ${skillName}:`, err.message);
      }
    }

  } catch (err) {
    console.debug('Could not perform supply chain audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// IOC (Indicators of Compromise) & Threat Intelligence Checks
// ============================================================
async function auditIOCExtended(context) {
  const extendedFindings = [];

  try {
    // IOC-001: Check for known C2 server connections
    // (Simplified: check for obvious C2 patterns in logs if available)
    const connectionLogs = context.connectionLogs || [];
    const suspiciousIPs = [];
    const c2Patterns = [
      /\b(127\.0\.0\.1|192\.168\.|10\.0\.)\b/,  // Placeholder: normally would check against IOC database
      /malicious\-.*\.net|c2\-|botnet\-/i       // Simple pattern matching
    ];

    for (const log of connectionLogs) {
      for (const pattern of c2Patterns) {
        if (pattern.test(log) && !log.includes('127.0.0.1')) {
          suspiciousIPs.push(log);
        }
      }
    }

    if (suspiciousIPs.length > 0) {
      extendedFindings.push({
        id: 'SC-IOC-001',
        severity: 'CRITICAL',
        category: 'ioc',
        title: 'Suspicious outbound connections detected',
        description: `Found ${suspiciousIPs.length} suspicious connection pattern(s) in logs. May indicate C2 activity.`,
        evidence: `Suspicious connections: ${suspiciousIPs.slice(0, 3).join('; ')}`,
        remediation: 'Investigate these connections immediately and block if malicious',
        autoFixable: false,
        threat: 'command-and-control',
        references: [],
        owaspAsi: 'ASI10',
        maestroLayer: 'L6',
        nistCategory: 'evasion',
      });
    }

    // IOC-002: Check for known malicious domains in skill sources
    const skillDir = context.skillDir || (context.stateDir ? path.join(context.stateDir, 'skills') : null);
    const maliciousDomains = [
      'bit.ly', '*.short', 'tinyurl', 'github-malicious', 'raw-githubusercontent-evil'
    ];

    if (skillDir && await fileExists(skillDir)) {
      try {
        const skillDirs = await fs.readdir(skillDir);
        for (const skillName of skillDirs) {
          const skillPath = path.join(skillDir, skillName);
          const stats = await fs.stat(skillPath);
          if (stats.isDirectory()) {
            // Quick scan for URLs in skill files
            try {
              const files = await fs.readdir(skillPath);
              for (const file of files.slice(0, 5)) { // Limit to first 5 files
                if (file.endsWith('.json') || file.endsWith('.md')) {
                  const filePath = path.join(skillPath, file);
                  const content = await fs.readFile(filePath, 'utf8').catch(() => '');
                  for (const domain of maliciousDomains) {
                    if (content.includes(domain)) {
                      extendedFindings.push({
                        id: 'SC-IOC-002',
                        severity: 'HIGH',
                        category: 'ioc',
                        title: `Suspicious domain reference in skill "${skillName}"`,
                        description: `Skill contains reference to potentially malicious domain: ${domain}`,
                        evidence: `Skill: ${skillName}, File: ${file}, Domain: ${domain}`,
                        remediation: 'Review and remove the suspicious domain reference or uninstall skill',
                        autoFixable: false,
                        threat: 'supply-chain',
                        references: [],
                        owaspAsi: 'ASI04',
                        maestroLayer: 'L7',
                        nistCategory: 'poisoning',
                      });
                    }
                  }
                }
              }
            } catch (err) {
              // Skill directory scan failed, continue
            }
          }
        }
      } catch (err) {
        // Skill directory read failed
      }
    }

    // IOC-003: Check for known hash patterns (simplified)
    // In production, would compare against a real IOC database
    extendedFindings.push({
      id: 'SC-IOC-003',
      severity: 'INFO',
      category: 'ioc',
      title: 'IOC database check (requires deep scan)',
      description: 'Full IOC hash database verification requires --deep flag and external IOC resources',
      evidence: 'Not available without IOC database subscription',
      remediation: 'Enable deep scan mode for comprehensive threat intelligence',
      autoFixable: false,
      references: [],
      owaspAsi: 'ASI04',
      maestroLayer: 'L6',
      nistCategory: 'poisoning',
    });

    // IOC-004: Check for macOS infostealer artifacts
    if (IS_MACOS) {
      const macArtifacts = [
        path.join(os.homedir(), 'Library/Caches/.mos'),
        path.join(os.homedir(), 'Library/Application Support/.amos'),
        path.join(os.homedir(), '.cache/amos'),
      ];

      for (const artifactPath of macArtifacts) {
        if (await fileExists(artifactPath)) {
          extendedFindings.push({
            id: 'SC-IOC-004',
            severity: 'CRITICAL',
            category: 'ioc',
            title: 'Potential macOS infostealer artifact detected',
            description: `Found suspicious file/directory matching known AMOS infostealer pattern: ${path.basename(artifactPath)}`,
            evidence: `Path: ${artifactPath}`,
            remediation: 'Run full system malware scan immediately. Consider system reset if compromised.',
            autoFixable: false,
            threat: 'infostealer',
            references: ['AMOS', 'Atomic Stealer'],
            owaspAsi: 'ASI10',
            maestroLayer: 'L4',
            nistCategory: 'privacy',
          });
        }
      }
    }

    // IOC-005: Check for Linux infostealer artifacts
    if (IS_LINUX) {
      const linuxArtifacts = [
        path.join(os.homedir(), '.cache/.redline'),
        path.join(os.homedir(), '.local/share/.lumma'),
        path.join(os.homedir(), '.config/.vidar'),
      ];

      for (const artifactPath of linuxArtifacts) {
        if (await fileExists(artifactPath)) {
          extendedFindings.push({
            id: 'SC-IOC-005',
            severity: 'CRITICAL',
            category: 'ioc',
            title: 'Potential Linux infostealer artifact detected',
            description: `Found suspicious file/directory matching known infostealer pattern (Redline/Lumma/Vidar): ${path.basename(artifactPath)}`,
            evidence: `Path: ${artifactPath}`,
            remediation: 'Run full system malware scan immediately. Consider system reset if compromised.',
            autoFixable: false,
            threat: 'infostealer',
            references: ['Redline', 'Lumma', 'Vidar'],
            owaspAsi: 'ASI10',
            maestroLayer: 'L4',
            nistCategory: 'privacy',
          });
        }
      }
    }

  } catch (err) {
    console.debug('Could not perform IOC audit:', err.message);
  }

  return extendedFindings;
}

// ============================================================
// Integration point: Create audit context (backward compatible)\n// ============================================================

export async function createAuditContext(stateDir, pluginConfig = {}) {
  const configPath = getConfigPath(stateDir);
  const config = await readJsonIfExists(configPath);
  const skillDir = getSkillInstallPath(stateDir);
  return {
    stateDir,
    configPath,
    soulPath: getSoulPath(stateDir),
    skillDir,
    skillInstalled: await fileExists(skillDir),
    config,
    strictMode: Boolean(pluginConfig.strictMode)
  };
}

// ============================================================
// Main audit execution function (complete version - includes all cross-platform compatible checks)
// ============================================================

export async function runAuditExtended(context, options = {}) {
  const findings = [];
  
  // 1. Run existing controls
  for (const control of getControls()) {
    const outcome = await control.describe(context);
    if (!outcome) continue;
    
    const autoFixable = outcome.autoFixable ?? Boolean(control.remediate);
    const finding = {
      id: control.id,
      category: control.category,
      threat: control.threat,
      intent: control.intent,
      severity: outcome.severity ?? control.severity,
      title: control.title,
      description: outcome.description,
      evidence: outcome.evidence ?? {},
      remediation: outcome.remediation,
      autoFixable,
      canAutoFix: autoFixable,
      nextStep: buildNextStep({
        autoFixable,
        severity: outcome.severity ?? control.severity,
        remediation: outcome.remediation,
        id: control.id
      }),
      
      // Extended fields (compatible with secureclaw)
      references: outcome.references || [],
      owaspAsi: outcome.owaspAsi || '',
      maestroLayer: outcome.maestroLayer || '',
      nistCategory: outcome.nistCategory || '',
    };
    findings.push(finding);
  }

  // 2. Run extended advanced audit functions (always execute) - now includes all new features
  const extendedAudits = [
    auditGatewayExtended(context),
    auditCredentialsExtended(context),
    auditExecutionExtended(context),
    auditAccessControlExtended(context),        
    auditMemoryIntegrityExtended(context),      
    auditCostExposureExtended(context),         
    auditMultiFrameworkExtended(context),       
    auditSupplyChainExtended(context),          // Unified supply chain checks
    auditIOCExtended(context),                  // IOC & Threat Intelligence
  ];

  const [gatewayEx, credsEx, execEx, acEx, memEx, costEx, mfEx, scEx, iocEx] = await Promise.all(extendedAudits);
  findings.push(...gatewayEx, ...credsEx, ...execEx, ...acEx, ...memEx, ...costEx, ...mfEx, ...scEx, ...iocEx);

  // 3. Perform cross-layer risk detection (after all checks are complete)
  const crossLayerFindings = auditCrossLayerRisk(findings);
  findings.push(...crossLayerFindings);

  return {
    tool: PLUGIN_NAME,
    version: VERSION,
    timestamp: new Date().toISOString(),
    stateDir: context.stateDir,
    configPath: context.configPath,
    score: calculateScore(findings),
    summary: summarize(findings),
    threatSummary: summarizeThreats(findings),
    nextSteps: buildNextSteps(findings),
    findings
  };
}

// ============================================================
// Helper functions (existing report generation logic)
// ============================================================

function calculateScore(findings) {
  const deducted = findings.reduce((sum, item) => sum + (SCORE_BY_SEVERITY[item.severity] || 0), 0);
  return Math.max(0, 100 - deducted);
}

function summarize(findings) {
  return findings.reduce((summary, item) => {
    const severityKey = item.severity.toLowerCase();
    if (summary[severityKey] !== undefined) {
      summary[severityKey] += 1;
    }
    if (item.autoFixable) summary.autoFixable += 1;
    return summary;
  }, {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    autoFixable: 0
  });
}

function summarizeThreats(findings) {
  return findings.reduce((summary, item) => {
    if (item.threat) {
      summary[item.threat] = (summary[item.threat] ?? 0) + 1;
    }
    return summary;
  }, {});
}

function buildNextStep({ autoFixable, severity, remediation, id }) {
  if (autoFixable) {
    return `Can be auto-fixed. First run \`npx openclaw clawkeeper harden\`, then re-run \`npx openclaw clawkeeper audit\` to verify ${id}.`;
  }

  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return `Manual action required. Fix according to "${remediation}", then re-run \`npx openclaw clawkeeper audit\`.`;
  }

  return `After adjusting per "${remediation}", re-run \`npx openclaw clawkeeper audit\` to confirm the results.`;
}

function buildNextSteps(findings) {
  if (findings.length === 0) {
    return ['No issues found. Continue maintaining security posture and regularly run `npx openclaw clawkeeper audit`.'];
  }

  const criticalOrHigh = findings.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH');
  const autoFixable = findings.filter((item) => item.autoFixable);
  const manual = findings.filter((item) => !item.autoFixable);
  const steps = [];

  if (criticalOrHigh.length > 0) {
    steps.push(`Address high-severity items first: ${criticalOrHigh.map((item) => item.id).join(', ')}.`);
  }

  if (autoFixable.length > 0) {
    steps.push('Run `npx openclaw clawkeeper harden` for items that can be auto-fixed.');
  }

  if (manual.length > 0) {
    steps.push(`Items requiring manual fixes: ${manual.map((item) => item.id).join(', ')}.`);
  }

  steps.push('After fixes are complete, run `npx openclaw clawkeeper audit` to verify.');
  return steps;
}

