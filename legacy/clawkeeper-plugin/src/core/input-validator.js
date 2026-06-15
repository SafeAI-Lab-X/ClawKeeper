/**
 * Clawkeeper Input Validator (v1.1 feature: Structured Input Validation)
 *
 * Lightweight, zero-dependency JSON-Schema-subset validator that runs
 * before path-guard / exec-gate inside the before_tool_call hook. The
 * goal is to reject obviously malformed tool inputs (missing required
 * fields, wrong type, oversize strings, NUL bytes, etc.) at the
 * interface boundary, so the heavier semantic gates downstream get a
 * cleaner stream and the agent's bad params don't reach tool runtimes.
 *
 * Supported keywords (only what we actually need):
 *   type            string | number | boolean | object | array
 *   required        string[]
 *   properties      { [k]: schema }
 *   additionalProperties  boolean (default: true)
 *   minLength       number  (string)
 *   maxLength       number  (string)
 *   pattern         string  (regex source, applied to strings)
 *   enum            any[]
 *
 * Schemas live in src/config/tool-schemas/*.json. Each schema declares
 * its primary `tool` name and optional `aliases`. Unknown tools are
 * passed through (configurable).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_PATH = path.join(__dirname, '..', 'config', 'core-rules.json');
const DEFAULT_SCHEMA_DIR = path.join(__dirname, '..', 'config', 'tool-schemas');

let cached = null;
const DEFAULT_FAILURE_POLICY = 'fail-open';

/** Load schemas + config; cached on first call. */
export function loadValidator(rulesPath = DEFAULT_RULES_PATH, schemaDir = DEFAULT_SCHEMA_DIR) {
  if (cached && cached._rules === rulesPath && cached._dir === schemaDir) return cached;

  let cfg = {};
  try {
    const raw = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
    cfg = raw.inputValidator || {};
  } catch {
    cfg = {};
  }

  const schemas = new Map();
  try {
    const files = fs.readdirSync(schemaDir).filter((f) => f.endsWith('.json'));
    for (const f of files) {
      try {
        const schema = JSON.parse(fs.readFileSync(path.join(schemaDir, f), 'utf-8'));
        const names = [schema.tool, ...(schema.aliases || [])].filter(Boolean);
        for (const n of names) schemas.set(String(n).toLowerCase(), schema);
      } catch (err) {
        // Bad schema file: skip but don't crash the plugin.
        console.error('[Clawkeeper] Failed to load tool schema:', f, err.message);
      }
    }
  } catch {
    // Schema dir missing — pass-through mode for everything.
  }

  cached = {
    schemas,
    config: {
      enabled: cfg.enabled !== false,
      failurePolicy: cfg.failurePolicy || 'fail-open',
      unknownToolPolicy: cfg.unknownToolPolicy || 'pass',
    },
    _rules: rulesPath,
    _dir: schemaDir,
  };
  return cached;
}

/** Force cache invalidation (primarily for tests). */
export function resetValidatorCache() { cached = null; }

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

/** Core schema check. Returns array of error strings. */
function checkSchema(schema, value, where = '$') {
  const errors = [];
  if (!schema || typeof schema !== 'object') return errors;

  const expected = schema.type;
  const actual = typeOf(value);
  if (expected) {
    const ok =
      (expected === 'number' && actual === 'number') ||
      (expected === 'string' && actual === 'string') ||
      (expected === 'boolean' && actual === 'boolean') ||
      (expected === 'object' && actual === 'object') ||
      (expected === 'array' && actual === 'array');
    if (!ok) {
      errors.push(`${where}: expected ${expected}, got ${actual}`);
      return errors;
    }
  }

  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${where}: value not in enum`);
  }

  if (actual === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) {
      errors.push(`${where}: string shorter than minLength=${schema.minLength}`);
    }
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) {
      errors.push(`${where}: string longer than maxLength=${schema.maxLength} (got ${value.length})`);
    }
    if (schema.pattern) {
      try {
        const re = new RegExp(schema.pattern);
        if (!re.test(value)) errors.push(`${where}: string does not match pattern`);
      } catch {
        // bad regex in schema — ignore
      }
    }
  }

  if (actual === 'object') {
    if (Array.isArray(schema.required)) {
      for (const k of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, k) || value[k] == null || value[k] === '') {
          errors.push(`${where}.${k}: required field missing`);
        }
      }
    }
    const props = schema.properties || {};
    const allowExtra = schema.additionalProperties !== false;
    for (const [k, v] of Object.entries(value)) {
      if (props[k]) {
        errors.push(...checkSchema(props[k], v, `${where}.${k}`));
      } else if (!allowExtra) {
        errors.push(`${where}.${k}: unknown property`);
      }
    }
  }

  return errors;
}

/**
 * Main entry: validate a tool call's params against its schema.
 *
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 * @returns {{ block: boolean, reason?: string, errors?: string[], unknownTool?: boolean }}
 */
export function validateToolInput(toolName, params) {
  let loaded;
  try {
    loaded = loadValidator();
  } catch (err) {
    const policy = cached?.config?.failurePolicy || DEFAULT_FAILURE_POLICY;
    if (policy === 'fail-closed') {
      return { block: true, error: err.message, reason: 'input-validator load failed (fail-closed policy)' };
    }
    return { block: false, error: err.message };
  }
  const { schemas, config } = loaded;
  if (!config.enabled) return { block: false };

  const key = String(toolName || '').toLowerCase();
  const schema = schemas.get(key);
  if (!schema) {
    if (config.unknownToolPolicy === 'block') {
      return { block: true, unknownTool: true, reason: `no schema registered for tool '${toolName}'` };
    }
    return { block: false, unknownTool: true };
  }

  const errors = checkSchema(schema, params || {});
  if (errors.length > 0) {
    return {
      block: true,
      reason: `input validation failed: ${errors[0]}`,
      errors,
    };
  }
  return { block: false };
}
