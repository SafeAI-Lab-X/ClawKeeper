const DEFAULT_THRESHOLD = 0.4;

export const VERB_CATEGORIES = {
  create: [
    "write",
    "create",
    "build",
    "generate",
    "make",
    "add",
    "implement",
    "develop",
    "scaffold",
    "写",
    "创建",
  ],
  read: [
    "read",
    "show",
    "display",
    "list",
    "find",
    "search",
    "look",
    "check",
    "view",
    "get",
    "print",
    "读取",
    "查看",
  ],
  modify: [
    "edit",
    "update",
    "change",
    "modify",
    "refactor",
    "rename",
    "replace",
    "fix",
    "patch",
    "修改",
    "编辑",
  ],
  delete: ["delete", "remove", "drop", "clean", "purge", "clear", "uninstall", "删除"],
  execute: [
    "run",
    "execute",
    "start",
    "launch",
    "deploy",
    "install",
    "test",
    "debug",
    "compile",
    "运行",
    "执行",
  ],
  network: [
    "download",
    "upload",
    "fetch",
    "curl",
    "request",
    "send",
    "post",
    "push",
    "pull",
    "clone",
  ],
  analyze: [
    "analyze",
    "explain",
    "summarize",
    "review",
    "compare",
    "audit",
    "inspect",
    "diagnose",
    "help",
    "分析",
    "帮我",
  ],
};

export const STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "for",
  "from",
  "i",
  "in",
  "into",
  "is",
  "it",
  "me",
  "my",
  "of",
  "on",
  "or",
  "please",
  "the",
  "this",
  "to",
  "with",
  "一下",
  "这个",
  "那个",
  "请",
  "把",
  "并",
  "然后",
  "一个",
  "现在",
  "需要",
  "想要",
  "帮",
  "我",
  "你",
  "他",
]);

export const SENSITIVE_TOPIC_PATTERNS = [
  {
    id: "ssh_keys",
    label: "SSH keys",
    pattern: /(?:^|\/)\.ssh\/|id_rsa|id_ed25519|authorized_keys/i,
  },
  {
    id: "cloud_creds",
    label: "Cloud credentials",
    pattern: /(?:^|\/)\.aws\/|credentials|(?:^|\/)\.env(?:\.|$)?/i,
  },
  {
    id: "system_creds",
    label: "System credentials",
    pattern: /\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers/i,
  },
  { id: "crypto_keys", label: "Crypto keys", pattern: /(?:^|\/)\.gnupg|private_key/i },
  {
    id: "exfiltration",
    label: "Exfiltration primitives",
    pattern: /curl\|bash|nc\s+-l|reverse shell/i,
  },
  { id: "priv_esc", label: "Privilege escalation", pattern: /\bsudo\b|chmod\s+777|chown\s+root/i },
  {
    id: "persistence",
    label: "Persistence locations",
    pattern: /\bcrontab\b|(?:^|\/)\.bashrc|(?:^|\/)\.zshrc|git hooks/i,
  },
];

const PATH_RE = /(?:^|[\s(])((?:~|\.{1,2}|\/)[^\s"'`<>|)]+)/g;
const QUOTED_RE = /"([^"\n]{2,})"|'([^'\n]{2,})'|`([^`\n]{2,})`/g;
const LATIN_TOKEN_RE = /[a-zA-Z][a-zA-Z0-9_.-]{1,}/g;
const CJK_TOKEN_RE = /[\u4e00-\u9fff]{2,}/g;

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function normalizeText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function lower(value) {
  return normalizeText(value).toLowerCase();
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].toSorted((a, b) => a.localeCompare(b));
}

function matchesTerm(text, term) {
  if (!text || !term) {
    return false;
  }
  if (/[\u4e00-\u9fff]/.test(term)) {
    return text.includes(term);
  }
  return new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(text);
}

function extractPathsFromText(text) {
  const paths = [];
  const source = normalizeText(text);
  for (const match of source.matchAll(PATH_RE)) {
    const path = match[1]?.trim();
    if (path) {
      paths.push(path);
    }
  }
  return uniqueSorted(paths);
}

function extractQuotedStrings(text) {
  const values = [];
  const source = normalizeText(text);
  for (const match of source.matchAll(QUOTED_RE)) {
    const value = normalizeText(match[1] || match[2] || match[3]);
    if (value.length >= 2) {
      values.push(value);
    }
  }
  return uniqueSorted(values);
}

function tokenizeText(text) {
  const tokens = [];
  const source = normalizeText(text);
  for (const match of source.matchAll(LATIN_TOKEN_RE)) {
    tokens.push(match[0].toLowerCase());
  }
  for (const match of source.matchAll(CJK_TOKEN_RE)) {
    tokens.push(match[0]);
  }
  return tokens;
}

function extractVerbMatches(text) {
  const source = normalizeText(text);
  const verbs = [];
  const verbCategories = [];

  for (const [category, terms] of Object.entries(VERB_CATEGORIES)) {
    for (const term of terms) {
      if (matchesTerm(source, term)) {
        verbs.push(term);
        verbCategories.push(category);
      }
    }
  }

  return {
    verbs: uniqueSorted(verbs),
    verbCategories: uniqueSorted(verbCategories),
  };
}

function extractTopicsFromText(text, options = {}) {
  const source = normalizeText(text);
  if (!source) {
    return [];
  }

  const quotedStrings = options.includeQuoted === false ? [] : extractQuotedStrings(source);
  const quotedTokens = quotedStrings.map((value) => lower(value)).filter(Boolean);
  const pathTokens = new Set(extractPathsFromText(source).map((value) => lower(value)));
  const verbTokens = new Set(
    Object.values(VERB_CATEGORIES)
      .flat()
      .map((value) => lower(value))
      .filter(Boolean),
  );

  const tokens = tokenizeText(source).filter((token) => {
    if (token.length < 2) {
      return false;
    }
    if (STOPWORDS.has(token)) {
      return false;
    }
    if (verbTokens.has(token)) {
      return false;
    }
    if (pathTokens.has(token)) {
      return false;
    }
    return true;
  });

  return uniqueSorted([...quotedTokens, ...tokens]);
}

function mapToolNameToCategories(toolName) {
  const name = lower(toolName);
  if (!name) {
    return [];
  }

  const categories = [];
  if (/(read|grep|glob|find|search|open|cat|list|view)/.test(name)) {
    categories.push("read");
  }
  if (/(write|edit|replace|patch|update|rename)/.test(name)) {
    categories.push("modify");
  }
  if (/(create|scaffold|generate)/.test(name)) {
    categories.push("create");
  }
  if (/(delete|remove|rm|unlink|purge)/.test(name)) {
    categories.push("delete");
  }
  if (/(bash|exec|shell|run|test|debug|compile)/.test(name)) {
    categories.push("execute");
  }
  if (/(curl|request|fetch|download|upload|clone|post|push|pull)/.test(name)) {
    categories.push("network");
  }
  if (/(review|analy|audit|inspect|explain)/.test(name)) {
    categories.push("analyze");
  }

  return uniqueSorted(categories);
}

export function extractIntent(messages) {
  const list = Array.isArray(messages) ? messages : [];
  const seedMessage = list.find(
    (message) => message?.role === "user" && normalizeText(message.content),
  );
  const rawIntent = normalizeText(seedMessage?.content);

  if (rawIntent.length < 3) {
    return null;
  }

  const { verbs, verbCategories } = extractVerbMatches(rawIntent);
  return {
    verbs,
    verbCategories,
    topics: extractTopicsFromText(rawIntent),
    paths: extractPathsFromText(rawIntent),
    quotedStrings: extractQuotedStrings(rawIntent),
    rawIntent,
  };
}

export function summarizeToolChain(messages) {
  const list = Array.isArray(messages) ? messages : [];
  const tools = [];
  const allPaths = [];
  const allTopics = [];
  const allVerbCategories = [];
  const fullTextParts = [];

  for (const message of list) {
    if (!isRecord(message)) {
      continue;
    }
    const toolName = normalizeText(message.toolName || message.name).toLowerCase();
    if (!toolName) {
      continue;
    }

    const textParts = [
      normalizeText(message.content),
      normalizeText(message.raw),
      normalizeText(message.result),
      normalizeText(message.error),
    ].filter(Boolean);
    const combinedText = textParts.join("\n");
    const paths = extractPathsFromText(combinedText);
    const topics = extractTopicsFromText(combinedText);
    const verbCategories = mapToolNameToCategories(toolName);

    tools.push({
      toolName,
      paths,
      topics,
      verbCategories,
    });
    allPaths.push(...paths);
    allTopics.push(...topics);
    allVerbCategories.push(...verbCategories);
    fullTextParts.push(toolName, combinedText);
  }

  return {
    tools,
    paths: uniqueSorted(allPaths),
    topics: uniqueSorted(allTopics),
    verbCategories: uniqueSorted(allVerbCategories),
    fullText: fullTextParts.filter(Boolean).join("\n"),
  };
}

function computeTopicDivergence(intentTopics, toolTopics) {
  const intentSet = new Set(intentTopics);
  const toolSet = new Set(toolTopics);
  if (intentSet.size === 0) {
    return { overlap: 0, divergence: toolSet.size > 0 ? 1 : 0, intersection: [] };
  }

  const intersection = [...intentSet].filter((topic) => toolSet.has(topic));
  const overlap = intersection.length / Math.max(intentSet.size, 1);
  return {
    overlap,
    divergence: 1 - overlap,
    intersection,
  };
}

function computeVerbMismatch(intentCategories, observedCategories) {
  const intentSet = new Set(intentCategories);
  const observedSet = new Set(observedCategories);
  if (intentSet.size === 0 || observedSet.size === 0) {
    return { mismatch: 0, matched: [], unexpected: [] };
  }

  const matched = [...observedSet].filter((category) => intentSet.has(category));
  const unexpected = [...observedSet].filter((category) => !intentSet.has(category));
  if (matched.length > 0) {
    return {
      mismatch: unexpected.length / observedSet.size,
      matched,
      unexpected,
    };
  }

  return {
    mismatch: 1,
    matched: [],
    unexpected,
  };
}

function detectSensitiveHits(toolChain) {
  const searchable = [toolChain.fullText, ...toolChain.paths, ...toolChain.topics].join("\n");
  return SENSITIVE_TOPIC_PATTERNS.filter((entry) => entry.pattern.test(searchable)).map(
    (entry) => ({
      id: entry.id,
      label: entry.label,
    }),
  );
}

export function scoreToDriftSeverity(score) {
  if (score >= 0.8) {
    return "critical";
  }
  if (score >= 0.6) {
    return "high";
  }
  if (score >= 0.4) {
    return "medium";
  }
  return "low";
}

export function detectDrift(intent, toolChain, options = {}) {
  const threshold = Math.max(0, Math.min(1, Number(options.threshold ?? DEFAULT_THRESHOLD)));
  const topic = computeTopicDivergence(intent?.topics ?? [], toolChain?.topics ?? []);
  const verb = computeVerbMismatch(intent?.verbCategories ?? [], toolChain?.verbCategories ?? []);
  const sensitiveHits = detectSensitiveHits(toolChain ?? {});
  const sensitiveScore = Math.min(1, sensitiveHits.length / 2);
  const score = Math.min(1, 0.3 * topic.divergence + 0.3 * verb.mismatch + 0.4 * sensitiveScore);
  const severity = scoreToDriftSeverity(score);
  const detected = score >= threshold;

  return {
    detected,
    score,
    threshold,
    severity,
    intent: {
      rawIntent: intent?.rawIntent ?? "",
      verbCategories: uniqueSorted(intent?.verbCategories ?? []),
      topics: uniqueSorted(intent?.topics ?? []),
      paths: uniqueSorted(intent?.paths ?? []),
    },
    toolChain: {
      toolCount: Array.isArray(toolChain?.tools) ? toolChain.tools.length : 0,
      toolNames: uniqueSorted((toolChain?.tools ?? []).map((tool) => tool.toolName)),
      verbCategories: uniqueSorted(toolChain?.verbCategories ?? []),
      topics: uniqueSorted(toolChain?.topics ?? []),
      paths: uniqueSorted(toolChain?.paths ?? []),
    },
    signals: {
      topicDivergence: topic.divergence,
      topicOverlap: topic.overlap,
      sharedTopics: uniqueSorted(topic.intersection),
      verbMismatch: verb.mismatch,
      matchedVerbCategories: uniqueSorted(verb.matched),
      unexpectedVerbCategories: uniqueSorted(verb.unexpected),
      sensitiveScore,
    },
    sensitiveHits,
    warning: detected
      ? `Current tool chain appears semantically drifted from the user's original intent (score=${score.toFixed(2)}, severity=${severity}).`
      : null,
  };
}

export function resolveIntentDrift({ body, config = {} }) {
  const driftConfig = isRecord(config.intentDrift) ? config.intentDrift : {};
  if (!driftConfig.enabled) {
    return null;
  }

  const messages = body?.forwardedContext?.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    return null;
  }

  const threshold = Math.max(0, Math.min(1, Number(driftConfig.threshold ?? DEFAULT_THRESHOLD)));
  const intent = extractIntent(messages);
  if (!intent) {
    return null;
  }

  const toolChain = summarizeToolChain(messages);
  if (toolChain.tools.length === 0) {
    return null;
  }

  const result = detectDrift(intent, toolChain, { threshold });
  return result.detected ? result : null;
}

export const _testExports = {
  STOPWORDS,
  SENSITIVE_TOPIC_PATTERNS,
  VERB_CATEGORIES,
  extractPathsFromText,
  extractQuotedStrings,
  extractTopicsFromText,
  scoreToDriftSeverity,
};
