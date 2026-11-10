// Detectors that run on text crossing the gate: secrets (both directions),
// prompt-injection phrasing, and invisible Unicode used to hide instructions.
// Everything is plain regex — no network, no model calls, nothing leaves the box.

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------
// `group` names the capture group that holds the secret value. When set, only
// that part is replaced, so "password: hunter22" becomes
// "password: [REDACTED:password_assignment]" and the reader still sees which
// field was there. Order matters: specific vendor formats run before the
// generic catch-alls, and each replacement token starts with "[" so later
// rules never re-match it.
const SECRET_RULES = [
  {
    id: "private_key",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  },
  { id: "aws_access_key_id", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  {
    id: "aws_secret_access_key",
    re: /((?:aws_secret_access_key|aws_secret_key|secret_access_key|SecretAccessKey)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    group: 2,
  },
  { id: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { id: "gitlab_token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: "slack_token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { id: "slack_webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g },
  { id: "discord_webhook", re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
  { id: "stripe_key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: "stripe_webhook_secret", re: /\bwhsec_[A-Za-z0-9]{24,}\b/g },
  { id: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: "openai_key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g },
  { id: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "google_oauth_secret", re: /\bGOCSPX-[A-Za-z0-9_-]{20,}/g },
  { id: "huggingface_token", re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { id: "npm_token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "twilio_key", re: /\bSK[0-9a-f]{32}\b/g },
  { id: "sendgrid_key", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
  { id: "telegram_bot_token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  // scheme://user:PASSWORD@host — keep the user and host, drop the password.
  { id: "url_credentials", re: /\b([a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,100}:)([^\s@/]{1,200})(@)/gi, group: 2 },

  // --- network device configs (Cisco IOS/NX-OS, Junos, EdgeOS/VyOS, Palo Alto) ---
  // "enable secret 9 $9$...", "username x secret 5 $1$...", "password 7 0822455D0A16"
  { id: "device_secret", re: /\b((?:enable\s+)?(?:secret|password)\s+[0-9]\s+)(\S+)/g, group: 2 },
  { id: "snmp_community", re: /\b(snmp-server\s+community\s+)(\S+)/gi, group: 2 },
  {
    id: "device_key",
    re: /\b((?:encrypted-password|plaintext-password|pre-shared-secret|pre-shared-key|key-string|ascii-text|authentication-key)\s+(?:(?:ascii|hex|local|remote|[0-9])\s+)*)("[^"\n]+"|\S+)/gi,
    group: 2,
  },
  { id: "aaa_server_key", re: /\b((?:tacacs-server|radius-server|tacacs|radius)\b[^\n]{0,80}?\bkey\s+(?:[0-9]\s+)?)(\S+)/gi, group: 2 },

  // --- generic "name = value" pairs (JSON, YAML, .env, CLI flags) ---
  {
    id: "password_assignment",
    re: /\b((?:password|passwd|pwd|passphrase|secret|client_secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|private[_-]?key|token)["']?\s*[:=]\s*["']?)((?![\[$<{])[^\s"',;}{]{6,})/gi,
    group: 2,
  },
  { id: "bearer_header", re: /\b(Authorization:\s*(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{12,})/gi, group: 2 },
];

// Values that look like an assignment but are documentation, types or templates.
const PLACEHOLDER = /^(?:string|number|integer|boolean|null|none|true|false|undefined|required|optional|redacted|example|changeme|password|your[_-].*|x{3,}.*|\*+|\.{3,}|<.*>|\$\{.*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_]+%|\{\{.*\}\})$/i;

/** True for documentation words, types and templates that only look like a value. */
export const isPlaceholder = (value) => PLACEHOLDER.test(String(value));

const token = (id) => `[REDACTED:${id}]`;

/** Redact secrets in one string. Returns { text, findings: {id: count} }. */
export function redactSecrets(text) {
  const findings = {};
  if (typeof text !== "string" || text.length < 8) return { text, findings };
  let out = text;
  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, (...m) => {
      const groups = m.slice(1, -2);
      if (rule.group) {
        const value = groups[rule.group - 1];
        if (!value || PLACEHOLDER.test(value.replace(/^"|"$/g, ""))) return m[0];
        findings[rule.id] = (findings[rule.id] || 0) + 1;
        // Rebuild the match: every group before the secret, the token, every group after.
        return groups.slice(0, rule.group - 1).join("") + token(rule.id) + groups.slice(rule.group).filter((g) => typeof g === "string").join("");
      }
      findings[rule.id] = (findings[rule.id] || 0) + 1;
      return token(rule.id);
    });
  }
  return { text: out, findings };
}

// ---------------------------------------------------------------------------
// Invisible Unicode
// ---------------------------------------------------------------------------
// Unicode "tag" characters (U+E0000–E007F) mirror ASCII one-to-one and render as
// nothing, which makes them the standard way to smuggle instructions past a
// human reviewer. Zero-width and bidi-override characters are the older tricks.
// U+200D (zero-width joiner) is left alone because emoji sequences need it.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const ZERO_WIDTH = /[​‌‎‏⁠-⁤﻿]/g;
const BIDI = /[‪-‮⁦-⁩]/g;

/** Decode tag-character smuggling back to readable ASCII (for the audit log). */
export function revealTagText(text) {
  let hidden = "";
  for (const ch of text.matchAll(TAG_CHARS)) {
    const cp = ch[0].codePointAt(0) - 0xe0000;
    if (cp >= 0x20 && cp < 0x7f) hidden += String.fromCharCode(cp);
  }
  return hidden;
}

/** Strip invisible characters. Returns { text, findings, hidden } where hidden is decoded tag text. */
export function stripInvisible(text) {
  const findings = {};
  if (typeof text !== "string") return { text, findings, hidden: "" };
  const hidden = revealTagText(text);
  let out = text;
  for (const [id, re] of [["tag_characters", TAG_CHARS], ["zero_width", ZERO_WIDTH], ["bidi_override", BIDI]]) {
    re.lastIndex = 0;
    const n = (out.match(re) || []).length;
    if (n) {
      findings[id] = n;
      out = out.replace(re, "");
    }
  }
  return { text: out, findings, hidden };
}

// ---------------------------------------------------------------------------
// Prompt injection / tool poisoning
// ---------------------------------------------------------------------------
// "high" rules are phrasings with almost no legitimate use inside a tool
// description or a tool result. "medium" rules are suspicious but do turn up in
// real documentation, so they only warn.
const INJECTION_RULES = [
  {
    id: "ignore_instructions", severity: "high",
    re: /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|system)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules|directions|guidelines)\b/i,
  },
  {
    id: "conceal_from_user", severity: "high",
    re: /\b(?:do not|don't|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|reveal|revealing|show|showing|notify|notifying|alert|alerting)\b[^.\n]{0,30}\buser\b/i,
  },
  {
    id: "fake_control_tag", severity: "high",
    re: /<\/?(?:important|system|instructions?|admin|override|secret)>|\[\/?(?:system|inst)\]|<\|im_start\|>|<\|(?:system|assistant)\|>/i,
  },
  {
    id: "credential_lure", severity: "high",
    re: /\b(?:read|cat|open|send|include|attach|upload|pass|provide|copy)\b[^\n]{0,60}?(?:~\/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.env\b|\.aws\/credentials|\.npmrc|\.netrc|\bmcp\.json\b|claude_desktop_config|\.claude\.json|\/etc\/shadow)/i,
  },
  {
    id: "role_reassignment", severity: "medium",
    re: /\byou are now\b|\byou are no longer\b|\bnew (?:system )?instructions?\s*:|\bfrom now on,? you (?:must|will|should)\b/i,
  },
  {
    id: "exfiltration_instruction", severity: "medium",
    re: /\b(?:send|post|upload|forward|exfiltrate|transmit|bcc)\b[^\n]{0,80}?\b(?:to|at)\b[^\n]{0,20}?(?:https?:\/\/\S+|\b[\w.+-]+@[\w-]+\.[\w.-]+)/i,
  },
];

/** Scan text for injection phrasing. Returns [{id, severity, excerpt}]. */
export function findInjection(text) {
  if (typeof text !== "string" || text.length < 10) return [];
  // Excerpts go to the audit log, so the WHOLE text is redacted before any excerpt is cut.
  // Redacting only the excerpt would leak the tail of a secret whenever the excerpt window
  // starts part-way through it: the fragment no longer matches the secret's pattern.
  const safe = redactSecrets(text).text;
  const hits = [];
  for (const rule of INJECTION_RULES) {
    const m = rule.re.exec(safe);
    if (m) hits.push({ id: rule.id, severity: rule.severity, excerpt: excerpt(safe, m.index, m[0].length) });
  }
  return hits;
}

function excerpt(text, at, len) {
  const start = Math.max(0, at - 20);
  const end = Math.min(text.length, at + len + 20);
  return (start > 0 ? "…" : "") + text.slice(start, end).replace(/\s+/g, " ") + (end < text.length ? "…" : "");
}

// ---------------------------------------------------------------------------
// Walking JSON
// ---------------------------------------------------------------------------
// Binary payloads (image/audio data, resource blobs) are base64 — scanning them
// wastes time and produces false positives, so those keys are skipped.
const SKIP_KEYS = new Set(["data", "blob", "mimeType", "_meta"]);

/** Return a copy of `value` with fn(string, key) applied to every string leaf. */
export function mapStrings(value, fn, key = "") {
  if (typeof value === "string") return SKIP_KEYS.has(key) ? value : fn(value, key);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn, key));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = SKIP_KEYS.has(k) ? v : mapStrings(v, fn, k);
    return out;
  }
  return value;
}

/** Collect every string leaf (skipping binary keys). */
export function collectStrings(value, out = [], key = "") {
  if (typeof value === "string") { if (!SKIP_KEYS.has(key)) out.push(value); }
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out, key));
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) { if (!SKIP_KEYS.has(k)) collectStrings(v, out, k); }
  return out;
}

// Structured JSON hands us {"password": "x"} as a bare "x" with the key alongside,
// so field names are checked separately from the text rules.
const SECRET_FIELDS = new Set([
  "password", "passwd", "pwd", "passphrase", "secret", "clientsecret", "apikey", "xapikey", "accesskey",
  "secretkey", "secretaccesskey", "accesstoken", "authtoken", "refreshtoken", "idtoken", "sessiontoken",
  "bearertoken", "privatekey", "token", "authorization", "credentials", "presharedkey", "psk", "community",
]);
const isSecretField = (key) => SECRET_FIELDS.has(String(key).toLowerCase().replace(/[^a-z]/g, ""));

/** Redact a string held under a secret-looking key. Returns { text, hit }. */
export function redactField(text, key) {
  if (!key || !isSecretField(key) || typeof text !== "string") return { text, hit: false };
  const v = text.trim();
  if (v.length < 6 || v.startsWith("[REDACTED") || PLACEHOLDER.test(v)) return { text, hit: false };
  return { text: token("secret_field"), hit: true };
}

export function mergeCounts(into, from) {
  for (const [k, v] of Object.entries(from)) into[k] = (into[k] || 0) + v;
  return into;
}

/**
 * Scan a whole JSON value. Options: { redact, strip }.
 * Returns { value, secrets: {id: n}, invisible: {id: n}, hidden: string, injection: [...] }.
 */
export function scanValue(value, { redact = true, strip = true } = {}) {
  const secrets = {};
  const invisible = {};
  let hidden = "";
  const injection = [];
  const seen = new Set();
  const out = mapStrings(value, (s, key) => {
    let text = s;
    const inv = stripInvisible(text);
    if (Object.keys(inv.findings).length) {
      mergeCounts(invisible, inv.findings);
      if (inv.hidden) hidden += (hidden ? " | " : "") + inv.hidden;
      if (strip) text = inv.text;
    }
    // Injection is checked on the visible text AND on anything decoded from tag characters.
    for (const hit of [...findInjection(inv.text), ...findInjection(inv.hidden)]) {
      if (!seen.has(hit.id)) { seen.add(hit.id); injection.push(hit); }
    }
    const field = redactField(text, key);
    if (field.hit) {
      mergeCounts(secrets, { secret_field: 1 });
      return redact ? field.text : text;
    }
    const red = redactSecrets(text);
    if (Object.keys(red.findings).length) {
      mergeCounts(secrets, red.findings);
      if (redact) text = red.text;
    }
    return text;
  });
  // Decoded tag text is logged and printed, so it is redacted in full before it is cut.
  const safeHidden = redactSecrets(hidden).text;
  if (invisible.tag_characters && !seen.has("hidden_tag_text")) {
    injection.push({ id: "hidden_tag_text", severity: "high", excerpt: safeHidden.slice(0, 160) || "(tag characters with no printable payload)" });
  }
  return { value: out, secrets, invisible, hidden: safeHidden, injection };
}

export const SECRET_RULE_IDS = SECRET_RULES.map((r) => r.id);
export const INJECTION_RULE_IDS = INJECTION_RULES.map((r) => r.id);
