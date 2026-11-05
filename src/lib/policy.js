// Policy: one JSON file can cover every server you wrap. Top-level keys are the
// defaults; `servers.<name>` overrides them for one server. Security lists
// (`tools.deny`, `arguments`) ADD to the defaults; everything else replaces.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const HOME = process.env.MCP_GATEHOUSE_HOME || path.join(os.homedir(), ".mcp-gatehouse");

export const DEFAULTS = Object.freeze({
  mode: "enforce", // enforce | monitor (monitor logs what it WOULD do and changes nothing)
  tools: { allow: ["*"], deny: [] },
  arguments: [], // [{ tool: "glob", deny_pattern: "regex", flags: "i", reason: "..." }]
  secrets: {
    output: "redact", // redact | block | warn | off   (secrets coming back from the server)
    input: "block", // block | redact | warn | off     (secrets the model sends to the server)
    exempt_tools: [], // globs: tools allowed to receive secrets in their arguments
  },
  injection: {
    output: "warn", // warn | block | off   (instruction-like text in tool results)
    descriptions: "hide", // hide | warn | off   (tool poisoning in tool definitions)
    strip_invisible: true, // remove tag / zero-width / bidi characters from what the model sees
  },
  pinning: {
    enabled: true,
    on_change: "block", // block | warn   (a pinned tool's definition changed: rug pull)
    new_tools: "warn", // allow | warn | block   (a tool appeared after the first pin)
  },
  rate_limit: { per_minute: 0, per_tool_per_minute: 0 }, // 0 = off
  max_output_chars: 0, // 0 = off; otherwise long results are cut to this many characters
  audit: { file: path.join(HOME, "audit.jsonl"), arguments: "redacted" }, // arguments: redacted | none | full
  servers: {},
});

const ENUMS = {
  mode: ["enforce", "monitor"],
  "secrets.output": ["redact", "block", "warn", "off"],
  "secrets.input": ["block", "redact", "warn", "off"],
  "injection.output": ["warn", "block", "off"],
  "injection.descriptions": ["hide", "warn", "off"],
  "pinning.on_change": ["block", "warn"],
  "pinning.new_tools": ["allow", "warn", "block"],
  "audit.arguments": ["redacted", "none", "full"],
};

const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

function merge(base, over, pathParts = []) {
  const out = { ...base };
  for (const [k, v] of Object.entries(over || {})) {
    const key = [...pathParts, k].join(".");
    if (key === "servers") continue;
    if (isObj(v) && isObj(base[k])) out[k] = merge(base[k], v, [...pathParts, k]);
    else if (Array.isArray(v) && (key === "tools.deny" || key === "arguments") && Array.isArray(base[k])) out[k] = [...base[k], ...v];
    else out[k] = v;
  }
  return out;
}

export function expandHome(p) {
  return typeof p === "string" && p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

/** Find the policy file: explicit path, then $MCP_GATEHOUSE_POLICY, then ~/.mcp-gatehouse/policy.json. */
export function locatePolicy(explicit) {
  if (explicit) return expandHome(explicit);
  if (process.env.MCP_GATEHOUSE_POLICY) return expandHome(process.env.MCP_GATEHOUSE_POLICY);
  const fallback = path.join(HOME, "policy.json");
  return fs.existsSync(fallback) ? fallback : null;
}

/** Load and validate the effective policy for one server. Throws with a readable message on bad input. */
export function loadPolicy(file, serverName) {
  let raw = {};
  if (file) {
    try {
      raw = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
      throw new Error(`policy ${file}: ${e.code === "ENOENT" ? "file not found" : e.message}`);
    }
    if (!isObj(raw)) throw new Error(`policy ${file}: top level must be a JSON object`);
  }
  let p = merge(DEFAULTS, raw);
  const perServer = raw.servers && serverName ? raw.servers[serverName] : null;
  if (perServer) p = merge(p, perServer);
  p.audit = { ...p.audit, file: expandHome(p.audit.file) };
  return compile(p, file || "(built-in defaults)");
}

function get(obj, dotted) {
  return dotted.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
}

function compile(p, source) {
  const errors = [];
  for (const [key, allowed] of Object.entries(ENUMS)) {
    const v = get(p, key);
    if (!allowed.includes(v)) errors.push(`${key} is "${v}"; expected one of ${allowed.join(", ")}`);
  }
  for (const key of ["tools.allow", "tools.deny", "secrets.exempt_tools"]) {
    const v = get(p, key);
    if (!Array.isArray(v) || v.some((g) => typeof g !== "string")) errors.push(`${key} must be a list of glob strings`);
  }
  const rules = [];
  (Array.isArray(p.arguments) ? p.arguments : []).forEach((r, i) => {
    if (!isObj(r) || typeof r.deny_pattern !== "string") {
      errors.push(`arguments[${i}] needs a "deny_pattern" string`);
      return;
    }
    try {
      rules.push({ tool: globRe(r.tool || "*"), re: new RegExp(r.deny_pattern, r.flags || ""), reason: r.reason || `matched ${r.deny_pattern}`, source: r });
    } catch (e) {
      errors.push(`arguments[${i}].deny_pattern: ${e.message}`);
    }
  });
  if (errors.length) throw new Error(`policy ${source}:\n  - ${errors.join("\n  - ")}`);
  return {
    ...p,
    source,
    _allow: p.tools.allow.map(globRe),
    _deny: p.tools.deny.map(globRe),
    _exempt: p.secrets.exempt_tools.map(globRe),
    _argRules: rules,
  };
}

/** "*" = any run of characters, "?" = one character. Anchored, case-sensitive (tool names are). */
export function globRe(glob) {
  const body = String(glob).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${body}$`);
}

export const anyMatch = (res, name) => res.some((re) => re.test(name));

/** A starter policy with every knob present, for `mcp-gatehouse init`. */
export function starterPolicy() {
  return {
    mode: "enforce",
    tools: { allow: ["*"], deny: ["*delete*", "*drop*", "*destroy*"] },
    arguments: [
      { tool: "*", deny_pattern: "\\brm\\s+-[a-z]*(r[a-z]*f|f[a-z]*r)", flags: "i", reason: "recursive force delete" },
      { tool: "*", deny_pattern: "(^|/)\\.ssh/|id_rsa|id_ed25519|/etc/shadow", flags: "i", reason: "credential file path" },
    ],
    secrets: { output: "redact", input: "block", exempt_tools: [] },
    injection: { output: "warn", descriptions: "hide", strip_invisible: true },
    pinning: { enabled: true, on_change: "block", new_tools: "warn" },
    rate_limit: { per_minute: 120, per_tool_per_minute: 0 },
    max_output_chars: 200000,
    audit: { file: "~/.mcp-gatehouse/audit.jsonl", arguments: "redacted" },
    servers: {
      filesystem: { tools: { deny: ["write_file", "move_file"] } },
      vault: { secrets: { exempt_tools: ["write_secret"] } },
    },
  };
}
