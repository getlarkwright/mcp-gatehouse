// Where MCP clients keep their server lists, and how to read each one into the
// same shape. Used by `mcp-gatehouse audit`. Nothing here starts a server or
// touches the network: it only reads config files that already exist.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/** JSON that may carry // and /* *\/ comments and trailing commas (VS Code, Zed). */
export function parseJsonc(text) {
  const src = text.replace(/^\uFEFF/, "");
  try {
    return JSON.parse(src);
  } catch { /* fall through to the tolerant path */ }
  let out = "";
  let i = 0;
  let inStr = false;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\") { out += n ?? ""; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
    } else if (c === '"') { inStr = true; out += c; i++; }
    else if (c === "/" && n === "/") { while (i < src.length && src[i] !== "\n") i++; }
    else if (c === "/" && n === "*") { const end = src.indexOf("*/", i + 2); i = end === -1 ? src.length : end + 2; }
    else if (c === ",") {
      // A comma followed only by whitespace, comments and a closing bracket is a trailing comma.
      let j = i + 1;
      for (;;) {
        while (j < src.length && /\s/.test(src[j])) j++;
        if (src[j] === "/" && src[j + 1] === "/") { while (j < src.length && src[j] !== "\n") j++; }
        else if (src[j] === "/" && src[j + 1] === "*") { const end = src.indexOf("*/", j + 2); j = end === -1 ? src.length : end + 2; }
        else break;
      }
      if (src[j] !== "}" && src[j] !== "]") out += c;
      i++;
    } else { out += c; i++; }
  }
  return JSON.parse(out);
}

/**
 * A small TOML reader: tables, dotted and quoted keys, strings, arrays, inline
 * tables, booleans and numbers. That covers the Codex config file. Anything it
 * does not understand throws, and the audit then reports the file as unreadable
 * instead of guessing.
 */
export function parseToml(text) {
  const src = text.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  let i = 0;
  const root = {};
  let cur = root;
  const fail = (what) => {
    const line = src.slice(0, i).split("\n").length;
    throw new Error(`TOML line ${line}: ${what}`);
  };
  const ws = () => { while (src[i] === " " || src[i] === "\t") i++; };
  const skipLine = () => { while (i < src.length && src[i] !== "\n") i++; };
  const wsNl = () => {
    for (;;) {
      while (i < src.length && /\s/.test(src[i])) i++;
      if (src[i] === "#") skipLine(); else return;
    }
  };
  const ESC = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };
  const basic = () => {
    const multi = src.startsWith('"""', i);
    i += multi ? 3 : 1;
    if (multi && src[i] === "\n") i++;
    let s = "";
    for (;;) {
      if (i >= src.length) fail("string never closes");
      if (multi ? src.startsWith('"""', i) : src[i] === '"') { i += multi ? 3 : 1; return s; }
      if (!multi && src[i] === "\n") fail("string never closes");
      if (src[i] === "\\") {
        const e = src[i + 1];
        if (e === "u" || e === "U") {
          const len = e === "u" ? 4 : 8;
          s += String.fromCodePoint(parseInt(src.slice(i + 2, i + 2 + len), 16));
          i += 2 + len;
        } else if (e === "\n") { i += 2; while (/\s/.test(src[i] ?? "")) i++; }
        else if (e in ESC) { s += ESC[e]; i += 2; }
        else fail(`unknown escape \\${e}`);
      } else s += src[i++];
    }
  };
  const literal = () => {
    const multi = src.startsWith("'''", i);
    i += multi ? 3 : 1;
    if (multi && src[i] === "\n") i++;
    const end = src.indexOf(multi ? "'''" : "'", i);
    if (end === -1) fail("string never closes");
    const s = src.slice(i, end);
    i = end + (multi ? 3 : 1);
    return s;
  };
  const key = () => {
    const parts = [];
    for (;;) {
      ws();
      if (src[i] === '"') parts.push(basic());
      else if (src[i] === "'") parts.push(literal());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(src.slice(i, i + 200));
        if (!m) fail("expected a key");
        parts.push(m[0]);
        i += m[0].length;
      }
      ws();
      if (src[i] !== ".") return parts;
      i++;
    }
  };
  const put = (table, parts, v) => {
    let t = table;
    for (const p of parts.slice(0, -1)) t = t[p] && typeof t[p] === "object" ? t[p] : (t[p] = {});
    t[parts.at(-1)] = v;
  };
  const value = () => {
    ws();
    const c = src[i];
    if (c === '"') return basic();
    if (c === "'") return literal();
    if (c === "[") {
      i++;
      const arr = [];
      for (;;) {
        wsNl();
        if (src[i] === "]") { i++; return arr; }
        arr.push(value());
        wsNl();
        if (src[i] === ",") i++;
        else if (src[i] !== "]") fail("expected , or ] in array");
      }
    }
    if (c === "{") {
      i++;
      const obj = {};
      for (;;) {
        wsNl();
        if (src[i] === "}") { i++; return obj; }
        const parts = key();
        if (src[i] !== "=") fail("expected = in inline table");
        i++;
        put(obj, parts, value());
        wsNl();
        if (src[i] === ",") i++;
        else if (src[i] !== "}") fail("expected , or } in inline table");
      }
    }
    const m = /^[^\s,\]}#]+/.exec(src.slice(i, i + 200));
    if (!m) fail("expected a value");
    i += m[0].length;
    if (m[0] === "true") return true;
    if (m[0] === "false") return false;
    const num = Number(m[0].replace(/_/g, ""));
    return Number.isNaN(num) ? m[0] : num;
  };
  const descend = (parts) => {
    let t = root;
    for (const p of parts) {
      if (Array.isArray(t[p])) t = t[p].at(-1);
      else t = t[p] && typeof t[p] === "object" ? t[p] : (t[p] = {});
    }
    return t;
  };
  for (;;) {
    wsNl();
    if (i >= src.length) return root;
    if (src.startsWith("[[", i)) {
      i += 2;
      const parts = key();
      if (!src.startsWith("]]", i)) fail("expected ]]");
      i += 2;
      const parent = descend(parts.slice(0, -1));
      const list = Array.isArray(parent[parts.at(-1)]) ? parent[parts.at(-1)] : (parent[parts.at(-1)] = []);
      list.push({});
      cur = list.at(-1);
    } else if (src[i] === "[") {
      i++;
      const parts = key();
      if (src[i] !== "]") fail("expected ]");
      i++;
      cur = descend(parts);
    } else {
      const parts = key();
      if (src[i] !== "=") fail("expected =");
      i++;
      put(cur, parts, value());
    }
    ws();
    if (src[i] === "#") skipLine();
    if (i < src.length && src[i] !== "\n") fail("unexpected text after a value");
  }
}

// ---------------------------------------------------------------------------
// One server entry → one shape
// ---------------------------------------------------------------------------
const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" || typeof x === "number").map(String) : []);
const strMap = (v) => (v && typeof v === "object" && !Array.isArray(v)
  ? Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x === "string" || typeof x === "number").map(([k, x]) => [k, String(x)]))
  : {});

/**
 * Normalise a server entry. Clients disagree on field names (url / serverUrl /
 * httpUrl, autoApprove / alwaysAllow / trust), so this is the one place that knows.
 * Returns null for entries that are not a server definition.
 */
export function normaliseServer(name, raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  let { command, args, env } = raw;
  // Zed's older shape nests the launch under `command: { path, args, env }`.
  if (command && typeof command === "object" && !Array.isArray(command)) {
    args = args ?? command.args;
    env = env ?? command.env;
    command = command.path;
  }
  // Some configs put the whole command line in an array.
  if (Array.isArray(command)) {
    args = [...command.slice(1), ...(Array.isArray(args) ? args : [])];
    command = command[0];
  }
  const url = [raw.url, raw.serverUrl, raw.httpUrl, raw.uri].find((u) => typeof u === "string" && u) || null;
  if (typeof command !== "string" && !url) return null;

  const auto = raw.autoApprove ?? raw.alwaysAllow ?? raw.always_allow;
  const autoApprove = raw.trust === true ? true : Array.isArray(auto) ? auto.filter((x) => typeof x === "string") : [];
  const disabled = raw.disabled === true || raw.enabled === false;

  return {
    name: String(name),
    command: typeof command === "string" ? command : null,
    args: strList(args),
    env: strMap(env),
    url,
    // Codex names the variable that holds the token instead of the token; that is a reference, not a secret.
    headers: { ...strMap(raw.headers), ...strMap(raw.http_headers) },
    transport: typeof raw.type === "string" ? raw.type : typeof raw.transport === "string" ? raw.transport : url ? "http" : "stdio",
    disabled,
    autoApprove,
  };
}

// ---------------------------------------------------------------------------
// Where to look
// ---------------------------------------------------------------------------

/** Per-user application data directory for GUI apps. */
function appDataDir({ home, platform, env }) {
  if (platform === "darwin") return path.join(home, "Library", "Application Support");
  if (platform === "win32") return env.APPDATA || path.join(home, "AppData", "Roaming");
  return env.XDG_CONFIG_HOME || path.join(home, ".config");
}

/**
 * Every config file worth checking. Each source is
 *   { client, scope, file, format: "json"|"toml", pick(doc) → [{ scope?, servers: {name: raw} }] }
 * `projectDirs` adds per-project files (.mcp.json, .cursor/mcp.json, …).
 */
export function knownSources({ home = os.homedir(), platform = process.platform, env = process.env, projectDirs = [] } = {}) {
  const app = appDataDir({ home, platform, env });
  const key = (k) => (doc) => [{ servers: doc?.[k] }];
  const out = [];
  const add = (client, scope, file, pick, format = "json", dir = null) => out.push({ client, scope, file, pick, format, dir });

  // Claude Code keeps user-scope servers and per-project "local" servers in one file.
  const claudeDir = env.CLAUDE_CONFIG_DIR || home;
  add("Claude Code", "user", path.join(claudeDir, ".claude.json"), (doc) => [
    { servers: doc?.mcpServers },
    ...Object.entries(doc?.projects && typeof doc.projects === "object" ? doc.projects : {})
      .map(([dir, p]) => ({ scope: `local, ${dir}`, dir, servers: p?.mcpServers })),
  ]);
  const managed = platform === "darwin" ? "/Library/Application Support/ClaudeCode/managed-mcp.json"
    : platform === "win32" ? "C:\\Program Files\\ClaudeCode\\managed-mcp.json"
      : "/etc/claude-code/managed-mcp.json";
  add("Claude Code", "managed", managed, key("mcpServers"));

  add("Claude Desktop", "user", path.join(app, "Claude", "claude_desktop_config.json"), key("mcpServers"));
  add("Cursor", "user", path.join(home, ".cursor", "mcp.json"), key("mcpServers"));
  for (const code of ["Code", "Code - Insiders"]) {
    add("VS Code", "user", path.join(app, code, "User", "mcp.json"), key("servers"));
    add("Cline", "user", path.join(app, code, "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), key("mcpServers"));
    add("Roo Code", "user", path.join(app, code, "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), key("mcpServers"));
  }
  add("VS Code", "user", path.join(env.COPILOT_HOME || path.join(home, ".copilot"), "mcp-config.json"), key("mcpServers"));
  add("Cline", "user", env.CLINE_MCP_SETTINGS_PATH || path.join(home, ".cline", "data", "settings", "cline_mcp_settings.json"), key("mcpServers"));
  // Windsurf's current file sits under "devin"; the older Codeium path is still read by the editor.
  const xdg = platform === "win32" ? app : env.XDG_CONFIG_HOME || path.join(home, ".config");
  add("Windsurf", "user", path.join(xdg, "devin", "mcp_config.json"), key("mcpServers"));
  for (const w of ["windsurf", "windsurf-next"]) add("Windsurf", "user", path.join(home, ".codeium", w, "mcp_config.json"), key("mcpServers"));
  add("Gemini CLI", "user", path.join(home, ".gemini", "settings.json"), key("mcpServers"));
  const geminiSystem = platform === "darwin" ? "/Library/Application Support/GeminiCli/settings.json"
    : platform === "win32" ? "C:\\ProgramData\\gemini-cli\\settings.json"
      : "/etc/gemini-cli/settings.json";
  add("Gemini CLI", "system", geminiSystem, key("mcpServers"));
  add("Zed", "user", platform === "win32" ? path.join(app, "Zed", "settings.json") : path.join(xdg, "zed", "settings.json"), key("context_servers"));
  if (platform !== "win32") add("Zed", "user", path.join(home, ".config", "zed", "settings.json"), key("context_servers"));
  add("Codex", "user", path.join(env.CODEX_HOME || path.join(home, ".codex"), "config.toml"), key("mcp_servers"), "toml");

  for (const dir of projectDirs) {
    const scope = `project, ${dir}`;
    const proj = (client, rel, k, format = "json") => add(client, scope, path.join(dir, ...rel), key(k), format, dir);
    proj("Claude Code", [".mcp.json"], "mcpServers"); // VS Code reads this file too
    proj("Cursor", [".cursor", "mcp.json"], "mcpServers");
    proj("VS Code", [".vscode", "mcp.json"], "servers");
    proj("Roo Code", [".roo", "mcp.json"], "mcpServers");
    proj("Windsurf", [".devin", "mcp_config.json"], "mcpServers");
    proj("Windsurf", [".devin", "mcp_config.local.json"], "mcpServers");
    proj("Gemini CLI", [".gemini", "settings.json"], "mcpServers");
    proj("Zed", [".zed", "settings.json"], "context_servers");
    proj("Codex", [".codex", "config.toml"], "mcp_servers", "toml");
  }
  return out;
}

/** A file named on the command line: accept any of the known top-level keys. */
export function adHocSource(file) {
  return {
    client: "custom", scope: "file", file, format: file.endsWith(".toml") ? "toml" : "json",
    pick: (doc) => ["mcpServers", "servers", "context_servers", "mcp_servers"].map((k) => ({ servers: doc?.[k] })),
  };
}

/** Project directories Claude Code already knows about (the keys of `projects`). */
export function claudeProjectDirs({ home = os.homedir(), env = process.env } = {}) {
  try {
    const doc = parseJsonc(fs.readFileSync(path.join(env.CLAUDE_CONFIG_DIR || home, ".claude.json"), "utf8"));
    return Object.keys(doc?.projects && typeof doc.projects === "object" ? doc.projects : {}).filter((d) => path.isAbsolute(d));
  } catch {
    return [];
  }
}

/**
 * Read every source that exists. Returns
 *   { files: [{ client, scope, file, mode, servers: n, error? }], servers: [normalised + { client, scope, file }] }
 */
export function readSources(sources) {
  const files = [];
  const servers = [];
  const seen = new Set();
  for (const src of sources) {
    let real;
    try { real = fs.realpathSync(src.file); } catch { continue; } // not installed / not configured
    if (seen.has(real)) continue;
    seen.add(real);
    const entry = { client: src.client, scope: src.scope, file: src.file, mode: null, servers: 0 };
    try {
      const st = fs.statSync(real);
      if (!st.isFile()) continue;
      entry.mode = st.mode & 0o777;
      const text = fs.readFileSync(real, "utf8");
      let doc;
      try {
        doc = src.format === "toml" ? parseToml(text) : parseJsonc(text);
      } catch (e) {
        // JSON.parse quotes the text around the error, which could be half a token. Never pass it on.
        throw new Error(src.format === "toml" ? e.message : "not valid JSON");
      }
      for (const group of src.pick(doc)) {
        if (!group.servers || typeof group.servers !== "object" || Array.isArray(group.servers)) continue;
        for (const [name, raw] of Object.entries(group.servers)) {
          const s = normaliseServer(name, raw);
          if (!s) continue;
          servers.push({ ...s, client: src.client, scope: group.scope || src.scope, file: src.file, dir: group.dir || src.dir || null });
          entry.servers++;
        }
      }
    } catch (e) {
      entry.error = e.code === "EACCES" ? "permission denied" : e.code ? `could not be read (${e.code})` : `could not be read (${e.message})`;
    }
    files.push(entry);
  }
  return { files, servers };
}
