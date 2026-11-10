// `mcp-gatehouse audit`: read every MCP client config on this machine and say
// what is risky about each server before it ever runs. The default pass is
// static: it reads files and starts nothing. `--live` also starts each server
// the way the client would, asks for its tool list, and scans the definitions.
//
// Nothing printed here may contain a secret. Values are classified, never echoed.
import os from "node:os";
import path from "node:path";
import { redactSecrets, isPlaceholder, scanValue } from "./detect.js";
import { readPins, safeName, deriveName } from "./pins.js";

const RANK = { high: 0, medium: 1, low: 2 };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const base = (cmd) => String(cmd).replace(/\\/g, "/").split("/").pop().replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();

/** A value that points at a variable instead of holding the secret itself. */
const isReference = (v) => /\$\{[^}]*\}|\{\{[^}]*\}\}/.test(v) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v) || /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v) || /^<[^>]+>$/.test(v);

const looksLikePath = (v) => /^(?:~|\.{1,2})?[\\/]/.test(v) || /^[A-Za-z]:[\\/]/.test(v);

// Names that mean "this holds a credential". Matched on whole segments so that
// AUTH_METHOD or KEYBOARD do not count, and names that only point at a secret
// (TOKEN_FILE, API_KEY_ENV) are left out.
const SECRET_NAME = /(?:^|[_.-])(?:token|secret|password|passwd|pwd|passphrase|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?|authorization|pat|cookie)(?:$|[_.-])|(?:^|[_.-])key$/i;
const NOT_A_SECRET_NAME = /(?:^|[_.-])(?:file|path|dir|name|env|type|ttl|header|prefix|url|id|var)$/i;
const isSecretName = (name) => SECRET_NAME.test(name) && !NOT_A_SECRET_NAME.test(name);

function charClasses(v) {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(v)).length;
}

/**
 * Decide whether `value`, stored under `name`, is a literal secret.
 * Returns a type label ("github_token", "secret", …) or null.
 */
export function classifySecret(name, value) {
  if (typeof value !== "string") return null;
  const v = value.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, "");
  if (!v || isReference(v) || isPlaceholder(v)) return null;
  const known = Object.keys(redactSecrets(value).findings);
  if (known.length) return known[0];
  if (!isSecretName(String(name || ""))) return null;
  if (v.length < 8 || looksLikePath(v) || /^(?:true|false|\d+)$/i.test(v)) return null;
  // "disabled" or "production" under a secret-looking name is a setting, not a credential.
  if (v.length < 20 && charClasses(v) < 2) return null;
  return "secret";
}

const tilde = (p, home) => (home && (p === home || p.startsWith(home + path.sep)) ? "~" + p.slice(home.length) : p);
const quote = (t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t);

// ---------------------------------------------------------------------------
// Reading a command line
// ---------------------------------------------------------------------------
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "fish", "ksh", "powershell", "pwsh"]);

/** Split a shell string into words. Quotes are respected; operators stay as their own words. */
function shellWords(text) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\|\||&&|[|;&])|([^\s|;&"']+)/g;
  let m;
  while ((m = re.exec(text))) out.push(m[1] ?? m[2] ?? m[3] ?? m[4]);
  return out;
}

/**
 * Peel launch wrappers that are not the server itself: `cmd /c`, `env K=V`,
 * `sh -c "..."`. Returns { tokens, shellText, envPairs }.
 */
function unwrap(tokens) {
  let t = [...tokens];
  let shellText = null;
  const envPairs = [];
  for (let guard = 0; guard < 4 && t.length; guard++) {
    const b = base(t[0]);
    if (b === "cmd" && /^\/[ck]$/i.test(t[1] || "")) { t = t.slice(2); continue; }
    if (b === "env") {
      let i = 1;
      while (i < t.length) {
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t[i])) { envPairs.push(t[i]); i++; }
        else if (t[i] === "-u" || t[i] === "--unset") i += 2;
        else if (t[i].startsWith("-")) i++;
        else break;
      }
      t = t.slice(i);
      continue;
    }
    if (SHELLS.has(b)) {
      const c = t.findIndex((a, i) => i > 0 && (/^-[a-z]*c$/i.test(a) || /^-command$/i.test(a)));
      if (c !== -1 && t[c + 1]) {
        shellText = t.slice(c + 1).join(" ");
        t = shellWords(shellText);
      }
    }
    break;
  }
  return { tokens: t, shellText, envPairs };
}

const isGatehouse = (token) => base(token).replace(/@.*$/, "") === "mcp-gatehouse" || /mcp-gatehouse[\\/]src[\\/]index\.js$/.test(token);

/** If the command line runs through mcp-gatehouse, split off its options and the wrapped server. */
function splitGuard(tokens) {
  const firstSep = tokens.indexOf("--");
  const g = tokens.findIndex((t, i) => (firstSep === -1 || i < firstSep) && isGatehouse(t));
  if (g === -1) return null;
  const sep = tokens.indexOf("--", g);
  const opts = sep === -1 ? tokens.slice(g + 1) : tokens.slice(g + 1, sep);
  const inner = sep === -1 ? [] : tokens.slice(sep + 1);
  const val = (flag) => {
    const eq = opts.find((o) => o.startsWith(`--${flag}=`));
    if (eq) return eq.slice(flag.length + 3);
    const i = opts.indexOf(`--${flag}`);
    return i !== -1 ? opts[i + 1] : undefined;
  };
  const headers = {};
  opts.forEach((o, i) => {
    const h = o === "--header" ? opts[i + 1] : o.startsWith("--header=") ? o.slice(9) : null;
    if (h && h.includes(":")) headers[h.slice(0, h.indexOf(":")).trim()] = h.slice(h.indexOf(":") + 1).trim();
  });
  return { outer: tokens.slice(0, g + 1), inner, name: val("name"), url: val("url"), headers, monitor: opts.includes("--monitor") };
}

// --- package pins ------------------------------------------------------------
const LOCAL_SPEC = /^(?:\.{0,2}[\\/]|~[\\/]|[A-Za-z]:[\\/]|file:)/;
const REMOTE_SPEC = /^(?:git\+|git:\/\/|github:|gitlab:|bitbucket:|https?:\/\/)/;

/** The first word that is a package, skipping flags and the values some flags take. */
function firstSpec(args, valueFlags, specFlags = []) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") return args[i + 1];
    if (specFlags.includes(a)) return args[i + 1];
    const eq = specFlags.find((f) => a.startsWith(f + "="));
    if (eq) return a.slice(eq.length + 1);
    if (valueFlags.includes(a)) { i++; continue; }
    if (a.startsWith("-")) continue;
    return a;
  }
  return undefined;
}

/**
 * A package fetched straight from Git or a URL. The ref decides how fixed it is:
 * a commit hash cannot move, a version tag can be moved but rarely is, a branch
 * (or no ref at all) changes with every push.
 */
function remotePin(spec, kind) {
  const clean = redactSecrets(spec).text;
  const tail = clean.slice(clean.lastIndexOf("/") + 1);
  const hash = /#([^#]+)$/.exec(tail)?.[1];
  const at = /@([^@#]+)(?:#.*)?$/.exec(tail)?.[1];
  const ref = hash && !/^(?:egg|subdirectory)=/.test(hash) ? hash : at;
  const cut = ref ? clean.lastIndexOf(ref) - 1 : clean.search(/[#?]/);
  const name = cut > 0 ? clean.slice(0, cut) : clean;
  const pin = !ref ? "remote"
    : /^[0-9a-f]{7,40}$/i.test(ref) ? "commit"
      : /^semver:/.test(ref) ? "range"
        : /^v?\d+(?:\.\d+)*(?:[-+][\w.]+)?$/.test(ref) ? "gittag" : "branch";
  return { kind, name, version: ref, pin };
}

function npmPin(spec) {
  if (!spec) return null;
  if (LOCAL_SPEC.test(spec)) return { kind: "local" };
  if (REMOTE_SPEC.test(spec) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec)) return remotePin(spec, "npm");
  const m = /^(@[^/@]+\/[^@]+|[^@]+)(?:@(.*))?$/.exec(spec);
  if (!m) return null;
  const version = m[2];
  const pin = !version ? "none"
    : /^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$/.test(version) ? "exact"
      : /^[a-z][\w.-]*$/i.test(version) ? "tag" : "range";
  return { kind: "npm", name: m[1], version, pin };
}

function pyPin(spec) {
  if (!spec) return null;
  if (LOCAL_SPEC.test(spec)) return { kind: "local" };
  if (REMOTE_SPEC.test(spec)) return remotePin(spec, "pypi");
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(?:(==|@|>=|<=|~=|!=|>|<)(.+))?$/.exec(spec);
  if (!m) return null;
  const [, name, , op, version] = m;
  const pin = !op ? "none"
    : op === "==" && !version.includes("*") ? "exact"
      : op === "@" ? (/^\d/.test(version) ? "exact" : "tag") : "range";
  return { kind: "pypi", name, version, pin };
}

const NPX_VALUE_FLAGS = ["-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace", "--node-options"];
const UV_VALUE_FLAGS = ["--with", "--with-editable", "--with-requirements", "--python", "-p", "--index", "--index-url", "-i",
  "--extra-index-url", "--default-index", "--find-links", "-f", "--directory", "--project", "--env-file", "--refresh-package",
  "--upgrade-package", "-P", "--constraints", "-c", "--overrides", "--cache-dir", "--config-file", "--python-preference",
  "--resolution", "--prerelease", "--index-strategy", "--keyring-provider", "--link-mode", "--color", "--exclude-newer"];
const DOCKER_BOOL = new Set(["--rm", "--init", "--privileged", "--read-only", "--interactive", "--tty", "--detach", "--no-healthcheck",
  "--publish-all", "--quiet", "--sig-proxy", "--oom-kill-disable"]);

function dockerRun(args) {
  const flags = []; // [name, value]
  let image;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith("-")) { image = a; break; }
    if (a.startsWith("--")) {
      if (a.includes("=")) flags.push([a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)]);
      else if (DOCKER_BOOL.has(a)) flags.push([a, true]);
      else flags.push([a, args[++i]]);
    } else if (/^-[itdPq]+$/.test(a)) flags.push([a, true]);
    else if (a.length > 2) flags.push([a.slice(0, 2), a.slice(2)]); // -e=X or -eX
    else flags.push([a, args[++i]]);
  }
  if (!image) return null;
  const digest = image.includes("@sha256:");
  const tag = /:([^/:@]+)(?:@|$)/.exec(image.slice(image.lastIndexOf("/") + 1))?.[1];
  const pin = digest ? "digest" : !tag ? "none" : tag === "latest" ? "tag" : "exact";
  return { kind: "docker", name: image.replace(/@sha256:.*$/, "").replace(/:[^/:]+$/, ""), version: tag, pin, flags };
}

/** What kind of thing a command line starts, and how firmly its version is fixed. */
export function describeLaunch(tokens) {
  if (!tokens.length) return null;
  const b = base(tokens[0]);
  const rest = tokens.slice(1);
  if (["npx", "bunx", "pnpx"].includes(b)) return npmPin(firstSpec(rest, NPX_VALUE_FLAGS, ["-p", "--package"]));
  if (["pnpm", "yarn", "bun"].includes(b) && ["dlx", "x"].includes(rest[0])) return npmPin(firstSpec(rest.slice(1), NPX_VALUE_FLAGS, ["-p", "--package"]));
  if (b === "npm" && ["exec", "x"].includes(rest[0])) return npmPin(firstSpec(rest.slice(1), NPX_VALUE_FLAGS, ["-p", "--package"]));
  if (b === "uvx") return pyPin(firstSpec(rest, UV_VALUE_FLAGS, ["--from"]));
  if (b === "uv" && rest[0] === "tool" && rest[1] === "run") return pyPin(firstSpec(rest.slice(2), UV_VALUE_FLAGS, ["--from"]));
  if (b === "pipx" && rest[0] === "run") return pyPin(firstSpec(rest.slice(1), ["--python", "--index-url", "-i", "--pip-args"], ["--spec"]));
  if (["docker", "podman", "nerdctl"].includes(b)) {
    const run = rest.indexOf("run");
    return run === -1 ? { kind: "local" } : dockerRun(rest.slice(run + 1));
  }
  if (b === "deno" && rest[0] === "run") {
    const spec = firstSpec(rest.slice(1), ["--allow-read", "--allow-write", "--allow-net", "--allow-env", "--allow-run", "--config", "-c", "--import-map"]);
    if (spec && /^(?:npm|jsr):/.test(spec)) return npmPin(spec.replace(/^(?:npm|jsr):/, ""));
    if (spec && REMOTE_SPEC.test(spec)) return remotePin(spec, "url");
  }
  return { kind: "local" };
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
const FIX = {
  secret_in_config: "Move it out of the file into an environment variable or a secret manager, then rotate it. It has been sitting in a plain file, so treat it as exposed.",
  config_readable_by_others: "Make the file private to your account (chmod 600).",
  plain_http: "Use https, or keep the server on localhost.",
  pipe_to_shell: "Install the server, read it, and point the config at the installed copy.",
  unpinned: "Pin the exact version you reviewed, for example name@1.2.3 (or a commit hash for a Git source).",
  git_tag: "Fine for a repository you control. For someone else's code, use the full commit hash in place of the tag.",
  docker_privileged: "Remove the flag. An MCP server should not need full control of the host.",
  docker_socket: "Remove the Docker socket mount. It gives the container control of every other container and the host.",
  docker_root_mount: "Mount only the folders the server needs.",
  docker_host_network: "Drop host networking unless the server truly needs it.",
  broad_path: "Give the server only the folders it needs.",
  auto_approve: "Keep auto-approval for read-only tools only. Tools that write, delete or send should ask first.",
  shell_wrapper: "Read the script. A shell line can hide what really runs.",
  poisoned_tool: "Stop using this server until you have read that tool's full definition. mcp-gatehouse hides tools like this by default.",
  hidden_text: "Treat it as hostile until explained. Invisible characters in a tool definition have no honest use.",
  suspicious_tool: "Read the tool's definition and decide whether the wording is ordinary documentation.",
  pending_change: "Review what changed with: mcp-gatehouse pins <server>",
  monitor_only: "Switch to enforce mode once the report looks right.",
};

const TITLE = {
  secret_in_config: "Secrets written in config files",
  config_readable_by_others: "Config files with secrets that other users can read",
  plain_http: "Servers reached over plain http",
  pipe_to_shell: "Servers installed by piping a download into a shell",
  unpinned: "Servers with no fixed version",
  git_tag: "Servers set to a Git tag instead of a commit",
  docker_privileged: "Containers running privileged",
  docker_socket: "Containers given the Docker socket",
  docker_root_mount: "Containers given the whole disk or home folder",
  docker_host_network: "Containers on the host network",
  broad_path: "Servers given the whole disk or home folder",
  auto_approve: "Tools that run without asking",
  shell_wrapper: "Servers started through a shell line",
  poisoned_tool: "Tool definitions that carry instructions for the model",
  hidden_text: "Tool definitions with invisible characters",
  suspicious_tool: "Tool definitions worth reading",
  pending_change: "Tool definitions that changed and wait for approval",
  monitor_only: "Guards that only watch",
};

/** Read a list of words for secrets. Returns { shown: [words safe to print], hits: [{where, type}] }. */
function scanWords(words) {
  const shown = [];
  const hits = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const flag = /^--?([A-Za-z][\w-]*)$/.exec(w);
    if (flag && isSecretName(flag[1]) && words[i + 1] !== undefined && !words[i + 1].startsWith("-")) {
      const type = classifySecret(flag[1], words[i + 1]);
      if (type) {
        hits.push({ where: `argument ${w}`, type });
        shown.push(w, `[REDACTED:${type}]`);
        i++;
        continue;
      }
    }
    const kv = /^(-{0,2}[A-Za-z_][\w.-]*)=([\s\S]*)$/.exec(w);
    if (kv) {
      const type = classifySecret(kv[1].replace(/^-+/, ""), kv[2]);
      if (type) {
        hits.push({ where: `argument ${kv[1]}`, type });
        shown.push(`${kv[1]}=[REDACTED:${type}]`);
        continue;
      }
    }
    const red = redactSecrets(w);
    for (const type of Object.keys(red.findings)) hits.push({ where: "an argument", type });
    shown.push(red.text);
  }
  return { shown, hits };
}

function hostKind(url) {
  let host;
  try { host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase(); } catch { return null; }
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127\./.test(host)) return "loopback";
  if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(host) || /^169\.254\./.test(host)
    || /\.(?:local|lan|internal|home|corp)$/.test(host) || !host.includes(".") || /^f[cd][0-9a-f]{2}:/.test(host)) return "private";
  return "public";
}

function broadPath(word, home) {
  let p = word.replace(/^~(?=$|[\\/])/, home).replace(/^\$\{?HOME\}?(?=$|[\\/])/, home).replace(/^%USERPROFILE%(?=$|[\\/])/i, home);
  if (p.length > 1) p = p.replace(/[\\/]+$/, "") || "/";
  if (p === "/" || /^[A-Za-z]:$/.test(p) || /^[A-Za-z]:[\\/]$/.test(word)) return "the whole disk";
  if (p === home) return "your whole home folder";
  if (p === "/home" || p === "/Users" || /^[A-Za-z]:[\\/]Users$/i.test(p)) return "every user's home folder";
  return null;
}

/**
 * Check one normalised server entry (from clients.js). Static only.
 * Returns { ...identity, display, guarded, guard, launch, target, findings: [{id, severity, text}] }.
 */
export function inspectServer(server, { home = os.homedir() } = {}) {
  const findings = [];
  const add = (id, severity, text) => findings.push({ id, severity, text });
  const tokensRaw = server.command ? [server.command, ...server.args] : [];
  const un = unwrap(tokensRaw);
  const guard = splitGuard(un.tokens);
  const innerTokens = guard ? guard.inner : un.tokens;
  const url = guard?.url || server.url;
  const headers = { ...server.headers, ...(guard?.headers || {}) };

  // --- secrets -------------------------------------------------------------
  const secret = (where, type) => {
    const what = type === "secret" ? "A secret" : type === "url_credentials" ? "A password inside a URL" : `A secret (${type.replace(/_/g, " ")})`;
    add("secret_in_config", "high", `${what} is written in the config (${where}).`);
  };
  for (const [k, v] of Object.entries(server.env)) {
    const type = classifySecret(k, v);
    if (type) secret(`env ${k}`, type);
  }
  for (const [k, v] of Object.entries(headers)) {
    const type = classifySecret(/^(?:authorization|proxy-authorization|cookie|x-api-key|api-key)$/i.test(k) ? "authorization" : k, v);
    if (type) secret(`header ${k}`, type);
  }
  const words = scanWords(tokensRaw);
  for (const h of words.hits) secret(h.where, h.type);
  for (const pair of un.envPairs) {
    const type = classifySecret(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
    if (type && !words.hits.length) secret(`env ${pair.slice(0, pair.indexOf("="))}`, type);
  }
  let shownUrl = null;
  if (url) {
    const red = redactSecrets(url);
    for (const type of Object.keys(red.findings)) secret("the server URL", type);
    shownUrl = red.text;
  }

  // --- transport -----------------------------------------------------------
  if (typeof url === "string" && /^http:\/\//i.test(url)) {
    const kind = hostKind(url);
    if (kind === "public") add("plain_http", "high", "The server is reached over plain http across the internet. Tool traffic and any token sent with it can be read or changed on the way.");
    else if (kind === "private") add("plain_http", "medium", "The server is reached over plain http on the local network. Anyone on that network can read the traffic.");
  }
  // The same for addresses handed to a local command (a bridge such as mcp-remote, or a download).
  const argUrls = new Set([...tokensRaw, ...un.tokens].filter((t) => /^http:\/\//i.test(t) && t !== url));
  for (const u of argUrls) {
    const kind = hostKind(u);
    if (!kind) continue;
    const host = new URL(u).hostname;
    if (kind === "public") add("plain_http", "high", `The start command uses a plain http address across the internet (${host}). What is sent and what comes back can be read or changed on the way.`);
    else if (kind === "private") add("plain_http", "medium", `The start command uses a plain http address on the local network (${host}). Anyone on that network can read the traffic.`);
  }

  // --- how it is started ---------------------------------------------------
  if (un.shellText !== null) {
    if (/\b(?:curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex)\b/i.test(un.shellText)) {
      add("pipe_to_shell", "high", "The start command downloads a script and runs it straight away. Whatever is at that address today is what runs.");
    } else add("shell_wrapper", "low", "The server is started through a shell line.");
  }

  const launches = [];
  if (guard) launches.push(describeLaunch(guard.outer));
  if (innerTokens.length) launches.push(describeLaunch(innerTokens));
  for (const l of launches) {
    if (!l || !l.name) continue;
    const what = l.kind === "docker" ? `The image ${l.name}` : l.name;
    if (l.pin === "none") add("unpinned", "medium", `${what} has no version set, so every start can run newer code than the code you reviewed.`);
    else if (l.pin === "tag") add("unpinned", "medium", `${what} is set to "${l.version}", which moves. Every start can run newer code than the code you reviewed.`);
    else if (l.pin === "range") add("unpinned", "medium", `${what} is set to a version range (${l.version}), so new releases are picked up without review.`);
    else if (l.pin === "remote") add("unpinned", "medium", `${what} is fetched with no version or commit set, so every start can run whatever is there that day.`);
    else if (l.pin === "branch") add("unpinned", "medium", `${what} is set to "${l.version}", which looks like a branch. A branch changes with every push.`);
    else if (l.pin === "gittag") add("git_tag", "low", `${what} is set to the Git tag ${l.version}. That is a fixed version in practice, but the repository owner can move a tag. A commit hash cannot move.`);
  }
  const launch = launches.at(-1) || null;

  if (launch?.kind === "docker") {
    const has = (...names) => launch.flags.filter(([n]) => names.includes(n));
    if (has("--privileged").length) add("docker_privileged", "high", "The container runs with --privileged, which gives it full control of the host.");
    const mounts = [...has("-v", "--volume").map(([, v]) => String(v).split(":")[0]), ...has("--mount").map(([, v]) => /(?:^|,)(?:source|src)=([^,]+)/.exec(String(v))?.[1] || "")];
    for (const src of mounts) {
      if (/docker\.sock$/.test(src)) add("docker_socket", "high", "The container is given the Docker socket.");
      else {
        const broad = broadPath(src, home);
        if (broad) add("docker_root_mount", broad === "the whole disk" ? "high" : "medium", `The container is given ${broad} (${tilde(src, home)}).`);
      }
    }
    if (has("--network", "--net").some(([, v]) => v === "host")) add("docker_host_network", "medium", "The container shares the host's network, so it can reach every local service.");
  } else {
    for (const w of innerTokens.slice(1)) {
      if (w.startsWith("-")) continue;
      const broad = broadPath(w, home);
      if (broad) add("broad_path", "medium", `The server is given ${broad} (${w}).`);
    }
  }

  // --- approvals -----------------------------------------------------------
  if (server.autoApprove === true) add("auto_approve", "medium", "Every tool on this server runs without asking (trust is on).");
  else if (server.autoApprove.length) {
    const names = server.autoApprove.slice(0, 5).join(", ") + (server.autoApprove.length > 5 ? ", …" : "");
    add("auto_approve", server.autoApprove.includes("*") ? "medium" : "low", `${server.autoApprove.length} tool(s) run without asking: ${names}.`);
  }

  // --- the guard itself ----------------------------------------------------
  let pinName = null;
  if (guard) {
    pinName = safeName(guard.name || (guard.url ? new URL(guard.url).hostname : innerTokens.length ? deriveName(innerTokens[0], innerTokens.slice(1)) : server.name));
    if (guard.monitor) add("monitor_only", "low", "mcp-gatehouse is in monitor mode here: it logs what it would block and blocks nothing.");
  }

  const display = shownUrl && !tokensRaw.length ? shownUrl : words.shown.map((w) => quote(tilde(w, home))).join(" ");
  const target = innerTokens.length
    ? { kind: "stdio", command: innerTokens[0], args: innerTokens.slice(1), env: server.env, cwd: server.dir }
    : url ? { kind: /sse/i.test(server.transport) ? "sse" : "http", url, headers } : null;

  return {
    client: server.client, scope: server.scope, file: server.file, name: server.name, disabled: server.disabled,
    display: display.length > 220 ? display.slice(0, 217) + "…" : display,
    guarded: !!guard, pinName, launch: launch && { kind: launch.kind, name: launch.name, version: launch.version, pin: launch.pin },
    target, findings, tools: null, toolSource: null,
  };
}

/** Scan tool definitions (from a live listing or from saved pins) and add findings to `result`. */
export function inspectTools(result, tools, source, extraText = "") {
  result.tools = tools.length;
  result.toolSource = source;
  const flag = (tool, scan) => {
    const high = scan.injection.filter((h) => h.severity === "high" && h.id !== "hidden_tag_text");
    const medium = scan.injection.filter((h) => h.severity !== "high");
    if (high.length) result.findings.push({ id: "poisoned_tool", severity: "high", text: `Tool "${tool}" carries instructions aimed at the model (${high.map((h) => h.id).join(", ")}): ${high[0].excerpt}` });
    if (scan.invisible.tag_characters) result.findings.push({ id: "hidden_text", severity: "high", text: `Tool "${tool}" hides text in invisible characters. Decoded: ${scan.hidden.slice(0, 160) || "(nothing printable)"}` });
    else if (Object.keys(scan.invisible).length) result.findings.push({ id: "hidden_text", severity: "medium", text: `Tool "${tool}" contains invisible characters (${Object.keys(scan.invisible).join(", ")}).` });
    if (medium.length && !high.length) result.findings.push({ id: "suspicious_tool", severity: "low", text: `Tool "${tool}" has wording worth reading (${medium.map((h) => h.id).join(", ")}): ${medium[0].excerpt}` });
  };
  for (const tool of tools) {
    if (!tool || typeof tool.name !== "string") continue;
    flag(tool.name, scanValue(tool, { redact: true, strip: true }));
  }
  if (extraText) flag("(server instructions)", scanValue(extraText, { redact: true, strip: true }));
}

/** For a guarded server: use the definitions mcp-gatehouse already saved, without starting anything. */
export function inspectPins(result) {
  if (!result.pinName) return;
  let pins;
  try { pins = readPins(result.pinName); } catch { return; }
  if (!pins?.tools) return;
  const defs = [];
  let pending = 0;
  for (const [name, pin] of Object.entries(pins.tools)) {
    if (pin.definition) defs.push(pin.definition);
    if (pin.pending) {
      pending++;
      if (pin.pending.definition) defs.push({ ...pin.pending.definition, name: `${name} (new version, not approved)` });
    }
  }
  inspectTools(result, defs, "pins");
  result.tools = Object.keys(pins.tools).length;
  if (pending) result.findings.push({ id: "pending_change", severity: "medium", text: `${pending} tool definition(s) changed or appeared since you approved them and are being held.` });
}

// ---------------------------------------------------------------------------
// Live listing (opt-in)
// ---------------------------------------------------------------------------
const expandRefs = (v, env) => String(v).replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, name, dflt) => env[name] ?? dflt ?? "");

/**
 * Start (or connect to) one server, list its tools, and stop it. No tool is called.
 * Returns { tools, instructions } or throws with a short reason.
 */
export async function listLive(target, { timeoutMs = 20000, env = process.env } = {}) {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  let transport;
  if (target.kind === "stdio") {
    const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
    const childEnv = Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === "string"));
    for (const [k, v] of Object.entries(target.env || {})) childEnv[k] = expandRefs(v, env);
    transport = new StdioClientTransport({
      command: expandRefs(target.command, env), args: target.args.map((a) => expandRefs(a, env)),
      env: childEnv, stderr: "ignore", cwd: target.cwd || undefined,
    });
  } else {
    const headers = Object.fromEntries(Object.entries(target.headers || {}).map(([k, v]) => [k, expandRefs(v, env)]));
    const mod = target.kind === "sse"
      ? (await import("@modelcontextprotocol/sdk/client/sse.js")).SSEClientTransport
      : (await import("@modelcontextprotocol/sdk/client/streamableHttp.js")).StreamableHTTPClientTransport;
    transport = new mod(new URL(expandRefs(target.url, env)), { requestInit: { headers } });
  }
  const client = new Client({ name: "mcp-gatehouse-audit", version: "1.0.0" });
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`no answer in ${Math.round(timeoutMs / 1000)}s`)), timeoutMs); });
  try {
    return await Promise.race([deadline, (async () => {
      await client.connect(transport);
      const tools = [];
      let cursor;
      do {
        const page = await client.listTools(cursor ? { cursor } : undefined);
        tools.push(...(page.tools || []));
        cursor = page.nextCursor;
      } while (cursor && tools.length < 5000);
      return { tools, instructions: client.getInstructions?.() || "" };
    })()]);
  } finally {
    clearTimeout(timer);
    try { await client.close(); } catch { /* already gone */ }
    try { await transport.close(); } catch { /* already gone */ }
  }
}

/** Turn a connection failure into one short line that cannot carry a secret. */
function liveError(e, remote = false) {
  const msg = String(e?.message || e);
  if (/\b401\b|unauthori[sz]ed|\b403\b/i.test(msg)) return "needs sign-in, so its tools could not be listed";
  if (e?.code === "ENOENT" || /ENOENT/.test(msg)) return "the command was not found";
  if (/no answer in/.test(msg)) return msg;
  return `could not be ${remote ? "reached" : "started"} (${redactSecrets(msg).text.replace(/\s+/g, " ").slice(0, 100)})`;
}

// ---------------------------------------------------------------------------
// The whole audit
// ---------------------------------------------------------------------------
/**
 * @param {{files: object[], servers: object[]}} read   output of clients.readSources()
 * @param {{live?: boolean, home?: string, timeoutMs?: number, list?: Function}} opts
 */
export async function runAudit(read, { live = false, home = os.homedir(), timeoutMs = 20000, list = listLive } = {}) {
  const results = read.servers.map((s) => inspectServer(s, { home }));

  // A config file that holds a secret should not be readable by other accounts.
  const files = read.files.map((f) => ({ ...f, findings: [] }));
  if (process.platform !== "win32") {
    for (const f of files) {
      const leaky = results.some((r) => r.file === f.file && r.findings.some((x) => x.id === "secret_in_config"));
      if (leaky && f.mode !== null && (f.mode & 0o077)) {
        f.findings.push({ id: "config_readable_by_others", severity: "medium", text: `This file holds secrets and other accounts on this computer can read it (mode ${f.mode.toString(8)}).` });
      }
    }
  }

  if (live) {
    // A start command that downloads and runs a script is not something an audit should set off.
    for (const r of results) {
      if (r.target && !r.disabled && r.findings.some((f) => f.id === "pipe_to_shell")) {
        r.liveError = "not started by the audit, because its start command downloads and runs a script";
        r.target = null;
      }
    }
    const queue = results.filter((r) => r.target && !r.disabled);
    const worker = async () => {
      for (let r = queue.shift(); r; r = queue.shift()) {
        try {
          const { tools, instructions } = await list(r.target, { timeoutMs });
          inspectTools(r, tools, "live", instructions);
        } catch (e) {
          r.liveError = liveError(e, r.target.kind !== "stdio");
        }
      }
    };
    await Promise.all(Array.from({ length: 4 }, worker));
  }
  for (const r of results) if (r.tools === null) inspectPins(r);

  for (const r of results) {
    r.findings.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
    delete r.target; // holds raw env values; never leaves this function
  }

  const all = [...results.flatMap((r) => r.findings.map((f) => ({ ...f, server: r.name }))), ...files.flatMap((f) => f.findings.map((x) => ({ ...x, server: tilde(f.file, home) })))];
  const count = (sev) => all.filter((f) => f.severity === sev).length;
  const groups = new Map();
  for (const f of all) {
    const g = groups.get(f.id) || { id: f.id, severity: f.severity, servers: new Set() };
    if (RANK[f.severity] < RANK[g.severity]) g.severity = f.severity;
    g.servers.add(f.server);
    groups.set(f.id, g);
  }
  const fixFirst = [...groups.values()]
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || b.servers.size - a.servers.size)
    .map((g) => ({ id: g.id, severity: g.severity, title: TITLE[g.id] || g.id, servers: [...g.servers], fix: FIX[g.id] || "" }));

  return {
    live,
    files: files.map((f) => ({ ...f, file: tilde(f.file, home), scope: f.scope.replace(home, "~") })),
    servers: results.map((r) => ({ ...r, file: tilde(r.file, home), scope: r.scope.replace(home, "~") })),
    summary: {
      servers: results.length, disabled: results.filter((r) => r.disabled).length,
      guarded: results.filter((r) => r.guarded).length,
      high: count("high"), medium: count("medium"), low: count("low"),
      toolsListed: results.filter((r) => r.tools !== null).length,
    },
    fixFirst,
  };
}

/** Plain-text report. */
export function renderAudit(report, { version = "" } = {}) {
  const L = [];
  const { summary: s } = report;
  const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  L.push(`MCP Gatehouse audit${version ? ` ${version}` : ""}: ${plural(s.servers, "server")} in ${plural(report.files.length, "config file")}`);
  L.push("");
  if (!report.files.length) {
    L.push("No MCP client config files were found on this account.");
    L.push("Point at one directly with: mcp-gatehouse audit --config <file>");
    return L.join("\n");
  }
  const width = Math.min(24, Math.max(4, ...report.servers.map((r) => r.name.length)));
  for (const f of report.files) {
    L.push(`${f.client} (${f.scope})  ${f.file}`);
    if (f.error) { L.push(`  ! ${f.error}`, ""); continue; }
    for (const x of f.findings) L.push(`  ${x.severity.toUpperCase().padEnd(7)} ${x.text}`);
    const mine = report.servers.filter((r) => r.file === f.file);
    const scopes = [...new Set(mine.map((r) => r.scope))];
    if (!mine.length) L.push("  (no servers)");
    for (const scope of scopes) {
      if (scopes.length > 1 || scope !== f.scope) L.push(`  [${scope}]`);
      for (const r of mine.filter((x) => x.scope === scope)) {
        L.push(`  ${r.name.padEnd(width)}  ${r.display}${r.disabled ? "   (disabled)" : ""}`);
        const pad = " ".repeat(6);
        for (const x of r.findings) L.push(`${pad}${x.severity.toUpperCase().padEnd(7)} ${x.text}`);
        const notes = [r.guarded ? "guarded by mcp-gatehouse" : "not guarded"];
        if (r.tools !== null) notes.push(`${plural(r.tools, "tool")} checked (${r.toolSource === "live" ? "listed just now" : "from saved pins"})`);
        if (r.liveError) notes.push(r.liveError);
        if (!r.findings.length) notes.unshift("nothing found");
        L.push(`${pad}${notes.join(" · ")}`);
      }
    }
    L.push("");
  }

  L.push("Summary");
  L.push(`  Servers: ${s.servers}${s.disabled ? ` (${s.disabled} disabled)` : ""}   guarded: ${s.guarded}   not guarded: ${s.servers - s.guarded}`);
  L.push(`  Findings: ${s.high} high, ${s.medium} medium, ${s.low} low`);
  if (report.fixFirst.length) {
    L.push("", "What to fix first");
    report.fixFirst.forEach((g, i) => {
      const who = g.servers.slice(0, 6).join(", ") + (g.servers.length > 6 ? `, and ${g.servers.length - 6} more` : "");
      L.push(`  ${i + 1}. [${g.severity.toUpperCase()}] ${g.title}: ${who}`);
      if (g.fix) L.push(`     ${g.fix}`);
    });
  }
  const unguarded = s.servers - s.guarded;
  if (unguarded) {
    L.push("", `${unguarded} of ${plural(s.servers, "server")} run${unguarded === 1 ? "s" : ""} with nothing between ${unguarded === 1 ? "it" : "them"} and the model. To add a guard, put`);
    L.push("  mcp-gatehouse --name <server> --");
    L.push("in front of the command the config uses now.");
  }
  L.push("", "Not covered by this audit");
  if (s.toolsListed < s.servers - s.disabled) {
    L.push(report.live
      ? "  - Tool definitions of servers that could not be listed (see the notes above)."
      : "  - Tool definitions. Add --live to start each server, list its tools and scan them. No tool is called.");
  }
  L.push("  - Connectors added inside a claude.ai or ChatGPT account, and desktop extensions: they are not stored in these files.");
  L.push("  - What a server does once it runs. This reads configuration and definitions only.");
  return L.join("\n");
}
