#!/usr/bin/env node
// MCP Gatehouse — a guard that sits between an MCP client (Claude Code, Claude
// Desktop, Cursor…) and any MCP server. The client launches the gatehouse; the
// gatehouse launches (or connects to) the real server and checks every message.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { loadPolicy, locatePolicy, starterPolicy, HOME, expandHome } from "./lib/policy.js";
import { AuditLog, readAudit, renderReport, parseSince } from "./lib/audit.js";
import { Gate } from "./lib/gate.js";
import { readPins, approve, listServers, pinFile, describeChange, safeName, deriveName } from "./lib/pins.js";
import { scanValue } from "./lib/detect.js";
import { knownSources, adHocSource, claudeProjectDirs, readSources } from "./lib/clients.js";
import { runAudit, renderAudit } from "./lib/configaudit.js";

const require = createRequire(import.meta.url);
const VERSION = require("../package.json").version;

const HELP = `mcp-gatehouse ${VERSION} — guard any MCP server

Wrap a local (stdio) server:
  mcp-gatehouse [options] -- <command> [args...]

Wrap a remote (Streamable HTTP) server:
  mcp-gatehouse [options] --url https://host/mcp [--header "Authorization: Bearer \${TOKEN}"]

Options:
  --name <server>     name for pins and the audit log (default: derived from the command)
  --policy <file>     policy JSON (default: $MCP_GATEHOUSE_POLICY, then ~/.mcp-gatehouse/policy.json,
                      then built-in defaults)
  --monitor           log what would be blocked, change nothing
  --header "K: V"     extra HTTP header for --url (repeatable; \${VAR} expands from the environment)

Audit this computer (reads the MCP config files of Claude Code, Claude Desktop, Cursor, VS Code,
Windsurf, Cline, Roo Code, Gemini CLI, Zed and Codex; starts nothing unless you add --live):
  mcp-gatehouse audit [--live] [--json] [--dir <project>] [--config <file>]

Other commands:
  mcp-gatehouse report [--since 24h] [--server <name>] [--file audit.jsonl]
  mcp-gatehouse pins [<server>]                 show pinned tools and pending changes
  mcp-gatehouse approve <server> <tool...>|--all
  mcp-gatehouse init [file]                     write a starter policy (default ~/.mcp-gatehouse/policy.json)
  mcp-gatehouse check [--policy <file>] [--name <server>]   validate a policy, print the effective rules
  mcp-gatehouse scan [file]                     run the secret + injection detectors on a file or stdin

Claude Code example:
  claude mcp add fs-guarded -- mcp-gatehouse --name filesystem -- \\
      npx -y @modelcontextprotocol/server-filesystem /srv/project
`;

const die = (msg, code = 1) => {
  process.stderr.write(`mcp-gatehouse: ${msg}\n`);
  process.exit(code);
};

function parseFlags(argv, spec) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split(/=(.*)/s);
      if (!(k in spec)) die(`unknown option --${k}\n\n${HELP}`);
      if (spec[k] === "bool") out[k] = true;
      else {
        const v = inline ?? argv[++i];
        if (v === undefined) die(`--${k} needs a value`);
        if (spec[k] === "list") (out[k] ||= []).push(v);
        else out[k] = v;
      }
    } else out._.push(a);
  }
  return out;
}

const expandEnv = (s) => s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, v) => process.env[v] ?? "");

// ------------------------------------------------------------------ run (proxy)
async function runProxy(argv) {
  const sep = argv.indexOf("--");
  const own = sep === -1 ? argv : argv.slice(0, sep);
  const upstreamCmd = sep === -1 ? [] : argv.slice(sep + 1);
  const f = parseFlags(own, { name: "str", policy: "str", monitor: "bool", url: "str", header: "list" });
  if (f._.length) die(`unexpected "${f._[0]}" — put the server command after "--"\n\n${HELP}`);
  if (!f.url && !upstreamCmd.length) die(`nothing to wrap: give "-- <command>" or --url\n\n${HELP}`);
  if (f.url && upstreamCmd.length) die("give either --url or a command after --, not both");

  const name = safeName(f.name || (f.url ? new URL(f.url).hostname : deriveName(upstreamCmd[0], upstreamCmd.slice(1))));
  let policy;
  try {
    policy = loadPolicy(locatePolicy(f.policy), name);
  } catch (e) {
    die(e.message);
  }
  if (f.monitor) policy.mode = "monitor";

  const notice = (line) => process.stderr.write(`[mcp-gatehouse] ${name}: ${line}\n`);
  const audit = new AuditLog(policy.audit.file, name, policy.mode);

  let up;
  if (f.url) {
    const headers = {};
    for (const h of f.header || []) {
      const i = h.indexOf(":");
      if (i < 1) die(`--header "${h}" is not "Name: value"`);
      headers[h.slice(0, i).trim()] = expandEnv(h.slice(i + 1).trim());
    }
    up = new StreamableHTTPClientTransport(new URL(f.url), { requestInit: { headers } });
  } else {
    up = new StdioClientTransport({
      command: upstreamCmd[0], args: upstreamCmd.slice(1),
      env: Object.fromEntries(Object.entries(process.env).filter(([, v]) => typeof v === "string")),
      stderr: "inherit", cwd: process.cwd(),
    });
  }
  const down = new StdioServerTransport();

  const gate = new Gate({
    server: name, policy, audit, notice,
    onProtocolVersion: (v) => typeof up.setProtocolVersion === "function" && up.setProtocolVersion(v),
  });

  let closing = false;
  const shutdown = async (code = 0, why = "") => {
    if (closing) return;
    closing = true;
    audit.write({ event: "session_end", reason: why || undefined });
    try { await up.close(); } catch { /* already gone */ }
    process.stdout.write("", () => process.exit(code));
    setTimeout(() => process.exit(code), 1500).unref();
  };

  const toServer = (m) => {
    up.send(m).catch((e) => {
      notice(`upstream send failed: ${e.message}`);
      // Answer the request ourselves so the client never waits forever.
      if (m && typeof m.method === "string" && m.id !== undefined) {
        gate.pending.delete(`${typeof m.id}:${m.id}`);
        down.send({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: `mcp-gatehouse: upstream server unreachable (${e.message})` } });
      }
    });
  };

  up.onmessage = (m) => { for (const out of gate.fromServer(m)) down.send(out); };
  up.onerror = (e) => notice(`upstream error: ${e.message}`);
  up.onclose = () => shutdown(0, "upstream closed");
  down.onmessage = (m) => {
    const r = gate.fromClient(m);
    for (const out of r.toServer) toServer(out);
    for (const out of r.toClient) down.send(out);
  };
  down.onerror = (e) => notice(`client message error: ${e.message}`);

  process.stdin.on("end", () => shutdown(0, "client closed"));
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => shutdown(0, sig));

  try {
    await up.start();
  } catch (e) {
    audit.write({ event: "session_error", error: e.message });
    die(`could not start upstream ${f.url || upstreamCmd.join(" ")}: ${e.message}`);
  }
  await down.start();
  if (policy.mode === "monitor") notice("MONITOR mode — nothing is blocked, decisions are only logged");
}

// ------------------------------------------------------------------ subcommands
function cmdReport(argv) {
  const f = parseFlags(argv, { since: "str", server: "str", file: "str", policy: "str" });
  let file = f.file ? expandHome(f.file) : null;
  if (!file) {
    try { file = loadPolicy(locatePolicy(f.policy), f.server).audit.file; } catch (e) { die(e.message); }
  }
  let since = 0;
  try { since = parseSince(f.since); } catch (e) { die(e.message); }
  const records = readAudit(file, { since, server: f.server ? safeName(f.server) : null });
  console.log(renderReport(records, { file, sinceLabel: f.since }));
}

function cmdPins(argv) {
  const server = argv[0];
  if (!server) {
    const all = listServers();
    if (!all.length) return console.log(`No pinned servers yet (${path.join(HOME, "pins")}).`);
    for (const s of all) {
      const p = readPins(s);
      const tools = Object.values(p.tools || {});
      const pending = tools.filter((t) => t.pending).length;
      console.log(`${s.padEnd(32)} ${String(tools.length).padStart(4)} tools${pending ? `   ${pending} PENDING APPROVAL` : ""}`);
    }
    return;
  }
  const p = readPins(safeName(server));
  if (!p) die(`no pins for "${server}" (${pinFile(server)})`);
  console.log(`${p.server} — pinned ${p.created}  (${pinFile(server)})\n`);
  for (const [name, pin] of Object.entries(p.tools).sort()) {
    if (!pin.pending) { console.log(`  ✓ ${name}`); continue; }
    if (!pin.hash) {
      console.log(`  ⏸ ${name}   NEW TOOL waiting for approval (seen ${pin.pending.seen})`);
      console.log(`      description: ${String(pin.pending.definition?.description ?? "").slice(0, 300)}`);
      continue;
    }
    const changes = describeChange(pin.definition, pin.pending.definition);
    console.log(`  ⏸ ${name}   CHANGED since approval (seen ${pin.pending.seen}) — fields: ${changes.join(", ") || "(none visible)"}`);
    if (changes.includes("description")) {
      console.log(`      - ${String(pin.definition?.description ?? "").slice(0, 400)}`);
      console.log(`      + ${String(pin.pending.definition?.description ?? "").slice(0, 400)}`);
    }
  }
  const pending = Object.values(p.tools).filter((t) => t.pending).length;
  if (pending) console.log(`\nApprove with: mcp-gatehouse approve ${p.server} <tool...>   (or --all). The client must re-list tools (restart the session) to see them.`);
}

function cmdApprove(argv) {
  const f = parseFlags(argv, { all: "bool" });
  const [server, ...tools] = f._;
  if (!server || (!tools.length && !f.all)) die("usage: mcp-gatehouse approve <server> <tool...>|--all");
  let res;
  try { res = approve(safeName(server), tools, !!f.all); } catch (e) { die(e.message); }
  if (res.approved.length) console.log(`Approved ${res.approved.length}: ${res.approved.join(", ")}`);
  else console.log("Nothing was pending approval.");
  if (res.missing.length) console.log(`Not pending (nothing to approve): ${res.missing.join(", ")}`);
}

function cmdInit(argv) {
  const target = expandHome(argv[0] || path.join(HOME, "policy.json"));
  if (fs.existsSync(target)) die(`${target} already exists — not overwriting`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(starterPolicy(), null, 2) + "\n", { mode: 0o600 });
  console.log(`Wrote ${target}\nCheck it with: mcp-gatehouse check --policy ${target}`);
}

function cmdCheck(argv) {
  const f = parseFlags(argv, { policy: "str", name: "str" });
  const file = locatePolicy(f.policy);
  let p;
  try { p = loadPolicy(file, f.name ? safeName(f.name) : null); } catch (e) { die(e.message); }
  const view = Object.fromEntries(Object.entries(p).filter(([k]) => !k.startsWith("_") && k !== "servers"));
  console.log(`Policy OK — ${p.source}${f.name ? ` (effective for "${f.name}")` : ""}\n`);
  console.log(JSON.stringify(view, null, 2));
}

async function cmdScan(argv) {
  const file = argv[0];
  let text;
  if (!file || file === "-") {
    const chunks = [];
    for await (const c of process.stdin) chunks.push(c);
    text = Buffer.concat(chunks).toString("utf8");
  } else {
    text = fs.readFileSync(file, "utf8");
  }
  const r = scanValue(text, { redact: true, strip: true });
  const secrets = Object.entries(r.secrets);
  console.log(secrets.length ? `Secrets: ${secrets.map(([k, v]) => `${k}×${v}`).join(", ")}` : "Secrets: none");
  console.log(Object.keys(r.invisible).length ? `Invisible characters: ${Object.entries(r.invisible).map(([k, v]) => `${k}×${v}`).join(", ")}` : "Invisible characters: none");
  if (r.hidden) console.log(`Hidden tag text decodes to: ${r.hidden.slice(0, 300)}`);
  if (r.injection.length) {
    console.log("Injection patterns:");
    for (const h of r.injection) console.log(`  [${h.severity}] ${h.id}: ${h.excerpt}`);
  } else console.log("Injection patterns: none");
  if (secrets.length) console.log(`\n--- redacted ---\n${r.value}`);
  process.exitCode = secrets.length || r.injection.length ? 2 : 0;
}

// ------------------------------------------------------------------ audit
async function cmdAudit(argv) {
  const f = parseFlags(argv, { live: "bool", json: "bool", config: "list", dir: "list", timeout: "str" });
  if (f._.length) die(`unexpected "${f._[0]}". To check one file use: mcp-gatehouse audit --config <file>`);
  const timeoutMs = f.timeout === undefined ? 20000 : Number(f.timeout) * 1000;
  if (!(timeoutMs > 0)) die("--timeout takes a number of seconds");
  const home = os.homedir();
  const abs = (p) => path.resolve(expandHome(p));

  let sources;
  if (f.config) {
    // Named files only: this is "check this file", not "check this computer".
    for (const c of f.config) if (!fs.existsSync(abs(c))) die(`no such file: ${c}`);
    sources = f.config.map((c) => adHocSource(abs(c)));
  } else {
    const dirs = [...new Set([process.cwd(), ...(f.dir || []).map(abs), ...claudeProjectDirs({ home })])];
    sources = knownSources({ home, projectDirs: dirs });
  }
  const read = readSources(sources);
  const startable = read.servers.filter((s) => !s.disabled).length;
  if (f.live && startable && !f.json) {
    process.stderr.write(`Starting ${startable} server(s) to list their tools. No tool is called.\n`);
  }
  const report = await runAudit(read, { live: !!f.live, home, timeoutMs });
  const text = f.json ? JSON.stringify({ version: VERSION, ...report }, null, 2) : renderAudit(report, { version: VERSION });
  // Exit explicitly (a child that ignores stdin closing must not keep the audit alive), but only
  // once the report is fully written: a pipe can still be draining when exit is called.
  process.stdout.write(text + "\n", () => process.exit(report.summary.high || report.summary.medium ? 2 : 0));
}

// ------------------------------------------------------------------ main
const argv = process.argv.slice(2);
const sub = argv[0];
const commands = { report: cmdReport, pins: cmdPins, approve: cmdApprove, init: cmdInit, check: cmdCheck, scan: cmdScan, audit: cmdAudit };

if (sub === "--help" || sub === "-h" || sub === "help" || argv.length === 0) {
  process.stdout.write(HELP);
} else if (sub === "--version" || sub === "-v") {
  console.log(VERSION);
} else if (commands[sub]) {
  await commands[sub](argv.slice(1));
} else {
  await runProxy(argv);
}
