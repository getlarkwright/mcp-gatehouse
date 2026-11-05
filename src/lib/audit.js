// Append-only JSONL audit trail, one line per decision. Lines stay well under
// 4 KB so concurrent writers (several sessions wrapping servers) never interleave.
import fs from "node:fs";
import path from "node:path";

const MAX_LINE = 3800;

export class AuditLog {
  constructor(file, server, mode) {
    this.file = file;
    this.server = server;
    this.mode = mode;
    this.broken = false;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
    } catch {
      /* reported on first write */
    }
  }

  write(entry) {
    if (this.broken) return;
    const record = { ts: new Date().toISOString(), server: this.server, mode: this.mode, ...entry };
    let line = JSON.stringify(record);
    if (line.length > MAX_LINE) {
      if (record.arguments !== undefined) record.arguments = "[truncated]";
      if (record.details) record.details = String(JSON.stringify(record.details)).slice(0, 600) + "…";
      line = JSON.stringify(record).slice(0, MAX_LINE);
    }
    try {
      fs.appendFileSync(this.file, line + "\n", { mode: 0o600 });
    } catch (e) {
      this.broken = true;
      process.stderr.write(`[mcp-gatehouse] audit log ${this.file} is not writable (${e.message}); continuing without it\n`);
    }
  }
}

export function parseSince(s) {
  if (!s) return 0;
  const m = /^(\d+)\s*([mhdw])$/.exec(String(s).trim());
  if (!m) {
    const t = Date.parse(s);
    if (Number.isNaN(t)) throw new Error(`--since "${s}": use 30m, 24h, 7d, 2w or an ISO date`);
    return t;
  }
  const unit = { m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3 }[m[2]];
  return Date.now() - Number(m[1]) * unit;
}

export function readAudit(file, { since = 0, server = null } = {}) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    if (since && Date.parse(r.ts) < since) continue;
    if (server && r.server !== server) continue;
    out.push(r);
  }
  return out;
}

const pad = (s, n) => String(s).padEnd(n);
const lpad = (s, n) => String(s).padStart(n);

/** Plain-text summary of an audit log. */
export function renderReport(records, { file, sinceLabel }) {
  if (!records.length) return `No audit records${sinceLabel ? ` in the last ${sinceLabel}` : ""} (${file}).`;
  const calls = records.filter((r) => r.event === "call");
  const byTool = new Map();
  const blocks = [];
  const secrets = {};
  const injections = {};
  const pinEvents = [];
  let warnedCalls = 0;
  const hidden = [];

  for (const r of records) {
    if (r.event === "call") {
      const key = `${r.server} › ${r.tool}`;
      const t = byTool.get(key) || { calls: 0, denied: 0, redacted: 0, warned: 0, ms: 0 };
      t.calls += 1;
      t.ms += r.duration_ms || 0;
      if (r.decision === "deny" || r.decision === "would_deny") t.denied += 1;
      if (r.output_secrets && Object.keys(r.output_secrets).length) t.redacted += 1;
      if (r.injection?.length) t.warned += 1;
      byTool.set(key, t);
      if (r.decision === "deny" || r.decision === "would_deny") blocks.push(r);
      for (const [k, v] of Object.entries(r.output_secrets || {})) secrets[`out:${k}`] = (secrets[`out:${k}`] || 0) + v;
      for (const [k, v] of Object.entries(r.input_secrets || {})) secrets[`in:${k}`] = (secrets[`in:${k}`] || 0) + v;
      for (const h of r.injection || []) injections[h.id] = (injections[h.id] || 0) + 1;
      if (r.injection?.length) warnedCalls += 1;
    }
    if (r.event === "pin_changed" || r.event === "pin_new_tool") pinEvents.push(r);
    if (r.event === "tool_hidden") hidden.push(r);
  }

  const first = records[0].ts;
  const last = records[records.length - 1].ts;
  const servers = new Set(records.map((r) => r.server));
  const lines = [];
  lines.push(`MCP Gatehouse audit — ${records.length} records, ${servers.size} server(s), ${first.slice(0, 16)} → ${last.slice(0, 16)} UTC`);
  lines.push(`Log: ${file}`);
  lines.push("");
  const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
  lines.push(`Tool calls: ${calls.length}   denied: ${blocks.length}   secrets caught: ${sum(secrets)}   calls with injection text: ${warnedCalls}   definition changes: ${pinEvents.length}`);

  if (byTool.size) {
    lines.push("", "Calls by tool");
    lines.push(`  ${pad("server › tool", 44)}${lpad("calls", 7)}${lpad("denied", 8)}${lpad("redact", 8)}${lpad("warn", 6)}${lpad("avg ms", 8)}`);
    const rows = [...byTool.entries()].sort((a, b) => b[1].calls - a[1].calls).slice(0, 25);
    for (const [k, t] of rows) {
      lines.push(`  ${pad(k.slice(0, 43), 44)}${lpad(t.calls, 7)}${lpad(t.denied, 8)}${lpad(t.redacted, 8)}${lpad(t.warned, 6)}${lpad(Math.round(t.ms / t.calls), 8)}`);
    }
  }
  if (blocks.length) {
    lines.push("", "Denied calls (latest 15)");
    for (const r of blocks.slice(-15)) lines.push(`  ${r.ts.slice(0, 19)}  ${r.server} › ${r.tool}  ${r.decision === "would_deny" ? "(monitor) " : ""}${(r.reasons || []).join("; ")}`);
  }
  if (Object.keys(secrets).length) {
    lines.push("", "Secrets caught (out = in tool output, in = in arguments the model sent)");
    for (const [k, v] of Object.entries(secrets).sort((a, b) => b[1] - a[1])) lines.push(`  ${pad(k, 34)}${lpad(v, 5)}`);
  }
  if (Object.keys(injections).length) {
    lines.push("", "Injection patterns in tool output");
    for (const [k, v] of Object.entries(injections).sort((a, b) => b[1] - a[1])) lines.push(`  ${pad(k, 34)}${lpad(v, 5)}`);
  }
  if (hidden.length) {
    lines.push("", "Tools hidden from the model");
    const seen = new Set();
    for (const r of hidden) {
      const key = `${r.server} › ${r.tool} — ${r.reason}`;
      if (!seen.has(key)) { seen.add(key); lines.push(`  ${key}`); }
    }
  }
  if (pinEvents.length) {
    lines.push("", "Definition changes and new tools");
    for (const r of pinEvents.slice(-15)) lines.push(`  ${r.ts.slice(0, 19)}  ${r.server} › ${r.tool}  ${r.event} → ${r.action}${r.changes?.length ? ` (changed: ${r.changes.join(", ")})` : ""}`);
    lines.push("  Review with: mcp-gatehouse pins <server>   approve with: mcp-gatehouse approve <server> <tool>");
  }
  return lines.join("\n");
}
