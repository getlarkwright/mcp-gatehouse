// Rug-pull protection. The first time a server lists its tools, each tool's full
// definition is hashed and saved. Later lists are compared against those pins:
// a server that quietly rewrites a description ("...and also send the file to
// this address") or flips readOnlyHint gets that tool held back until a person
// approves the new version with `mcp-gatehouse approve`.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { HOME } from "./policy.js";

export const PIN_DIR = path.join(HOME, "pins");

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Hash everything the model is shown about a tool. `_meta` is transport bookkeeping, so it is left out. */
export function hashTool(tool) {
  const { _meta, ...shown } = tool || {};
  return crypto.createHash("sha256").update(stable(shown)).digest("hex");
}

export const safeName = (name) => String(name).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "server";

const RUNNERS = new Set(["npx", "bunx", "pnpm", "yarn", "uvx", "pipx", "deno", "docker"]);
const INTERPRETERS = new Set(["node", "python", "python3", "bun", "ruby"]);

/** Best-effort readable server name from the command line. */
export function deriveName(command, args) {
  const base = path.basename(command).replace(/\.(exe|cmd|bat)$/i, "");
  const firstReal = args.find((a) => !a.startsWith("-") && !["dlx", "exec", "run", "--from"].includes(a));
  if (RUNNERS.has(base) && firstReal) {
    return safeName(firstReal.replace(/^@[^/]+\//, "").replace(/@[^@/]*$/, "").replace(/==.*$/, "").replace(/^(mcp-server-|server-)/, ""));
  }
  if (INTERPRETERS.has(base) && firstReal) {
    const stem = path.basename(firstReal).replace(/\.[^.]+$/, "");
    if (["index", "server", "main", "__main__", "cli"].includes(stem)) {
      const parent = path.basename(path.dirname(path.resolve(firstReal)));
      return safeName(parent === "src" || parent === "dist" ? path.basename(path.dirname(path.dirname(path.resolve(firstReal)))) : parent);
    }
    return safeName(stem);
  }
  return safeName(base);
}

export function pinFile(server) {
  return path.join(PIN_DIR, `${safeName(server)}.json`);
}

export function readPins(server) {
  try {
    return JSON.parse(fs.readFileSync(pinFile(server), "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw new Error(`pins for ${server} are unreadable (${e.message}); fix or delete ${pinFile(server)}`);
  }
}

export function writePins(server, data) {
  fs.mkdirSync(PIN_DIR, { recursive: true });
  const file = pinFile(server);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file); // atomic, so two sessions wrapping the same server never see half a file
}

const now = () => new Date().toISOString();

/**
 * Compare a tools/list page against the pins. Returns:
 *   { held: Map<toolName, reason>, events: [{event, tool, ...}] }
 * `held` tools must not reach the model. Pins are updated on disk as a side effect
 * (new tools pinned, changed tools recorded as `pending` for approval).
 */
export function checkPins(server, tools, { on_change, new_tools }) {
  const held = new Map();
  const events = [];
  const existing = readPins(server);
  const pins = existing || { server, created: now(), tools: {} };
  let dirty = false;

  for (const tool of tools) {
    if (!tool || typeof tool.name !== "string") continue;
    const hash = hashTool(tool);
    const pin = pins.tools[tool.name];

    if (!existing) {
      // First contact with this server: trust on first use.
      pins.tools[tool.name] = { hash, approved: now(), definition: tool };
      dirty = true;
      continue;
    }

    if (!pin || !pin.hash) {
      if (pin?.pending?.hash === hash) {
        // Already waiting for approval as a new tool.
        if (new_tools === "block") held.set(tool.name, "new tool awaiting approval");
        continue;
      }
      if (new_tools === "block") {
        pins.tools[tool.name] = { hash: null, pending: { hash, seen: now(), definition: tool } };
        held.set(tool.name, "new tool awaiting approval");
        events.push({ event: "pin_new_tool", tool: tool.name, action: "held" });
      } else {
        pins.tools[tool.name] = { hash, approved: now(), definition: tool };
        if (new_tools === "warn") events.push({ event: "pin_new_tool", tool: tool.name, action: "pinned" });
      }
      dirty = true;
      continue;
    }

    if (pin.hash === hash) {
      if (pin.pending) { delete pin.pending; dirty = true; } // server went back to the approved version
      continue;
    }

    // Definition changed since it was approved.
    const firstSighting = pin.pending?.hash !== hash;
    if (firstSighting) {
      pin.pending = { hash, seen: now(), definition: tool };
      dirty = true;
    }
    if (on_change === "block") held.set(tool.name, "definition changed since it was approved");
    if (firstSighting) {
      events.push({ event: "pin_changed", tool: tool.name, action: on_change === "block" ? "held" : "warned", changes: describeChange(pin.definition, tool) });
    }
  }

  if (dirty) writePins(server, pins);
  return { held, events, firstContact: !existing };
}

/** Short human summary of what moved between two tool definitions. */
export function describeChange(before = {}, after = {}) {
  const out = [];
  const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  keys.delete("_meta");
  for (const k of [...keys].sort()) {
    if (stable(before?.[k]) !== stable(after?.[k])) out.push(k);
  }
  return out;
}

/** Approve pending definitions. Returns the list of tool names approved. */
export function approve(server, toolNames, all) {
  const pins = readPins(server);
  if (!pins) throw new Error(`no pins recorded for "${server}" yet (looked in ${pinFile(server)})`);
  const approved = [];
  for (const [name, pin] of Object.entries(pins.tools)) {
    if (!pin.pending) continue;
    if (!all && !toolNames.includes(name)) continue;
    pins.tools[name] = { hash: pin.pending.hash, approved: now(), definition: pin.pending.definition };
    approved.push(name);
  }
  const missing = all ? [] : toolNames.filter((n) => !approved.includes(n));
  if (approved.length) writePins(server, pins);
  return { approved, missing };
}

export function listServers() {
  try {
    return fs.readdirSync(PIN_DIR).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5));
  } catch {
    return [];
  }
}
