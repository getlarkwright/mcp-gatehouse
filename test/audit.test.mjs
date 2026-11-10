// `mcp-gatehouse audit`: build a pretend home directory full of client configs,
// run the audit against it, and check what it reports. Never reads the real home.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { FAKE } from "./fixtures/fake-secrets.mjs";
import { buildHome, write, FIXTURE, HOME_PASSWORD, FLAG_SECRET } from "./fixtures/audit-home.mjs";
import { parseJsonc, parseToml, normaliseServer, knownSources, readSources } from "../src/lib/clients.js";
import { classifySecret, describeLaunch, inspectServer } from "../src/lib/configaudit.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLI = path.join(ROOT, "src/index.js");

let home;
let project;
let gatehouseHome;

function audit(args = [], { cwd = project, extraEnv = {} } = {}) {
  const r = spawnSync("node", [CLI, "audit", ...args], {
    cwd, encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, ".config"), MCP_GATEHOUSE_HOME: gatehouseHome, ...extraEnv },
  });
  return { out: r.stdout, err: r.stderr, code: r.status };
}
const server = (report, name) => report.servers.find((s) => s.name === name);
const ids = (s) => s.findings.map((f) => f.id);

before(() => {
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "gatehouse-audit-home-")));
  ({ project, gatehouseHome } = buildHome(home));
});
after(() => fs.rmSync(home, { recursive: true, force: true }));

test("parsers: JSON with comments and trailing commas, and TOML", () => {
  assert.deepEqual(parseJsonc('{ "a": "http://x/y", /* c */ "b": [1, 2,], // tail\n }'), { a: "http://x/y", b: [1, 2] });
  const t = parseToml('top = 1\n[mcp_servers."my.server"]\ncommand = "npx" # run\nargs = ["-y", \'lit\\eral\',\n  "two"]\nenv = { A = "1", B = true }\n[mcp_servers.other.env]\nK = """\nmulti"""\n');
  assert.equal(t.top, 1);
  assert.deepEqual(t.mcp_servers["my.server"], { command: "npx", args: ["-y", "lit\\eral", "two"], env: { A: "1", B: true } });
  assert.equal(t.mcp_servers.other.env.K, "multi");
  assert.throws(() => parseToml("a = \n"), /TOML line 1/);
});

test("normaliseServer reads each client's spelling", () => {
  assert.equal(normaliseServer("z", { command: { path: "node", args: ["s.js"], env: { A: "b" } } }).command, "node");
  assert.equal(normaliseServer("w", { serverUrl: "https://h/mcp" }).url, "https://h/mcp");
  assert.equal(normaliseServer("g", { httpUrl: "https://h/mcp", trust: true }).autoApprove, true);
  assert.deepEqual(normaliseServer("r", { command: "x", alwaysAllow: ["a"] }).autoApprove, ["a"]);
  assert.equal(normaliseServer("c", { command: "x", enabled: false }).disabled, true);
  assert.equal(normaliseServer("n", "nope"), null);
});

test("knownSources follows the platform", () => {
  const mac = knownSources({ home: "/Users/a", platform: "darwin", env: {}, projectDirs: [] }).map((s) => s.file);
  assert.ok(mac.includes("/Users/a/Library/Application Support/Claude/claude_desktop_config.json"));
  assert.ok(mac.includes("/Users/a/.cursor/mcp.json"));
  const win = knownSources({ home: "C:\\Users\\a", platform: "win32", env: { APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, projectDirs: [] }).map((s) => s.file);
  assert.ok(win.some((f) => f.includes("AppData") && f.endsWith("claude_desktop_config.json")));
  assert.equal(readSources(knownSources({ home: "/nonexistent-home", platform: "linux", env: {}, projectDirs: [] })).files.filter((f) => f.file.startsWith("/nonexistent-home")).length, 0);
});

test("classifySecret: literals are flagged, references and settings are not", () => {
  assert.equal(classifySecret("GITHUB_TOKEN", FAKE.github), "github_token");
  assert.equal(classifySecret("ANYTHING", FAKE.anthropic) !== null, true);
  assert.equal(classifySecret("NAS_PASSWORD", HOME_PASSWORD), "secret");
  assert.equal(classifySecret("Authorization", "Bearer " + "q".repeat(12) + "A1b2C3d4"), "secret");
  for (const [k, v] of [
    ["API_KEY", "${API_KEY}"], ["API_KEY", "${env:API_KEY}"], ["TOKEN", "$TOKEN"], ["TOKEN", "%TOKEN%"], ["TOKEN", "${input:token}"],
    ["API_KEY", "<your-api-key>"], ["API_KEY", "YOUR_API_KEY_HERE"], ["TOKEN_FILE", "/run/secrets/token"], ["SSH_KEY", "~/.ssh/id_ed25519"],
    ["PASSWORD_AUTH", "disabled"], ["USE_TOKEN", "true"], ["LOG_LEVEL", "debug"], ["KEYBOARD", "us-international"], ["API_KEY", ""],
    ["AUTH_METHOD", "oauth2-device-flow"],
  ]) assert.equal(classifySecret(k, v), null, `${k}=${v}`);
});

test("describeLaunch: what counts as a fixed version", () => {
  const pin = (...t) => describeLaunch(t)?.pin;
  assert.equal(pin("npx", "-y", "some-mcp"), "none");
  assert.equal(pin("npx", "-y", "@scope/some-mcp"), "none");
  assert.equal(pin("npx", "-y", "@scope/some-mcp@latest"), "tag");
  assert.equal(pin("npx", "-y", "@scope/some-mcp@^1.2.0"), "range");
  assert.equal(pin("npx", "-y", "@scope/some-mcp@1.2.3"), "exact");
  assert.equal(pin("npx", "--package", "tool@2.0.0", "run-it"), "exact");
  assert.equal(pin("npx", "github:acme/tool"), "remote");
  assert.equal(pin("npx", "-y", "github:acme/tool#v0.1.1"), "gittag");
  assert.equal(pin("npx", "-y", "github:acme/tool#main"), "branch");
  assert.equal(pin("npx", "-y", "acme/tool#semver:^1.0.0"), "range");
  assert.equal(pin("npx", "-y", "git+ssh://git@github.com/acme/tool.git"), "remote");
  assert.equal(pin("npx", "-y", "github:acme/tool#0123abc"), "commit");
  assert.equal(pin("uvx", "--from", "git+https://github.com/a/b@v0.1.0", "b"), "gittag");
  assert.equal(pin("uvx", "--from", "git+https://github.com/a/b@develop", "b"), "branch");
  assert.deepEqual(describeLaunch(["uvx", "--from", "git+https://github.com/a/b@v0.1.0", "b"]), { kind: "pypi", name: "git+https://github.com/a/b", version: "v0.1.0", pin: "gittag" });
  assert.equal(pin("bunx", "tool"), "none");
  assert.equal(pin("pnpm", "dlx", "tool@1.0.0"), "exact");
  assert.equal(pin("uvx", "mcp-server-git"), "none");
  assert.equal(pin("uvx", "mcp-server-git==0.6.2"), "exact");
  assert.equal(pin("uvx", "mcp-server-git@latest"), "tag");
  assert.equal(pin("uvx", "--from", "git+https://github.com/a/b@0123456789abcdef0123456789abcdef01234567", "b"), "commit");
  assert.equal(pin("uvx", "--from", "git+https://github.com/a/b", "b"), "remote");
  assert.equal(pin("uv", "tool", "run", "--python", "3.12", "thing>=1"), "range");
  assert.equal(pin("docker", "run", "-i", "--rm", "-e", "A=b", "mcp/fetch"), "none");
  assert.equal(pin("docker", "run", "-i", "mcp/fetch:latest"), "tag");
  assert.equal(pin("docker", "run", "-i", "localhost:5000/mcp/fetch:1.2"), "exact");
  assert.equal(pin("docker", "run", "-i", "mcp/fetch@sha256:" + "a".repeat(64)), "digest");
  assert.equal(describeLaunch(["node", "/opt/server.js"]).kind, "local");
  assert.equal(describeLaunch(["npx", "-y", "./local-server"]).kind, "local");
});

test("inspectServer sees through wrappers", () => {
  const mk = (command, args, extra = {}) => inspectServer({ name: "t", command, args, env: {}, headers: {}, url: null, transport: "stdio", disabled: false, autoApprove: [], client: "x", scope: "user", file: "/f", dir: null, ...extra }, { home: "/home/u" });
  const win = mk("cmd", ["/c", "npx", "-y", "tool"]);
  assert.deepEqual(ids(win), ["unpinned"]);
  const env = mk("env", ["API_TOKEN=" + "z9Y8x7W6v5U4t3S2", "npx", "-y", "tool@1.0.0"]);
  assert.deepEqual(ids(env), ["secret_in_config"]);
  assert.ok(!env.display.includes("z9Y8x7W6"));
  const guard = mk("npx", ["-y", "mcp-gatehouse@0.2.0", "--monitor", "--name", "fs", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/u"]);
  assert.equal(guard.guarded, true);
  assert.equal(guard.pinName, "fs");
  assert.deepEqual(ids(guard).sort(), ["broad_path", "monitor_only", "unpinned"]);
  const loose = mk("npx", ["-y", "mcp-gatehouse", "--", "node", "s.js"]);
  assert.deepEqual(ids(loose), ["unpinned"]);
  assert.equal(mk("npx", ["-y", "tool@1.0.0", "/home/u/projects/site"]).findings.length, 0);
  assert.deepEqual(mk("npx", ["-y", "github:acme/tool#v0.1.1"]).findings.map((f) => [f.id, f.severity]), [["git_tag", "low"]]);
  assert.deepEqual(ids(mk("docker", ["run", "-i", "-v", "/home/u:/data", "img:1.0"])), ["docker_root_mount"]);
});

test("audit: the whole pretend home, as JSON", () => {
  const { out, code } = audit(["--json"]);
  assert.equal(code, 2);
  const report = JSON.parse(out);

  assert.deepEqual(ids(server(report, "github")).sort(), ["secret_in_config", "unpinned"]);
  assert.deepEqual(ids(server(report, "files")), ["broad_path"]);
  assert.deepEqual(ids(server(report, "docs")), []);
  assert.deepEqual(ids(server(report, "db")).sort(), ["secret_in_config", "unpinned"]);
  assert.match(server(report, "db").scope, /^local, ~/);

  assert.deepEqual(ids(server(report, "installer")).sort(), ["pipe_to_shell", "plain_http"]);
  assert.deepEqual(server(report, "intranet").findings.map((f) => [f.id, f.severity]), [["plain_http", "medium"]]);
  assert.deepEqual(ids(server(report, "local")), []);

  assert.deepEqual(ids(server(report, "box")).sort(), ["docker_host_network", "docker_privileged", "docker_socket", "unpinned"]);
  assert.deepEqual(ids(server(report, "pinned")), []);

  assert.deepEqual(ids(server(report, "search")).sort(), ["secret_in_config", "unpinned"]);
  assert.deepEqual(ids(server(report, "stripe")), []);

  assert.deepEqual(server(report, "shell").findings.map((f) => [f.id, f.severity]), [["auto_approve", "low"]]);
  assert.equal(server(report, "old").disabled, true);
  assert.deepEqual(ids(server(report, "nas")).sort(), ["auto_approve", "secret_in_config"]);

  assert.deepEqual(ids(server(report, "linear")), []);
  assert.deepEqual(ids(server(report, "pytool")).sort(), ["secret_in_config", "unpinned"]);

  // The guarded server is judged from its saved pins without being started.
  const guarded = server(report, "guarded");
  assert.equal(guarded.guarded, true);
  assert.equal(guarded.toolSource, "pins");
  assert.equal(guarded.tools, 2);
  assert.deepEqual(ids(guarded).sort(), ["pending_change", "poisoned_tool"]);

  // File-level: the world-readable file with a secret, and the file that does not parse.
  const claude = report.files.find((f) => f.file === "~/.claude.json");
  assert.deepEqual(claude.findings.map((f) => f.id), ["config_readable_by_others"]);
  assert.equal(report.files.find((f) => f.client === "Zed").error, "could not be read (not valid JSON)");
  assert.equal(report.files.find((f) => f.client === "Cursor").findings.length, 0);

  assert.equal(report.summary.guarded, 1);
  assert.equal(report.summary.disabled, 1);
  assert.equal(report.fixFirst[0].severity, "high");
  assert.ok(report.fixFirst.find((g) => g.id === "secret_in_config").servers.includes("github"));
});

test("audit never prints a secret, in text or JSON, static or live", () => {
  const secrets = [FAKE.github, FAKE.openai, FAKE.anthropic, "S3cr3tPass", HOME_PASSWORD, FLAG_SECRET];
  for (const args of [[], ["--json"]]) {
    const { out, err } = audit(args);
    for (const s of secrets) assert.ok(!(out + err).includes(s), `secret shown with ${args.join(" ") || "no flags"}`);
    assert.ok(out.includes("github"));
  }
  // Live, against commands that are safe to start: one works, one dies, one cannot connect.
  const file = path.join(home, "leaky.json");
  write(file, {
    mcpServers: {
      works: { command: "node", args: [FIXTURE, "--token", FLAG_SECRET], env: { GITHUB_TOKEN: FAKE.github } },
      dies: { command: "node", args: ["-e", "console.error(process.argv[1]); process.exit(1)", FAKE.db] },
      refused: { url: "http://admin:" + "S3cr3tPass" + "@127.0.0.1:9/mcp", headers: { Authorization: "Bearer " + FAKE.openai } },
    },
  });
  for (const args of [["--live"], ["--live", "--json"]]) {
    const { out, err, code } = audit(["--config", file, "--timeout", "5", ...args]);
    assert.equal(code, 2);
    for (const s of secrets) assert.ok(!(out + err).includes(s), `secret shown with ${args.join(" ")}`);
    assert.match(out, /works/);
  }
});

test("audit: the text report reads top to bottom", () => {
  const { out, code } = audit();
  assert.equal(code, 2);
  assert.match(out, /^MCP Gatehouse audit \S+: 17 servers in 8 config files/);
  assert.match(out, /Claude Code \(user\) {2}~\/\.claude\.json/);
  assert.match(out, /HIGH {4}A secret \(github token\) is written in the config \(env GITHUB_PERSONAL_ACCESS_TOKEN\)\./);
  assert.match(out, /\[local, ~\/work\/shop\]/);
  assert.match(out, /postgres:\/\/admin:\[REDACTED:[a-z_]+\]@db\.internal/);
  assert.match(out, /--api-key \[REDACTED:secret\]/);
  assert.match(out, /guarded by mcp-gatehouse · 2 tools checked \(from saved pins\)/);
  assert.match(out, /What to fix first\n {2}1\. \[HIGH\]/);
  assert.match(out, /Add --live to start each server/);
  assert.ok(!out.includes(home), "home directory is shown as ~");
});

test("audit --config checks one named file and nothing else", () => {
  const file = path.join(home, "one.json");
  write(file, { servers: { tidy: { command: "npx", args: ["-y", "tidy-mcp@3.1.0"] } } });
  const { out, code } = audit(["--config", file, "--json"]);
  assert.equal(code, 0);
  const report = JSON.parse(out);
  assert.equal(report.servers.length, 1);
  assert.deepEqual(report.servers[0].findings, []);
  assert.equal(audit(["--config", path.join(home, "missing.json")]).code, 1);
});

test("audit --live starts the server, lists its tools and finds the poisoned ones", () => {
  const file = path.join(home, "live.json");
  write(file, {
    mcpServers: {
      hostile: { command: "node", args: [FIXTURE] },
      wrapped: { command: "node", args: [CLI, "--name", "wrapped-live", "--", "node", FIXTURE] },
      missing: { command: path.join(home, "no-such-binary"), args: [] },
      asleep: { command: "node", args: ["-e", "setTimeout(() => {}, 60000)"] },
    },
  });
  const { out, code } = audit(["--config", file, "--live", "--json", "--timeout", "3"]);
  assert.equal(code, 2);
  const report = JSON.parse(out);
  for (const name of ["hostile", "wrapped"]) {
    const s = server(report, name);
    assert.equal(s.toolSource, "live", name);
    assert.equal(s.tools, 7, name);
    assert.ok(s.findings.some((f) => f.id === "poisoned_tool" && f.text.includes('"read_notes"')), name);
    assert.ok(s.findings.some((f) => f.id === "hidden_text" && f.text.includes('"sneaky"') && /Ignore all previous instructions/.test(f.text)), name);
  }
  assert.equal(server(report, "missing").liveError, "the command was not found");
  assert.match(server(report, "asleep").liveError, /no answer in 3s/);
  // Listing for an audit must not write pins: only the gatehouse proxy does that.
  assert.ok(!fs.existsSync(path.join(gatehouseHome, "pins", "wrapped-live.json")));
});

test("audit with nothing installed says so and exits clean", () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "gatehouse-audit-empty-"));
  try {
    const r = spawnSync("node", [CLI, "audit"], { cwd: empty, encoding: "utf8", env: { PATH: process.env.PATH, HOME: empty, USERPROFILE: empty, MCP_GATEHOUSE_HOME: path.join(empty, "g") } });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No MCP client config files were found/);
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});
