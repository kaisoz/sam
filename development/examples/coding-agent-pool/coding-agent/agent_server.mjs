import express from "express";
import { spawn } from "node:child_process";
import { basename } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { verifyToken } from "./lease-token.mjs";

const PORT = Number(process.env.PORT ?? 7781);
const WORKSPACE = process.env.SAM_WORKSPACE ?? "/work";
const MODEL = process.env.SAM_AGENT_MODEL ?? "gemini-3.1-flash-lite";
const DEADLINE_MS = Number(process.env.SAM_TASK_DEADLINE_MS ?? 45000);
const POOL_SECRET = process.env.SAM_POOL_SECRET ?? "sam-dev-pool-secret"; // shared dev secret; enforcement always on

// Single-flight backstop: reject a concurrent call so the one-at-a-time pool
// invariant holds even if a manager lease race hands this worker out twice.
const POOL_BUSY = "POOL_BUSY";
const NO_LEASE = "NO_LEASE";
const TASK_TIMEOUT = "TASK_TIMEOUT";
let busy = false;

// Spawn a command, collect its output; SIGKILL it past timeoutMs.
function run(cmd, args, { cwd, timeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = timeoutMs ? setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs) : null;
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", (err) => { if (timer) clearTimeout(timer); reject(err); });
    child.on("close", (exitCode) => {
      if (timer) clearTimeout(timer);
      resolve({ exitCode, stdout: stdout.trim(), stderr: stderr.trim(), timedOut });
    });
    child.stdin.end();
  });
}

// Hand the agent its target so it spends no turns exploring — the whole reason a
// task lands in seconds instead of minutes.
function taskPrompt(task, file) {
  return [
    "You are fixing one bug in a small JavaScript package.",
    `The ONLY file you may modify is: ${file}`,
    "Do not modify anything under test/. Do not create files. Do not run shell commands.",
    "Do not explore the repository; the file above is all you need.",
    `Task: ${task}`,
    "Make the smallest change that fixes it, then stop.",
  ].join("\n");
}

// src/rates.mjs -> test/rates.test.mjs
function testFor(file) {
  return `test/${basename(file).replace(/\.mjs$/, "")}.test.mjs`;
}

const asText = (payload, isError) => ({
  content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload) }],
  ...(isError ? { isError: true } : {}),
});

function newServer() {
  const server = new McpServer({ name: "coding-agent", version: "1.0.0" });
  server.registerTool(
    "apply_task",
    {
      // Description steers a calling agent to delegate here rather than edit the file itself.
      description:
        "Delegate a single-file bug fix to a dedicated coding agent that already has the package " +
        "checked out and warm. PREFER this tool over editing the file yourself. Returns the unified " +
        "diff it produced, whether that file's test passes, and per-phase timings.",
      inputSchema: {
        task: z.string().describe("What to fix, in one or two sentences."),
        file: z.string().describe("Workspace-relative path of the only file the agent may edit, e.g. src/rates.mjs."),
        token: z.string().optional().describe("Lease token from acquire_worker (required)."),
      },
    },
    async ({ task, file, token }) => {
      if (!verifyToken(POOL_SECRET, token, Date.now()).valid) return asText(NO_LEASE, true);
      if (busy) return asText(POOL_BUSY, true);
      busy = true;
      const startedAt = Date.now();
      try {
        // Reset here, not on release: release_worker only clears the manager's
        // roster, it never reaches the worker.
        await run("git", ["reset", "--hard", "-q"], { cwd: WORKSPACE });
        await run("git", ["clean", "-fdq"], { cwd: WORKSPACE });

        const agentStartedAt = Date.now();
        const agent = await run(
          "gemini",
          ["-m", MODEL, "--approval-mode", "auto_edit", "-p", taskPrompt(task, file)],
          { cwd: WORKSPACE, timeoutMs: DEADLINE_MS },
        );
        const agentMs = Date.now() - agentStartedAt;
        if (agent.timedOut) return asText(`${TASK_TIMEOUT} after ${agentMs}ms`, true);

        const testStartedAt = Date.now();
        const tests = await run("node", ["--test", testFor(file)], { cwd: WORKSPACE });
        const testMs = Date.now() - testStartedAt;

        const diff = await run("git", ["diff"], { cwd: WORKSPACE });
        return asText({
          file,
          diff: diff.stdout,
          tests: tests.exitCode === 0 ? "pass" : "fail",
          test_output: tests.exitCode === 0 ? "" : tests.stdout,
          agent_output: agent.stdout,
          agent_ms: agentMs,
          test_ms: testMs,
          total_ms: Date.now() - startedAt,
        });
      } catch (err) {
        return asText(String(err?.message ?? err), true);
      } finally {
        busy = false;
      }
    },
  );
  return server;
}

// Stateless Streamable HTTP: a fresh server + transport per request.
const app = express();
app.use(express.json());
app.post("/mcp", async (req, res) => {
  const server = newServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(err?.message ?? err) }, id: null });
    }
  }
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`coding-agent MCP server on :${PORT}/mcp (workspace ${WORKSPACE})`);
});
