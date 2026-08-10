import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { mintToken } from "./lease-token.mjs";

const PORT = Number(process.env.PORT ?? 7780);
const NODE_URL = process.env.SAM_NODE_URL ?? "http://127.0.0.1:8080/mcp";
const API_TOKEN = process.env.SAM_API_TOKEN ?? "devtoken";
const POOL_SERVICE = process.env.SAM_POOL_SERVICE ?? "code-reviewer";
const DISCOVERY_MS = Number(process.env.SAM_DISCOVERY_MS ?? 3000);
const LEASE_MS = Number(process.env.SAM_LEASE_MS ?? 60000);
const GRACE_MISSES = Number(process.env.SAM_GRACE_MISSES ?? 2);
const POOL_SECRET = process.env.SAM_POOL_SECRET ?? "sam-dev-pool-secret"; // shared dev secret; enforcement always on
const NODE_TIMEOUT_MS = Number(process.env.SAM_NODE_TIMEOUT_MS ?? 5000);
const ACQUIRE_POLL_MS = 200;

// roster: peer_id -> { tool, leasedUntil, leaseId, missCount }.
// leasedUntil in the future = busy; leaseId fences stale releases.
const roster = new Map();
const now = () => Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let leaseSeq = 0;

// Northbound MCP client to the local node for DHT discovery. Null until connected.
let node = null;
let discovering = false;
let lastSize = -1;

// Bound an await that has no timeout of its own.
function withTimeout(promise, ms, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

// (Re)connect to the local node. The node may not be serving yet, or may restart
// under us; a bounded, retried attempt keeps that from wedging discovery forever.
async function ensureConnected() {
  if (node) return true;
  const client = new Client({ name: "pool-manager", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(NODE_URL), {
    requestInit: { headers: { "X-Sam-Authentication": `Bearer ${API_TOKEN}` } },
  });
  try {
    await withTimeout(client.connect(transport), NODE_TIMEOUT_MS, `connect ${NODE_URL}`);
    node = client;
    console.log(`connected to node ${NODE_URL}`);
    return true;
  } catch (err) {
    console.error(`connect failed: ${err?.message ?? err}`);
    try { await client.close(); } catch { /* already dead */ }
    return false;
  }
}

// Refresh the roster from DHT discovery. Preserve lease state for known peers;
// never evict a leased (busy) worker on a transient miss, and only drop a free
// worker after it has been missing for GRACE_MISSES consecutive passes.
async function discover() {
  if (discovering) return; // a slow pass must not race a reconnect
  discovering = true;
  try {
    if (!(await ensureConnected())) return;
    const res = await withTimeout(
      node.callTool({ name: "find_remote_tools", arguments: {} }),
      NODE_TIMEOUT_MS,
      "find_remote_tools",
    );
    const rows = JSON.parse(res.content[0].text); // [{peer_id, tool_name, ...}]
    const prefix = `mcp://${POOL_SERVICE}/`; // tool names are full URIs, e.g. mcp://code-reviewer/review_code
    const seen = new Set();
    for (const r of rows) {
      if (!r.peer_id || !r.tool_name || !r.tool_name.startsWith(prefix)) continue;
      seen.add(r.peer_id);
      const entry = roster.get(r.peer_id) ?? { leasedUntil: 0, leaseId: null, missCount: 0 };
      entry.tool = r.tool_name;
      entry.missCount = 0;
      roster.set(r.peer_id, entry);
    }
    for (const [peer, entry] of roster) {
      if (seen.has(peer)) continue;
      if (entry.leasedUntil > now()) continue; // busy → keep despite the miss
      entry.missCount++;
      if (entry.missCount >= GRACE_MISSES) roster.delete(peer);
    }
    // Zero workers must always say why: no rows at all points at the mesh or at
    // this node's view of it; rows that matched nothing points at the filter.
    if (!roster.size) console.error(`discovery: ${rows.length} rows from ${NODE_URL}, none matched '${prefix}'`);
    else if (roster.size !== lastSize) console.log(`discovery: ${roster.size} worker(s) in the '${POOL_SERVICE}' pool`);
    lastSize = roster.size;
  } catch (err) {
    console.error(`discovery failed: ${err?.message ?? err}`);
    node = null; // drop the session so the next pass reconnects
  } finally {
    discovering = false;
  }
}

// Pick and lease a free worker, or null. Synchronous → collision-free between awaits.
function leaseFree() {
  for (const [peer, entry] of roster) {
    if (entry.leasedUntil <= now()) {
      entry.leasedUntil = now() + LEASE_MS;
      entry.leaseId = String(++leaseSeq);
      const lease = { peer_id: peer, tool: entry.tool, lease_id: entry.leaseId };
      lease.token = mintToken(POOL_SECRET, peer, entry.leasedUntil);
      return lease;
    }
  }
  return null;
}

const server = new McpServer({ name: "pool-manager", version: "1.0.0" });

server.registerTool(
  "acquire_worker",
  {
    description:
      `Acquire (lease) a free worker from the '${POOL_SERVICE}' pool. Returns {peer_id, tool, lease_id, token}: ` +
      "call the tool via call_remote_tool — forward token in the tool arguments (the pool requires it) — then release_worker with the same peer_id and lease_id. " +
      "Blocks up to timeout_secs if all workers are busy; returns {available:false} if none free by then.",
    inputSchema: { timeout_secs: z.number().optional().describe("Max seconds to wait for a free worker (default 10).") },
  },
  async ({ timeout_secs }) => {
    const deadline = now() + (timeout_secs ?? 10) * 1000;
    for (;;) {
      const w = leaseFree();
      if (w) return { content: [{ type: "text", text: JSON.stringify(w) }] };
      if (now() >= deadline) return { content: [{ type: "text", text: JSON.stringify({ available: false }) }] };
      await sleep(ACQUIRE_POLL_MS);
    }
  },
);

server.registerTool(
  "release_worker",
  {
    description:
      "Release a worker previously acquired with acquire_worker. Pass the lease_id from acquire so a " +
      "stale release cannot clear a newer lease; released:false means the lease_id did not match.",
    inputSchema: {
      peer_id: z.string().describe("Peer id returned by acquire_worker."),
      lease_id: z.string().optional().describe("Lease id returned by acquire_worker (recommended)."),
    },
  },
  async ({ peer_id, lease_id }) => {
    const entry = roster.get(peer_id);
    let released = false;
    // Fencing: only clear if the caller holds the current lease (or no id given).
    if (entry && (lease_id === undefined || entry.leaseId === lease_id)) {
      entry.leasedUntil = 0;
      entry.leaseId = null;
      released = true;
    }
    return { content: [{ type: "text", text: JSON.stringify({ released }) }] };
  },
);

server.registerTool(
  "list_workers",
  {
    description: `List the '${POOL_SERVICE}' pool with per-worker free/busy state.`,
    inputSchema: {},
  },
  async () => {
    const workers = [...roster.entries()].map(([peer, e]) => ({ peer_id: peer, tool: e.tool, free: e.leasedUntil <= now() }));
    return { content: [{ type: "text", text: JSON.stringify(workers) }] };
  },
);

const app = express();
app.use(express.json());
app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`pool-manager MCP server on :${PORT}/mcp (pooling '${POOL_SERVICE}')`);
  // Not awaited: connecting happens inside the discovery loop so a node that is
  // slow or restarting delays discovery instead of wedging it.
  discover();
  setInterval(discover, DISCOVERY_MS);
});
