import type { Vulnerability } from "@/types/issues";
import {
  parseRunJson,
  parseVulnerabilitiesJson,
  type ParsedRunSummary,
} from "@/lib/local-run-parser";

/**
 * Data seam for the local viewer: fetches against the local Python server's
 * JSON endpoints (same origin, relative URLs), producing the in-memory
 * `LoadedRun` shape the UI renders plus a `finished` flag driving live polling.
 *
 * The server serves a live in-progress run and a finished one identically; the
 * only signal is `run.finished`.
 */

/** A transcript agent as emitted by GET /api/transcript (already parsed). */
export interface TranscriptAgent {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Chat/tool event data as emitted by GET /api/transcript. */
export interface TranscriptEvent {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface Transcript {
  agents: TranscriptAgent[];
  events: TranscriptEvent[];
}

export interface WorkflowLane {
  id: string;
  label: string;
  order: number;
  active: boolean;
  node_count: number;
}

export interface WorkflowNode {
  id: string;
  label: string;
  type: string;
  role: string;
  phase: string;
  lane: string;
  status: string;
  risk: string;
  dispatch_key: string;
  dependencies: string[];
  source_nodes: string[];
  source_information: string[];
  generated_by: string | null;
  attempts: number;
  created_at: string | null;
  updated_at: string | null;
  metadata: Record<string, unknown>;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}

export interface WorkflowGraph {
  schema_version: number;
  status: string;
  phase: string;
  recon_finalized: boolean;
  lanes: WorkflowLane[];
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
}

/**
 * One global MCP connection's non-secret status.  This is returned by
 * `/api/mcp/status` and is intentionally independent of any persisted run.
 * The optional `dead` field remains for compatibility with older run payloads.
 */
export interface McpConnectionStatus {
  name: string;
  provider: string | null;
  toolCount: number;
  status: "ready" | "online" | "offline";
  dead?: boolean;
}

export interface McpStatusPayload {
  status: "ready" | "online" | "offline";
  connections: McpConnectionStatus[];
}

/**
 * Read the MCP connection roster out of a raw run record. Tolerates the field
 * being absent (older runs, or a run with no MCP) and any malformed entry,
 * yielding an empty list rather than throwing.
 */
export function parseMcpConnectionStatus(raw: Record<string, unknown>): McpConnectionStatus[] {
  const list = raw?.mcp_connection_status;
  if (!Array.isArray(list)) return [];
  return list.flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const record = entry as Record<string, unknown>;
    const name = typeof record.name === "string" ? record.name.trim() : "";
    if (!name) return [];
    const provider = typeof record.provider === "string" && record.provider.trim() ? record.provider.trim() : null;
    const toolCount = typeof record.tool_count === "number" ? record.tool_count : 0;
    const dead = record.dead === true;
    const rawStatus = record.status;
    const status: McpConnectionStatus["status"] =
      rawStatus === "online" || rawStatus === "offline"
        ? rawStatus
        : dead
          ? "offline"
          : "ready";
    return [{ name, provider, toolCount, status, dead }];
  });
}

export interface LoadedRun {
  summary: ParsedRunSummary;
  /** Whole raw run record (for llm_usage, targets_info details, etc.). */
  raw: Record<string, unknown>;
  finished: boolean;
  vulnerabilities: Vulnerability[];
  reportMarkdown: string | null;
  transcript: Transcript;
  workflow: WorkflowGraph;
}

async function getJson(path: string): Promise<unknown> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} responded ${res.status}`);
  return res.json();
}

/** Read the MCP roster shared by Pent6d, not the status persisted by a run. */
export async function fetchMcpStatus(): Promise<McpStatusPayload> {
  const obj = (await getJson("/api/mcp/status")) as Partial<McpStatusPayload>;
  const rawConnections = Array.isArray(obj?.connections) ? obj.connections : [];
  const connections = rawConnections.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const record = entry as Partial<McpConnectionStatus>;
    if (typeof record.name !== "string" || !record.name.trim()) return [];
    const status = record.status === "offline" || record.status === "online" ? record.status : "ready";
    const rawToolCount = (entry as { tool_count?: unknown }).tool_count;
    return [{
      name: record.name.trim(),
      provider: typeof record.provider === "string" && record.provider.trim() ? record.provider.trim() : null,
      toolCount: typeof record.toolCount === "number" ? record.toolCount : typeof rawToolCount === "number" ? rawToolCount : 0,
      status,
    }];
  });
  return {
    status: obj?.status === "ready" || obj?.status === "online" ? obj.status : "offline",
    connections,
  };
}

/** Build a ``?run=<name>`` suffix for run-scoped data endpoints. */
function runQuery(runName?: string | null): string {
  return runName ? `?run=${encodeURIComponent(runName)}` : "";
}

export async function fetchRunSummary(runName?: string | null): Promise<{
  summary: ParsedRunSummary;
  raw: Record<string, unknown>;
  finished: boolean;
}> {
  const raw = (await getJson("/api/run" + runQuery(runName))) as Record<string, unknown>;
  // parseRunJson tolerates extra keys and takes raw TEXT.
  const summary = parseRunJson(JSON.stringify(raw));
  const finished = raw.finished === true;
  return { summary, raw, finished };
}

export async function fetchIssues(
  runId: string | null,
  runName?: string | null
): Promise<Vulnerability[]> {
  const arr = await getJson("/api/issues" + runQuery(runName));
  return parseVulnerabilitiesJson(JSON.stringify(arr), runId);
}

/** Backwards-compatible alias for consumers that still use the old name. */
export const fetchVulnerabilities = fetchIssues;

export async function fetchReportMarkdown(runName?: string | null): Promise<string | null> {
  const obj = (await getJson("/api/report" + runQuery(runName))) as { markdown?: string };
  return obj?.markdown ?? null;
}

export async function fetchTranscript(runName?: string | null): Promise<Transcript> {
  const obj = (await getJson("/api/transcript" + runQuery(runName))) as Partial<Transcript>;
  return {
    agents: Array.isArray(obj?.agents) ? obj.agents : [],
    events: Array.isArray(obj?.events) ? obj.events : [],
  };
}

export async function fetchWorkflow(runName?: string | null): Promise<WorkflowGraph> {
  const obj = (await getJson("/api/workflow" + runQuery(runName))) as Partial<WorkflowGraph>;
  return {
    schema_version: typeof obj.schema_version === "number" ? obj.schema_version : 1,
    status: typeof obj.status === "string" ? obj.status : "unknown",
    phase: typeof obj.phase === "string" ? obj.phase : "created",
    recon_finalized: obj.recon_finalized === true,
    lanes: Array.isArray(obj.lanes) ? (obj.lanes as WorkflowLane[]) : [],
    nodes: Array.isArray(obj.nodes) ? (obj.nodes as WorkflowNode[]) : [],
    edges: Array.isArray(obj.edges) ? (obj.edges as WorkflowEdge[]) : [],
  };
}

/** One-shot fetch of every endpoint (used on mount and on final settle). */
export async function fetchAll(runName?: string | null): Promise<LoadedRun> {
  const { summary, raw, finished } = await fetchRunSummary(runName);
  const [vulnerabilities, reportMarkdown, transcript, workflow] = await Promise.all([
    fetchIssues(summary.runId, runName).catch(() => [] as Vulnerability[]),
    fetchReportMarkdown(runName).catch(() => null),
    fetchTranscript(runName).catch(() => ({ agents: [], events: [] }) as Transcript),
    fetchWorkflow(runName).catch(() => emptyWorkflow()),
  ]);
  return { summary, raw, finished, vulnerabilities, reportMarkdown, transcript, workflow };
}

function emptyWorkflow(): WorkflowGraph {
  return {
    schema_version: 1,
    status: "unknown",
    phase: "created",
    recon_finalized: false,
    lanes: [],
    nodes: [],
    edges: [],
  };
}

// ---------------------------------------------------------------------------
// Run history + email auth + report send
//
// These endpoints back the "Your runs" sidebar section. Auth and report-send
// responses carry a meaningful JSON body on non-2xx statuses (an ``error``
// code), so they read the body regardless of status rather than throwing.
// ---------------------------------------------------------------------------

export interface RunSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RunListEntry {
  name: string;
  target: string | null;
  scan_mode: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  finished: boolean;
  project_id?: string | null;
  project_name?: string | null;
  severity_counts: RunSeverityCounts;
}

export interface RunsPayload {
  locked: boolean;
  count: number;
  runs: RunListEntry[];
}

export interface AuthStatus {
  verified: boolean;
  email: string | null;
}

export type OtpStartResult = { ok: true } | { ok: false; error: string };
export type OtpVerifyResult =
  | { verified: true; email: string }
  | { verified: false; error: string };
export type SendReportResult =
  | { ok: true; password: string; filename: string }
  | { ok: false; error: string };

async function postJson(
  path: string,
  body: Record<string, unknown>
): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body */
  }
  return { ok: res.ok, status: res.status, data };
}

export async function fetchRuns(): Promise<RunsPayload> {
  const obj = (await getJson("/api/runs")) as Partial<RunsPayload>;
  return {
    locked: obj?.locked ?? true,
    count: typeof obj?.count === "number" ? obj.count : 0,
    runs: Array.isArray(obj?.runs) ? (obj.runs as RunListEntry[]) : [],
  };
}

export interface Capabilities {
  can_steer: boolean;
  can_web_control: boolean;
}

export type SteerResult = { ok: true } | { ok: false; error: string };

/** GET /api/capabilities. can_steer is true only inside a live in-TUI scan. */
export async function fetchCapabilities(): Promise<Capabilities> {
  const obj = (await getJson("/api/capabilities")) as Partial<Capabilities>;
  return {
    can_steer: obj?.can_steer === true,
    can_web_control: obj?.can_web_control === true,
  };
}

/** POST /api/agents/steer. Sends a steering instruction to a running agent. */
export async function steerAgent(agentId: string, message: string): Promise<SteerResult> {
  const { ok, data } = await postJson("/api/agents/steer", {
    agent_id: agentId,
    message,
  });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
  const obj = (await getJson("/api/auth/status")) as Partial<AuthStatus>;
  return { verified: obj?.verified === true, email: obj?.email ?? null };
}

export async function otpStart(email: string): Promise<OtpStartResult> {
  const { ok, data } = await postJson("/api/auth/otp/start", { email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function otpVerify(email: string, code: string): Promise<OtpVerifyResult> {
  const { ok, data } = await postJson("/api/auth/otp/verify", { email, code });
  if (ok && data.verified === true) {
    return { verified: true, email: String(data.email ?? email) };
  }
  return { verified: false, error: String(data.error ?? "invalid_code") };
}

export async function forgetAuth(): Promise<void> {
  await postJson("/api/auth/forget", {});
}

export async function sendReport(runName?: string | null): Promise<SendReportResult> {
  const { ok, data } = await postJson("/api/report/send", runName ? { run: runName } : {});
  if (ok && data.ok === true) {
    return {
      ok: true,
      password: String(data.password ?? ""),
      filename: String(data.filename ?? "pent6d-report.pdf"),
    };
  }
  return { ok: false, error: String(data.error ?? "unavailable") };
}

// ---------------------------------------------------------------------------
// Browser-first local control plane (`strix web`)
// ---------------------------------------------------------------------------

export interface WebControlState {
  enabled: boolean;
  state: {
    setup_mode: boolean;
    scan_started: boolean;
    scan_state: string;
    targets: string[];
    instruction: string;
    scan_mode: "quick" | "standard" | "deep";
    max_budget_usd: number | null;
    scope_mode: "auto" | "diff" | "full";
    diff_base: string | null;
    active_project_id: string | null;
    active_project_name: string | null;
    projects: Array<{
      id: string;
      name: string;
      targets: string[];
      run_names: string[];
      run_count: number;
      updated_at: string | null;
    }>;
    model: string;
    api_key_configured: boolean;
    api_base: string;
    llm_rate_limit_requests: number;
    llm_rate_limit_unit: "seconds" | "minutes" | "hours";
    llm_max_retries: number;
    /**
     * Names of saved custom model request headers. Values are never sent to
     * the browser, so an existing row can only keep or replace its value.
     */
    llm_extra_headers: string[];
    web_search_provider: "auto" | "native" | "ddgs" | "exa" | "perplexity";
    native_web_search_available: boolean;
    model_warning: string;
    messages: Array<{ id: string; text: string; level: string }>;
    error: string | null;
    workers: Array<{
      run_name: string;
      pid: number;
      state: "running" | "stopping" | "exited";
      return_code: number | null;
    }>;
  };
}

export async function fetchWebControlState(): Promise<WebControlState | null> {
  const res = await fetch("/api/web/state", { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`/api/web/state responded ${res.status}`);
  return (await res.json()) as WebControlState;
}

export async function webCommand(
  command: string,
  payload: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const { ok, data } = await postJson("/api/web/command", { command, payload });
  if (!ok || data.ok !== true) throw new Error(String(data.error ?? "Command failed"));
  return (data.result && typeof data.result === "object" ? data.result : {}) as Record<string, unknown>;
}
