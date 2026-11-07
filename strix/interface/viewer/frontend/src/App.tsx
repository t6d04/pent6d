import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  AlertCircle,
  Bot,
  ChevronDown,
  History,
  Plus,
} from "lucide-react";
import type { Vulnerability, VulnerabilitySeverity } from "@/types/issues";
import { SEVERITY_COLORS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { ContentSection } from "@/components/vulnerability/ContentSection";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import WorkflowGraph from "@/components/live/WorkflowGraph";
import AgentDetailModal from "@/components/live/AgentDetailModal";
import { ScanPromptComposer } from "@/components/live/ScanPromptComposer";
import { severityCounts, type ParsedRunSummary } from "@/lib/local-run-parser";
import {
  fetchAll,
  fetchCapabilities,
  fetchRunSummary,
  fetchRuns,
  fetchTranscript,
  fetchWorkflow,
  fetchIssues,
  fetchWebControlState,
  fetchMcpStatus,
  webCommand,
  type LoadedRun,
  type RunsPayload,
} from "@/data/serverSource";
import WebSetup from "@/components/WebSetup";
import ProjectsView from "@/components/ProjectsView";
import { runTitle } from "@/lib/target-utils";
import Sidebar from "@/components/Sidebar";
import PastRunsView from "@/components/PastRunsView";
import { RunDetails } from "@/components/RunDetails";
import ExportButtons from "@/components/ExportButtons";
import { TrustToast } from "@/components/TrustToast";
import RunChat from "@/components/RunChat";
import ReconView from "@/components/ReconView";

export type View = "overview" | "issues" | "agents" | "history" | "new_run" | "projects" | "chat" | "recon";

const TRUST_BANNER =
  "Your findings stay on your machine. They're rendered here locally in your browser and never uploaded or stored by Pent6d.";

const SEVERITY_ORDER: VulnerabilitySeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
  "thinking",
];
const POLL_MS = 500;

function ViewerApp({
  initialRun,
  webControl,
  onRefreshWebControl,
}: {
  initialRun?: string | null;
  webControl?: NonNullable<Awaited<ReturnType<typeof fetchWebControlState>>>;
  onRefreshWebControl?: () => Promise<void>;
}) {
  const [activeRun, setActiveRun] = useState<string | null>(() => {
    if (initialRun) return initialRun;
    const project = webControl?.state.projects.find(
      (item) => item.id === webControl.state.active_project_id
    );
    return project?.run_names[0] ?? null;
  });
  const [run, setRun] = useState<LoadedRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [runs, setRuns] = useState<RunsPayload | null>(null);
  // Whether this viewer can steer a live scan (true only inside the in-TUI
  // launcher that shares the running scan's coordinator + event loop).
  const [canSteer, setCanSteer] = useState(false);
  const [canWebControl, setCanWebControl] = useState(false);
  const [mcpStatus, setMcpStatus] = useState<Awaited<ReturnType<typeof fetchMcpStatus>> | null>(null);

  const refreshRuns = useCallback(async () => {
    try {
      setRuns(await fetchRuns());
    } catch {
      /* history list is best-effort */
    }
  }, []);

  useEffect(() => {
    void refreshRuns();
    // Capabilities never change over a session, so fetch once on mount.
    fetchCapabilities()
      .then((caps) => {
        setCanSteer(caps.can_steer);
        setCanWebControl(caps.can_web_control);
      })
      .catch(() => {
        /* absence of steering is the safe default */
      });
  }, [refreshRuns]);

  // MCP is a Pent6d-wide service roster, not a property of the selected run.
  // Poll it independently so switching to an old/finished run cannot revive
  // a persisted `dead` flag from that run.
  useEffect(() => {
    let cancelled = false;
    const refreshMcp = async () => {
      try {
        const status = await fetchMcpStatus();
        if (!cancelled) setMcpStatus(status);
      } catch {
        if (!cancelled) setMcpStatus({ status: "offline", connections: [] });
      }
    };
    void refreshMcp();
    const timer = window.setInterval(() => void refreshMcp(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  // A hub can add workers after this page mounted. Refresh its shared run
  // list so a newly started worker appears without a browser reload.
  useEffect(() => {
    if (!canWebControl) return;
    const timer = window.setInterval(() => void refreshRuns(), 1000);
    return () => window.clearInterval(timer);
  }, [canWebControl, refreshRuns]);

  // Live polling, scoped to the active run. Re-runs when the active run changes
  // so switching to a past run (?run=<name>) reloads its data; a finished run
  // does a single full fetch and stops.
  const finishedRef = useRef(false);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    finishedRef.current = false;

    // A hub with no run in the selected project must not fall back to the
    // newest run from another project via the server's default endpoint.
    if (webControl && !activeRun) {
      setRun(null);
      setError(null);
      return () => {};
    }

    const schedule = () => {
      timer = setTimeout(tick, POLL_MS);
    };

    const tick = async () => {
      if (cancelled) return;
      try {
        const { summary, raw, finished } = await fetchRunSummary(activeRun);
        if (cancelled) return;
        setError(null);
        if (finished && !finishedRef.current) {
          finishedRef.current = true;
          const full = await fetchAll(activeRun);
          if (!cancelled) setRun(full);
          return; // stop polling
        }
        const [transcript, vulnerabilities, workflow] = await Promise.all([
          fetchTranscript(activeRun).catch(() => ({ agents: [], events: [] })),
          fetchIssues(summary.runId, activeRun).catch(() => [] as Vulnerability[]),
          fetchWorkflow(activeRun).catch(() => ({
            schema_version: 1,
            status: "unknown",
            phase: "created",
            recon_finalized: false,
            lanes: [],
            nodes: [],
            edges: [],
          })),
        ]);
        if (cancelled) return;
        setRun((prev) => ({
          summary,
          raw,
          finished,
          transcript,
          vulnerabilities,
          workflow,
          reportMarkdown: prev?.reportMarkdown ?? null,
        }));
        schedule();
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Could not load run data.");
        schedule();
      }
    };

    (async () => {
      try {
        const full = await fetchAll(activeRun);
        if (cancelled) return;
        setError(null);
        setRun(full);
        if (full.finished) {
          finishedRef.current = true;
        } else {
          schedule();
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Could not load run data.");
        schedule();
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeRun, webControl]);

  const counts = useMemo(
    () => (run ? severityCounts(run.vulnerabilities) : null),
    [run]
  );
  const selected = run?.vulnerabilities.find((v) => v.id === selectedId) ?? null;
  const agentCount = run?.transcript.agents.length ?? 0;

  // The global MCP roster comes from /api/mcp/status. The selected run only
  // contributes the set of connections with a tool call currently in flight.
  // "In use" is derived here from connection-tagged tool events rather than
  // carried on the global roster:
  // an MCP dispatch event carries its connection name and a status that moves
  // running -> completed, so a connection is "online" only while one of its
  // events is still running; a connected idle MCP is shown as "ready".
  const mcpConnections = mcpStatus?.connections ?? [];
  const mcpInUse = useMemo(() => {
    const inUse = new Set<string>();
    for (const event of run?.transcript.events ?? []) {
      if (event.type !== "tool") continue;
      const connection = event.data?.mcp_connection;
      if (typeof connection !== "string" || !connection) continue;
      if (event.data?.status === "running") inUse.add(connection);
    }
    return inUse;
  }, [run]);

  // Per-run guard for the default view: land on Workflow while a scan is live,
  // Overview once it finishes. Applied at most once per run and never once the
  // user has navigated manually (userSetView flips the guard).
  const initialViewAppliedRef = useRef(false);

  // Reset the guard whenever the active run changes so the newly selected run
  // gets its own default.
  useEffect(() => {
    initialViewAppliedRef.current = false;
  }, [activeRun]);

  useEffect(() => {
    if (initialViewAppliedRef.current || !run) return;
    if (run.finished) {
      initialViewAppliedRef.current = true;
      setView("overview");
    } else if (agentCount > 0) {
      // Live and agents have appeared: default to the workflow graph. If it is
      // live but no agents exist yet, wait (do not apply, do not set the flag).
      initialViewAppliedRef.current = true;
      setView("agents");
    }
  }, [run, agentCount]);

  // User-initiated navigation: mark the default guard applied so the per-run
  // default effect never yanks the user off the view they chose.
  const userSetView = useCallback((v: View) => {
    initialViewAppliedRef.current = true;
    setView(v);
  }, []);

  const selectRun = useCallback((name: string) => {
    setActiveRun(name);
    setSelectedId(null);
    setRun(null);
    setError(null);
    // Reset the guard so the per-run default applies to the newly selected run.
    initialViewAppliedRef.current = false;
  }, []);

  const openHistory = useCallback(() => {
    void refreshRuns();
    userSetView("history");
  }, [refreshRuns, userSetView]);

  const openNewRun = useCallback(() => {
    setSelectedId(null);
    userSetView("new_run");
  }, [userSetView]);

  const openProjects = useCallback(() => {
    setSelectedId(null);
    userSetView("projects");
  }, [userSetView]);

  const openChat = useCallback(() => {
    setSelectedId(null);
    userSetView("chat");
  }, [userSetView]);

  const onRunStarted = useCallback((runName: string) => {
    if (runName) selectRun(runName);
    userSetView("overview");
  }, [selectRun, userSetView]);

  const stopActiveRun = useCallback(async () => {
    if (!activeRun) throw new Error("Không xác định được run cần dừng.");
    await webCommand("run.stop", { run_name: activeRun });
    await onRefreshWebControl?.();
  }, [activeRun, onRefreshWebControl]);

  const canStopActiveRun = Boolean(
    webControl &&
      activeRun &&
      !run?.finished &&
      webControl.state.workers.some(
        (worker) => worker.run_name === activeRun && worker.state === "running"
      )
  );

  const chatWorker = webControl?.state.workers.find((worker) => worker.run_name === activeRun);
  const chatWorking = chatWorker?.state === "running";

  const refreshActiveRun = useCallback(async () => {
    if (!activeRun) return;
    const full = await fetchAll(activeRun);
    setRun(full);
    await refreshRuns();
  }, [activeRun, refreshRuns]);

  const sendChatMessage = useCallback(async (message: string) => {
    if (!activeRun) throw new Error("Không xác định được run để tiếp tục.");
    await webCommand("run.chat", { run_name: activeRun, message });
    await onRefreshWebControl?.();
  }, [activeRun, onRefreshWebControl]);

  const visibleRuns = useMemo(() => {
    if (!runs || !webControl) return runs;
    const activeProject = webControl.state.projects.find(
      (project) => project.id === webControl.state.active_project_id
    );
    if (!activeProject) return { ...runs, runs: [] };
    const knownRuns = new Set(activeProject.run_names);
    return {
      ...runs,
      runs: runs.runs.filter(
        (entry) => entry.project_id === activeProject.id || knownRuns.has(entry.name)
      ),
    };
  }, [runs, webControl]);

  useEffect(() => {
    if (!webControl || activeRun || !visibleRuns || visibleRuns.runs.length === 0) return;
    selectRun(visibleRuns.runs[0].name);
  }, [activeRun, selectRun, visibleRuns, webControl]);

  return (
    <div className="min-h-screen bg-black text-white flex">
      <Sidebar
        view={view}
        onSelectView={(v) => {
          // Clicking a sidebar view always lands on that section's top level,
          // so leaving a specific issue's detail view and clicking "Issues"
          // returns to the full findings list.
          setSelectedId(null);
          if (v === "history") openHistory();
          else userSetView(v);
        }}
        issuesCount={run?.vulnerabilities.length ?? 0}
        agentCount={agentCount}
        mcpConnections={mcpConnections}
        mcpInUse={mcpInUse}
        runCount={visibleRuns?.runs.length ?? 0}
        onOpenHistory={openHistory}
        onNewRun={webControl ? openNewRun : undefined}
        newRunActive={view === "new_run"}
        onOpenProjects={webControl ? openProjects : undefined}
        onOpenChat={webControl && activeRun ? openChat : undefined}
        chatActive={view === "chat"}
      />

      <div className="flex-1 min-w-0">
        {/* Top bar */}
        <div className="border-b border-[#222]">
          <div className="mx-auto flex w-full max-w-[min(100%,120rem)] items-center gap-1.5 px-[clamp(0.75rem,2.2vw,2.5rem)] py-4">
            <div className="flex items-center gap-1.5 opacity-90 lg:hidden">
              <img src="./logo.png" alt="Pent6d" className="w-10 h-8 object-cover" />
              <div className="text-base text-white font-medium tracking-tight">Pent6d</div>
            </div>
            {run && <LiveIndicator finished={run.finished} />}
            {webControl?.state.active_project_name && (
              <span className="ml-2 max-w-48 truncate text-sm text-[#888]">
                {webControl.state.active_project_name}
              </span>
            )}
            <div className="ml-auto flex items-center gap-3">
              {webControl && (
                <button
                  onClick={openNewRun}
                  className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-[#3a3a3a] bg-[rgba(255,255,255,0.05)] px-3 py-2 text-sm font-medium text-white transition-colors hover:border-[#555] hover:bg-[rgba(255,255,255,0.09)]"
                >
                  <Plus className="h-4 w-4" aria-hidden="true" /> New run
                </button>
              )}
              {visibleRuns && !visibleRuns.locked && visibleRuns.runs.length > 0 && (
                <RunSwitcher
                  runs={visibleRuns}
                  activeRun={activeRun}
                  launchedName={runTitle(run?.summary.targets[0] ?? null, run?.summary.runName ?? run?.summary.runId ?? "Current run")}
                  onSelect={selectRun}
                />
              )}
            </div>
          </div>
        </div>

        <div className="mx-auto w-full max-w-[min(100%,120rem)] space-y-6 px-[clamp(0.75rem,2.2vw,2.5rem)] py-[clamp(1.5rem,4vw,3rem)]">
          {error && !run && view !== "history" && !webControl && (
            <div className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {/* Keyed wrapper: re-mounts on every view / finding / run change so the
              page-in transition replays. */}
          <div
            key={`${activeRun ?? "launched"}:${view}:${selectedId ?? ""}`}
            className="animate-page-in space-y-6"
          >
          {view === "new_run" && webControl && onRefreshWebControl ? (
            <WebSetup
              embedded
              control={webControl}
              onRefresh={onRefreshWebControl}
              onStarted={onRunStarted}
              onCancel={() => userSetView("overview")}
            />
          ) : view === "projects" && webControl && onRefreshWebControl ? (
            <ProjectsView
              control={webControl}
              onRefresh={onRefreshWebControl}
              onOpenNewRun={openNewRun}
              onProjectSelected={() => {
                setActiveRun(null);
                setRun(null);
                setError(null);
                userSetView("overview");
              }}
            />
          ) : view === "history" ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-[#888]" aria-hidden="true" />
                <h1 className="text-2xl font-semibold text-white">Past runs</h1>
              </div>
              <PastRunsView
                runs={visibleRuns}
                activeRun={activeRun}
                onSelectRun={selectRun}
              />
            </div>
          ) : !run && webControl && !activeRun ? (
            <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-10 text-center">
              <p className="text-sm text-[#888]">No runs yet. Start one from the New run tab.</p>
              <button
                onClick={openNewRun}
                className="mt-4 cursor-pointer rounded-lg bg-white px-4 py-2 text-sm font-semibold text-black transition-opacity hover:opacity-90"
              >
                New run
              </button>
            </div>
          ) : !run && !error ? (
            <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-10 text-center">
              <div className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[#333] border-t-white animate-spin" />
              <p className="text-sm text-[#888]">Loading run data…</p>
            </div>
          ) : run && counts ? (
            <>
              <SummaryHeader summary={run.summary} />

              {/* Tab strip: shown on small screens where the sidebar is hidden. */}
              <div className="flex gap-5 border-b border-[#2a2a2a] lg:hidden">
                <TabButton active={view === "recon"} onClick={() => userSetView("recon")}>
                  Recon
                </TabButton>
                <TabButton active={view === "overview"} onClick={() => userSetView("overview")}>
                  Pentest Overview
                </TabButton>
                <TabButton active={view === "issues"} onClick={() => userSetView("issues")}>
                  Issues{run.vulnerabilities.length > 0 ? ` (${run.vulnerabilities.length})` : ""}
                </TabButton>
                {agentCount > 0 && (
                  <TabButton active={view === "agents"} onClick={() => userSetView("agents")}>
                    Workflow ({run.workflow.nodes.length || agentCount})
                  </TabButton>
                )}
                {webControl && activeRun && (
                  <TabButton active={view === "chat"} onClick={openChat}>
                    Chat
                  </TabButton>
                )}
              </div>

              {view === "overview" ? (
                <OverviewTab
                  summary={run.summary}
                  counts={counts}
                  total={run.vulnerabilities.length}
                  reportMarkdown={run.reportMarkdown}
                  raw={run.raw}
                  onStop={canStopActiveRun ? stopActiveRun : undefined}
                  runName={activeRun}
                />
              ) : view === "recon" ? (
                <ReconView runName={activeRun} finished={run.finished} />
              ) : view === "chat" && activeRun && webControl ? (
                <RunChat
                  runName={activeRun}
                  transcript={run.transcript}
                  working={chatWorking === true}
                  exitCode={chatWorker?.state === "exited" ? chatWorker.return_code : null}
                  onSend={sendChatMessage}
                  onRefresh={refreshActiveRun}
                  onRefreshControl={onRefreshWebControl}
                />
              ) : view === "agents" && agentCount > 0 ? (
                <AgentsTab run={run} canSteer={canSteer} />
              ) : selected ? (
                <div className="space-y-4">
                  <button
                    onClick={() => setSelectedId(null)}
                    className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] hover:text-white transition-colors"
                  >
                    <ArrowLeft className="w-4 h-4" /> Back to all findings
                  </button>
                  <VulnerabilityDetail vulnerability={selected} runName={activeRun} />
                </div>
              ) : (
                <FindingsList
                  vulnerabilities={run.vulnerabilities}
                  finished={run.finished}
                  onSelect={(id) => setSelectedId(id)}
                />
              )}
            </>
          ) : null}
          </div>
        </div>
      </div>
      <TrustToast message={TRUST_BANNER} />
    </div>
  );
}

function RunSwitcher({
  runs,
  activeRun,
  launchedName,
  onSelect,
}: {
  runs: RunsPayload;
  activeRun: string | null;
  launchedName: string;
  onSelect: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const activeEntry = runs.runs.find((r) => r.name === activeRun);
  const current = activeEntry ? runTitle(activeEntry.target, activeEntry.name) : launchedName;
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="Switch pentest"
        className="flex items-center gap-2 rounded-lg border border-[#3a3a3a] bg-[rgba(255,255,255,0.05)] px-3 py-2 text-sm text-white transition-colors hover:border-[#555] hover:bg-[rgba(255,255,255,0.09)]"
      >
        <History className="h-4 w-4 flex-shrink-0 text-[#888]" aria-hidden="true" />
        <span className="flex-shrink-0 text-[#888]">Pentest</span>
        <span className="max-w-[min(32rem,42vw)] truncate font-medium">{current}</span>
        <ChevronDown className="h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />
      </button>
      {open && (
        <div
          className="absolute right-0 z-50 mt-2 max-h-[min(70vh,32rem)] w-[min(28rem,calc(100vw-1.5rem))] overflow-y-auto rounded-xl py-1.5 shadow-2xl"
          style={{ border: "1px solid #3a3a3a", background: "#0a0a0a" }}
        >
          <div className="border-b border-[#222] px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-[#666]">
            Switch pentest
          </div>
          {runs.runs.map((r) => {
            const active = r.name === activeRun;
            return (
              <button
                key={r.name}
                onMouseDown={() => onSelect(r.name)}
                className={`flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm transition-colors hover:bg-[rgba(255,255,255,0.06)] ${
                  active ? "bg-[rgba(255,255,255,0.04)] text-white" : "text-[#aaa]"
                }`}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{runTitle(r.target, r.name)}</span>
                  {r.target && <span className="block truncate font-mono text-xs text-[#666]">{r.target}</span>}
                </span>
                {active && <span className="h-2 w-2 flex-shrink-0 rounded-full bg-emerald-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function LiveIndicator({ finished }: { finished: boolean }) {
  if (finished) {
    return (
      <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-[#888]">
        <span className="w-1.5 h-1.5 rounded-full bg-[#555]" />
        Complete
      </span>
    );
  }
  return (
    <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-emerald-400">
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
      </span>
      Live
    </span>
  );
}

function formatDuration(seconds: number | null): string | null {
  if (seconds == null) return null;
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function SummaryHeader({ summary }: { summary: ParsedRunSummary }) {
  const duration = formatDuration(summary.durationSeconds);
  return (
    <div>
      <h1 className="text-2xl font-semibold text-white">
        {runTitle(summary.targets[0] ?? null, summary.runName ?? summary.runId ?? "Pentest results")}
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[#888]">
        {summary.targets.length > 0 && (
          <span className="font-mono text-[#aaa]">{summary.targets.join(", ")}</span>
        )}
        {summary.scanMode && <Meta label={summary.scanMode} />}
        {duration && <Meta label={duration} />}
        {summary.status && <Meta label={summary.status} />}
      </div>
    </div>
  );
}

function Meta({ label }: { label: string }) {
  return (
    <>
      <span className="text-[#333]">·</span>
      <span className="capitalize">{label}</span>
    </>
  );
}

function FindingsList({
  vulnerabilities,
  finished,
  onSelect,
}: {
  vulnerabilities: Vulnerability[];
  finished: boolean;
  onSelect: (id: string) => void;
}) {
  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-8 text-center text-sm text-[#888]">
          {finished ? "No findings in this run." : "No findings yet. The pentest is still running…"}
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {sorted.map((v) => (
        <button
          key={v.id}
          onClick={() => onSelect(v.id)}
          className="animate-card-in cursor-pointer w-full text-left rounded-lg border border-[#222] hover:border-[#444] bg-[rgba(255,255,255,0.02)] px-4 py-3 transition-colors flex items-center gap-3"
        >
          <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${getSeverityDot(v.severity)}`} aria-hidden="true" />
          <span className="flex-1 min-w-0">
            <span className="block text-sm font-medium text-white truncate">{v.title}</span>
            {v.target && (
              <span className="block text-xs text-[#666] font-mono truncate">{v.target}</span>
            )}
          </span>
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${SEVERITY_COLORS[v.severity]}`}
          >
            {v.severity === "informational" ? "Information" : v.severity}
          </span>
        </button>
      ))}
    </div>
  );
}

/** Strip a single leading markdown heading (report sections embed their own). */
function stripLeadingHeading(md: string): string {
  return md.replace(/^\s*#{1,6}[ \t]+.*(?:\r?\n)+/, "").trimStart();
}

function dedupeHeadings(md: string): string {
  const out: string[] = [];
  let lastHeading: string | null = null;
  for (const line of md.split("\n")) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) {
      const norm = m[1].trim().toLowerCase();
      if (norm === lastHeading) continue;
      lastHeading = norm;
    } else if (line.trim() !== "") {
      lastHeading = null;
    }
    out.push(line);
  }
  return out.join("\n");
}

function OverviewTab({
  summary,
  counts,
  total,
  reportMarkdown,
  raw,
  onStop,
  runName,
}: {
  summary: ParsedRunSummary;
  counts: Record<VulnerabilitySeverity, number>;
  total: number;
  reportMarkdown: string | null;
  raw: Record<string, unknown>;
  onStop?: () => Promise<void>;
  runName: string | null;
}) {
  const sections = (
    [
      ["Executive Summary", summary.executiveSummary],
      ["Technical Analysis", summary.technicalAnalysis],
      ["Methodology", summary.methodology],
      ["Recommendations", summary.recommendations],
    ] as const
  )
    .filter(([, content]) => !!content)
    .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }));

  return (
    <div className="space-y-6">
      <div className="animate-card-in">
        <RunDetails raw={raw} durationSeconds={summary.durationSeconds} onStop={onStop} />
      </div>

      <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] px-5 py-3">
        <ExportButtons scope="overview" runName={runName} />
      </div>

      {total > 0 && (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <IssueSeveritySummary findings={{ total, ...counts }} />
        </div>
      )}

      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 space-y-8">
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : (
        total === 0 && (
          <p className="text-sm text-[#888]">No summary available for this run yet.</p>
        )
      )}

    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer relative pb-2.5 text-sm font-semibold transition-colors ${
        active ? "text-white" : "text-[#666] hover:text-white"
      }`}
    >
      {children}
      {active && <span className="absolute bottom-0 inset-x-0 h-0.5 bg-white rounded-full" />}
    </button>
  );
}

function AgentsTab({ run, canSteer }: { run: LoadedRun; canSteer: boolean }) {
  const { agents, events } = run.transcript;
  // Clicking a graph node opens the agent's transcript in a modal; no node selected means no modal.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedAgent = selectedId ? (agents.find((a) => a.id === selectedId) ?? null) : null;
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);
  const selectedWorkflow = run.workflow.nodes.find((node) => node.id === selectedWorkflowId) ?? null;

  // Live steering is only possible in-process (canSteer) while the scan runs.
  const steerable = canSteer && !run.finished;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[#888]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-white">Pentest workflow</h2>
          <span className="text-xs text-[#666]">
            {run.workflow.nodes.length} node{run.workflow.nodes.length === 1 ? "" : "s"}
          </span>
        </div>
        <p className="mt-1 mb-4 text-xs text-[#666]">
          Lane shows the stage. Each node records its type, status, source evidence and dependencies.
        </p>
        <div className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-[#687579]">
          <span><i className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-blue-500" />running</span>
          <span><i className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />succeeded</span>
          <span><i className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />blocked</span>
          <span><i className="mr-1 inline-block w-4 border-t border-cyan-400" />dependency</span>
          <span><i className="mr-1 inline-block w-4 border-t border-dashed border-slate-500" />source</span>
          <span><i className="mr-1 inline-block w-4 border-t border-violet-400" />agent</span>
          <span><i className="mr-1 inline-block w-4 border-t border-amber-400" />assignment</span>
          <span><i className="mr-1 inline-block w-4 border-t border-orange-400" />impact</span>
          <span><i className="mr-1 inline-block w-4 border-t border-yellow-400" />chain/report</span>
        </div>
        <div className="h-[clamp(22rem,62vh,48rem)] min-h-[20rem] overflow-hidden rounded-lg border border-[#1a1a1a]">
          <WorkflowGraph
            workflow={run.workflow}
            selectedNodeId={selectedWorkflowId ?? (selectedId ? `agent:${selectedId}` : null)}
            onSelectNode={(id) => {
              setSelectedWorkflowId(id);
              if (id?.startsWith("agent:")) {
                setSelectedId(id.slice("agent:".length));
              } else {
                setSelectedId(null);
              }
            }}
          />
        </div>
        {selectedWorkflow && (
          <div className="mt-3 rounded-lg border border-[#222] bg-black/40 p-3 text-xs text-[#aaa]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-white">{selectedWorkflow.label}</span>
              <span className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-[#bbb] border border-[#333]">
                {selectedWorkflow.status}
              </span>
            </div>
            <div className="mt-2 grid gap-1 sm:grid-cols-2">
              <span>Type: {selectedWorkflow.type}</span>
              <span>Risk: {selectedWorkflow.risk}</span>
              <span>Generated by: {selectedWorkflow.generated_by ?? "Planner/root"}</span>
              <span>Attempts: {selectedWorkflow.attempts}</span>
              <span>Information: {selectedWorkflow.source_information.length || "none"}</span>
              <span>Dependencies: {selectedWorkflow.dependencies.length || "none"}</span>
            </div>
            <div className="mt-2 space-y-1 border-t border-[#222] pt-2">
              <div>Source nodes: {selectedWorkflow.source_nodes.length ? selectedWorkflow.source_nodes.join(", ") : "none"}</div>
              <div>Evidence IDs: {selectedWorkflow.source_information.length ? selectedWorkflow.source_information.join(", ") : "none"}</div>
            </div>
          </div>
        )}
      </div>

      {/* Live steering: only in-process while the scan runs. Otherwise omitted. */}
      {steerable && <ScanPromptComposer agents={agents} />}

      <AgentDetailModal
        open={selectedAgent !== null}
        agent={selectedAgent}
        events={events}
        steerable={steerable}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}

/**
 * Detect the browser-first runtime before mounting the legacy report viewer.
 * A normal ``strix view`` server returns 404 for this endpoint and keeps its
 * existing behaviour untouched.
 */
export default function App() {
  const [webControl, setWebControl] = useState<Awaited<ReturnType<typeof fetchWebControlState>> | undefined>(undefined);
  const [controlError, setControlError] = useState<string | null>(null);

  const refreshWebControl = useCallback(async () => {
    try {
      const state = await fetchWebControlState();
      setWebControl(state);
      setControlError(null);
    } catch (cause) {
      setControlError(cause instanceof Error ? cause.message : "Could not reach local scan control.");
    }
  }, []);

  useEffect(() => {
    void refreshWebControl();
  }, [refreshWebControl]);

  if (webControl === undefined) {
    return <div className="min-h-screen bg-black text-[#a3a3a3] grid place-items-center text-sm">Loading Pent6d…</div>;
  }

  if (webControl) {
    return <ViewerApp webControl={webControl} onRefreshWebControl={refreshWebControl} />;
  }

  if (controlError && webControl) {
    return <div className="min-h-screen bg-black text-red-200 grid place-items-center px-6 text-sm">{controlError}</div>;
  }

  return <ViewerApp />;
}
