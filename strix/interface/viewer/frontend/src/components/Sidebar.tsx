import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Bot,
  FolderKanban,
  Radar,
  History,
  MessageSquare,
  Plus,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { McpConnectionStatus } from "@/data/serverSource";
import type { View } from "@/App";

/**
 * Persistent left rail: a black rail with a right hairline border, an
 * account-switcher-style header, a single ungrouped list of h-9 nav rows (36px
 * icon slot, 14px label, rgba(255,255,255,0.12) active fill), a hairline
 * separator, and a user footer. Drag the right edge to resize; drag past the
 * collapse threshold to hide it, then click the left pull-zone to bring it back.
 */

const MIN_WIDTH = 160;
const DEFAULT_WIDTH = 260;
const MAX_WIDTH = 400;
const COLLAPSE_THRESHOLD = 140;

const WIDTH_KEY = "pent6d_viewer_sidebar_width";
const COLLAPSE_KEY = "pent6d_viewer_sidebar_collapsed";

interface SidebarProps {
  view: View;
  onSelectView: (view: View) => void;
  issuesCount: number;
  agentCount: number;
  mcpConnections: McpConnectionStatus[];
  mcpInUse: Set<string>;
  runCount: number;
  onOpenHistory: () => void;
  onNewRun?: () => void;
  newRunActive?: boolean;
  onOpenProjects?: () => void;
  onOpenChat?: () => void;
  chatActive?: boolean;
}

function readInt(key: string, fallback: number): number {
  try {
    const raw = localStorage.getItem(key);
    const n = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

export default function Sidebar({
  view,
  onSelectView,
  issuesCount,
  agentCount,
  mcpConnections,
  mcpInUse,
  runCount,
  onOpenHistory,
  onNewRun,
  newRunActive = false,
  onOpenProjects,
  onOpenChat,
  chatActive = false,
}: SidebarProps) {
  const [width, setWidth] = useState(() => {
    const w = readInt(WIDTH_KEY, DEFAULT_WIDTH);
    return Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, w));
  });
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [isResizing, setIsResizing] = useState(false);

  const persistWidth = useCallback((w: number) => {
    setWidth(w);
    try {
      localStorage.setItem(WIDTH_KEY, String(w));
    } catch {
      /* best-effort persistence */
    }
  }, []);

  const persistCollapsed = useCallback((c: boolean) => {
    setCollapsed(c);
    try {
      localStorage.setItem(COLLAPSE_KEY, c ? "1" : "0");
    } catch {
      /* best-effort persistence */
    }
  }, []);

  const expandSidebar = useCallback(() => {
    persistCollapsed(false);
    persistWidth(DEFAULT_WIDTH);
  }, [persistCollapsed, persistWidth]);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  // Global drag handlers for the resize handle. Dragging below the collapse
  // threshold hides the rail entirely.
  useEffect(() => {
    if (!isResizing || collapsed) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newWidth = e.clientX;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setWidth(newWidth);
      } else if (newWidth > MAX_WIDTH) {
        setWidth(MAX_WIDTH);
      }
    };
    const handleMouseUp = (e: MouseEvent) => {
      const finalWidth = e.clientX;
      if (finalWidth < COLLAPSE_THRESHOLD) {
        persistCollapsed(true);
        persistWidth(DEFAULT_WIDTH);
      } else {
        persistWidth(Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, finalWidth)));
      }
      setIsResizing(false);
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing, collapsed, persistCollapsed, persistWidth]);

  return (
    <>
      {/* Left-edge pull zone: click to bring the rail back when collapsed. */}
      {collapsed && (
        <div
          className="fixed left-0 top-0 z-40 hidden h-full w-4 cursor-pointer transition-colors hover:bg-[rgba(255,255,255,0.08)] lg:block"
          onClick={expandSidebar}
          title="Expand sidebar"
        />
      )}

      <aside
        className={cn(
          "sticky top-0 z-20 hidden h-screen flex-shrink-0 flex-col overflow-hidden border-r border-[rgba(255,255,255,0.08)] bg-black lg:flex",
          !isResizing && "transition-[width] duration-200 ease-out"
        )}
        style={{ width: collapsed ? 0 : width }}
      >
        {/* Local viewer branding. */}
        <header className="relative flex flex-col gap-1 pt-1 min-w-[160px]">
          <div className="flex flex-row py-1 px-2">
            <div className="flex h-10 w-full flex-row items-center">
              <div className="flex flex-1 flex-row items-center gap-2 rounded-md py-2 pl-2.5 pr-1 min-w-0">
                <span
                  className="flex flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-cyan-500"
                  style={{ width: 20, height: 20 }}
                >
                  <span className="text-[10px] font-semibold text-white">S</span>
                </span>
                <span className="flex flex-1 flex-row items-center gap-2 min-w-0">
                  <span className="truncate min-w-0 text-[14px] font-medium text-[#ededed]">Pent6d</span>
                  <span className="flex h-5 flex-shrink-0 items-center rounded px-2 text-[11px] font-medium text-[#888] bg-[rgba(255,255,255,0.08)]">
                    Local
                  </span>
                </span>
              </div>
            </div>
          </div>
        </header>

        {/* Navigation */}
        <nav className="relative min-w-[160px] flex-1 overflow-y-auto overflow-x-clip scrollbar-thin pb-10 pt-2">
          <div className="relative flex flex-col gap-px px-2">
            {onOpenProjects && (
              <NavItem
                icon={<FolderKanban className="h-4 w-4" />}
                label="Projects"
                active={view === "projects"}
                onClick={onOpenProjects}
              />
            )}
            {onNewRun && (
              <NavItem
                icon={<Plus className="h-4 w-4" />}
                label="New run"
                active={newRunActive}
                onClick={onNewRun}
              />
            )}
            {onOpenChat && (
              <NavItem
                icon={<MessageSquare className="h-4 w-4" />}
                label="Chat with agent"
                active={chatActive}
                onClick={onOpenChat}
              />
            )}
            <NavItem
              icon={<ProjectsIcon />}
              label="Pentest Overview"
              active={view === "overview"}
              onClick={() => onSelectView("overview")}
            />
            <NavItem
              icon={<AlertTriangle className="h-4 w-4" />}
              label="Issues"
              count={issuesCount > 0 ? issuesCount : undefined}
              active={view === "issues"}
              onClick={() => onSelectView("issues")}
            />
            <NavItem
              icon={<Radar className="h-4 w-4" />}
              label="Recon"
              active={view === "recon"}
              onClick={() => onSelectView("recon")}
            />
            {agentCount > 0 && (
              <NavItem
                icon={<Bot className="h-4 w-4" />}
                label="Workflow"
                count={agentCount}
                active={view === "agents"}
                onClick={() => onSelectView("agents")}
              />
            )}
            <McpConnectionsPanel connections={mcpConnections} inUse={mcpInUse} />
            <NavItem
              icon={<History className="h-4 w-4" />}
              label="Past runs"
              count={runCount > 0 ? runCount : undefined}
              active={view === "history"}
              onClick={onOpenHistory}
            />
          </div>
        </nav>

        {/* Local-only footer. */}
        <section className="flex min-w-[160px] flex-col gap-0.5">
          <div className="relative p-2">
            <div className="flex items-center gap-2 rounded-md px-2.5 py-2">
              <span
                className="flex flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-cyan-500"
                style={{ width: 20, height: 20 }}
              >
                <span className="text-[9px] font-semibold text-white">S</span>
              </span>
              <span className="flex min-w-0 flex-1 flex-col text-left">
                <span className="truncate text-[13px] font-medium text-[#ededed]">Local viewer</span>
              </span>
            </div>
          </div>
        </section>

        {/* Resize handle */}
        <div
          className="group absolute right-0 top-0 z-30 h-full w-1 cursor-col-resize"
          onMouseDown={handleResizeStart}
        >
          <div
            className={cn(
              "absolute right-0 top-0 h-full w-px bg-[rgba(255,255,255,0.08)] transition-all duration-100",
              isResizing ? "w-0.5 bg-[rgba(255,255,255,0.3)]" : "group-hover:bg-[rgba(255,255,255,0.2)]"
            )}
          />
        </div>
      </aside>

      {/* Overlay during resize to prevent text selection. */}
      {isResizing && <div className="fixed inset-0 z-10 cursor-col-resize" />}

    </>
  );
}

interface NavItemProps {
  icon: React.ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
  count?: number;
}

function NavItem({ icon, label, active, onClick, count }: NavItemProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "group flex h-9 w-full origin-left flex-row items-center rounded-md transition-colors",
        active
          ? "bg-[rgba(255,255,255,0.12)] text-white"
          : "text-[#888] hover:bg-[rgba(255,255,255,0.06)] hover:text-[#ededed]"
      )}
    >
      <div className="grid flex-none place-content-center" style={{ width: 36, height: 36 }}>
        {icon}
      </div>
      <span className="min-w-0 flex-1 truncate text-left text-[14px] font-medium">{label}</span>
      {count != null && (
        <span className="mr-2 flex-none rounded-full border border-white/10 px-2 py-0.5 text-[10px] tabular-nums leading-none text-[#777]">
          {count}
        </span>
      )}
    </button>
  );
}

// The quarter-circle sweep frames the terminal UI cycles for an in-use
// connection, and the sub-second tick that advances them.
const SWEEP_FRAMES = ["◐", "◓", "◑", "◒"] as const;
const SWEEP_MS = 220;

/**
 * The MCP connections panel: a compact roster of Pent6d's globally configured
 * MCP servers, independent of the selected run. A header carries the
 * total count; each row exposes a simple lifecycle state:
 *   - ready: MCP is connected and currently idle;
 *   - online: a tool call is currently using that MCP;
 *   - offline: no MCP was detected, or the connection's live session died.
 *
 * "In use" is derived by the caller from the connection-tagged tool events, not
 * carried on the roster, so a call in flight shows motion with no extra signal.
 * The roster scrolls within a bounded height so a long list never blows out the
 * rail, mirroring how the nav above it scrolls.
 */
function McpConnectionsPanel({
  connections,
  inUse,
}: {
  connections: McpConnectionStatus[];
  inUse: Set<string>;
}) {
  const anyInUse = connections.some((c) => c.status !== "offline" && inUse.has(c.name));
  const [frame, setFrame] = useState(0);

  // Advance the sweep only while at least one connection is in use, so an idle
  // panel does no work.
  useEffect(() => {
    if (!anyInUse) return;
    const id = setInterval(() => setFrame((f) => (f + 1) % SWEEP_FRAMES.length), SWEEP_MS);
    return () => clearInterval(id);
  }, [anyInUse]);

  return (
    <div className="mt-1">
      <div className="flex h-7 items-center px-2 text-[11px] font-medium text-[#666]">
        MCP Connections ({connections.length})
      </div>
      <div className="max-h-48 overflow-y-auto overflow-x-clip scrollbar-thin">
        {connections.length === 0 ? (
          <div className="flex h-7 items-center gap-2 rounded-md px-2" title="No MCP connection detected">
            <span className="w-3 flex-none text-center text-[11px] leading-none text-red-400" aria-hidden="true">
              ●
            </span>
            <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-[#ededed]">MCP</span>
            <span className="flex-none text-[11px] text-red-400">offline</span>
          </div>
        ) : (
          connections.map((conn) => {
            const busy = conn.status !== "offline" && inUse.has(conn.name);
            const status = busy ? "online" : conn.status;
            const statusClass = status === "offline" ? "text-red-400" : status === "online" ? "text-cyan-400" : "text-emerald-400";
            return (
              <div
                key={conn.name}
                className="flex h-7 items-center gap-2 rounded-md px-2"
                title={conn.provider ? `${conn.name} · ${conn.provider}` : conn.name}
              >
                <span className={cn("w-3 flex-none text-center text-[11px] leading-none", statusClass)} aria-hidden="true">
                  {status === "online" ? SWEEP_FRAMES[frame] : "●"}
                </span>
                <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-[#ededed]">
                  {conn.name}
                </span>
                <span className={cn("flex-none text-[11px]", statusClass)}>{status}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

// Overview icon: a dashboard grid glyph (16x16 viewBox).
function ProjectsIcon() {
  return (
    <svg style={{ width: 16, height: 16, color: "currentcolor" }} viewBox="0 0 16 16" fill="currentColor">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M2.5 5.5V2.5H5.5V5.5H2.5ZM1 2C1 1.44772 1.44772 1 2 1H6C6.55228 1 7 1.44772 7 2V6C7 6.55228 6.55228 7 6 7H2C1.44772 7 1 6.55228 1 6V2ZM2.5 13.5V10.5H5.5V13.5H2.5ZM1 10C1 9.44772 1.44772 9 2 9H6C6.55228 9 7 9.44772 7 10V14C7 14.5523 6.55228 15 6 15H2C1.44772 15 1 14.5523 1 14V10ZM10.5 2.5V5.5H13.5V2.5H10.5ZM10 1C9.44772 1 9 1.44772 9 2V6C9 6.55228 9.44772 7 10 7H14C14.5523 7 15 6.55228 15 6V2C15 1.44772 14.5523 1 14 1H10ZM10.5 13.5V10.5H13.5V13.5H10.5ZM9 10C9 9.44772 9.44772 9 10 9H14C14.5523 9 15 9.44772 15 10V14C15 14.5523 14.5523 15 14 15H10C9.44772 15 9 14.5523 9 14V10Z"
      />
    </svg>
  );
}
