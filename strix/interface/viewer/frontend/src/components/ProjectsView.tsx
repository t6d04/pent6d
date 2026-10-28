import { useState } from "react";
import { FolderPlus, Plus } from "lucide-react";
import type { WebControlState } from "@/data/serverSource";
import { webCommand } from "@/data/serverSource";

type Props = {
  control: WebControlState;
  onRefresh: () => Promise<void>;
  onOpenNewRun: () => void;
  onProjectSelected: () => void;
};

export default function ProjectsView({ control, onRefresh, onOpenNewRun, onProjectSelected }: Props) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { projects, active_project_id: activeProjectId } = control.state;

  const create = async () => {
    const value = name.trim();
    if (!value) return;
    setBusy(true);
    setError(null);
    try {
      await webCommand("project.create", { name: value });
      setName("");
      await onRefresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create project.");
    } finally {
      setBusy(false);
    }
  };

  const select = async (projectId: string) => {
    setBusy(true);
    setError(null);
    try {
      await webCommand("project.select", { project_id: projectId });
      await onRefresh();
      onProjectSelected();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not switch project.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="max-w-3xl space-y-6">
      <header>
        <div className="flex items-center gap-2 text-emerald-400">
          <FolderPlus className="h-5 w-5" aria-hidden="true" />
          <span className="text-sm font-semibold">Project scopes</span>
        </div>
        <h1 className="mt-2 text-2xl font-semibold text-white">Projects</h1>
        <p className="mt-1 text-sm text-[#888]">
          A project owns its authorized targets, scan settings, and run history.
        </p>
      </header>

      <div className="rounded-xl border border-[#272727] bg-[#101010] p-5">
        <label className="text-sm font-semibold text-white">New project</label>
        <div className="mt-3 flex flex-col gap-2 sm:flex-row">
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") void create(); }}
            placeholder="e.g. Customer portal staging"
            className="min-w-0 flex-1 rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm text-white outline-none focus:border-white"
          />
          <button
            disabled={busy || !name.trim()}
            onClick={() => void create()}
            className="inline-flex cursor-pointer items-center justify-center gap-2 rounded-md bg-white px-4 py-2.5 text-sm font-semibold text-black disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus className="h-4 w-4" aria-hidden="true" /> Create project
          </button>
        </div>
        {error && <p className="mt-3 text-sm text-red-300">{error}</p>}
      </div>

      <div className="space-y-2">
        {projects.map((project) => {
          const active = project.id === activeProjectId;
          return (
            <div
              key={project.id}
              className={`flex items-center gap-4 rounded-xl border p-4 ${active ? "border-emerald-500/40 bg-emerald-500/[0.05]" : "border-[#272727] bg-[#101010]"}`}
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <h2 className="truncate text-sm font-semibold text-white">{project.name}</h2>
                  {active && <span className="rounded-full border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-emerald-400">Active</span>}
                </div>
                <p className="mt-1 text-xs text-[#777]">
                  {project.targets.length} target{project.targets.length === 1 ? "" : "s"} · {project.run_count} run{project.run_count === 1 ? "" : "s"}
                </p>
              </div>
              {active ? (
                <button onClick={onOpenNewRun} className="cursor-pointer rounded-md border border-[#444] px-3 py-2 text-xs font-semibold text-white hover:border-[#777]">New run</button>
              ) : (
                <button disabled={busy} onClick={() => void select(project.id)} className="cursor-pointer rounded-md border border-[#444] px-3 py-2 text-xs font-semibold text-white hover:border-[#777] disabled:opacity-50">Open</button>
              )}
            </div>
          );
        })}
        {projects.length === 0 && <p className="rounded-xl border border-[#272727] bg-[#101010] p-6 text-sm text-[#888]">Create a project before starting a scan.</p>}
      </div>
    </section>
  );
}
