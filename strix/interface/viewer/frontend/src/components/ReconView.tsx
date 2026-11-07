import { useEffect, useMemo, useState } from "react";

interface Observation {
  id: string;
  kind: string;
  value: string;
  source: string;
  scope: string;
  attribution?: string;
  attribution_evidence?: string;
  alive: string;
  status_code: number | null;
  title: string;
  ip_addresses: string[];
  technologies: string[];
  method: string;
  evidence: string;
  confidence: string;
  screenshot?: string;
  screenshot_error?: string;
  finding_id: string;
  source_location?: string;
  source_location_type?: "local_path" | "web_url" | "";
  source_download_status?: "downloaded" | "online_only" | "";
  first_seen: string;
  last_seen: string;
}

interface CoverageRecord {
  category: string;
  status: "completed" | "not_applicable" | "blocked" | "not_run";
  tools?: string[];
  evidence?: string;
  reason?: string;
  updated_at?: string;
}

const groups = ["all", "subdomain", "javascript", "js_leak", "source_leak", "endpoint", "service", "technology", "screenshots"];
const coverageCategories = ["asset_discovery", "dns_resolution", "live_probe", "service_discovery", "web_surface", "javascript_analysis", "content_discovery", "parameter_discovery", "technology_fingerprint", "authentication_surface", "visual_capture"];
const label = (value: string) => value === "js_leak" ? "JS leak candidates" : value === "source_leak" ? "Source leaks" : value.replaceAll("_", " ");

function screenshotUrl(run: string | null, name: string) {
  return `/api/recon/screenshot?name=${encodeURIComponent(name)}${run ? `&run=${encodeURIComponent(run)}` : ""}`;
}

export default function ReconView({ runName, finished }: { runName: string | null; finished: boolean }) {
  const [entries, setEntries] = useState<Observation[]>([]);
  const [coverage, setCoverage] = useState<CoverageRecord[]>([]);
  const [requiredCoverage, setRequiredCoverage] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState("all");
  const [alive, setAlive] = useState("all");
  const [page, setPage] = useState(0);
  const [preview, setPreview] = useState<Observation | null>(null);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    setEntries([]); setCoverage([]); setRequiredCoverage([]); setLoading(true); setPreview(null); setPage(0);
    async function refresh() {
      try {
        const response = await fetch(`/api/recon${runName ? `?run=${encodeURIComponent(runName)}` : ""}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`Could not load recon (${response.status})`);
        const document = await response.json();
        if (!stopped) { setEntries(document.entries ?? []); setCoverage(document.coverage ?? []); setRequiredCoverage(document.required_coverage ?? []); setError(null); }
      } catch (e) {
        if (!stopped) setError(e instanceof Error ? e.message : "Could not load recon");
      } finally {
        if (!stopped) { setLoading(false); if (!finished) timer = setTimeout(refresh, 3000); }
      }
    }
    void refresh();
    return () => { stopped = true; clearTimeout(timer); };
  }, [runName, finished]);
  const filtered = useMemo(() => entries.filter(entry =>
    (group === "all" || (group === "screenshots" ? !!entry.screenshot : entry.kind === group)) &&
    (alive === "all" || entry.alive === alive) &&
    JSON.stringify(entry).toLowerCase().includes(query.toLowerCase())
  ), [entries, group, alive, query]);
  const visible = filtered.slice(page * 50, (page + 1) * 50);
  const exportData = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ schema_version: 1, entries: filtered, coverage, required_coverage: requiredCoverage }, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `recon-${runName ?? "current"}.json`; anchor.click(); URL.revokeObjectURL(url);
  };
  const coverageByCategory = new Map(coverage.map(item => [item.category, item]));
  const contractRequired = requiredCoverage.length > 0;
  const displayedCoverage = requiredCoverage.length > 0 ? requiredCoverage : coverageCategories;
  const missingCoverage = contractRequired ? displayedCoverage.filter(category => !coverageByCategory.has(category)) : [];
  const unresolvedCoverage = contractRequired ? displayedCoverage.filter(category => {
    const status = coverageByCategory.get(category)?.status;
    return status === "blocked" || status === "not_run";
  }) : [];
  return <section className="space-y-5">
    <div className="flex justify-between gap-4">
      <div><h2 className="text-xl font-semibold">Recon inventory</h2><p className="text-sm text-[#999]">{entries.length} observations · {entries.filter(e => e.kind === "subdomain").length} hosts · {entries.filter(e => e.screenshot).length} screenshots</p></div>
      <button onClick={exportData} className="rounded border border-[#444] px-3 text-sm">Export JSON</button>
    </div>
    <div className="rounded-lg border border-[#333] bg-white/[0.02] p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><h3 className="text-sm font-semibold">Recon coverage contract</h3><p className="text-xs text-[#999]">{contractRequired ? `${displayedCoverage.filter(category => coverageByCategory.has(category)).length}/${displayedCoverage.length} required workstreams recorded` : `${coverage.length} workstreams recorded · no mandatory contract for this scan`}</p></div>
        {(missingCoverage.length > 0 || unresolvedCoverage.length > 0) && <span className="text-xs text-amber-300">Coverage gaps remain</span>}
        {!missingCoverage.length && !unresolvedCoverage.length && contractRequired && <span className="text-xs text-emerald-400">All required workstreams closed</span>}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {displayedCoverage.map(category => {
          const item = coverageByCategory.get(category);
          const status = item?.status ?? "not_run";
          const color = status === "completed" ? "border-emerald-500/40 text-emerald-300" : status === "not_applicable" ? "border-sky-500/40 text-sky-300" : "border-amber-500/40 text-amber-300";
          return <span key={category} className={`rounded border px-2 py-1 text-xs ${color}`} title={item?.reason || item?.evidence || "Not recorded"}>{label(category)} · {status.replaceAll("_", " ")}</span>;
        })}
      </div>
    </div>
    <div className="flex flex-wrap gap-2">
      {groups.map(value => <button key={value} onClick={() => { setGroup(value); setPage(0); }} className={`rounded border px-3 py-1 text-sm capitalize ${group === value ? "border-emerald-500 text-emerald-300" : "border-[#333] text-[#aaa]"}`}>{label(value)}</button>)}
    </div>
    <div className="flex gap-3">
      <input aria-label="Search recon" placeholder="Search host, URL, IP, technology or evidence…" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} className="min-w-0 flex-1 rounded border border-[#333] bg-black px-3 py-2 text-sm" />
      <select aria-label="Alive status" value={alive} onChange={e => { setAlive(e.target.value); setPage(0); }} className="rounded border border-[#333] bg-black px-3 text-sm">
        <option value="all">All statuses</option><option value="alive">Alive</option><option value="unreachable">Unreachable</option><option value="unknown">Not checked / unknown</option>
      </select>
    </div>
    {error && <p role="alert" className="text-red-300">{error}</p>}
    {loading ? <p>Loading recon…</p> : !entries.length ? <p className="rounded border border-[#333] p-6 text-sm text-[#aaa]">No structured recon has been recorded for this run. Older runs may contain recon in agent transcripts. This does not mean the target has no attack surface.</p> : !filtered.length ? <p>No matching observations.</p> : <div className={group === "screenshots" ? "grid gap-4 sm:grid-cols-2" : "space-y-3"}>
      {visible.map(entry => <article key={entry.id} className="overflow-hidden rounded-lg border border-[#333] bg-white/[0.02] p-4">
        <div className="flex flex-wrap gap-2 text-xs text-[#999]"><span className="uppercase">{label(entry.kind)}</span><span className={entry.alive === "alive" ? "text-emerald-400" : ""}>{entry.alive}</span>{entry.status_code && <span>HTTP {entry.status_code}</span>}<span>{entry.scope}</span><span>ownership: {entry.attribution ?? "unknown"}</span><span>{entry.confidence}</span></div>
        <div className="mt-2 break-all font-mono text-sm">{entry.method && `${entry.method} `}{entry.value}</div>
        {entry.title && <p className="mt-1 text-sm">{entry.title}</p>}
        <p className="mt-1 text-xs text-[#aaa]">{[...(entry.ip_addresses ?? []), ...(entry.technologies ?? [])].join(" · ")}</p>
        {entry.kind === "source_leak" && entry.source_location && <div className="mt-3 rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
          <p className="font-semibold text-amber-300">Source artifact location ({entry.source_download_status === "downloaded" ? "downloaded" : "online only"})</p>
          {entry.source_location_type === "web_url" ? <a className="mt-1 block break-all text-sky-300 underline" href={entry.source_location} target="_blank" rel="noreferrer">{entry.source_location}</a> : <code className="mt-1 block break-all text-[#ddd]">{entry.source_location}</code>}
        </div>}
        {entry.screenshot && <button className="mt-3 block w-full" onClick={() => setPreview(entry)} aria-label={`Enlarge screenshot of ${entry.value}`}><img loading="lazy" className="max-h-56 w-full rounded object-contain object-top" src={screenshotUrl(runName, entry.screenshot)} alt={`Page capture: ${entry.value}`} /></button>}
        {!entry.screenshot && entry.kind === "subdomain" && entry.alive === "alive" && <p className="mt-2 text-xs text-amber-300">{entry.screenshot_error ? `Screenshot could not be saved (${entry.screenshot_error})` : "Screenshot not captured yet"}</p>}
        {entry.evidence && <details className="mt-2 text-sm"><summary className="cursor-pointer text-[#aaa]">Evidence</summary><pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs">{entry.evidence}</pre></details>}
        {entry.attribution_evidence && <details className="mt-2 text-sm"><summary className="cursor-pointer text-[#aaa]">Ownership evidence</summary><pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs">{entry.attribution_evidence}</pre></details>}
        <p className="mt-2 break-all text-xs text-[#777]">Source: {entry.source}</p>
        <p className="mt-1 text-xs text-[#777]">Last observed: {new Date(entry.last_seen).toLocaleString()}{entry.finding_id && ` · Finding: ${entry.finding_id}`}</p>
      </article>)}
    </div>}
    {filtered.length > 50 && <div className="flex items-center gap-4 text-sm"><button disabled={!page} onClick={() => setPage(page - 1)}>Previous</button><span>{page + 1} / {Math.ceil(filtered.length / 50)}</span><button disabled={(page + 1) * 50 >= filtered.length} onClick={() => setPage(page + 1)}>Next</button></div>}
    {preview?.screenshot && <div role="dialog" aria-modal="true" aria-label="Screenshot preview" className="fixed inset-0 z-50 flex flex-col gap-3 overflow-auto bg-black/95 p-[clamp(0.75rem,3vw,2rem)]"><button autoFocus className="self-end rounded border px-4 py-2" onClick={() => setPreview(null)}>Close</button><p className="break-all text-sm">{preview.value}</p><img className="mx-auto max-h-[78vh] max-w-full object-contain" src={screenshotUrl(runName, preview.screenshot)} alt={preview.value} /></div>}
  </section>;
}
