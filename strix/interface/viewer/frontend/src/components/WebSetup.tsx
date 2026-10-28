import { useState } from "react";
import { AlertCircle, ArrowLeft, Plus, ShieldCheck, Trash2 } from "lucide-react";
import type { WebControlState } from "@/data/serverSource";
import { webCommand } from "@/data/serverSource";

type Props = {
  control: WebControlState;
  onRefresh: () => Promise<void>;
  onStarted?: (runName: string) => void;
  onCancel?: () => void;
  embedded?: boolean;
};

export default function WebSetup({
  control,
  onRefresh,
  onStarted,
  onCancel,
  embedded = false,
}: Props) {
  const initial = control.state;
  const [target, setTarget] = useState("");
  const [instruction, setInstruction] = useState(initial.instruction);
  const [model, setModel] = useState(initial.model);
  const [apiKey, setApiKey] = useState("");
  const [apiBase, setApiBase] = useState(initial.api_base);
  const [rateLimitRequests, setRateLimitRequests] = useState(
    initial.llm_rate_limit_requests.toString(),
  );
  const [rateLimitUnit, setRateLimitUnit] = useState(initial.llm_rate_limit_unit);
  const [maxRetries, setMaxRetries] = useState(initial.llm_max_retries.toString());
  const [webSearchProvider, setWebSearchProvider] = useState(initial.web_search_provider);
  const [scanMode, setScanMode] = useState(initial.scan_mode);
  const [budget, setBudget] = useState(initial.max_budget_usd?.toString() ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(initial.error);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await onRefresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Command failed");
    } finally {
      setBusy(false);
    }
  };

  const addTarget = () => run(async () => {
    const value = target.trim();
    if (!value) throw new Error("Enter a URL, repository, local directory, domain, or API spec first.");
    await webCommand("setup.add_target", { target: value });
    setTarget("");
  });

  const saveModel = () => run(async () => {
    if (!model.trim()) throw new Error("Enter a model route first.");
    const parsedRateLimit = Number(rateLimitRequests.trim() || "0");
    if (!Number.isInteger(parsedRateLimit) || parsedRateLimit < 0) {
      throw new Error("Model rate limit must be a non-negative whole number.");
    }
    const parsedMaxRetries = Number(maxRetries.trim() || "0");
    if (!Number.isInteger(parsedMaxRetries) || parsedMaxRetries < 0) {
      throw new Error("Retry attempts must be a non-negative whole number.");
    }
    await webCommand("settings.save_llm", {
      model: model.trim(),
      ...(apiKey ? { api_key: apiKey } : {}),
      api_base: apiBase,
      rate_limit_requests: parsedRateLimit,
      rate_limit_unit: rateLimitUnit,
      max_retries: parsedMaxRetries,
    });
    setApiKey("");
  });

  const start = () => run(async () => {
    if (!initial.model) throw new Error("Configure and save a model before starting the scan.");
    await webCommand("setup.set_instruction", { instruction });
    const parsedBudget = budget.trim() ? Number(budget) : undefined;
    if (parsedBudget !== undefined && (!Number.isFinite(parsedBudget) || parsedBudget <= 0)) {
      throw new Error("Budget must be a positive number.");
    }
    await webCommand("setup.set_options", {
      scan_mode: scanMode,
      ...(parsedBudget === undefined ? {} : { max_budget_usd: parsedBudget }),
    });
    const result = await webCommand("setup.start", { mount_working_dir: false });
    const runName = typeof result.run_name === "string" ? result.run_name : "";
    onStarted?.(runName);
  });

  const saveWebSearch = () => run(async () => {
    await webCommand("settings.save_web_search", { provider: webSearchProvider });
  });

  const content = (
    <>
        <header className="space-y-2">
          {onCancel && (
            <button
              onClick={onCancel}
              className="inline-flex cursor-pointer items-center gap-1.5 text-sm text-[#888] transition-colors hover:text-white"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to runs
            </button>
          )}
          <div className="flex items-center gap-2 text-emerald-400">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Local browser control</span>
          </div>
          <h1 className="text-3xl font-semibold tracking-tight">Start a Pent6d security scan</h1>
          {initial.active_project_name ? (
            <p className="text-sm text-emerald-300">Project: {initial.active_project_name}</p>
          ) : (
            <p className="text-sm text-amber-300">Select a project before configuring its scan scope.</p>
          )}
          <p className="text-sm leading-6 text-[#a3a3a3]">
            Only add systems and source code you are authorized to assess. The scan runs locally in Docker; this browser is its control surface.
          </p>
        </header>

        {(error || initial.error) && (
          <div className="flex gap-3 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-200">
            <AlertCircle className="h-5 w-5 flex-none" aria-hidden="true" />
            <p>{error ?? initial.error}</p>
          </div>
        )}

        <section className="rounded-xl border border-[#272727] bg-[#101010] p-5 space-y-4">
          <div>
            <h2 className="font-semibold">Model</h2>
            <p className="mt-1 text-sm text-[#a3a3a3]">
              {initial.model ? `Configured: ${initial.model}` : "Configure a local provider before starting."}
            </p>
            {initial.model_warning && <p className="mt-2 text-sm text-amber-300">{initial.model_warning}</p>}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-2 text-sm font-semibold">Model route
              <input value={model} onChange={(event) => setModel(event.target.value)} placeholder="openrouter/z-ai/glm-5.3" className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
            </label>
            <label className="space-y-2 text-sm font-semibold">API key {initial.api_key_configured && <span className="font-normal text-emerald-400">configured</span>}
              <input value={apiKey} onChange={(event) => setApiKey(event.target.value)} type="password" autoComplete="new-password" placeholder={initial.api_key_configured ? "Leave empty to keep current key" : "Required by most providers"} className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
            </label>
          </div>
          <label className="block space-y-2 text-sm font-semibold">API base <span className="font-normal text-[#777]">optional</span>
            <input value={apiBase} onChange={(event) => setApiBase(event.target.value)} placeholder="https://gateway.example/v1" className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
          </label>
          <div className="rounded-lg border border-[#272727] bg-black/40 p-4 space-y-3">
            <div>
              <h3 className="text-sm font-semibold">Model request rate limit</h3>
              <p className="mt-1 text-xs leading-5 text-[#888]">
                Maximum number of model requests in the selected window. Use 0 to disable. The limit is shared by local scan worker processes.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className="space-y-2 text-sm font-semibold">Requests per window
                <input value={rateLimitRequests} onChange={(event) => setRateLimitRequests(event.target.value)} inputMode="numeric" min="0" step="1" placeholder="0" className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
              </label>
              <label className="space-y-2 text-sm font-semibold">Time unit
                <select value={rateLimitUnit} onChange={(event) => setRateLimitUnit(event.target.value as typeof rateLimitUnit)} className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white">
                  <option value="seconds">Seconds</option>
                  <option value="minutes">Minutes</option>
                  <option value="hours">Hours</option>
                </select>
              </label>
            </div>
          </div>
          <label className="block space-y-2 text-sm font-semibold">Retry attempts
            <input value={maxRetries} onChange={(event) => setMaxRetries(event.target.value)} inputMode="numeric" min="0" step="1" placeholder="5" className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
            <span className="block text-xs font-normal leading-5 text-[#888]">Retries transient provider errors only: rate limits, timeouts, connection errors, and 5xx responses. Backoff is 2s, 4s, 8s… up to 90s. Set 0 to disable.</span>
          </label>
          <button disabled={busy || !model.trim()} onClick={() => void saveModel()} className="rounded-md border border-[#444] px-4 py-2 text-sm font-semibold hover:border-[#777] disabled:opacity-50">Save local model settings</button>
        </section>

        <section className="rounded-xl border border-[#272727] bg-[#101010] p-5 space-y-4">
          <div>
            <h2 className="font-semibold">Web research</h2>
            <p className="mt-1 text-sm text-[#a3a3a3]">
              Native uses the configured OpenAI Responses model directly. DDGS is a no-key public-web fallback for any model.
            </p>
            {!initial.native_web_search_available && webSearchProvider === "native" && (
              <p className="mt-2 text-sm text-amber-300">Native search needs an OpenAI `gpt-*` model, an API key, no custom API base, and the Responses API.</p>
            )}
          </div>
          <label className="block space-y-2 text-sm font-semibold">Research provider
            <select value={webSearchProvider} onChange={(event) => setWebSearchProvider(event.target.value as typeof webSearchProvider)} className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white">
              <option value="auto">Auto (native OpenAI first, then configured provider, then free DDGS)</option>
              <option value="native">Native OpenAI web search</option>
              <option value="ddgs">DuckDuckGo / DDGS (free, no API key)</option>
              <option value="exa">Exa</option>
              <option value="perplexity">Perplexity</option>
            </select>
          </label>
          <button disabled={busy} onClick={() => void saveWebSearch()} className="rounded-md border border-[#444] px-4 py-2 text-sm font-semibold hover:border-[#777] disabled:opacity-50">Save web research settings</button>
        </section>

        <section className="rounded-xl border border-[#272727] bg-[#101010] p-5 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="font-semibold">Authorized targets</h2>
              <p className="mt-1 text-sm text-[#a3a3a3]">URLs, domains, repositories, local directories, or API specs.</p>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void addTarget(); }} placeholder="https://staging.example.com or D:\Projects\app" className="min-w-0 flex-1 rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm outline-none focus:border-white" />
            <button disabled={busy} onClick={() => void addTarget()} className="inline-flex items-center justify-center gap-2 rounded-md border border-[#444] px-4 py-2.5 text-sm font-semibold hover:border-[#777] disabled:opacity-50">
              <Plus className="h-4 w-4" aria-hidden="true" /> Add target
            </button>
          </div>
          {initial.targets.length > 0 ? <ul className="space-y-2">{initial.targets.map((value) => (
            <li key={value} className="flex items-center justify-between gap-4 rounded-md bg-black px-3 py-2 text-sm">
              <code className="min-w-0 truncate text-[#d4d4d4]">{value}</code>
              <button disabled={busy} onClick={() => void run(async () => { await webCommand("setup.remove_target", { target: value }); })} className="text-[#a3a3a3] hover:text-red-300 disabled:opacity-50" aria-label={`Remove ${value}`}><Trash2 className="h-4 w-4" /></button>
            </li>
          ))}</ul> : <p className="text-sm text-[#777]">No targets added yet.</p>}
        </section>

        <section className="rounded-xl border border-[#272727] bg-[#101010] p-5 space-y-4">
          <label className="block text-sm font-semibold" htmlFor="instruction">Instructions <span className="font-normal text-[#777]">optional</span></label>
          <textarea id="instruction" value={instruction} onChange={(event) => setInstruction(event.target.value)} rows={4} placeholder="For example: focus on authentication and authorization flows." className="w-full resize-y rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm outline-none focus:border-white" />
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-2 text-sm font-semibold">Scan depth
              <select value={scanMode} onChange={(event) => setScanMode(event.target.value as typeof scanMode)} className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white"><option value="quick">Quick</option><option value="standard">Standard</option><option value="deep">Deep</option></select>
            </label>
            <label className="space-y-2 text-sm font-semibold">Max LLM budget (USD) <span className="font-normal text-[#777]">optional</span>
              <input value={budget} onChange={(event) => setBudget(event.target.value)} inputMode="decimal" placeholder="10" className="block w-full rounded-md border border-[#333] bg-black px-3 py-2.5 text-sm font-normal outline-none focus:border-white" />
            </label>
          </div>
        </section>

        <button disabled={busy || !initial.model || initial.targets.length === 0} onClick={() => void start()} className="w-full rounded-md bg-white px-5 py-3 text-sm font-semibold text-black hover:bg-[#e5e5e5] disabled:cursor-not-allowed disabled:opacity-40">
          {busy ? "Preparing scan…" : "Verify model and start scan"}
        </button>
        {initial.messages.length > 0 && <div className="rounded-lg border border-[#272727] p-4 text-sm text-[#a3a3a3] space-y-1">{initial.messages.map((message) => <p key={message.id}>{message.text}</p>)}</div>}
    </>
  );

  if (embedded) return <section className="max-w-3xl space-y-7">{content}</section>;

  return (
    <main className="min-h-screen bg-black px-4 py-10 text-white sm:px-8">
      <section className="mx-auto max-w-3xl space-y-7">{content}</section>
    </main>
  );
}
