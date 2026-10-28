import { Download, FileText } from "lucide-react";

type Props = {
  scope: "overview" | "finding";
  runName: string | null;
  findingId?: string;
  compact?: boolean;
};

export default function ExportButtons({ scope, runName, findingId, compact = false }: Props) {
  const params = new URLSearchParams();
  if (runName) params.set("run", runName);
  if (scope === "finding" && findingId) params.set("finding", findingId);
  const base = `/api/export/${scope}?${params.toString()}`;
  const label = compact ? "Export" : scope === "overview" ? "Export report" : "Export finding";

  return (
    <div className="flex flex-wrap items-center gap-2">
      {!compact && <span className="text-xs font-medium text-[#888]">{label}</span>}
      <a
        href={`${base}&format=pdf`}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#3a3a3a] px-2.5 py-1.5 text-xs font-medium text-[#ddd] transition-colors hover:border-[#666] hover:bg-white/[0.06]"
      >
        <Download className="h-3.5 w-3.5" aria-hidden="true" /> PDF
      </a>
      <a
        href={`${base}&format=md`}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#3a3a3a] px-2.5 py-1.5 text-xs font-medium text-[#ddd] transition-colors hover:border-[#666] hover:bg-white/[0.06]"
      >
        <FileText className="h-3.5 w-3.5" aria-hidden="true" /> Markdown
      </a>
    </div>
  );
}
