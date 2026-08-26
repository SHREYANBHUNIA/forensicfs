import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";
import type { ForensicTimelineEvent } from "@shared/forensics";
import {
  AlertTriangle,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  Clock3,
  Database,
  FileSearch,
  Files,
  FolderTree,
  Grid2X2,
  HardDrive,
  Loader2,
  PanelRightOpen,
  Plus,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useMemo, useState } from "react";

type View = "overview" | "files" | "directory" | "timeline";

const views: { id: View; label: string; icon: typeof Grid2X2 }[] = [
  { id: "overview", label: "Overview", icon: Grid2X2 },
  { id: "files", label: "File records", icon: Files },
  { id: "directory", label: "Directory map", icon: FolderTree },
  { id: "timeline", label: "Timeline", icon: Clock3 },
];

function bytes(value: number) {
  if (value >= 1024 * 1024 * 1024) return `${(value / 1024 ** 3).toFixed(1)} GB`;
  if (value >= 1024 * 1024) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${value.toLocaleString()} B`;
}

function stamp(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(value));
}

function severityClass(value: string) {
  return value === "high" ? "border-red-700 bg-red-700 text-white" : value === "medium" ? "border-red-200 bg-red-50 text-red-800" : "border-stone-200 bg-stone-100 text-stone-700";
}

function eventLabel(event: ForensicTimelineEvent) {
  return event.eventType === "created" ? "FILE CREATED" : event.eventType === "modified" ? "FILE MODIFIED" : event.eventType === "accessed" ? "FILE ACCESSED" : event.eventType === "changed" ? "METADATA CHANGED" : "FILE DELETED";
}

export default function Home() {
  const { data: workspace, isLoading } = trpc.forensic.workspace.useQuery(undefined, { staleTime: 60_000 });
  const [view, setView] = useState<View>("overview");
  const [search, setSearch] = useState("");

  const files = useMemo(() => {
    if (!workspace) return [];
    const term = search.trim().toLowerCase();
    return term ? workspace.files.filter((file) => `${file.path} ${file.signature ?? ""} ${file.allocationState}`.toLowerCase().includes(term)) : workspace.files;
  }, [workspace, search]);

  if (isLoading || !workspace) {
    return <div className="min-h-screen grid place-items-center"><Loader2 className="h-5 w-5 animate-spin text-red-700" /></div>;
  }

  const deletedCount = workspace.files.filter((file) => file.allocationState === "deleted").length;
  const mismatchCount = workspace.files.filter((file) => file.signatureMatchesExtension === false).length;
  const groups = Array.from(new Set(workspace.files.map((file) => file.parentPath)));

  return (
    <div className="min-h-screen bg-white text-stone-950">
      <div className="border-b border-stone-200 px-4 py-3 md:px-8">
        <div className="mx-auto flex max-w-[1560px] items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-stone-500"><span className="h-2 w-2 rounded-full bg-red-700" /> ForensicFS / Investigation workspace</div>
          <div className="font-mono hidden text-[10px] uppercase tracking-wider text-stone-400 md:block">Evidence bytes isolated · Result set v0.1</div>
        </div>
      </div>

      <div className="mx-auto grid max-w-[1560px] lg:grid-cols-[250px_minmax(0,1fr)]">
        <aside className="border-b border-stone-200 px-4 py-6 lg:min-h-[calc(100vh-49px)] lg:border-b-0 lg:border-r lg:px-6">
          <div className="mb-8 flex items-center justify-between lg:block">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-stone-400">Active case</p>
              <p className="mt-1 font-mono text-xs font-medium tracking-tight">{workspace.displayName}</p>
            </div>
            <Badge variant="outline" className="border-emerald-200 bg-emerald-50 font-mono text-[9px] uppercase tracking-wider text-emerald-700">{workspace.status}</Badge>
          </div>

          <nav className="grid grid-cols-2 gap-1 sm:grid-cols-4 lg:grid-cols-1" aria-label="Case sections">
            {views.map((item) => {
              const Icon = item.icon;
              return <button key={item.id} onClick={() => setView(item.id)} className={cn("group flex items-center gap-3 border px-3 py-2.5 text-left text-sm transition-all duration-150 active:scale-[0.98]", view === item.id ? "border-stone-950 bg-stone-950 text-white" : "border-transparent text-stone-500 hover:border-stone-200 hover:bg-stone-50 hover:text-stone-950")}>
                <Icon className="h-4 w-4 shrink-0" /><span className="truncate">{item.label}</span><ChevronRight className={cn("ml-auto h-3.5 w-3.5 transition-transform", view === item.id ? "translate-x-0.5" : "opacity-0 group-hover:opacity-100")} />
              </button>;
            })}
          </nav>

          <div className="mt-8 hidden lg:block">
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-stone-400">Evidence</p>
            <div className="border border-stone-200 p-3">
              <div className="mb-3 flex items-center justify-between"><HardDrive className="h-4 w-4 text-red-700" /><span className="font-mono text-[9px] text-stone-400">SHA-256</span></div>
              <p className="truncate font-mono text-[11px] font-medium">{workspace.evidence.originalName}</p>
              <p className="mt-1 font-mono text-[10px] text-stone-500">{bytes(workspace.evidence.sizeBytes)} · {workspace.filesystemType}</p>
              <p className="mt-3 break-all font-mono text-[8px] leading-relaxed text-stone-400">{workspace.evidence.sha256}</p>
            </div>
          </div>
        </aside>

        <main className="min-w-0 px-4 py-8 sm:px-8 lg:px-12 lg:py-11">
          <header className="mb-12 flex flex-col items-center text-center">
            <p className="mb-5 text-[10px] font-semibold uppercase tracking-[0.28em] text-red-700">Forensic filesystem analysis</p>
            <h1 className="display-layers text-[clamp(4rem,12vw,9rem)]" aria-label="ForensicFS"><span className="layer-1">FORENSICFS</span><span className="layer-2">FORENSICFS</span><span className="layer-3">FORENSICFS</span></h1>
            <p className="mt-9 max-w-md text-sm leading-relaxed text-stone-500">Inspect evidence with traceable file metadata, deleted-entry recovery signals, signature consistency, and a chronological MAC timeline.</p>
          </header>

          <div className="mb-8 flex flex-col justify-between gap-4 border-y border-stone-200 py-3 sm:flex-row sm:items-center">
            <div className="flex items-center gap-3"><span className="font-mono text-[10px] uppercase tracking-[0.16em] text-stone-400">Case / 02794</span><span className="h-1 w-1 rounded-full bg-stone-300" /><span className="font-mono text-[10px] uppercase tracking-[0.16em] text-stone-500">{workspace.files.length} records · {workspace.findings.length} findings</span></div>
            <Button variant="outline" size="sm" className="border-stone-300 text-[11px] font-semibold uppercase tracking-wider hover:bg-stone-950 hover:text-white" onClick={() => setView("files")}><FileSearch className="mr-2 h-3.5 w-3.5" />Review records</Button>
          </div>

          {view === "overview" && <section className="animate-in fade-in slide-in-from-bottom-1 duration-300">
            <div className="grid border-l border-t border-stone-200 sm:grid-cols-2 xl:grid-cols-4">
              {[
                ["FILES INDEXED", workspace.files.length.toString(), "Live and unallocated entries"],
                ["HIGH SIGNAL", workspace.findings.filter((finding) => finding.severity === "high").length.toString(), "Requires investigator review"],
                ["DELETED", deletedCount.toString(), "Unallocated directory entries"],
                ["MISMATCHES", mismatchCount.toString(), "Signature / extension conflicts"],
              ].map(([label, value, description]) => <div key={label} className="border-b border-r border-stone-200 p-5"><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-stone-400">{label}</p><p className="mt-4 font-mono text-4xl font-medium tracking-tighter">{value}</p><p className="mt-4 text-xs text-stone-500">{description}</p></div>)}
            </div>

            <div className="mt-10 grid gap-10 xl:grid-cols-[minmax(0,1.3fr)_minmax(280px,0.7fr)]">
              <div>
                <div className="mb-4 flex items-baseline justify-between"><h2 className="text-base font-semibold uppercase tracking-tight">Priority findings</h2><button onClick={() => setView("files")} className="text-[10px] font-semibold uppercase tracking-wider text-red-700 hover:underline">Open records</button></div>
                <div className="divide-y divide-stone-200 border-y border-stone-200">
                  {workspace.findings.map((finding) => <article key={finding.findingId} className="group grid gap-4 py-5 sm:grid-cols-[auto_1fr_auto]"><Badge variant="outline" className={cn("h-fit w-fit rounded-none px-2 py-1 font-mono text-[9px] uppercase", severityClass(finding.severity))}>{finding.severity}</Badge><div><h3 className="font-medium">{finding.title}</h3><p className="mt-1 text-sm leading-relaxed text-stone-500">{finding.rationale}</p></div><ArrowUpRight className="h-4 w-4 text-stone-300 transition-colors group-hover:text-red-700" /></article>)}
                </div>
              </div>
              <div className="border-t-2 border-stone-950 pt-4"><div className="mb-6 flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-red-700" /><h2 className="text-base font-semibold uppercase tracking-tight">Evidence integrity</h2></div><dl className="space-y-5"><div><dt className="text-[10px] font-semibold uppercase tracking-[0.18em] text-stone-400">Storage posture</dt><dd className="mt-1 text-sm leading-relaxed text-stone-700">Original image content is referenced outside the result database.</dd></div><div><dt className="text-[10px] font-semibold uppercase tracking-[0.18em] text-stone-400">Analysis boundary</dt><dd className="mt-1 text-sm leading-relaxed text-stone-700">The native parser is invoked by an isolated FastAPI worker.</dd></div><div><dt className="text-[10px] font-semibold uppercase tracking-[0.18em] text-stone-400">Result provenance</dt><dd className="mt-1 font-mono text-xs text-stone-700">{workspace.caseId}</dd></div></dl></div>
            </div>
          </section>}

          {view === "files" && <section className="animate-in fade-in slide-in-from-bottom-1 duration-300"><div className="mb-5 flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-red-700">Evidence records</p><h2 className="mt-1 text-3xl font-semibold tracking-tighter">File inventory</h2></div><label className="relative block sm:w-80"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-stone-400" /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search paths, signatures, state" className="h-10 rounded-none border-stone-300 pl-9 text-sm focus-visible:ring-red-700" /></label></div><div className="overflow-x-auto border-y border-stone-200"><table className="w-full min-w-[780px] text-left"><thead className="border-b border-stone-200 text-[10px] font-semibold uppercase tracking-[0.16em] text-stone-400"><tr><th className="px-3 py-3">Path</th><th className="px-3 py-3">State</th><th className="px-3 py-3">Signature</th><th className="px-3 py-3">Modified</th><th className="px-3 py-3 text-right">Size</th></tr></thead><tbody className="divide-y divide-stone-100">{files.map((file) => <tr key={file.recordId} className="hover:bg-stone-50"><td className="px-3 py-4"><p className="font-medium">{file.name}</p><p className="mt-0.5 font-mono text-[10px] text-stone-400">{file.path}</p></td><td className="px-3 py-4"><span className={cn("font-mono text-[10px] uppercase", file.allocationState === "deleted" ? "text-red-700" : "text-stone-500")}>{file.allocationState}</span></td><td className="px-3 py-4"><div className="flex items-center gap-2 text-sm">{file.signature ?? "—"}{file.signatureMatchesExtension === false && <AlertTriangle className="h-3.5 w-3.5 text-red-700" />}</div></td><td className="px-3 py-4 font-mono text-xs text-stone-600">{stamp(file.macTimes.modifiedAt)}</td><td className="px-3 py-4 text-right font-mono text-xs text-stone-600">{bytes(file.sizeBytes)}</td></tr>)}{files.length === 0 && <tr><td colSpan={5} className="px-3 py-12 text-center text-sm text-stone-500">No matching file records.</td></tr>}</tbody></table></div></section>}

          {view === "directory" && <section className="animate-in fade-in slide-in-from-bottom-1 duration-300"><div className="mb-7"><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-red-700">Filesystem hierarchy</p><h2 className="mt-1 text-3xl font-semibold tracking-tighter">Directory map</h2></div><div className="border-y border-stone-200 py-3"><div className="flex items-center gap-2 py-2 font-mono text-xs font-medium"><ChevronDown className="h-4 w-4" /><FolderTree className="h-4 w-4 text-red-700" /> /</div>{groups.map((group) => <div key={group} className="ml-5 border-l border-stone-200 pl-4"><div className="flex items-center gap-2 py-2 font-mono text-xs text-stone-700"><ChevronDown className="h-3.5 w-3.5 text-stone-400" /><FolderTree className="h-3.5 w-3.5 text-stone-400" />{group}</div>{workspace.files.filter((file) => file.parentPath === group).map((file) => <div key={file.recordId} className="ml-5 flex items-center gap-2 py-2 font-mono text-xs"><Files className={cn("h-3.5 w-3.5", file.allocationState === "deleted" ? "text-red-700" : "text-stone-400")} /><span>{file.name}</span>{file.allocationState === "deleted" && <span className="ml-1 text-[9px] uppercase tracking-wider text-red-700">unallocated</span>}<span className="ml-auto text-[10px] text-stone-400">{bytes(file.sizeBytes)}</span></div>)}</div>)}</div></section>}

          {view === "timeline" && <section className="animate-in fade-in slide-in-from-bottom-1 duration-300"><div className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-red-700">Case chronology</p><h2 className="mt-1 text-3xl font-semibold tracking-tighter">Activity timeline</h2></div><p className="font-mono text-[10px] uppercase tracking-wider text-stone-400">All times shown in UTC</p></div><div className="border-l border-stone-200 pl-6 sm:pl-9">{workspace.timeline.map((event) => <article key={event.eventId} className="relative border-b border-stone-100 py-5 first:pt-0"><span className={cn("absolute -left-[31px] top-7 h-2.5 w-2.5 rounded-full border-2 border-white", event.eventType === "deleted" ? "bg-red-700" : "bg-stone-300")} /><div className="grid gap-2 sm:grid-cols-[130px_1fr]"><time className="font-mono text-[11px] text-stone-500">{new Date(event.occurredAt).toISOString().replace("T", " · ").replace(".000Z", " UTC")}</time><div><p className={cn("text-[10px] font-semibold uppercase tracking-[0.16em]", event.eventType === "deleted" ? "text-red-700" : "text-stone-500")}>{eventLabel(event)}</p><p className="mt-1 font-mono text-sm text-stone-900">{event.path}</p><p className="mt-1 text-xs text-stone-400">{event.source}</p></div></div></article>)}</div></section>}

          <footer className="mt-14 flex flex-col items-center justify-between gap-3 border-t border-stone-200 pt-5 text-center sm:flex-row sm:text-left"><p className="text-xs text-stone-400">ForensicFS presents derived findings for investigator validation; it does not alter source evidence.</p><button className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-stone-500 hover:text-red-700" onClick={() => setView("overview")}><PanelRightOpen className="h-3.5 w-3.5" />Case overview</button></footer>
        </main>
      </div>
    </div>
  );
}
