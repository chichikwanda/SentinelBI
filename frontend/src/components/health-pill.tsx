import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { SourceHealth } from "@/lib/types";

const styles: Record<SourceHealth["state"], string> = {
  waiting: "bg-slate-500/15 text-slate-700 dark:text-slate-300",
  receiving: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  stale: "bg-amber-500/20 text-amber-800 dark:text-amber-300",
};

const labels: Record<SourceHealth["state"], string> = {
  waiting: "Waiting for flows",
  receiving: "Receiving",
  stale: "No recent flows",
};

export function HealthPill({ health }: { health?: SourceHealth }) {
  if (!health) return <Badge className="bg-slate-500/10">…</Badge>;
  return <Badge className={cn(styles[health.state])}>{labels[health.state]}</Badge>;
}
