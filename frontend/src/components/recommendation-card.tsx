"use client";

import Link from "next/link";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/client-api";
import type { RecStatus, Recommendation } from "@/lib/types";
import { cn } from "@/lib/utils";

const FRAMEWORK_LABEL = { mitre: "ATT&CK", cis: "CIS v8", nist: "NIST CSF 2.0" } as const;

export function useUpdateRecommendation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: RecStatus }) =>
      api<Recommendation>(`recommendations/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["recommendations"] }),
  });
}

/** One card per distinct action. ``others`` are the same action raised by further alerts: the
 *  status buttons apply to all of them, so the to-do list does not repeat itself. */
export function RecommendationCard({
  rec,
  others = [],
  showAlert,
}: {
  rec: Recommendation;
  others?: Recommendation[];
  showAlert?: boolean;
}) {
  const update = useUpdateRecommendation();
  const done = rec.status === "done" || rec.status === "dismissed";
  const all = [rec, ...others];
  const set = (status: RecStatus) => all.forEach((r) => update.mutate({ id: r.id, status }));

  return (
    <li className="rounded-md border border-black/10 p-3 dark:border-white/15" data-testid="recommendation">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge className="bg-blue-600/15 text-blue-800 dark:text-blue-300">Priority {rec.priority}</Badge>
        {rec.effort && <Badge className="bg-slate-500/15">effort: {rec.effort}</Badge>}
        {rec.status !== "open" && <Badge className="bg-emerald-600/15 text-emerald-800 dark:text-emerald-300">{rec.status.replace("_", " ")}</Badge>}
        {showAlert && (
          <span className="ml-auto flex flex-wrap items-center justify-end gap-x-3 gap-y-1">
            {all.slice(0, 3).map((r) =>
              r.alert ? (
                <Link key={r.id} href={`/alerts/${r.alert.id}`} className="flex items-center gap-1.5 hover:underline">
                  <SeverityBadge severity={r.alert.severity} />
                  {r.alert.attack_class} from {r.alert.src_ip ?? "unknown"}
                </Link>
              ) : (
                <Link key={r.id} href="/assessment" className="hover:underline" data-testid="from-assessment">
                  <Badge className="bg-violet-600/15 text-violet-800 dark:text-violet-300">From your self-assessment</Badge>
                </Link>
              ),
            )}
            {all.length > 3 && <span data-testid="more-alerts">+{all.length - 3} more alerts</span>}
          </span>
        )}
      </div>
      <p className={cn("mt-2 text-sm", done && "text-black/50 line-through dark:text-white/50")}>{rec.action}</p>

      {rec.references.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {rec.references.map((r) => {
            const label = `${FRAMEWORK_LABEL[r.framework]} ${r.id}`;
            const chip = (
              <Badge
                key={`${r.framework}-${r.id}`}
                className="bg-black/5 font-normal dark:bg-white/10"
                title={r.title ?? undefined}
              >
                {label}
                {r.title ? `: ${r.title}` : ""}
              </Badge>
            );
            return r.url ? (
              <a key={`${r.framework}-${r.id}`} href={r.url} target="_blank" rel="noreferrer" className="hover:underline">
                {chip}
              </a>
            ) : (
              chip
            );
          })}
        </div>
      )}

      {rec.compliance_note && (
        <p className="mt-2 rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-900 dark:text-amber-200">
          {rec.compliance_note}
        </p>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        {rec.status === "open" && (
          <Button size="sm" variant="outline" onClick={() => set("in_progress")} disabled={update.isPending}>
            Start
          </Button>
        )}
        {!done && (
          <Button size="sm" onClick={() => set("done")} disabled={update.isPending}>
            Mark done
          </Button>
        )}
        {!done && (
          <Button size="sm" variant="ghost" onClick={() => set("dismissed")} disabled={update.isPending}>
            Dismiss
          </Button>
        )}
        {done && (
          <Button size="sm" variant="outline" onClick={() => set("open")} disabled={update.isPending}>
            Reopen
          </Button>
        )}
        {update.isError && (
          <span role="alert" className="text-xs text-red-600">
            {(update.error as Error).message}
          </span>
        )}
      </div>
    </li>
  );
}
