"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/client-api";
import type { InventorySummary } from "@/lib/types";

const STATE_STYLES: Record<string, string> = {
  known: "bg-slate-500/15 text-slate-700 dark:text-slate-300",
  baseline: "bg-slate-500/15 text-slate-700 dark:text-slate-300",
  new: "bg-amber-500/20 text-amber-800 dark:text-amber-300",
  trusted: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  approved: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  quarantined: "bg-red-600/15 text-red-700 dark:text-red-300",
};

const STATE_LABELS: Record<string, string> = {
  known: "Known",
  baseline: "Regular",
  new: "New",
  trusted: "Trusted",
  approved: "Approved",
  quarantined: "Quarantined",
};

export function StateBadge({ state }: { state: string }) {
  return <Badge className={STATE_STYLES[state] ?? ""}>{STATE_LABELS[state] ?? state}</Badge>;
}

/** Approve or quarantine one device or network. The decision is recorded with the signed-in
 *  person's email, so the list shows who decided. */
export function DecisionButtons({
  kind,
  id,
  state,
  invalidate,
}: {
  kind: "devices" | "networks";
  id: string;
  state: string;
  invalidate: string[][];
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const decide = useMutation({
    mutationFn: (action: "approve" | "quarantine") =>
      api(`inventory/${kind}/${id}/decision`, {
        method: "POST",
        body: JSON.stringify({ action }),
      }),
    onSuccess: async () => {
      setError(null);
      await Promise.all(invalidate.map((queryKey) => qc.invalidateQueries({ queryKey })));
    },
    onError: (e) => setError((e as Error).message),
  });
  const held = state === "quarantined";
  const settled = state === "trusted" || state === "approved";
  return (
    <div className="flex flex-wrap items-center gap-1">
      {!settled && (
        <Button size="sm" variant="outline" disabled={decide.isPending} onClick={() => decide.mutate("approve")}>
          {held ? "Release" : "Approve"}
        </Button>
      )}
      {!held && (
        <Button size="sm" variant="outline" disabled={decide.isPending} onClick={() => decide.mutate("quarantine")}>
          Quarantine
        </Button>
      )}
      {error && (
        <span className="text-xs text-red-600" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

/** Remove a device or network that is gone from the list (administrators only; the server says no
 *  to anyone else, and refuses while it is held in quarantine). */
export function ForgetButton({
  kind,
  id,
  invalidate,
}: {
  kind: "devices" | "networks";
  id: string;
  invalidate: string[][];
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const forget = useMutation({
    mutationFn: () => api(`inventory/${kind}/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setError(null);
      await Promise.all(invalidate.map((queryKey) => qc.invalidateQueries({ queryKey })));
    },
    onError: (e) => setError((e as Error).message),
  });
  return (
    <>
      <Button size="sm" variant="ghost" disabled={forget.isPending} onClick={() => forget.mutate()}>
        Forget
      </Button>
      {error && (
        <span className="text-xs text-red-600" role="alert">
          {error}
        </span>
      )}
    </>
  );
}

/** Dashboard strip: what is waiting for a decision. Shows nothing when nothing is. */
export function AttentionBanner() {
  const summary = useQuery({
    queryKey: ["inventory-summary"],
    queryFn: () => api<InventorySummary>("inventory/summary"),
    refetchInterval: 5000,
  });
  const s = summary.data;
  if (!s) return null;
  const items = [
    { n: s.devices_quarantined + s.networks_quarantined, label: "in quarantine", href: "/quarantine", tone: "red" },
    { n: s.devices_new, label: "new devices", href: "/devices", tone: "amber" },
    { n: s.networks_new, label: "new networks", href: "/networks", tone: "amber" },
  ].filter((i) => i.n > 0);
  if (items.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
      <strong>Waiting for your decision:</strong>
      {items.map((i) => (
        <Link
          key={i.href}
          href={i.href}
          className={i.tone === "red" ? "font-medium text-red-700 underline dark:text-red-300" : "font-medium underline"}
        >
          {i.n} {i.label}
        </Link>
      ))}
    </div>
  );
}
