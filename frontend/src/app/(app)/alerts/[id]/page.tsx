"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { RecommendationCard } from "@/components/recommendation-card";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/client-api";
import { formatBytes, formatDateTime, formatNumber } from "@/lib/format";
import type { Alert, AlertStatus, Recommendation, TopFeature } from "@/lib/types";

const ACTIONS: { label: string; status: AlertStatus; variant: "default" | "outline" | "ghost" }[] = [
  { label: "Acknowledge", status: "acknowledged", variant: "outline" },
  { label: "Mark false positive", status: "false_positive", variant: "outline" },
  { label: "Resolve", status: "resolved", variant: "default" },
  { label: "Reopen", status: "new", variant: "ghost" },
];

/** Diverging bars centred on zero: blue pushes toward the predicted class, red away from it. */
function Contributions({ features }: { features: TopFeature[] }) {
  const max = Math.max(...features.map((f) => Math.abs(f.contribution)), 1e-9);
  return (
    <ul className="viz-root space-y-2" data-testid="top-features">
      {features.map((f) => {
        const pct = (Math.abs(f.contribution) / max) * 50;
        const positive = f.contribution >= 0;
        return (
          <li key={f.feature} title={`${f.feature} = ${f.value}: contribution ${f.contribution}`}>
            <div className="mb-0.5 flex justify-between text-xs">
              <span className="font-mono" style={{ color: "var(--viz-ink-2)" }}>
                {f.feature} = {formatNumber(Math.round(f.value * 100) / 100)}
              </span>
              <span className="tabular-nums">{f.contribution > 0 ? "+" : ""}{f.contribution.toFixed(2)}</span>
            </div>
            <div className="relative h-2 rounded-sm" style={{ background: "var(--viz-grid)" }}>
              <div className="absolute inset-y-0 left-1/2 w-px" style={{ background: "var(--viz-axis)" }} />
              <div
                className="absolute inset-y-0"
                style={{
                  width: `${pct}%`,
                  left: positive ? "50%" : `${50 - pct}%`,
                  background: positive ? "var(--series-1)" : "var(--div-neg)",
                  borderRadius: positive ? "0 4px 4px 0" : "4px 0 0 4px",
                }}
              />
            </div>
          </li>
        );
      })}
      <li className="flex gap-4 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--series-1)" }} />
          raises the score for this class
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--div-neg)" }} />
          lowers it
        </span>
      </li>
    </ul>
  );
}

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [label, setLabel] = useState("");

  const alert = useQuery({ queryKey: ["alert", id], queryFn: () => api<Alert>(`alerts/${id}`), refetchInterval: 5000 });
  const recs = useQuery({
    queryKey: ["recommendations", "alert", id],
    queryFn: () => api<Recommendation[]>(`recommendations?alert_id=${id}`),
    refetchInterval: 8000,
  });
  const patch = useMutation({
    mutationFn: (body: { status?: AlertStatus; analyst_label?: string }) =>
      api<Alert>(`alerts/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert", id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  if (alert.isError) {
    return (
      <p role="alert" className="text-sm text-red-600">
        {(alert.error as Error).message}. <Link href="/alerts" className="underline">Back to alerts</Link>
      </p>
    );
  }
  const a = alert.data;
  if (!a) return <div className="h-40" />;

  const ev = a.evidence as Record<string, unknown>;
  const topFeatures = (ev.top_features as TopFeature[] | null | undefined) ?? null;
  const ports = (ev.dst_ports_sample as number[] | undefined) ?? [];
  const ips = (ev.dst_ips_sample as string[] | undefined) ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Link href="/alerts" className="text-sm text-blue-700 hover:underline dark:text-blue-300">
          &larr; Alerts
        </Link>
        <h1 className="text-xl font-semibold" data-testid="alert-title">
          {a.attack_class} from {a.src_ip ?? "unknown source"}
        </h1>
        <SeverityBadge severity={a.severity} />
        <span className="text-sm text-black/60 dark:text-white/60">status: {a.status.replace("_", " ")}</span>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
              <div><dt className="text-xs text-black/55 dark:text-white/55">Risk score</dt><dd className="tabular-nums">{a.risk_score.toFixed(1)} / 100</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Flagged flows</dt><dd className="tabular-nums">{formatNumber(a.count)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Traffic</dt><dd>{formatBytes(Number(ev.bytes_total ?? 0))}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">First seen</dt><dd>{formatDateTime(a.first_seen)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Last seen</dt><dd>{formatDateTime(a.last_seen)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Detected by</dt><dd className="font-mono text-xs">{String(ev.model_version ?? "unknown")}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Target</dt><dd className="font-mono text-xs">{a.dst_ip ?? `${ips.length}+ hosts`}</dd></div>
              <div className="col-span-2">
                <dt className="text-xs text-black/55 dark:text-white/55">Ports touched (sample)</dt>
                <dd className="font-mono text-xs">{ports.length ? ports.join(", ") : "–"}</dd>
              </div>
              <div className="col-span-2 sm:col-span-3">
                <dt className="text-xs text-black/55 dark:text-white/55">Share of this source&apos;s flows in the window</dt>
                <dd className="tabular-nums">
                  {ev.all_flows_in_window ? `${ev.flows_in_window} of ${ev.all_flows_in_window} flows flagged` : "–"}
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Why this alert?</CardTitle>
          </CardHeader>
          <CardContent>
            {topFeatures && topFeatures.length > 0 ? (
              <Contributions features={topFeatures} />
            ) : (
              <p className="text-sm text-black/60 dark:text-white/60" data-testid="no-explanation">
                The active model does not provide per-alert explanations (only boosted-tree models do),
                so no feature contributions are shown.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Triage</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {ACTIONS.filter((x) => x.status !== a.status).map((x) => (
              <Button
                key={x.status}
                size="sm"
                variant={x.variant}
                disabled={patch.isPending}
                onClick={() => patch.mutate({ status: x.status })}
              >
                {x.label}
              </Button>
            ))}
          </div>
          <form
            className="flex max-w-md gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (label.trim()) patch.mutate({ analyst_label: label.trim() });
              setLabel("");
            }}
          >
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={a.analyst_label ?? "Analyst note or label"} maxLength={200} />
            <Button type="submit" size="sm" variant="outline" disabled={!label.trim() || patch.isPending}>
              Save note
            </Button>
          </form>
          <p className="text-xs text-black/55 dark:text-white/55">
            Marking false positives is stored as feedback and will be used as labelled data for retraining.
          </p>
          {patch.isError && (
            <p role="alert" className="text-sm text-red-600">{(patch.error as Error).message}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recommended actions</CardTitle>
        </CardHeader>
        <CardContent>
          {recs.data && recs.data.length === 0 ? (
            <p className="text-sm text-black/60 dark:text-white/60">No recommendations for this alert.</p>
          ) : (
            <ul className="space-y-3">
              {(recs.data ?? []).map((r) => (
                <RecommendationCard key={r.id} rec={r} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
