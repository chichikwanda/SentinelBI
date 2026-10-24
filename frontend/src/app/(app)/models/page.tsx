"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatDateTime, formatNumber } from "@/lib/format";
import type { EvalMetrics, ModelRow } from "@/lib/types";

const pct = (v: number | undefined) => (v === undefined || Number.isNaN(v) ? "–" : `${(v * 100).toFixed(1)}%`);
const num = (v: number | undefined, d = 3) => (v === undefined || Number.isNaN(v) ? "–" : v.toFixed(d));

function Comparison({ validation }: { validation: Record<string, EvalMetrics> }) {
  const rows = Object.entries(validation).sort((a, b) => b[1].f1_macro - a[1].f1_macro);
  return (
    <Table>
      <thead>
        <tr>
          <Th>Algorithm</Th>
          <Th className="text-right">Macro-F1</Th>
          <Th className="text-right">Accuracy</Th>
          <Th className="text-right">Attack recall</Th>
          <Th className="text-right">False alarms</Th>
          <Th className="text-right">Train (s)</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([algo, m]) => (
          <tr key={algo}>
            <Td className="font-medium">{algo}</Td>
            <Td className="text-right tabular-nums">{num(m.f1_macro)}</Td>
            <Td className="text-right tabular-nums">{pct(m.accuracy)}</Td>
            <Td className="text-right tabular-nums">{pct(m.attack_detection_rate)}</Td>
            <Td className="text-right tabular-nums">{pct(m.false_alarm_rate)}</Td>
            <Td className="text-right tabular-nums">{m.train_seconds ?? "–"}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function ModelDetail({ model }: { model: ModelRow }) {
  const t = model.metrics.test;
  return (
    <div className="space-y-5 p-4">
      {!t ? (
        <p className="text-sm" data-testid="no-metrics">
          No measured metrics: this is the placeholder rule set, not a trained model, and makes no accuracy claim.
        </p>
      ) : (
        <>
          <div>
            <h3 className="mb-1 text-sm font-semibold">Held-out test split ({formatNumber(t.n)} flows, evaluated once)</h3>
            <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
              <div><dt className="text-xs text-black/55 dark:text-white/55">Macro-F1</dt><dd className="tabular-nums" data-testid="test-f1">{num(t.f1_macro)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Accuracy</dt><dd className="tabular-nums">{pct(t.accuracy)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">Attack recall</dt><dd className="tabular-nums">{pct(t.attack_detection_rate)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">False-alarm rate</dt><dd className="tabular-nums">{pct(t.false_alarm_rate)}</dd></div>
              <div><dt className="text-xs text-black/55 dark:text-white/55">ROC-AUC (OvR)</dt><dd className="tabular-nums">{num(t.roc_auc_ovr_macro)}</dd></div>
            </dl>
            {model.metrics.latency_ms_per_500_flows != null && (
              <p className="mt-2 text-xs text-black/60 dark:text-white/60" data-testid="serving-latency">
                Serving latency: {model.metrics.latency_ms_per_500_flows} ms per 500 flows
                {model.metrics.latency_conditions ? ` (${model.metrics.latency_conditions})` : ""}.
              </p>
            )}
          </div>
          <div>
            <h3 className="mb-1 text-sm font-semibold">Per class (test)</h3>
            <Table>
              <thead>
                <tr><Th>Class</Th><Th className="text-right">Precision</Th><Th className="text-right">Recall</Th><Th className="text-right">F1</Th><Th className="text-right">Flows</Th></tr>
              </thead>
              <tbody>
                {Object.entries(t.per_class).map(([c, m]) => (
                  <tr key={c}>
                    <Td className="font-medium">{c}</Td>
                    <Td className="text-right tabular-nums">{num(m.precision)}</Td>
                    <Td className="text-right tabular-nums">{num(m.recall)}</Td>
                    <Td className="text-right tabular-nums">{num(m.f1)}</Td>
                    <Td className="text-right tabular-nums">{formatNumber(m.support)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </>
      )}
      {model.metrics.validation && (
        <div>
          <h3 className="mb-1 text-sm font-semibold">Algorithm comparison (validation split; the model above was chosen on macro-F1)</h3>
          <Comparison validation={model.metrics.validation} />
          <p className="mt-1 text-xs text-black/55 dark:text-white/55">
            Training-time latencies are not shown: they were measured under load and are not comparable.
          </p>
        </div>
      )}
      {model.metrics.limitations && (
        <div>
          <h3 className="mb-1 text-sm font-semibold">Limitations</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {model.metrics.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </div>
      )}
      {model.metrics.training?.not_done && (
        <p className="text-xs text-black/60 dark:text-white/60">
          Not done yet: {model.metrics.training.not_done.join(", ")}.
        </p>
      )}
    </div>
  );
}

export default function ModelsPage() {
  const qc = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);
  const models = useQuery({ queryKey: ["models"], queryFn: () => api<ModelRow[]>("models") });
  const activate = useMutation({
    mutationFn: (version: string) => api<ModelRow>(`models/${encodeURIComponent(version)}/activate`, { method: "POST" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["models"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Model registry</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <p className="p-4 pb-0 text-xs text-black/60 dark:text-white/60">
          The active model scores every flow. Switching is platform-wide, so only platform administrators
          can do it; the worker picks the change up within about 30 seconds.
        </p>
        {activate.isError && (
          <p role="alert" className="px-4 pt-2 text-sm text-red-600">{(activate.error as Error).message}</p>
        )}
        <Table>
          <thead>
            <tr>
              <Th>Version</Th>
              <Th>Algorithm</Th>
              <Th>Dataset</Th>
              <Th>Registered</Th>
              <Th>State</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {(models.data ?? []).flatMap((m) => [
              <tr key={m.version} data-testid="model-row">
                <Td className="font-mono text-xs">{m.version}</Td>
                <Td>{m.algo}</Td>
                <Td className="max-w-56 truncate text-xs" title={m.dataset ?? ""}>{m.dataset ?? "none"}</Td>
                <Td>{formatDateTime(m.created_at)}</Td>
                <Td>{m.active ? <Badge className="bg-emerald-600/15 text-emerald-800 dark:text-emerald-300">active</Badge> : "inactive"}</Td>
                <Td className="space-x-2 text-right">
                  <Button size="sm" variant="ghost" onClick={() => setOpen(open === m.version ? null : m.version)}>
                    {open === m.version ? "Hide details" : "Details"}
                  </Button>
                  {!m.active && (
                    <Button size="sm" variant="outline" disabled={activate.isPending} onClick={() => activate.mutate(m.version)}>
                      Activate
                    </Button>
                  )}
                </Td>
              </tr>,
              open === m.version ? (
                <tr key={`${m.version}-detail`}>
                  <td colSpan={6} className="border-t border-black/10 bg-black/[0.02] dark:border-white/10 dark:bg-white/[0.03]">
                    <ModelDetail model={m} />
                  </td>
                </tr>
              ) : null,
            ])}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}
