"use client";

import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { SystemHealth } from "@/lib/types";

const ok = "bg-green-600/15 text-green-700 dark:text-green-300";
const bad = "bg-red-600/15 text-red-700 dark:text-red-300";
const label = "text-xs text-black/55 dark:text-white/55";

export function HealthPanel() {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: () => api<SystemHealth>("settings/health"),
    refetchInterval: 5000,
  });
  if (q.isLoading) return <p className="text-sm">Checking…</p>;
  if (!q.data) return <p className="text-sm text-red-700">Could not reach the API.</p>;
  const h = q.data;
  const workers = h.queue.workers ?? [];
  const alive = workers.filter((w) => w.idle_seconds < 60);
  return (
    <Card data-testid="health-panel">
      <CardHeader>
        <CardTitle>System health</CardTitle>
        <span className={label}>refreshes every 5 seconds</span>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
          <div>
            <dt className={label}>Database</dt>
            <dd>
              <Badge className={h.database.ok ? ok : bad}>{h.database.ok ? "up" : `down (${h.database.error})`}</Badge>{" "}
              schema {h.schema_version ?? "?"}
            </dd>
          </div>
          <div>
            <dt className={label}>Queue (Redis)</dt>
            <dd>
              <Badge className={h.queue.ok ? ok : bad}>{h.queue.ok ? "up" : `down (${h.queue.error})`}</Badge>{" "}
              {h.queue.waiting ?? 0} waiting, {h.queue.dead_letters ?? 0} dead letters
            </dd>
          </div>
          <div>
            <dt className={label}>Workers</dt>
            <dd>
              <Badge className={alive.length ? ok : bad}>{alive.length ? `${alive.length} working` : "none seen"}</Badge>
              {workers.map((w) => ` ${w.name} (idle ${w.idle_seconds}s)`).join(",")}
            </dd>
          </div>
          <div data-testid="pipeline-lag">
            <dt className={label}>Delay from queued to stored (recent flows)</dt>
            <dd>
              {h.pipeline_lag?.samples
                ? `median ${h.pipeline_lag.median_ms} ms, 95th percentile ${h.pipeline_lag.p95_ms} ms (${h.pipeline_lag.samples} flows). The dashboard then refreshes every 5 s.`
                : "no flows processed recently"}
            </dd>
          </div>
          <div>
            <dt className={label}>Active model</dt>
            <dd>{h.active_model ?? "none (placeholder rules)"}</dd>
          </div>
          <div>
            <dt className={label}>Data kept for</dt>
            <dd>{h.retention_days ?? 30} days</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}
