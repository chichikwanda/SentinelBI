"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { BarList } from "@/components/charts/bar-list";
import { RiskGauge } from "@/components/charts/risk-gauge";
import { TrafficChart } from "@/components/charts/traffic-chart";
import { HealthPill } from "@/components/health-pill";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatBytes, formatNumber } from "@/lib/format";
import type {
  Alert,
  Overview,
  ProtocolShare,
  Severity,
  Source,
  SourceHealth,
  TopTalker,
  TrafficSeries,
} from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

const LIVE_MS = 3000;
const WINDOWS = [
  { label: "1 hour", minutes: 60 },
  { label: "6 hours", minutes: 360 },
  { label: "24 hours", minutes: 1440 },
];
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

function LiveDot({ active }: { active: boolean }) {
  return (
    <span className="flex items-center gap-2 text-xs text-black/60 dark:text-white/60">
      <span className={`h-2 w-2 rounded-full ${active ? "animate-pulse bg-emerald-500" : "bg-slate-400"}`} />
      {active ? "Live" : "Paused"}
    </span>
  );
}

function Stat({ label, value, sub, testId }: { label: string; value: React.ReactNode; sub?: string; testId?: string }) {
  return (
    <Card>
      <CardContent>
        <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">{label}</div>
        <div className="mt-1 text-3xl font-semibold tabular-nums" data-testid={testId}>
          {value}
        </div>
        {sub && <div className="mt-1 text-xs text-black/60 dark:text-white/60">{sub}</div>}
      </CardContent>
    </Card>
  );
}

function SourceRow({ source }: { source: Source }) {
  const { data: health } = useQuery({
    queryKey: ["source-health", source.id],
    queryFn: () => api<SourceHealth>(`sources/${source.id}/health`),
    refetchInterval: 5000,
  });
  return (
    <tr>
      <Td className="font-medium">{source.name}</Td>
      <Td className="font-mono text-xs">{source.cidr}</Td>
      <Td>{source.method}</Td>
      <Td>
        <HealthPill health={health} />
      </Td>
      <Td className="text-right tabular-nums">{health?.flows_total ?? "–"}</Td>
      <Td>{timeAgo(health?.last_seen ?? source.last_seen)}</Td>
    </tr>
  );
}

export function AlertsTable({ alerts }: { alerts: Alert[] }) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Severity</Th>
          <Th>Attack</Th>
          <Th>Source IP</Th>
          <Th>Target</Th>
          <Th className="text-right">Flows</Th>
          <Th className="text-right">Risk</Th>
          <Th>Last seen</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody data-testid="alerts-body">
        {alerts.map((a) => (
          <tr key={a.id} data-testid="alert-row">
            <Td>
              <SeverityBadge severity={a.severity} />
            </Td>
            <Td className="font-medium">
              <Link href={`/alerts/${a.id}`} className="text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
                {a.attack_class}
              </Link>
            </Td>
            <Td className="font-mono text-xs">{a.src_ip ?? "–"}</Td>
            <Td className="font-mono text-xs">{a.dst_ip ?? "multiple"}</Td>
            <Td className="text-right tabular-nums">{a.count}</Td>
            <Td className="text-right tabular-nums">{a.risk_score.toFixed(1)}</Td>
            <Td>{timeAgo(a.last_seen)}</Td>
            <Td>{a.status.replace("_", " ")}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default function DashboardPage() {
  const [minutes, setMinutes] = useState(60);
  const overview = useQuery({ queryKey: ["overview"], queryFn: () => api<Overview>("overview"), refetchInterval: 5000 });
  const traffic = useQuery({
    queryKey: ["traffic", minutes],
    queryFn: () => api<TrafficSeries>(`traffic/timeseries?minutes=${minutes}`),
    refetchInterval: 10000,
  });
  const talkers = useQuery({
    queryKey: ["talkers", minutes],
    queryFn: () => api<TopTalker[]>(`traffic/top-talkers?minutes=${minutes}&limit=8`),
    refetchInterval: 10000,
  });
  const protocols = useQuery({
    queryKey: ["protocols", minutes],
    queryFn: () => api<ProtocolShare[]>(`traffic/protocols?minutes=${minutes}`),
    refetchInterval: 10000,
  });
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api<Alert[]>("alerts?limit=50"),
    refetchInterval: LIVE_MS,
  });
  const sources = useQuery({ queryKey: ["sources"], queryFn: () => api<Source[]>("sources"), refetchInterval: 10000 });

  const ov = overview.data;

  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent>
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">
              Organisation risk
            </div>
            {ov ? <RiskGauge score={ov.risk.score} severity={ov.risk.severity} /> : <div className="h-20" />}
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">
              Open alerts
            </div>
            <div className="mt-1 text-3xl font-semibold tabular-nums" data-testid="open-alerts">
              {ov?.open_alerts ?? "–"}
            </div>
            <ul className="mt-2 grid grid-cols-2 gap-x-3 gap-y-0.5 text-xs">
              {SEVERITIES.map((s) => (
                <li key={s} className="flex justify-between">
                  <span>{s}</span>
                  <span className="tabular-nums">{ov?.open_by_severity[s] ?? 0}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <Stat label="Flows, last 24 h" value={ov ? formatNumber(ov.flows_24h) : "–"} sub="analysed by the model" testId="flows-24h" />
        <Stat
          label="Sources receiving"
          value={ov ? `${ov.sources_receiving} / ${ov.sources_total}` : "–"}
          sub={ov?.model.version ? `Model: ${ov.model.version}` : "No model active"}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Traffic</CardTitle>
          <div className="flex gap-1" role="group" aria-label="Time window">
            {WINDOWS.map((w) => (
              <Button
                key={w.minutes}
                size="sm"
                variant={minutes === w.minutes ? "default" : "outline"}
                aria-pressed={minutes === w.minutes}
                onClick={() => setMinutes(w.minutes)}
              >
                {w.label}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {traffic.data ? (
            <TrafficChart points={traffic.data.points} bucketMinutes={traffic.data.bucket_minutes} />
          ) : (
            <div className="h-48" />
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Top talkers (bytes)</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList
              items={(talkers.data ?? []).map((t) => ({
                label: t.ip,
                value: t.bytes,
                detail: `${t.ip}: ${formatBytes(t.bytes)} in ${formatNumber(t.flows)} flows`,
              }))}
              format={formatBytes}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Protocols (flows)</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList
              items={(protocols.data ?? []).map((p) => ({
                label: p.protocol,
                value: p.flows,
                detail: `${p.protocol}: ${formatNumber(p.flows)} flows, ${formatBytes(p.bytes)}`,
              }))}
              format={formatNumber}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Top attackers (open alerts)</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList
              items={(ov?.top_attackers ?? []).map((a) => ({
                label: a.ip,
                value: a.max_risk,
                detail: `${a.ip}: ${a.alerts} alert(s), ${formatNumber(a.flows)} flows, max risk ${a.max_risk}`,
              }))}
              format={(v) => `risk ${v.toFixed(1)}`}
              emptyText="No open alerts."
            />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Live alerts</CardTitle>
          <div className="flex items-center gap-3">
            <LiveDot active={!alerts.isError} />
            <Link href="/alerts" className="text-sm text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
              All alerts
            </Link>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {alerts.isError ? (
            <p className="p-4 text-sm text-red-600 dark:text-red-400" role="alert">
              Could not load alerts: {(alerts.error as Error).message}
            </p>
          ) : alerts.data && alerts.data.length === 0 ? (
            <p className="p-4 text-sm text-black/60 dark:text-white/60" data-testid="no-alerts">
              No alerts yet. Register a source and send traffic to see detections here.
            </p>
          ) : (
            <AlertsTable alerts={(alerts.data ?? []).slice(0, 10)} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sources</CardTitle>
          <Link href="/sources/new">
            <Button size="sm">Add source</Button>
          </Link>
        </CardHeader>
        <CardContent className="p-0">
          {sources.data && sources.data.length === 0 ? (
            <p className="p-4 text-sm text-black/60 dark:text-white/60">
              No sources yet. An IP address alone gives no traffic visibility: add a source and point your
              router&apos;s NetFlow export at the collector.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Network</Th>
                  <Th>Method</Th>
                  <Th>Status</Th>
                  <Th className={cn("text-right")}>Flows</Th>
                  <Th>Last seen</Th>
                </tr>
              </thead>
              <tbody>
                {(sources.data ?? []).map((s) => (
                  <SourceRow key={s.id} source={s} />
                ))}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  );
}
