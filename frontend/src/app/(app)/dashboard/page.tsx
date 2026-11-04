"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { BarList, type BarItem } from "@/components/charts/bar-list";
import { RiskGauge } from "@/components/charts/risk-gauge";
import { TrafficChart } from "@/components/charts/traffic-chart";
import { HealthPill } from "@/components/health-pill";
import { AttentionBanner } from "@/components/inventory";
import { InstallerButton } from "@/components/installer-button";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatBytes, formatNumber } from "@/lib/format";
import type {
  Alert,
  HostVolume,
  Overview,
  ProtocolShare,
  Severity,
  Source,
  SourceHealth,
  TopTalker,
  TrafficSeries,
  TrafficSummary,
} from "@/lib/types";
import { cn, quietFor, timeAgo } from "@/lib/utils";

const LIVE_MS = 3000;
const WINDOWS = [
  { label: "1 hour", minutes: 60 },
  { label: "6 hours", minutes: 360 },
  { label: "24 hours", minutes: 1440 },
];
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

/** Real traffic can carry dozens of IP protocol numbers: keep the biggest few and fold the
 *  rest into one "Other" bar so the card stays readable. */
function foldProtocols(rows: ProtocolShare[], keep = 6): BarItem[] {
  const items: BarItem[] = rows.slice(0, keep).map((p) => ({
    label: p.protocol,
    value: p.flows,
    detail: `${p.protocol}: ${formatNumber(p.flows)} flows, ${formatBytes(p.bytes)}`,
  }));
  const rest = rows.slice(keep);
  if (rest.length > 0) {
    items.push({
      label: `Other (${rest.length} protocols)`,
      value: rest.reduce((sum, p) => sum + p.flows, 0),
      detail: rest.map((p) => p.protocol).join(", "),
    });
  }
  return items;
}

/** Shown until the first source exists: the shortest path from "I have an IP" to data. */
function QuickStart() {
  const router = useRouter();
  const [ip, setIp] = useState("");
  return (
    <Card data-testid="quick-start">
      <CardHeader>
        <CardTitle>Start monitoring</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-black/75 dark:text-white/75">
          Enter the IP address of a computer or network you manage. You get one command to run on it: a small
          sensor that counts the traffic (it reads packet headers, never their contents). No router setup is
          needed, and you will see how much data each host sends and receives.
        </p>
        <form
          className="mt-3 flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            router.push(`/sources/new${ip.trim() ? `?ip=${encodeURIComponent(ip.trim())}` : ""}`);
          }}
        >
          <Input
            aria-label="IP address to monitor"
            data-testid="quick-start-ip"
            className="max-w-xs"
            placeholder="192.168.1.20 or 192.168.1.0/24"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
          <Button type="submit" data-testid="quick-start-go">
            Continue
          </Button>
        </form>
        <p className="mt-3 text-xs text-black/60 dark:text-white/60">
          Prefer your router? <Link className="underline" href="/sources/new?method=netflow">Use NetFlow instead</Link>.
        </p>
      </CardContent>
    </Card>
  );
}

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

function IpRow({ host }: { host: HostVolume }) {
  const { data: health } = useQuery({
    queryKey: ["source-health", host.source_id],
    queryFn: () => api<SourceHealth>(`sources/${host.source_id}/health`),
    refetchInterval: 5000,
    enabled: Boolean(host.source_id),
  });
  const href = `/traffic?ip=${encodeURIComponent(host.ip)}`;
  return (
    <tr data-testid="monitored-ip">
      <Td className="font-mono text-xs">
        <Link href={href} className="text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
          {host.ip}
        </Link>
      </Td>
      <Td>{host.source_name ?? "–"}</Td>
      <Td>{host.source_id ? <HealthPill health={health} /> : "–"}</Td>
      <Td className="text-right tabular-nums">{formatBytes(host.sent_bytes)}</Td>
      <Td className="text-right tabular-nums">{formatBytes(host.received_bytes)}</Td>
      <Td>{host.last_seen ? timeAgo(host.last_seen) : "none in 24 h"}</Td>
      <Td className="text-right">
        <Link href={href}>
          <Button size="sm" variant="outline" aria-label={`View traffic for ${host.ip}`}>
            View traffic
          </Button>
        </Link>
      </Td>
    </tr>
  );
}

/** Every IP the organisation registered (plus the hosts seen inside a registered range), whether or
 *  not it has traffic right now, each one a way into its traffic page. */
function MonitoredIps({ hosts, sources }: { hosts?: HostVolume[]; sources: Source[] }) {
  // a sensor that has stopped reporting is the usual reason an IP looks empty: say so
  const quiet = sources.filter((s) => quietFor(s.last_seen, 120));
  return (
    <Card data-testid="monitored-ips">
      <CardHeader>
        <div>
          <CardTitle>Monitored IPs</CardTitle>
          <p className="mt-0.5 text-xs text-black/60 dark:text-white/60">
            Last 24 hours. Open one to see what it sent and received, who it talked to and what it used.
          </p>
        </div>
        <Link href="/traffic" className="text-sm text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
          All hosts and details
        </Link>
      </CardHeader>
      <CardContent className="p-0">
        {hosts && hosts.length === 0 ? (
          <p className="p-4 text-sm text-black/60 dark:text-white/60" data-testid="no-hosts">
            No single IP is registered yet, and no host inside a registered range has had traffic. Hosts of a
            network range appear here once they send or receive data.
          </p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>IP</Th>
                <Th>Source</Th>
                <Th>Status</Th>
                <Th className="text-right">Sent</Th>
                <Th className="text-right">Received</Th>
                <Th>Last seen</Th>
                <Th />
              </tr>
            </thead>
            <tbody data-testid="top-hosts">
              {(hosts ?? []).map((h) => (
                <IpRow key={h.ip} host={h} />
              ))}
            </tbody>
          </Table>
        )}
        {quiet.length > 0 && (
          <p className="border-t border-black/10 px-4 py-3 text-xs text-black/65 dark:border-white/10 dark:text-white/65" data-testid="quiet-sources">
            {quiet
              .map((s) => (s.last_seen ? `${s.name} last reported ${timeAgo(s.last_seen)}` : `${s.name} has not reported yet`))
              .join("; ")}
            . Monitoring resumes when the sensor (or router) for it sends data again; what was already received
            is kept, and a longer window on the traffic page shows it.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function SourceRow({
  source,
  onRemove,
}: {
  source: Source;
  onRemove?: (source: Source) => void;
}) {
  const { data: health } = useQuery({
    queryKey: ["source-health", source.id],
    queryFn: () => api<SourceHealth>(`sources/${source.id}/health`),
    refetchInterval: 5000,
  });
  // a single address opens its own page; a range opens the list of hosts seen inside it
  const trafficHref = source.cidr.includes("/")
    ? `/traffic?source=${encodeURIComponent(source.id)}`
    : `/traffic?ip=${encodeURIComponent(source.cidr)}`;
  return (
    <tr>
      <Td className="font-medium">
        <Link href={trafficHref} className="text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
          {source.name}
        </Link>
      </Td>
      <Td className="font-mono text-xs">
        {source.cidr}
        {source.extra_cidrs && source.extra_cidrs.length > 0 && (
          <div
            className="font-sans text-black/55 dark:text-white/55"
            title={source.extra_cidrs.join("\n")}
            data-testid="extra-addresses"
          >
            + {source.extra_cidrs.length} more {source.extra_cidrs.length === 1 ? "address" : "addresses"} of
            this machine
          </div>
        )}
      </Td>
      <Td>{source.method}</Td>
      <Td>
        <HealthPill health={health} />
      </Td>
      <Td className="text-right tabular-nums">{health?.flows_total ?? "–"}</Td>
      <Td>{timeAgo(health?.last_seen ?? source.last_seen)}</Td>
      <Td className="text-right">
        <Link href={trafficHref}>
          <Button size="sm" variant="outline" aria-label={`View traffic for ${source.name}`}>
            View traffic
          </Button>
        </Link>
      </Td>
      {onRemove && (
        <Td className="text-right">
          {source.method === ("sensor" as Source["method"]) && (
            <div className="mb-1">
              <InstallerButton
                sourceId={source.id}
                sourceName={source.name}
                running={health?.state === "receiving"}
                size="sm"
              />
            </div>
          )}
          <Button
            size="sm"
            variant="outline"
            data-testid="remove-source"
            aria-label={`Remove ${source.name}`}
            onClick={() => onRemove(source)}
          >
            Remove
          </Button>
        </Td>
      )}
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
  const [metric, setMetric] = useState<"flows" | "bytes">("flows");
  const overview = useQuery({ queryKey: ["overview"], queryFn: () => api<Overview>("overview"), refetchInterval: 5000 });
  const traffic = useQuery({
    queryKey: ["traffic", minutes],
    queryFn: () => api<TrafficSeries>(`traffic/timeseries?minutes=${minutes}`),
    refetchInterval: 10000,
  });
  const volume = useQuery({
    queryKey: ["traffic-summary", 1440],
    queryFn: () => api<TrafficSummary>("traffic/summary?minutes=1440"),
    refetchInterval: 10000,
  });
  const ips = useQuery({
    queryKey: ["traffic-hosts", 1440, "monitored"],
    queryFn: () => api<HostVolume[]>("traffic/hosts?minutes=1440&limit=20&include_idle=true"),
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
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<{ role: string }>("auth/me") });
  const queryClient = useQueryClient();
  const removeSource = useMutation({
    mutationFn: (id: string) => api<null>(`sources/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      for (const key of ["sources", "overview", "traffic-summary", "traffic-hosts"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
  });
  // only an administrator can remove a source (the API enforces it; the button just is not offered)
  const canRemove = me.data?.role === "admin";
  function confirmRemove(source: Source) {
    const ok = window.confirm(
      `Remove "${source.name}" (${source.cidr})?\n\nIts API key stops working immediately, so a sensor or ` +
        "router using it stops reporting. Flows and alerts already stored are kept.",
    );
    if (ok) removeSource.mutate(source.id);
  }

  const ov = overview.data;
  const vol = volume.data;
  const noSources = sources.data !== undefined && sources.data.length === 0;

  return (
    <>
      {noSources && <QuickStart />}
      <AttentionBanner />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
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
          label="Data, last 24 h"
          value={vol ? formatBytes(vol.total_bytes) : "–"}
          sub={
            vol && vol.monitored_hosts > 0
              ? `Monitored hosts sent ${formatBytes(vol.monitored_sent_bytes)}, received ${formatBytes(vol.monitored_received_bytes)}`
              : "moved across all sources"
          }
          testId="data-24h"
        />
        <Stat
          label="Sources receiving"
          value={ov ? `${ov.sources_receiving} / ${ov.sources_total}` : "–"}
          sub={ov?.model.version ? `Model: ${ov.model.version}` : "No model active"}
        />
      </div>

      {!noSources && <MonitoredIps hosts={ips.data} sources={sources.data ?? []} />}

      <Card>
        <CardHeader>
          <CardTitle>Traffic</CardTitle>
          <div className="flex flex-wrap items-center gap-3">
          <div className="flex gap-1" role="group" aria-label="Measure">
            {(
              [
                ["flows", "Flows"],
                ["bytes", "Data"],
              ] as const
            ).map(([key, label]) => (
              <Button
                key={key}
                size="sm"
                variant={metric === key ? "default" : "outline"}
                aria-pressed={metric === key}
                data-testid={`metric-${key}`}
                onClick={() => setMetric(key)}
              >
                {label}
              </Button>
            ))}
          </div>
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
          </div>
        </CardHeader>
        <CardContent>
          {traffic.data ? (
            <TrafficChart points={traffic.data.points} bucketMinutes={traffic.data.bucket_minutes} metric={metric} />
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
            <BarList items={foldProtocols(protocols.data ?? [])} format={formatNumber} />
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
              No sources yet. Enter an IP above (or use Add source): a small sensor on that machine, or your
              router&apos;s NetFlow export, is what brings its traffic in.
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
                  <Th />
                  {canRemove && <Th />}
                </tr>
              </thead>
              <tbody data-testid="sources-body">
                {(sources.data ?? []).map((s) => (
                  <SourceRow key={s.id} source={s} onRemove={canRemove ? confirmRemove : undefined} />
                ))}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  );
}
