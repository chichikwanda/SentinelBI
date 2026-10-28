"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Suspense, useState } from "react";
import { SplitTable } from "@/components/charts/split-table";
import { VolumeChart } from "@/components/charts/volume-chart";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatBytes, formatNumber } from "@/lib/format";
import type { HostDetail, HostVolume, TrafficSummary } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

const WINDOWS = [
  { label: "1 hour", minutes: 60 },
  { label: "6 hours", minutes: 360 },
  { label: "24 hours", minutes: 1440 },
  { label: "7 days", minutes: 10080 },
  { label: "30 days", minutes: 43200 },
];

/** The smallest longer window that reaches back to ``lastSeen``, if there is one. */
function widerWindow(lastSeen: string | null, minutes: number) {
  if (!lastSeen) return null;
  const ageMinutes = (Date.now() - new Date(lastSeen).getTime()) / 60000;
  return WINDOWS.find((w) => w.minutes > minutes && w.minutes >= ageMinutes) ?? null;
}

function Tile({ label, value, sub, testId }: { label: string; value: string; sub?: string; testId?: string }) {
  return (
    <Card>
      <CardContent>
        <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">{label}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums" data-testid={testId}>
          {value}
        </div>
        {sub && <div className="mt-1 text-xs text-black/60 dark:text-white/60">{sub}</div>}
      </CardContent>
    </Card>
  );
}

function HostPanel({
  ip,
  minutes,
  onWiden,
}: {
  ip: string;
  minutes: number;
  onWiden: (minutes: number) => void;
}) {
  const detail = useQuery({
    queryKey: ["host", ip, minutes],
    queryFn: () => api<HostDetail>(`traffic/hosts/${encodeURIComponent(ip)}?minutes=${minutes}&top=25`),
    refetchInterval: 10000,
  });
  const d = detail.data;
  const windowLabel = WINDOWS.find((w) => w.minutes === minutes)?.label ?? `${minutes} minutes`;
  const wider = d && d.flows === 0 ? widerWindow(d.last_seen, minutes) : null;
  const hours = Math.min(720, Math.max(1, Math.round(minutes / 60)));

  return (
    <div className="space-y-4" data-testid="host-detail" data-ip={ip}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">
          <span className="font-mono">{ip}</span>
        </h2>
        <Link href={`/reports?ip=${encodeURIComponent(ip)}&hours=${hours}`} data-testid="make-report">
          <Button size="sm" variant="outline">
            Make a report for this address
          </Button>
        </Link>
      </div>

      {d && d.flows === 0 && (
        <Card data-testid="host-quiet">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <p>
              No traffic for this address in the last {windowLabel.toLowerCase()}.{" "}
              {d.last_seen
                ? `It was last active ${timeAgo(d.last_seen)}.`
                : "Nothing from it has been recorded yet. If its sensor is not running, start it on that machine."}
            </p>
            {wider && (
              <Button size="sm" onClick={() => onWiden(wider.minutes)} data-testid="widen-window">
                Show the last {wider.label.toLowerCase()}
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label="Sent" value={d ? formatBytes(d.sent_bytes) : "–"} sub="uploaded by this host" testId="host-sent" />
        <Tile label="Received" value={d ? formatBytes(d.received_bytes) : "–"} sub="downloaded by this host" testId="host-received" />
        <Tile label="Total" value={d ? formatBytes(d.total_bytes) : "–"} testId="host-total" />
        <Tile label="Flows" value={d ? formatNumber(d.flows) : "–"} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Data over time</CardTitle>
        </CardHeader>
        <CardContent>
          {detail.isError ? (
            <p role="alert" className="text-sm text-red-600 dark:text-red-400">
              Could not load this host: {(detail.error as Error).message}
            </p>
          ) : d ? (
            <VolumeChart points={d.points} bucketMinutes={d.bucket_minutes} />
          ) : (
            <div className="h-48" />
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Who it talked to</CardTitle>
          <span className="text-xs text-black/55 dark:text-white/55">biggest first, bytes</span>
        </CardHeader>
        <CardContent>
          <SplitTable
            testId="peers-table"
            labelHeader="Address"
            rows={(d?.peers ?? []).map((p) => ({
              label: p.ip,
              sent: p.sent_bytes,
              received: p.received_bytes,
              flows: p.flows,
            }))}
            emptyText="No traffic with this host in this window."
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>What it used</CardTitle>
          <span className="text-xs text-black/55 dark:text-white/55">by service, biggest first, bytes</span>
        </CardHeader>
        <CardContent>
          <SplitTable
            testId="services-table"
            labelHeader="Service"
            rows={(d?.services ?? []).map((s) => ({
              label: s.service,
              note: s.protocol,
              sent: s.sent_bytes,
              received: s.received_bytes,
              flows: s.flows,
            }))}
            emptyText="No traffic with this host in this window."
          />
        </CardContent>
      </Card>
    </div>
  );
}

function TrafficView() {
  const router = useRouter();
  const params = useSearchParams();
  const wanted = params.get("ip");
  const sourceId = params.get("source");
  const [minutes, setMinutes] = useState(1440);
  const summary = useQuery({
    queryKey: ["traffic-summary", minutes],
    queryFn: () => api<TrafficSummary>(`traffic/summary?minutes=${minutes}`),
    refetchInterval: 10000,
  });
  const hosts = useQuery({
    queryKey: ["traffic-hosts", minutes, "all", sourceId],
    queryFn: () =>
      api<HostVolume[]>(
        `traffic/hosts?minutes=${minutes}&limit=100&include_idle=true${sourceId ? `&source_id=${encodeURIComponent(sourceId)}` : ""}`,
      ),
    refetchInterval: 10000,
  });
  const list = hosts.data ?? [];
  const selected = wanted ?? list[0]?.ip ?? null;
  const s = summary.data;
  const hours = Math.min(720, Math.max(1, Math.round(minutes / 60)));
  const filteredName = sourceId ? (list.find((h) => h.source_name)?.source_name ?? "one source") : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Traffic</h1>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap gap-1" role="group" aria-label="Time window">
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
          <Link href={`/reports?hours=${hours}${selected ? `&ip=${encodeURIComponent(selected)}` : ""}`}>
            <Button size="sm" variant="outline" data-testid="open-reports">
              Reports
            </Button>
          </Link>
          <a href={`/api/proxy/reports/traffic.csv?hours=${hours}`} download>
            <Button size="sm" variant="outline" data-testid="download-traffic-csv">
              Download CSV
            </Button>
          </a>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label="Data moved" value={s ? formatBytes(s.total_bytes) : "–"} sub={s ? `${formatNumber(s.flows)} flows` : undefined} testId="traffic-total" />
        <Tile label="Sent by monitored hosts" value={s ? formatBytes(s.monitored_sent_bytes) : "–"} testId="traffic-sent" />
        <Tile label="Received by monitored hosts" value={s ? formatBytes(s.monitored_received_bytes) : "–"} testId="traffic-received" />
        <Tile label="Monitored hosts" value={s ? String(s.monitored_hosts) : "–"} sub="with traffic in this window" testId="traffic-hosts" />
      </div>

      {hosts.isError ? (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          Could not load traffic: {(hosts.error as Error).message}
        </p>
      ) : hosts.data && list.length === 0 ? (
        <Card data-testid="no-hosts">
          <CardContent>
            <p className="text-sm">
              No monitored address yet{sourceId ? " for this source" : ""}. Add a source, run the sensor on the
              machine you want to watch, and its data volume appears here within seconds. A network range shows
              its hosts once they have traffic.
            </p>
            <Link href="/sources/new" className="mt-3 inline-block">
              <Button size="sm">Add a source</Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Monitored IPs</CardTitle>
              {filteredName && (
                <span className="flex items-center gap-2 text-xs text-black/60 dark:text-white/60">
                  Showing {filteredName} only
                  <Link href="/traffic" className="text-blue-700 underline-offset-2 hover:underline dark:text-blue-300">
                    Show all
                  </Link>
                </span>
              )}
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <thead>
                  <tr>
                    <Th>Host</Th>
                    <Th>Source</Th>
                    <Th className="text-right">Sent</Th>
                    <Th className="text-right">Received</Th>
                    <Th className="text-right">Total</Th>
                    <Th className="text-right">Flows</Th>
                    <Th>Last seen</Th>
                  </tr>
                </thead>
                <tbody data-testid="hosts-body">
                  {list.map((h) => (
                    <tr key={h.ip} data-testid="host-row" className={cn(h.ip === selected && "bg-black/5 dark:bg-white/10")}>
                      <Td className="font-mono text-xs">
                        <button
                          type="button"
                          className="text-blue-700 underline-offset-2 hover:underline dark:text-blue-300"
                          aria-current={h.ip === selected}
                          onClick={() => router.replace(`/traffic?ip=${encodeURIComponent(h.ip)}${sourceId ? `&source=${encodeURIComponent(sourceId)}` : ""}`)}
                        >
                          {h.ip}
                        </button>
                      </Td>
                      <Td>{h.source_name ?? "–"}</Td>
                      <Td className="text-right tabular-nums">{formatBytes(h.sent_bytes)}</Td>
                      <Td className="text-right tabular-nums">{formatBytes(h.received_bytes)}</Td>
                      <Td className="text-right tabular-nums">{formatBytes(h.total_bytes)}</Td>
                      <Td className="text-right tabular-nums">{formatNumber(h.flows)}</Td>
                      <Td>{h.last_seen ? timeAgo(h.last_seen) : "none in this window"}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardContent>
          </Card>
          {selected && <HostPanel ip={selected} minutes={minutes} onWiden={setMinutes} />}
        </>
      )}
    </div>
  );
}

export default function TrafficPage() {
  return (
    <Suspense fallback={<div className="h-48" />}>
      <TrafficView />
    </Suspense>
  );
}
