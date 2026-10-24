"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { HealthPill } from "@/components/health-pill";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import type { Alert, Source, SourceHealth } from "@/lib/types";
import { timeAgo } from "@/lib/utils";

const LIVE_MS = 3000;

function LiveDot({ active }: { active: boolean }) {
  return (
    <span className="flex items-center gap-2 text-xs text-black/60 dark:text-white/60">
      <span
        className={`h-2 w-2 rounded-full ${active ? "animate-pulse bg-emerald-500" : "bg-slate-400"}`}
      />
      {active ? "Live" : "Paused"}
    </span>
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

export default function DashboardPage() {
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api<Alert[]>("alerts?limit=50"),
    refetchInterval: LIVE_MS,
  });
  const sources = useQuery({
    queryKey: ["sources"],
    queryFn: () => api<Source[]>("sources"),
    refetchInterval: 10000,
  });

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Live alerts</CardTitle>
          <LiveDot active={!alerts.isError} />
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
                {(alerts.data ?? []).map((a) => (
                  <tr key={a.id} data-testid="alert-row">
                    <Td>
                      <SeverityBadge severity={a.severity} />
                    </Td>
                    <Td className="font-medium">{a.attack_class}</Td>
                    <Td className="font-mono text-xs">{a.src_ip ?? "–"}</Td>
                    <Td className="font-mono text-xs">{a.dst_ip ?? "multiple"}</Td>
                    <Td className="text-right tabular-nums">{a.count}</Td>
                    <Td className="text-right tabular-nums">{a.risk_score.toFixed(1)}</Td>
                    <Td>{timeAgo(a.last_seen)}</Td>
                    <Td>{a.status}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
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
              No sources yet. An IP address alone gives no traffic visibility: add a source and
              point your router&apos;s NetFlow export at the collector.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Network</Th>
                  <Th>Method</Th>
                  <Th>Status</Th>
                  <Th className="text-right">Flows</Th>
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
