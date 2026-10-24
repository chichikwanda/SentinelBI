"use client";

import { useQuery } from "@tanstack/react-query";
import { RiskGauge } from "@/components/charts/risk-gauge";
import { TrendChart } from "@/components/charts/trend-chart";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import type { RiskOut, RiskTrend } from "@/lib/types";

const CRITICALITY = ["", "Low", "Medium", "High"];

export default function RiskPage() {
  const risk = useQuery({ queryKey: ["risk"], queryFn: () => api<RiskOut>("risk/assets"), refetchInterval: 8000 });
  const trend = useQuery({ queryKey: ["risk-trend"], queryFn: () => api<RiskTrend>("risk/trend?hours=24"), refetchInterval: 30000 });

  return (
    <>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Organisation risk</CardTitle>
          </CardHeader>
          <CardContent>
            {risk.data ? <RiskGauge score={risk.data.score} severity={risk.data.severity} /> : <div className="h-20" />}
            <p className="mt-3 text-xs text-black/60 dark:text-white/60">
              Criticality-weighted mean of asset risk over the last 24 hours. Highest single asset:{" "}
              {risk.data ? risk.data.peak_asset.toFixed(1) : "–"}.
            </p>
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Risk, last 24 hours</CardTitle>
          </CardHeader>
          <CardContent>{trend.data ? <TrendChart points={trend.data.points} /> : <div className="h-40" />}</CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Assets</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {risk.data && risk.data.assets.length === 0 ? (
            <p className="p-4 text-sm text-black/60 dark:text-white/60">
              No assets yet. Register a single-host source, or alerts will be grouped per source.
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Asset</Th>
                  <Th>Address</Th>
                  <Th>Criticality</Th>
                  <Th className="text-right">Open alerts</Th>
                  <Th className="text-right">Risk</Th>
                  <Th>Severity</Th>
                </tr>
              </thead>
              <tbody>
                {(risk.data?.assets ?? []).map((a) => (
                  <tr key={a.asset_id ?? a.label} data-testid="asset-row">
                    <Td className="font-medium">
                      {a.label}
                      {a.internet_facing && <Badge className="ml-2 bg-slate-500/15 font-normal">internet-facing</Badge>}
                      {!a.registered && <Badge className="ml-2 bg-slate-500/15 font-normal">not a registered asset</Badge>}
                    </Td>
                    <Td className="font-mono text-xs">{a.ip ?? "–"}</Td>
                    <Td>{CRITICALITY[a.criticality] ?? a.criticality}</Td>
                    <Td className="text-right tabular-nums">{a.open_alerts}</Td>
                    <Td className="text-right tabular-nums">{a.score.toFixed(1)}</Td>
                    <Td>{a.severity}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  );
}
