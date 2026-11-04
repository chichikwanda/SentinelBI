"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { DecisionButtons, ForgetButton, StateBadge } from "@/components/inventory";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatBytes, formatNumber } from "@/lib/format";
import type { InventorySummary, NetworkState, PeerNetwork, Source } from "@/lib/types";
import { timeAgo } from "@/lib/utils";

const PAGE = 500;
const FILTERS: { label: string; value: NetworkState | "all" }[] = [
  { label: "All", value: "all" },
  { label: "New", value: "new" },
  { label: "Quarantined", value: "quarantined" },
  { label: "Approved", value: "approved" },
  { label: "Regular", value: "baseline" },
];

export default function NetworksPage() {
  const [state, setState] = useState<NetworkState | "all">("new");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const networks = useQuery({
    queryKey: ["networks", state, limit],
    queryFn: () =>
      api<PeerNetwork[]>(`inventory/networks?limit=${limit}${state === "all" ? "" : `&state=${state}`}`),
    refetchInterval: 5000,
  });
  const summary = useQuery({
    queryKey: ["inventory-summary"],
    queryFn: () => api<InventorySummary>("inventory/summary"),
    refetchInterval: 5000,
  });
  const sources = useQuery({ queryKey: ["sources"], queryFn: () => api<Source[]>("sources") });
  const sourceName = new Map((sources.data ?? []).map((s) => [s.id, s.name]));

  const needle = search.trim().toLowerCase();
  const rows = (networks.data ?? []).filter((n) => !needle || n.network.toLowerCase().includes(needle));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Networks talking to yours</CardTitle>
        <p className="text-sm text-black/60 dark:text-white/60">
          The regular networks are the ones seen while a source was learning (its first days). Any network
          that appears afterwards is <strong>New</strong> until you approve it or quarantine it. Networks are
          grouped as a /24 (IPv4) or /48 (IPv6).
          {summary.data
            ? ` ${summary.data.networks_total} networks, ${summary.data.networks_new} new, ${summary.data.networks_quarantined} quarantined.`
            : ""}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by state">
            {FILTERS.map((f) => (
              <Button
                key={f.value}
                size="sm"
                variant={state === f.value ? "default" : "outline"}
                aria-pressed={state === f.value}
                onClick={() => setState(f.value)}
              >
                {f.label}
              </Button>
            ))}
          </div>
          <Input
            className="max-w-xs"
            placeholder="Search a network"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search networks"
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {networks.isError ? (
          <p className="p-4 text-sm text-red-600" role="alert">
            {(networks.error as Error).message}
          </p>
        ) : rows.length === 0 ? (
          <p className="p-4 text-sm text-black/60 dark:text-white/60">
            {state === "new"
              ? "Nothing new is waiting for a decision."
              : "No networks match. They appear as the sensor reports traffic."}
          </p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Network</Th>
                <Th>Talks to</Th>
                <Th>State</Th>
                <Th>Flows</Th>
                <Th>Data</Th>
                <Th>First seen</Th>
                <Th>Last seen</Th>
                <Th>Decision</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((n) => (
                <tr key={n.id}>
                  <Td className="font-mono">{n.network}</Td>
                  <Td>{sourceName.get(n.source_id) ?? "-"}</Td>
                  <Td>
                    <StateBadge state={n.state} />
                    {n.state_reason && n.state !== "baseline" && (
                      <div className="mt-1 max-w-xs text-xs text-black/55 dark:text-white/55">{n.state_reason}</div>
                    )}
                  </Td>
                  <Td>{formatNumber(n.flows)}</Td>
                  <Td>{formatBytes(n.bytes)}</Td>
                  <Td>{timeAgo(n.first_seen)}</Td>
                  <Td>{timeAgo(n.last_seen)}</Td>
                  <Td>
                    <DecisionButtons
                      kind="networks"
                      id={n.id}
                      state={n.state}
                      invalidate={[["networks"], ["inventory-summary"], ["quarantine"]]}
                    />
                    {n.state !== "quarantined" && (
                      <ForgetButton kind="networks" id={n.id} invalidate={[["networks"], ["inventory-summary"]]} />
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {(networks.data?.length ?? 0) >= limit && (
          <div className="p-3">
            <Button size="sm" variant="outline" onClick={() => setLimit((l) => l + PAGE)}>
              Show more
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
