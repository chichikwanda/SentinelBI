"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { DecisionButtons, ForgetButton, StateBadge } from "@/components/inventory";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import type { Device, DeviceState, InventorySummary, Source } from "@/lib/types";
import { timeAgo } from "@/lib/utils";

const FILTERS: { label: string; value: DeviceState | "all" }[] = [
  { label: "All", value: "all" },
  { label: "New", value: "new" },
  { label: "Quarantined", value: "quarantined" },
  { label: "Trusted", value: "trusted" },
  { label: "Known", value: "known" },
];
const ONLINE_MS = 10 * 60 * 1000;
const PAGE = 500;

export default function DevicesPage() {
  const [state, setState] = useState<DeviceState | "all">("all");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(PAGE);
  // the clock is state (not read while rendering) so "online" and "learning" stay correct and pure
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(t);
  }, []);
  const devices = useQuery({
    queryKey: ["devices", state, limit],
    queryFn: () =>
      api<Device[]>(`inventory/devices?limit=${limit}${state === "all" ? "" : `&state=${state}`}`),
    refetchInterval: 5000,
  });
  const summary = useQuery({
    queryKey: ["inventory-summary"],
    queryFn: () => api<InventorySummary>("inventory/summary"),
    refetchInterval: 5000,
  });
  const sources = useQuery({ queryKey: ["sources"], queryFn: () => api<Source[]>("sources") });
  const sourceName = new Map((sources.data ?? []).map((s) => [s.id, s.name]));
  const learning = (sources.data ?? []).filter(
    (s) => s.baseline_until && new Date(s.baseline_until).getTime() > now,
  );

  const needle = search.trim().toLowerCase();
  const rows = (devices.data ?? []).filter(
    (d) =>
      !needle ||
      [d.ip, d.mac ?? "", d.hostname ?? "", d.vendor ?? ""].some((v) => v.toLowerCase().includes(needle)),
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Devices on your networks</CardTitle>
          <p className="text-sm text-black/60 dark:text-white/60">
            Every device found on a registered network, from the sensor&apos;s discovery and from its traffic.
            {summary.data
              ? ` ${summary.data.devices_total} devices, ${summary.data.devices_new} new, ${summary.data.devices_quarantined} quarantined.`
              : ""}
          </p>
          {learning.length > 0 && (
            <p className="rounded bg-amber-500/15 px-3 py-2 text-sm text-amber-900 dark:text-amber-200">
              Still learning what is normal for {learning.map((s) => s.name).join(", ")} (until{" "}
              {new Date(learning[0].baseline_until as string).toLocaleDateString()}). Devices seen now count as
              known; anything that joins afterwards is marked <strong>New</strong> for you to decide.
            </p>
          )}
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
              placeholder="Search IP, MAC, vendor or name"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search devices"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {devices.isError ? (
            <p className="p-4 text-sm text-red-600" role="alert">
              {(devices.error as Error).message}
            </p>
          ) : rows.length === 0 ? (
            <p className="p-4 text-sm text-black/60 dark:text-white/60">
              {devices.data?.length === 0 && state === "all"
                ? "No devices yet. Register a network (Add source, method sensor) and run its sensor: it lists every device it finds within a few minutes."
                : "No devices match."}
            </p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Address</Th>
                  <Th>Name</Th>
                  <Th>MAC</Th>
                  <Th>Vendor</Th>
                  <Th>Network</Th>
                  <Th>State</Th>
                  <Th>First seen</Th>
                  <Th>Last seen</Th>
                  <Th>Decision</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => {
                  const online = now - new Date(d.last_seen).getTime() < ONLINE_MS;
                  return (
                    <tr key={d.id}>
                      <Td className="font-mono">
                        <span
                          className={`mr-2 inline-block h-2 w-2 rounded-full ${online ? "bg-emerald-500" : "bg-slate-400"}`}
                          title={online ? "seen in the last 10 minutes" : "not seen recently"}
                        />
                        {d.ip}
                      </Td>
                      <Td>{d.hostname ?? "-"}</Td>
                      <Td className="font-mono text-xs">{d.mac ?? "-"}</Td>
                      <Td>{d.vendor ?? "-"}</Td>
                      <Td>{sourceName.get(d.source_id) ?? "-"}</Td>
                      <Td>
                        <StateBadge state={d.state} />
                        {d.state_reason && d.state !== "known" && (
                          <div className="mt-1 max-w-xs text-xs text-black/55 dark:text-white/55">{d.state_reason}</div>
                        )}
                      </Td>
                      <Td>{timeAgo(d.first_seen)}</Td>
                      <Td>{timeAgo(d.last_seen)}</Td>
                      <Td>
                        <DecisionButtons
                          kind="devices"
                          id={d.id}
                          state={d.state}
                          invalidate={[["devices"], ["inventory-summary"], ["quarantine"]]}
                        />
                        {!online && d.state !== "quarantined" && (
                          <ForgetButton kind="devices" id={d.id} invalidate={[["devices"], ["inventory-summary"]]} />
                        )}
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
          {(devices.data?.length ?? 0) >= limit && (
            <div className="p-3">
              <Button size="sm" variant="outline" onClick={() => setLimit((l) => l + PAGE)}>
                Show more
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
