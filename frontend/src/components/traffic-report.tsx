"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { SplitTable } from "@/components/charts/split-table";
import { VolumeChart } from "@/components/charts/volume-chart";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import { formatBytes, formatDateTime, formatNumber } from "@/lib/format";
import type { HostDetail, HostVolume, TrafficSummary } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

const PERIODS = [
  { label: "Last hour", hours: 1 },
  { label: "Last 6 hours", hours: 6 },
  { label: "Last 24 hours", hours: 24 },
  { label: "Last 7 days", hours: 168 },
  { label: "Last 30 days", hours: 720 },
];

type SectionKey = "overview" | "hosts" | "charts" | "peers" | "services";
const SECTIONS: { key: SectionKey; label: string; help: string }[] = [
  { key: "overview", label: "Totals", help: "data moved, sent and received" },
  { key: "hosts", label: "Hosts table", help: "sent, received and total per host" },
  { key: "charts", label: "Graph: data over time", help: "sent and received, one per host" },
  { key: "peers", label: "Who each host talked to", help: "addresses, sent and received" },
  { key: "services", label: "What each host used", help: "services, sent and received" },
];
// "Summary" is what a manager reads; "Detailed" adds who each host talked to and what it used
const PRESETS: Record<"summary" | "detailed", SectionKey[]> = {
  summary: ["overview", "hosts", "charts"],
  detailed: ["overview", "hosts", "charts", "peers", "services"],
};
const MAX_HOSTS = 10;

function Figure({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="break-inside-avoid rounded-md border border-black/10 px-3 py-2 dark:border-white/15">
      <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">{label}</div>
      <div className="mt-0.5 text-xl font-semibold tabular-nums">{value}</div>
      {sub && <div className="text-xs text-black/60 dark:text-white/60">{sub}</div>}
    </div>
  );
}

function SectionHead({ title, note, csv }: { title: string; note?: string; csv?: string }) {
  return (
    <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
      <h3 className="text-base font-semibold">
        {title}
        {note && <span className="ml-2 text-xs font-normal text-black/55 dark:text-white/55">{note}</span>}
      </h3>
      {csv && (
        <a href={csv} download className="print:hidden">
          <Button size="sm" variant="outline">
            Download CSV
          </Button>
        </a>
      )}
    </div>
  );
}

export function TrafficReport() {
  const params = useSearchParams();
  const queryClient = useQueryClient();
  const [hours, setHours] = useState(() => {
    const wanted = Number(params.get("hours"));
    return PERIODS.some((p) => p.hours === wanted) ? wanted : 24;
  });
  const [level, setLevel] = useState<"summary" | "detailed">("summary");
  const [sections, setSections] = useState<Set<SectionKey>>(() => new Set(PRESETS.summary));
  const [picked, setPicked] = useState<string[] | null>(() => {
    const ip = params.get("ip");
    return ip ? [ip] : null;
  });

  const minutes = hours * 60;
  const hostsQuery = useQuery({
    queryKey: ["report", "hosts", hours],
    queryFn: () => api<HostVolume[]>(`traffic/hosts?minutes=${minutes}&limit=100&include_idle=true`),
    refetchOnWindowFocus: false,
  });
  const summary = useQuery({
    queryKey: ["report", "summary", hours],
    queryFn: () => api<TrafficSummary>(`traffic/summary?minutes=${minutes}`),
    refetchOnWindowFocus: false,
  });
  const all = hostsQuery.data ?? [];
  const chosen = picked ?? all.slice(0, MAX_HOSTS).map((h) => h.ip);
  const top = level === "detailed" ? 25 : 10;
  const needDetail = sections.has("charts") || sections.has("peers") || sections.has("services");
  const details = useQueries({
    queries: chosen.map((ip) => ({
      queryKey: ["report", "host", ip, hours, top],
      queryFn: () => api<HostDetail>(`traffic/hosts/${encodeURIComponent(ip)}?minutes=${minutes}&top=${top}`),
      enabled: needDetail,
      refetchOnWindowFocus: false,
    })),
  });

  function pickLevel(next: "summary" | "detailed") {
    setLevel(next);
    setSections(new Set(PRESETS[next]));
  }
  function toggleSection(key: SectionKey) {
    setSections((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  function toggleHost(ip: string) {
    setPicked(chosen.includes(ip) ? chosen.filter((x) => x !== ip) : [...chosen, ip].slice(0, MAX_HOSTS));
  }
  function csvHref(section: string) {
    const q = new URLSearchParams({ hours: String(hours), section });
    for (const ip of chosen) q.append("ip", ip);
    return `/api/proxy/reports/traffic.csv?${q.toString()}`;
  }

  const period = PERIODS.find((p) => p.hours === hours)?.label ?? `${hours} hours`;
  const generated = summary.dataUpdatedAt || hostsQuery.dataUpdatedAt;
  const rows = all.filter((h) => chosen.includes(h.ip));
  const sum = (pick: (h: HostVolume) => number) => rows.reduce((total, h) => total + pick(h), 0);
  const show = (key: SectionKey) => sections.has(key);
  const ready = hostsQuery.isSuccess && (!needDetail || details.every((d) => !d.isLoading));

  return (
    <div className="space-y-4" data-testid="traffic-report">
      <Card className="print:hidden">
        <CardHeader>
          <CardTitle>Data volume report</CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => queryClient.invalidateQueries({ queryKey: ["report"] })}
              data-testid="report-refresh"
            >
              Refresh
            </Button>
            <Button size="sm" onClick={() => window.print()} disabled={!ready} data-testid="report-print">
              Print or save as PDF
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <p className="text-black/70 dark:text-white/70">
            Pick what you need, check it below, then print it (choose &quot;Save as PDF&quot; in the print window to
            keep a file) or download any table as CSV. Sent and received are from each host&apos;s own point of view.
          </p>
          <div className="grid gap-4 md:grid-cols-3">
            <fieldset>
              <legend className="mb-1 text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">
                Period
              </legend>
              <select
                aria-label="Period"
                data-testid="report-period"
                className="h-9 w-full rounded-md border border-black/15 bg-transparent px-2 dark:border-white/20"
                value={hours}
                onChange={(e) => setHours(Number(e.target.value))}
              >
                {PERIODS.map((p) => (
                  <option key={p.hours} value={p.hours} className="text-black">
                    {p.label}
                  </option>
                ))}
              </select>
              <div className="mt-3 flex gap-1" role="group" aria-label="Level of detail">
                {(["summary", "detailed"] as const).map((l) => (
                  <Button
                    key={l}
                    size="sm"
                    variant={level === l ? "default" : "outline"}
                    aria-pressed={level === l}
                    data-testid={`level-${l}`}
                    onClick={() => pickLevel(l)}
                  >
                    {l === "summary" ? "Summary" : "Detailed"}
                  </Button>
                ))}
              </div>
              <p className="mt-1 text-xs text-black/55 dark:text-white/55">
                Summary: totals, hosts and graphs. Detailed adds who each host talked to and what it used.
              </p>
            </fieldset>
            <fieldset>
              <legend className="mb-1 text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">
                Include
              </legend>
              <ul className="space-y-1">
                {SECTIONS.map((s) => (
                  <li key={s.key}>
                    <label className="flex cursor-pointer items-start gap-2">
                      <input
                        type="checkbox"
                        className="mt-1"
                        checked={show(s.key)}
                        onChange={() => toggleSection(s.key)}
                        data-testid={`section-${s.key}`}
                      />
                      <span>
                        {s.label}
                        <span className="block text-xs text-black/55 dark:text-white/55">{s.help}</span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </fieldset>
            <fieldset>
              <legend className="mb-1 text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">
                Hosts (up to {MAX_HOSTS})
              </legend>
              <div className="mb-1 flex gap-3 text-xs">
                <button type="button" className="underline" onClick={() => setPicked(all.slice(0, MAX_HOSTS).map((h) => h.ip))}>
                  Select all
                </button>
                <button type="button" className="underline" onClick={() => setPicked([])}>
                  Clear
                </button>
              </div>
              {all.length === 0 ? (
                <p className="text-black/60 dark:text-white/60">
                  No monitored IP yet.{" "}
                  <Link href="/sources/new" className="underline">
                    Add a source
                  </Link>
                  .
                </p>
              ) : (
                <ul className="max-h-44 space-y-1 overflow-y-auto">
                  {all.map((h) => (
                    <li key={h.ip}>
                      <label className="flex cursor-pointer items-center gap-2">
                        <input
                          type="checkbox"
                          checked={chosen.includes(h.ip)}
                          disabled={!chosen.includes(h.ip) && chosen.length >= MAX_HOSTS}
                          onChange={() => toggleHost(h.ip)}
                          data-testid="report-host"
                          data-ip={h.ip}
                        />
                        <span className="font-mono text-xs">{h.ip}</span>
                        <span className="truncate text-xs text-black/55 dark:text-white/55">{h.source_name ?? ""}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
            </fieldset>
          </div>
        </CardContent>
      </Card>

      <article
        className="space-y-6 rounded-lg border border-black/10 p-5 dark:border-white/15 print:border-0 print:p-0"
        data-testid="report"
        aria-label="Data volume report"
      >
        <header className="border-b border-black/10 pb-3 dark:border-white/15">
          <h2 className="text-xl font-semibold">SentinelBI data volume report</h2>
          <p className="mt-1 text-sm text-black/70 dark:text-white/70" data-testid="report-meta">
            {period}
            {generated ? `, ${formatDateTime(new Date(generated - minutes * 60000).toISOString())} to ${formatDateTime(new Date(generated).toISOString())}` : ""}
            {" · "}
            {level === "detailed" ? "Detailed" : "Summary"} · {chosen.length} host{chosen.length === 1 ? "" : "s"}
          </p>
        </header>

        {chosen.length === 0 && (
          <p className="text-sm text-black/65 dark:text-white/65" data-testid="report-empty">
            No host is selected. Tick at least one host above.
          </p>
        )}

        {show("overview") && summary.data && (
          <section data-testid="report-overview">
            <SectionHead title="Totals" note="all traffic your sources reported in the period" />
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Figure label="Data moved" value={formatBytes(summary.data.total_bytes)} sub={`${formatNumber(summary.data.flows)} flows`} />
              <Figure label="Sent by monitored hosts" value={formatBytes(summary.data.monitored_sent_bytes)} />
              <Figure label="Received by monitored hosts" value={formatBytes(summary.data.monitored_received_bytes)} />
              <Figure label="Monitored hosts" value={String(summary.data.monitored_hosts)} sub="with traffic" />
            </div>
          </section>
        )}

        {show("hosts") && chosen.length > 0 && (
          <section data-testid="report-hosts" className="break-inside-avoid">
            <SectionHead title="Hosts" note="what each sent and received" csv={csvHref("hosts")} />
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
              <tbody>
                {rows.map((h) => (
                  <tr key={h.ip} data-testid="report-host-row">
                    <Td className="font-mono text-xs">{h.ip}</Td>
                    <Td>{h.source_name ?? "–"}</Td>
                    <Td className="text-right tabular-nums">{formatBytes(h.sent_bytes)}</Td>
                    <Td className="text-right tabular-nums">{formatBytes(h.received_bytes)}</Td>
                    <Td className="text-right tabular-nums">{formatBytes(h.total_bytes)}</Td>
                    <Td className="text-right tabular-nums">{formatNumber(h.flows)}</Td>
                    <Td>{h.last_seen ? timeAgo(h.last_seen) : "none in this period"}</Td>
                  </tr>
                ))}
                {rows.length > 1 && (
                  <tr className="font-semibold" data-testid="report-host-total">
                    <Td>All selected</Td>
                    <Td />
                    <Td className="text-right tabular-nums">{formatBytes(sum((h) => h.sent_bytes))}</Td>
                    <Td className="text-right tabular-nums">{formatBytes(sum((h) => h.received_bytes))}</Td>
                    <Td className="text-right tabular-nums">{formatBytes(sum((h) => h.total_bytes))}</Td>
                    <Td className="text-right tabular-nums">{formatNumber(sum((h) => h.flows))}</Td>
                    <Td />
                  </tr>
                )}
              </tbody>
            </Table>
          </section>
        )}

        {needDetail &&
          chosen.map((ip, i) => {
            const d = details[i]?.data;
            const failed = details[i]?.isError;
            const owner = all.find((h) => h.ip === ip)?.source_name;
            return (
              <section
                key={ip}
                data-testid="report-host-section"
                data-ip={ip}
                className={level === "detailed" ? cn("space-y-5", i > 0 && "print:break-before-page") : "space-y-5 break-inside-avoid"}
              >
                <div className="border-b border-black/10 pb-1 dark:border-white/15">
                  <h3 className="font-mono text-base font-semibold">
                    {ip}
                    {owner && <span className="ml-2 font-sans text-sm font-normal text-black/60 dark:text-white/60">{owner}</span>}
                  </h3>
                  {d && (
                    <p className="text-sm text-black/70 dark:text-white/70">
                      Sent {formatBytes(d.sent_bytes)} · received {formatBytes(d.received_bytes)} · total {formatBytes(d.total_bytes)} ·{" "}
                      {formatNumber(d.flows)} flows
                      {d.flows === 0 && d.last_seen ? ` · last active ${timeAgo(d.last_seen)}` : ""}
                    </p>
                  )}
                </div>
                {failed && (
                  <p role="alert" className="text-sm text-red-600 dark:text-red-400">
                    Could not load this host.
                  </p>
                )}
                {!d && !failed && <div className="h-24" />}
                {d && show("charts") && (
                  <div className="break-inside-avoid">
                    <SectionHead title="Data over time" csv={csvHref("timeline")} />
                    <VolumeChart points={d.points} bucketMinutes={d.bucket_minutes} />
                  </div>
                )}
                {d && show("peers") && (
                  <div>
                    <SectionHead title="Who it talked to" note={`top ${top}`} csv={csvHref("peers")} />
                    <SplitTable
                      testId="report-peers"
                      labelHeader="Address"
                      rows={d.peers.map((p) => ({ label: p.ip, sent: p.sent_bytes, received: p.received_bytes, flows: p.flows }))}
                      emptyText="No traffic with other addresses in this period."
                    />
                  </div>
                )}
                {d && show("services") && (
                  <div>
                    <SectionHead title="What it used" note={`top ${top}, by service`} csv={csvHref("services")} />
                    <SplitTable
                      testId="report-services"
                      labelHeader="Service"
                      rows={d.services.map((s) => ({ label: s.service, note: s.protocol, sent: s.sent_bytes, received: s.received_bytes, flows: s.flows }))}
                      emptyText="No traffic in this period."
                    />
                  </div>
                )}
              </section>
            );
          })}

        <footer className="border-t border-black/10 pt-2 text-xs text-black/55 dark:border-white/15 dark:text-white/55">
          Bytes are counted as the network carried them (IP headers included) and cover only what your sensors
          and routers reported; 1 kB is 1000 bytes. Sent and received are from each host&apos;s own point of view.
          Generated by SentinelBI, a research prototype.
        </footer>
      </article>
    </div>
  );
}
