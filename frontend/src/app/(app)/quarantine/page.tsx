"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { DecisionButtons } from "@/components/inventory";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { QuarantineItem } from "@/lib/types";
import { timeAgo } from "@/lib/utils";

type Platform = "windows" | "linux" | "gateway";
const PLATFORMS: { value: Platform; label: string; hint: string }[] = [
  { value: "windows", label: "This Windows PC", hint: "Administrator PowerShell on the machine you want to protect." },
  { value: "linux", label: "This Linux host", hint: "On the machine you want to protect." },
  { value: "gateway", label: "Router / gateway (Linux)", hint: "On the gateway: cuts the address off for the whole network." },
];

function BlockRules({ item }: { item: QuarantineItem }) {
  const [open, setOpen] = useState(false);
  const [platform, setPlatform] = useState<Platform>("gateway");
  const [copied, setCopied] = useState(false);
  const text = item.commands[platform].join("\n");
  return (
    <div className="space-y-2">
      <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? "Hide block commands" : "Show block commands"}
      </Button>
      {open && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1" role="group" aria-label="Where to run the commands">
            {PLATFORMS.map((p) => (
              <Button
                key={p.value}
                size="sm"
                variant={platform === p.value ? "default" : "outline"}
                aria-pressed={platform === p.value}
                onClick={() => setPlatform(p.value)}
              >
                {p.label}
              </Button>
            ))}
          </div>
          <p className="text-xs text-black/60 dark:text-white/60">
            {PLATFORMS.find((p) => p.value === platform)?.hint} SentinelBI does not run these for you; nothing
            is blocked until you do.
          </p>
          <pre className="overflow-x-auto rounded bg-black/5 p-3 text-xs dark:bg-white/10">{text}</pre>
          <Button
            size="sm"
            variant="outline"
            onClick={async () => {
              await navigator.clipboard.writeText(text).catch(() => undefined);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      )}
    </div>
  );
}

export default function QuarantinePage() {
  const queue = useQuery({
    queryKey: ["quarantine"],
    queryFn: () => api<QuarantineItem[]>("inventory/quarantine"),
    refetchInterval: 5000,
  });
  const items = queue.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quarantine</CardTitle>
        <p className="text-sm text-black/60 dark:text-white/60">
          Devices and networks flagged as suspicious, held here for your decision. A High or Critical alert flags
          the address it came from. <strong>Nothing on your network is blocked automatically</strong>: release
          what is a false alarm, and for what is real use the block commands.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {queue.isError ? (
          <p className="text-sm text-red-600" role="alert">
            {(queue.error as Error).message}
          </p>
        ) : items.length === 0 ? (
          <p className="text-sm text-black/60 dark:text-white/60">
            Nothing is in quarantine. Suspicious activity will appear here as it is detected.
          </p>
        ) : (
          items.map((item) => (
            <div key={`${item.kind}-${item.id}`} className="space-y-3 rounded-lg border border-red-600/30 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-base font-semibold">{item.target}</span>
                  <Badge className="bg-red-600/15 text-red-700 dark:text-red-300">
                    {item.kind === "device" ? "Device on your network" : "Outside network"}
                  </Badge>
                  <span className="text-xs text-black/55 dark:text-white/55">held {timeAgo(item.since)}</span>
                </div>
                <DecisionButtons
                  kind={item.kind === "device" ? "devices" : "networks"}
                  id={item.id}
                  state="quarantined"
                  invalidate={[["quarantine"], ["devices"], ["networks"], ["inventory-summary"]]}
                />
              </div>
              {item.reason && <p className="text-sm">{item.reason}</p>}
              {item.kind === "network" && item.flagged_ips.length > 0 && (
                <p className="text-sm">
                  Flagged addresses: <span className="font-mono">{item.flagged_ips.join(", ")}</span>
                </p>
              )}
              {item.alert_id && (
                <Link href={`/alerts/${item.alert_id}`} className="text-sm underline">
                  See the alert and recommended actions
                </Link>
              )}
              <BlockRules item={item} />
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
