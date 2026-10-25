"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, Copy, Loader2 } from "lucide-react";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { api } from "@/lib/client-api";
import type { SourceCreated, SourceHealth, SourceMethod } from "@/lib/types";

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      aria-label={label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard unavailable: the text is selectable on screen */
        }
      }}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

const METHODS: { value: SourceMethod; label: string; help: string }[] = [
  {
    value: "sensor",
    label: "Quick start: watch an IP with the sensor (no router setup)",
    help:
      "A small program (plain Python, nothing to install) that you run on the computer you want to watch, or " +
      "on a gateway or mirror port that sees its traffic. It counts packets (addresses, ports, sizes, timing) " +
      "and reports them here. It never reads or sends the contents of your traffic.",
  },
  {
    value: "netflow",
    label: "Router: NetFlow / IPFIX export",
    help:
      "Your router sends flow records to our collector. Best for covering a whole network. " +
      "You get copy-paste router settings in the next step.",
  },
  {
    value: "http",
    label: "Advanced: HTTP batch API / CSV replay",
    help: "For scripts, other sensors and replaying recorded flows over the HTTP API.",
  },
];

function CreateForm({ onCreated }: { onCreated: (s: SourceCreated) => void }) {
  const params = useSearchParams();
  const ip = params.get("ip") ?? "";
  const requested = params.get("method");
  const [method, setMethod] = useState<SourceMethod>(
    METHODS.some((m) => m.value === requested) ? (requested as SourceMethod) : "sensor",
  );
  const create = useMutation({
    mutationFn: (body: unknown) =>
      api<SourceCreated>("sources", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: onCreated,
  });
  const quick = method === "sensor";

  return (
    <Card>
      <CardHeader>
        <CardTitle>1. Choose what to watch</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-4 text-sm text-black/65 dark:text-white/65">
          {quick
            ? "Enter the address of the computer or network you manage. Traffic reaches us through the sensor you run on it in the next step."
            : "An IP address alone does not give us any traffic. Register what you own here, then connect a traffic source in the next step."}
        </p>
        <form
          className="grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            create.mutate({
              name: f.get("name"),
              cidr: f.get("cidr"),
              method: f.get("method"),
              criticality: Number(f.get("criticality")),
            });
          }}
        >
          <div className="sm:col-span-2">
            <Label htmlFor="method">How will traffic reach us?</Label>
            <Select
              id="method"
              name="method"
              value={method}
              onChange={(e) => setMethod(e.target.value as SourceMethod)}
              data-testid="source-method"
            >
              {METHODS.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </Select>
            <p className="mt-1.5 text-xs text-black/60 dark:text-white/60" data-testid="method-help">
              {METHODS.find((m) => m.value === method)?.help}
            </p>
          </div>
          <div>
            <Label htmlFor="cidr">{quick ? "IP address or network to watch" : "Public IP or CIDR you own"}</Label>
            <Input
              id="cidr"
              name="cidr"
              data-testid="source-cidr"
              required
              defaultValue={ip}
              placeholder={quick ? "192.168.1.20 or 192.168.1.0/24" : "203.0.113.10 or 10.20.0.0/24"}
            />
            {quick && (
              <p className="mt-1 text-xs text-black/60 dark:text-white/60" data-testid="address-help">
                Use the address your traffic really leaves from. Windows: run <code>ipconfig</code> and take the
                address of the Wi-Fi or Ethernet adapter that has a Default Gateway (not a &quot;vEthernet&quot;
                one: those are WSL and Hyper-V). Linux: <code>ip route get 1.1.1.1</code>.
              </p>
            )}
          </div>
          <div>
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              name="name"
              data-testid="source-name"
              required
              minLength={2}
              defaultValue={ip ? `Monitor ${ip}` : ""}
              placeholder={quick ? "My laptop" : "Head office router"}
            />
          </div>
          <div>
            <Label htmlFor="criticality">How important is it?</Label>
            <Select id="criticality" name="criticality" defaultValue="2">
              <option value="1">Low</option>
              <option value="2">Medium</option>
              <option value="3">High</option>
            </Select>
          </div>
          <div className="sm:col-span-2">
            {create.isError && (
              <p role="alert" className="mb-3 text-sm text-red-600 dark:text-red-400">
                {(create.error as Error).message}
              </p>
            )}
            <Button type="submit" data-testid="create-source" disabled={create.isPending}>
              {create.isPending ? "Creating…" : quick ? "Get the sensor command" : "Create source"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Instructions({ source }: { source: SourceCreated }) {
  const isNetflow = source.method === ("netflow" as SourceMethod);
  const isSensor = source.method === ("sensor" as SourceMethod);
  const windows = typeof navigator !== "undefined" && /windows/i.test(navigator.userAgent);
  const snippets = source.setup.snippets;
  const preferred = isSensor ? (windows ? "sensor-windows" : "sensor-linux") : undefined;
  const [active, setActive] = useState(snippets.find((s) => s.id === preferred)?.id ?? snippets[0]?.id);
  const snippet = snippets.find((s) => s.id === active);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{isSensor ? "2. Run the sensor" : "2. Connect your traffic"}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {isNetflow && (
          <p className="text-sm">
            Export NetFlow v9 / IPFIX from your router to{" "}
            <code className="rounded bg-black/5 px-1.5 py-0.5 font-mono dark:bg-white/10" data-testid="collector-address">
              {source.setup.collector_host}:{source.setup.collector_port}
            </code>{" "}
            (UDP). The collector only accepts exports from the registered address{" "}
            <code className="font-mono">{source.cidr}</code>; anything else is dropped.
          </p>
        )}
        {isSensor && (
          <div className="space-y-2 text-sm" data-testid="sensor-notes">
            <p>
              Pick your system, then run the commands <strong>on the machine you entered</strong> (
              <code className="font-mono">{source.cidr}</code>), or on a gateway or mirror port that sees its
              traffic. It needs Python 3.9 or newer and administrator / root rights to read packets. Run the
              self-test line first: it proves capture works before you rely on it.
            </p>
            <p className="text-xs text-black/60 dark:text-white/60">
              The sensor only counts packets: addresses, ports, sizes and timing. It never reads or sends their
              contents, and it does not count its own reports to this server. Run it only on machines and
              networks you administer. No admin rights? The last tab replays a bundled demo capture.
            </p>
          </div>
        )}

        <div>
          <Label>API key</Label>
          <div className="flex items-center gap-2">
            <code
              data-testid="api-key"
              className="block flex-1 overflow-x-auto rounded-md bg-black/5 px-3 py-2 font-mono text-xs dark:bg-white/10"
            >
              {source.api_key}
            </code>
            <CopyButton text={source.api_key} label="Copy API key" />
          </div>
          <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
            Shown once. Only a hash is stored, so copy it now (the commands below already contain it).
          </p>
        </div>

        {snippets.length > 0 && (
          <div>
            <div className="mb-2 flex flex-wrap gap-2" role="tablist">
              {snippets.map((s) => (
                <Button
                  key={s.id}
                  role="tab"
                  aria-selected={s.id === active}
                  size="sm"
                  variant={s.id === active ? "default" : "outline"}
                  onClick={() => setActive(s.id)}
                >
                  {s.title}
                </Button>
              ))}
            </div>
            {snippet && (
              <div className="relative">
                <pre className="overflow-x-auto rounded-md bg-black/5 p-3 pr-20 font-mono text-xs dark:bg-white/10" data-testid="snippet">
                  {snippet.content}
                </pre>
                <div className="absolute right-2 top-2">
                  <CopyButton text={snippet.content} label="Copy snippet" />
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Verify({ source }: { source: SourceCreated }) {
  const { data } = useQuery({
    queryKey: ["wizard-health", source.id],
    queryFn: () => api<SourceHealth>(`sources/${source.id}/health`),
    refetchInterval: 2000,
  });
  const received = data?.first_flows_received ?? false;
  const host = source.cidr.includes("/") ? null : source.cidr;

  return (
    <Card>
      <CardHeader>
        <CardTitle>3. Verify</CardTitle>
      </CardHeader>
      <CardContent>
        <div
          data-testid="first-flows-status"
          data-state={received ? "received" : "waiting"}
          className="flex flex-wrap items-center gap-3 text-sm"
        >
          {received ? (
            <>
              <Check className="text-emerald-600" size={18} />
              <span className="font-medium">
                First flows received ({data?.flows_total ?? 0} so far)
              </span>
              <Link href="/dashboard">
                <Button size="sm">Open dashboard</Button>
              </Link>
              <Link href={host ? `/traffic?ip=${encodeURIComponent(host)}` : "/traffic"}>
                <Button size="sm" variant="outline" data-testid="see-traffic">
                  See data volume
                </Button>
              </Link>
            </>
          ) : (
            <>
              <Loader2 className="animate-spin" size={18} />
              <span>
                Waiting for the first flows… this page checks every 2 seconds. The sensor reports a connection
                when it ends or after 15 seconds of silence, so the first records can take a moment.
              </span>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function Wizard() {
  const [created, setCreated] = useState<SourceCreated | null>(null);
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-xl font-semibold">Add a source</h1>
      {!created ? (
        <CreateForm onCreated={setCreated} />
      ) : (
        <>
          <Instructions source={created} />
          <Verify source={created} />
        </>
      )}
    </div>
  );
}

export default function NewSourcePage() {
  return (
    <Suspense fallback={<div className="h-48" />}>
      <Wizard />
    </Suspense>
  );
}
