"use client";

import Link from "next/link";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, Copy, Loader2 } from "lucide-react";
import { useState } from "react";
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

function CreateForm({ onCreated }: { onCreated: (s: SourceCreated) => void }) {
  const create = useMutation({
    mutationFn: (body: unknown) =>
      api<SourceCreated>("sources", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: onCreated,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>1. Describe the network</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-4 text-sm text-black/65 dark:text-white/65">
          An IP address alone does not give us any traffic. Register what you own here, then
          connect a traffic source in the next step.
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
          <div>
            <Label htmlFor="name">Name</Label>
            <Input id="name" name="name" data-testid="source-name" required minLength={2} placeholder="Head office router" />
          </div>
          <div>
            <Label htmlFor="cidr">Public IP or CIDR you own</Label>
            <Input id="cidr" name="cidr" data-testid="source-cidr" required placeholder="203.0.113.10 or 10.20.0.0/24" />
          </div>
          <div>
            <Label htmlFor="method">How will traffic reach us?</Label>
            <Select id="method" name="method" defaultValue="netflow" data-testid="source-method">
              <option value="netflow">NetFlow / IPFIX from your router (recommended)</option>
              <option value="http">HTTP batch API / CSV replay</option>
              <option value="sensor">Sensor container (SPAN port)</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="criticality">Asset criticality</Label>
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
              {create.isPending ? "Creating…" : "Create source"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Instructions({ source }: { source: SourceCreated }) {
  const [active, setActive] = useState(source.setup.snippets[0]?.id);
  const snippet = source.setup.snippets.find((s) => s.id === active);
  const isNetflow = source.method === ("netflow" as SourceMethod);

  return (
    <Card>
      <CardHeader>
        <CardTitle>2. Connect your traffic</CardTitle>
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
            Shown once. Only a hash is stored, so copy it now.
          </p>
        </div>

        {source.setup.snippets.length > 0 && (
          <div>
            <div className="mb-2 flex flex-wrap gap-2" role="tablist">
              {source.setup.snippets.map((s) => (
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>3. Verify</CardTitle>
      </CardHeader>
      <CardContent>
        <div
          data-testid="first-flows-status"
          data-state={received ? "received" : "waiting"}
          className="flex items-center gap-3 text-sm"
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
            </>
          ) : (
            <>
              <Loader2 className="animate-spin" size={18} />
              <span>Waiting for the first flows… this page checks every 2 seconds.</span>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function NewSourcePage() {
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
