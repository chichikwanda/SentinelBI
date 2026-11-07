"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { api } from "@/lib/client-api";
import type { SettingItem, SettingsResponse } from "@/lib/types";

type Value = string | number | boolean;
type Draft = Record<string, Value>;

function Field({
  item,
  value,
  disabled,
  onChange,
  onReset,
}: {
  item: SettingItem;
  value: Value;
  disabled: boolean;
  onChange: (v: Value) => void;
  onReset: () => void;
}) {
  const id = `setting-${item.key}`;
  return (
    <div className="grid gap-1 py-3 sm:grid-cols-[1fr_16rem] sm:items-start sm:gap-6" data-testid={id}>
      <div>
        <label htmlFor={id} className="text-sm font-medium">
          {item.label}
          {item.overridden && <Badge className="ml-2 bg-blue-600/15 text-blue-700 dark:text-blue-300">changed</Badge>}
        </label>
        <p className="text-xs text-black/60 dark:text-white/60">{item.help}</p>
        {item.overridden && !disabled && (
          <button type="button" className="mt-1 text-xs text-blue-700 underline dark:text-blue-300" onClick={onReset}>
            Reset to the default ({String(item.default) || "none"})
          </button>
        )}
      </div>
      <div className="flex items-center gap-2">
        {item.kind === "bool" ? (
          <label className="flex items-center gap-2 text-sm">
            <input
              id={id}
              type="checkbox"
              checked={Boolean(value)}
              disabled={disabled}
              onChange={(e) => onChange(e.target.checked)}
              className="h-4 w-4"
            />
            {value ? "On" : "Off"}
          </label>
        ) : item.kind === "choice" ? (
          <Select id={id} value={String(value)} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
            {item.choices.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </Select>
        ) : item.kind === "emails" ? (
          <Input
            id={id}
            value={String(value)}
            disabled={disabled}
            placeholder="a@x.com, b@y.com"
            onChange={(e) => onChange(e.target.value)}
          />
        ) : (
          <>
            <Input
              id={id}
              type="number"
              min={item.min ?? undefined}
              max={item.max ?? undefined}
              step={item.kind === "int" ? 1 : "any"}
              value={String(value)}
              disabled={disabled}
              onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
            />
            {item.unit && <span className="text-xs text-black/55 dark:text-white/55">{item.unit}</span>}
          </>
        )}
      </div>
    </div>
  );
}

export function SettingsForm({ groups }: { groups?: string[] }) {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api<SettingsResponse>("settings") });
  const [draft, setDraft] = useState<Draft>({});
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const save = useMutation({
    mutationFn: (values: Draft) =>
      api<SettingsResponse>("settings", { method: "PUT", body: JSON.stringify({ values }) }),
    onSuccess: (data) => {
      qc.setQueryData(["settings"], data);
      setDraft({});
      setMessage({ ok: true, text: "Saved. The worker picks changes up within about 10 seconds." });
    },
    onError: (e: Error) => setMessage({ ok: false, text: e.message }),
  });
  const reset = useMutation({
    mutationFn: (key: string) => api<SettingsResponse>(`settings/${key}`, { method: "DELETE" }),
    onSuccess: (data, key) => {
      qc.setQueryData(["settings"], data);
      setDraft((d) => Object.fromEntries(Object.entries(d).filter(([k]) => k !== key)));
      setMessage({ ok: true, text: "Back to the default." });
    },
    onError: (e: Error) => setMessage({ ok: false, text: e.message }),
  });

  if (settings.isLoading) return <p className="text-sm">Loading settings…</p>;
  if (settings.error || !settings.data) return <p className="text-sm text-red-700">Could not load settings.</p>;
  const { can_edit, items } = settings.data;
  const shown = groups ? items.filter((i) => groups.includes(i.group)) : items;
  const byGroup: Record<string, SettingItem[]> = {};
  for (const i of shown) (byGroup[i.group] ??= []).push(i);
  const dirty = Object.keys(draft).length > 0;

  return (
    <div className="space-y-4">
      {!can_edit && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm" data-testid="settings-readonly">
          You can read these settings but not change them. Only platform administrators can: their emails are in
          PLATFORM_ADMIN_EMAILS in the server&apos;s .env file, and they can add more under Access.
        </p>
      )}
      {Object.entries(byGroup).map(([group, list]) => (
        <Card key={group}>
          <CardHeader>
            <CardTitle>{group}</CardTitle>
          </CardHeader>
          <CardContent className="divide-y divide-black/10 py-1 dark:divide-white/10">
            {list.map((item) => (
              <Field
                key={item.key}
                item={item}
                value={draft[item.key] ?? item.value}
                disabled={!can_edit}
                onChange={(v) => setDraft((d) => ({ ...d, [item.key]: v }))}
                onReset={() => reset.mutate(item.key)}
              />
            ))}
          </CardContent>
        </Card>
      ))}
      {can_edit && (
        <div className="sticky bottom-0 flex items-center gap-3 border-t border-black/10 bg-background py-3 dark:border-white/15">
          <Button onClick={() => save.mutate(draft)} disabled={!dirty || save.isPending} data-testid="settings-save">
            {save.isPending ? "Saving…" : "Save changes"}
          </Button>
          {dirty && (
            <Button variant="ghost" onClick={() => setDraft({})}>
              Discard
            </Button>
          )}
          {message && (
            <span
              role="status"
              className={`text-sm ${message.ok ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"}`}
            >
              {message.text}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
