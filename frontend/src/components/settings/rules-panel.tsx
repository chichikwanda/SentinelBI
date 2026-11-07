"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { api } from "@/lib/client-api";
import type { RuleRow, RulesResponse } from "@/lib/types";

function RuleCard({ rule, canEdit, onSaved }: { rule: RuleRow; canEdit: boolean; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [actions, setActions] = useState(rule.actions.map((a) => ({ action: a.action, priority: a.priority, effort: a.effort })));
  const [error, setError] = useState<string | null>(null);
  const put = useMutation({
    mutationFn: (body: unknown) => api<RuleRow>(`rules/${rule.id}`, { method: "PUT", body: JSON.stringify(body) }),
    onSuccess: () => {
      setError(null);
      setEditing(false);
      onSaved();
    },
    onError: (e: Error) => setError(e.message),
  });
  const reset = useMutation({
    mutationFn: () => api<RuleRow>(`rules/${rule.id}`, { method: "DELETE" }),
    onSuccess: onSaved,
    onError: (e: Error) => setError(e.message),
  });
  const when = rule.profile_only
    ? `needs no alert: fires when "${rule.weak_area}" is ${rule.max_level} or lower`
    : `${Array.isArray(rule.attack_class) ? rule.attack_class.join(", ") : rule.attack_class === "*" ? "any attack class" : rule.attack_class}` +
      `, severity ${rule.min_severity} or higher` +
      (rule.weak_area ? `, and "${rule.weak_area}" is ${rule.max_level} or lower` : "") +
      (rule.ports ? `, on ports ${rule.ports.join(", ")}` : "");
  return (
    <li className="py-3" data-testid={`rule-${rule.id}`}>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-mono font-medium">{rule.id}</span>
        {!rule.enabled && <Badge className="bg-amber-500/20 text-amber-800 dark:text-amber-300">off</Badge>}
        {rule.changed && rule.enabled && <Badge className="bg-blue-600/15 text-blue-700 dark:text-blue-300">edited</Badge>}
        <span className="text-xs text-black/60 dark:text-white/60">{when}</span>
        <span className="ml-auto flex gap-2">
          {canEdit && (
            <>
              <Button size="sm" variant="outline" disabled={put.isPending} onClick={() => put.mutate({ enabled: !rule.enabled })}>
                {rule.enabled ? "Switch off" : "Switch on"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setEditing((e) => !e)}>
                {editing ? "Cancel" : "Edit actions"}
              </Button>
              {rule.changed && (
                <Button size="sm" variant="ghost" onClick={() => reset.mutate()}>
                  Reset
                </Button>
              )}
            </>
          )}
        </span>
      </div>
      <ul className="mt-2 space-y-2">
        {rule.actions.map((a, i) => (
          <li key={i} className="rounded-md border border-black/10 p-2 text-sm dark:border-white/15">
            {editing ? (
              <div className="grid gap-2 sm:grid-cols-[1fr_5rem_7rem]">
                <Input
                  aria-label={`Action ${i + 1} text`}
                  value={actions[i].action}
                  onChange={(e) => setActions((all) => all.map((x, j) => (j === i ? { ...x, action: e.target.value } : x)))}
                />
                <Input
                  aria-label={`Action ${i + 1} priority`}
                  type="number"
                  min={1}
                  max={5}
                  value={actions[i].priority}
                  onChange={(e) => setActions((all) => all.map((x, j) => (j === i ? { ...x, priority: Number(e.target.value) } : x)))}
                />
                <Select
                  aria-label={`Action ${i + 1} effort`}
                  value={actions[i].effort}
                  onChange={(e) => setActions((all) => all.map((x, j) => (j === i ? { ...x, effort: e.target.value } : x)))}
                >
                  <option>low</option>
                  <option>medium</option>
                  <option>high</option>
                </Select>
              </div>
            ) : (
              <p>
                {a.action} <span className="text-xs text-black/55 dark:text-white/55">(priority {a.priority}, effort {a.effort})</span>
              </p>
            )}
            <p className="mt-1 text-xs text-black/55 dark:text-white/55">
              {a.refs.map((r) => `${r.framework === "mitre" ? "ATT&CK" : r.framework.toUpperCase()} ${r.id}`).join(" · ") || "no references"}
            </p>
          </li>
        ))}
      </ul>
      {editing && (
        <div className="mt-2 flex items-center gap-3">
          <Button size="sm" disabled={put.isPending} onClick={() => put.mutate({ enabled: rule.enabled, actions })}>
            Save rule
          </Button>
          <span className="text-xs text-black/55 dark:text-white/55">
            Text, priority and effort can change; the attack class, conditions and framework references cannot.
          </span>
        </div>
      )}
      {error && <p role="alert" className="mt-1 text-sm text-red-700 dark:text-red-400">{error}</p>}
    </li>
  );
}

export function RulesPanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["rules"], queryFn: () => api<RulesResponse>("rules") });
  if (!q.data) return <p className="text-sm">Loading…</p>;
  const refresh = () => qc.invalidateQueries({ queryKey: ["rules"] });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommendation rules ({q.data.rules.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-2 text-xs text-black/60 dark:text-white/60">
          Every recommendation on the Actions page comes from one of these rules and carries its framework references.
          {q.data.can_edit
            ? " Changes apply to new and updated alerts straight away."
            : " Only platform administrators can change them."}
        </p>
        <ul className="divide-y divide-black/10 dark:divide-white/10">
          {q.data.rules.map((r) => (
            <RuleCard key={r.id + r.changed + r.enabled} rule={r} canEdit={q.data.can_edit} onSaved={refresh} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
