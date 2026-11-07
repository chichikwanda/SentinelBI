"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { AssessmentResponse, Maturity } from "@/lib/types";

const LEVEL_STYLE: Record<Maturity, string> = {
  Low: "bg-red-600/15 text-red-700 dark:text-red-300",
  Medium: "bg-amber-500/20 text-amber-800 dark:text-amber-300",
  High: "bg-green-600/15 text-green-700 dark:text-green-300",
  "Not assessed": "bg-slate-500/15 text-slate-700 dark:text-slate-300",
};
const GOV_STYLE: Record<string, string> = {
  "In place": LEVEL_STYLE.High,
  "Partly in place": LEVEL_STYLE.Medium,
  Gap: LEVEL_STYLE.Low,
  "Not assessed": LEVEL_STYLE["Not assessed"],
};
const CHOICES = [
  { score: 0, label: "No" },
  { score: 1, label: "Partly" },
  { score: 2, label: "Yes" },
];

export default function AssessmentPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["assessment"], queryFn: () => api<AssessmentResponse>("assessment") });
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (answers: Record<string, number | null>) =>
      api<AssessmentResponse>("assessment", { method: "PUT", body: JSON.stringify({ answers }) }),
    onSuccess: (data) => {
      setError(null);
      qc.setQueryData(["assessment"], data);
      qc.invalidateQueries({ queryKey: ["recommendations"] });
    },
    onError: (e: Error) => setError(e.message),
  });

  if (q.isLoading) return <p className="text-sm">Loading…</p>;
  if (!q.data) return <p className="text-sm text-red-700">Could not load the self-assessment.</p>;
  const { items, maturity, governance, can_edit, disclaimer } = q.data;
  const areas = [...new Set(items.map((i) => i.area))];
  const practice = areas.filter((a) => a !== "Governance");
  const answered = items.filter((i) => i.answer !== null).length;

  const choose = (id: string, score: number, current: number | null) =>
    save.mutate({ [id]: current === score ? null : score });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Security-practice self-assessment</h1>
        <p className="text-sm text-black/60 dark:text-white/60">
          {answered} of {items.length} questions answered. Answers set a maturity level for each control area. A weak
          area makes a detected threat more urgent and can add actions of its own on the{" "}
          <Link href="/recommendations" className="underline">Actions</Link> page. Nothing is guessed: an area with no
          answers is shown as not assessed.
        </p>
        {!can_edit && <p className="mt-1 text-sm">You can read the assessment; analysts and admins can answer it.</p>}
        {error && <p role="alert" className="mt-1 text-sm text-red-700 dark:text-red-400">{error}</p>}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Maturity by control area</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="maturity">
            {practice.map((a) => {
              const m = maturity[a];
              return (
                <li key={a} className="rounded-md border border-black/10 p-3 dark:border-white/15" data-testid={`maturity-${a}`}>
                  <div className="flex items-center justify-between gap-2 text-sm font-medium">
                    {a}
                    <Badge className={LEVEL_STYLE[m.level]}>{m.level}</Badge>
                  </div>
                  <p className="mt-1 text-xs text-black/55 dark:text-white/55">
                    {m.percent === null ? "no answers yet" : `${m.percent}%`} ({m.answered} of {m.items} answered)
                  </p>
                </li>
              );
            })}
          </ul>
          <p className="mt-3 text-xs text-black/55 dark:text-white/55">
            Level: High from 80%, Medium from 50%, otherwise Low. A &quot;Yes&quot; scores 2, &quot;Partly&quot; 1, &quot;No&quot; 0, and
            the questions marked as heavier count double.
          </p>
        </CardContent>
      </Card>

      {areas.map((area) => (
        <Card key={area}>
          <CardHeader>
            <CardTitle>{area === "Governance" ? "Governance (Cyber and Data Protection Act, SI 155 of 2024)" : area}</CardTitle>
            {area === "Governance" && <Badge className="bg-slate-500/15">indicative</Badge>}
          </CardHeader>
          <CardContent className="divide-y divide-black/10 dark:divide-white/10">
            {items
              .filter((i) => i.area === area)
              .map((i) => (
                <div key={i.id} className="flex flex-wrap items-center justify-between gap-3 py-3" data-testid={`item-${i.id}`}>
                  <div className="max-w-xl">
                    <p className="text-sm">{i.question}</p>
                    <p className="text-xs text-black/55 dark:text-white/55">
                      {i.source}
                      {i.weight === 2 ? " · counts double" : ""}
                    </p>
                  </div>
                  <div className="flex items-center gap-1" role="group" aria-label={`Answer for ${i.id}`}>
                    {CHOICES.map((c) => (
                      <Button
                        key={c.score}
                        size="sm"
                        variant={i.answer === c.score ? "default" : "outline"}
                        aria-pressed={i.answer === c.score}
                        disabled={!can_edit || save.isPending}
                        onClick={() => choose(i.id, c.score, i.answer)}
                      >
                        {c.label}
                      </Button>
                    ))}
                  </div>
                </div>
              ))}
          </CardContent>
        </Card>
      ))}

      <Card data-testid="governance">
        <CardHeader>
          <CardTitle>Governance indicators</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <ul className="space-y-2">
            {governance.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span>
                  {g.question} <span className="text-xs text-black/55 dark:text-white/55">({g.source})</span>
                </span>
                <Badge className={GOV_STYLE[g.status]}>{g.status}</Badge>
              </li>
            ))}
          </ul>
          <p className="rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-900 dark:text-amber-200">{disclaimer}</p>
        </CardContent>
      </Card>
    </div>
  );
}
