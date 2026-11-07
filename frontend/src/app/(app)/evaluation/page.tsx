"use client";

import { WalkthroughSheet } from "@/components/walkthrough-sheet";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { EvalSummary, Instruments } from "@/lib/types";

function Likert({
  title,
  items,
  scale,
  endpoint,
  describe,
}: {
  title: string;
  items: string[];
  scale: [number, number];
  endpoint: "sus" | "tam";
  describe: (r: Record<string, number>) => string;
}) {
  const [answers, setAnswers] = useState<(number | null)[]>(() => items.map(() => null));
  const submit = useMutation({
    mutationFn: () => api<Record<string, number>>(`evaluation/${endpoint}`, { method: "POST", body: JSON.stringify({ answers }) }),
  });
  const values = Array.from({ length: scale[1] - scale[0] + 1 }, (_, i) => scale[0] + i);
  const complete = answers.every((a) => a !== null);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-xs text-black/60 dark:text-white/60">
          {scale[0]} = strongly disagree, {scale[1]} = strongly agree.
        </p>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (complete) submit.mutate();
          }}
        >
          {items.map((text, i) => (
            <fieldset key={text} className="text-sm">
              <legend className="mb-1">
                {i + 1}. {text}
              </legend>
              <div className="flex gap-3">
                {values.map((v) => (
                  <label key={v} className="flex items-center gap-1">
                    <input
                      type="radio"
                      name={`${endpoint}-${i}`}
                      value={v}
                      checked={answers[i] === v}
                      onChange={() => setAnswers((a) => a.map((x, j) => (j === i ? v : x)))}
                    />
                    {v}
                  </label>
                ))}
              </div>
            </fieldset>
          ))}
          <Button type="submit" disabled={!complete || submit.isPending}>
            Submit
          </Button>
          {submit.isSuccess && (
            <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300" data-testid={`${endpoint}-result`}>
              Thank you. {describe(submit.data)}
            </p>
          )}
          {submit.isError && (
            <p role="alert" className="text-sm text-red-600">{(submit.error as Error).message}</p>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

export default function EvaluationPage() {
  const instruments = useQuery({ queryKey: ["instruments"], queryFn: () => api<Instruments>("evaluation/instruments") });
  // admins only: a 403 simply hides the summary
  const summary = useQuery({
    queryKey: ["eval-summary"],
    queryFn: () => api<EvalSummary>("evaluation/summary"),
    retry: false,
  });

  const ins = instruments.data;
  const s = summary.data;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-xl font-semibold">Evaluate SentinelBI</h1>
      <p className="text-sm text-black/65 dark:text-white/65">
        Two short questionnaires for the study: the System Usability Scale (SUS) and technology-acceptance
        (TAM) items. Answers are stored against your account.
      </p>
      {s && (
        <Card>
          <CardHeader>
            <CardTitle>Results so far (your organisation)</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 text-sm sm:grid-cols-2">
            <div data-testid="sus-summary">
              <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">SUS (n = {s.sus.n})</div>
              <div className="text-2xl font-semibold tabular-nums">{s.sus.mean ?? "–"}</div>
              <div className="text-xs">benchmark {s.sus.benchmark}{s.sus.sd !== null ? `, SD ${s.sus.sd}` : ""}</div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-black/55 dark:text-white/55">TAM (n = {s.tam.n})</div>
              {s.tam.means ? (
                <ul className="tabular-nums">
                  {Object.entries(s.tam.means).map(([k, v]) => (
                    <li key={k}>{k}: {v} / 7{s.tam.cronbach_alpha[k] != null ? ` (alpha ${s.tam.cronbach_alpha[k]})` : ""}</li>
                  ))}
                </ul>
              ) : (
                <div>–</div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
      <WalkthroughSheet />
      {ins && (
        <>
          <Likert
            title="System Usability Scale"
            items={ins.sus.items}
            scale={ins.sus.scale}
            endpoint="sus"
            describe={(r) => `Your SUS score is ${r.score} (benchmark ${ins.sus.benchmark}).`}
          />
          <Likert
            title="Usefulness and ease of use"
            items={ins.tam.items.map((i) => i.text)}
            scale={ins.tam.scale}
            endpoint="tam"
            describe={(r) => `Perceived usefulness ${r.PU}, ease of use ${r.PEOU}, intention ${r.BI} (out of 7).`}
          />
        </>
      )}
    </div>
  );
}
