"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import type { WalkthroughSummary } from "@/lib/types";

const TASKS = [
  ["UAT1", "Find the highest-priority action"],
  ["UAT2", "Explain why it is recommended"],
  ["UAT3", "Identify the most detected threat and its confidence"],
  ["UAT4", "Say which governance obligations are not met"],
  ["UAT5", "Compare two assets"],
];
const THEMES = [
  ["usefulness", "Perceived usefulness"],
  ["ease", "Ease of use without training"],
  ["clarity", "Clarity of explanations and sources"],
  ["improvement", "Suggested improvements"],
];

/** The researcher's observation sheet for the walkthrough. Participants are codes (P1, P2, ...), never names. */
export function WalkthroughSheet() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["walkthrough"], queryFn: () => api<WalkthroughSummary>("evaluation/walkthrough") });
  const [participant, setParticipant] = useState("P1");
  const [task, setTask] = useState("UAT1");
  const [completed, setCompleted] = useState(true);
  const [seconds, setSeconds] = useState("");
  const [errors, setErrors] = useState("0");
  const [theme, setTheme] = useState("usefulness");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const done = (data: WalkthroughSummary) => {
    qc.setQueryData(["walkthrough"], data);
    setError(null);
  };
  const addTask = useMutation({
    mutationFn: () =>
      api<WalkthroughSummary>("evaluation/walkthrough/tasks", {
        method: "POST",
        body: JSON.stringify({ participant, task, completed, seconds: seconds === "" ? null : Number(seconds), errors: Number(errors) }),
      }),
    onSuccess: (d) => {
      done(d);
      setSeconds("");
      setErrors("0");
    },
    onError: (e: Error) => setError(e.message),
  });
  const addComment = useMutation({
    mutationFn: () =>
      api<WalkthroughSummary>("evaluation/walkthrough/comments", { method: "POST", body: JSON.stringify({ participant, theme, text }) }),
    onSuccess: (d) => {
      done(d);
      setText("");
    },
    onError: (e: Error) => setError(e.message),
  });
  const s = q.data;
  return (
    <Card data-testid="walkthrough">
      <CardHeader>
        <CardTitle>Walkthrough observation sheet</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-xs text-black/60 dark:text-white/60">
          For the researcher. Record what each participant did on the five tasks and what they said. Use participant codes
          (P1, P2 ...) only, never names. A later record of the same task replaces an earlier one. The tables below are
          what the dissertation reports.
        </p>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-400">{error}</p>}
        <div className="grid gap-3 sm:grid-cols-[6rem_1fr_9rem_6rem_6rem_auto] sm:items-end">
          <div><Label htmlFor="w-p">Participant</Label><Input id="w-p" value={participant} onChange={(e) => setParticipant(e.target.value.toUpperCase())} /></div>
          <div>
            <Label htmlFor="w-t">Task</Label>
            <Select id="w-t" value={task} onChange={(e) => setTask(e.target.value)}>
              {TASKS.map(([id, label]) => <option key={id} value={id}>{id}: {label}</option>)}
            </Select>
          </div>
          <label className="flex items-center gap-2 pb-2 text-sm"><input type="checkbox" checked={completed} onChange={(e) => setCompleted(e.target.checked)} />Completed unaided</label>
          <div><Label htmlFor="w-s">Seconds</Label><Input id="w-s" type="number" min={0} value={seconds} onChange={(e) => setSeconds(e.target.value)} /></div>
          <div><Label htmlFor="w-e">Errors</Label><Input id="w-e" type="number" min={0} value={errors} onChange={(e) => setErrors(e.target.value)} /></div>
          <Button onClick={() => addTask.mutate()} disabled={addTask.isPending}>Record task</Button>
        </div>
        <div className="grid gap-3 sm:grid-cols-[12rem_1fr_auto] sm:items-end">
          <div>
            <Label htmlFor="w-th">Comment theme</Label>
            <Select id="w-th" value={theme} onChange={(e) => setTheme(e.target.value)}>
              {THEMES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
            </Select>
          </div>
          <div><Label htmlFor="w-c">What the participant said (paraphrase)</Label><Input id="w-c" value={text} onChange={(e) => setText(e.target.value)} /></div>
          <Button variant="outline" onClick={() => addComment.mutate()} disabled={addComment.isPending || text.length < 3}>Record comment</Button>
        </div>
        {s && (
          <>
            <p className="text-sm">Participants recorded: {s.participants.length ? s.participants.join(", ") : "none yet"}</p>
            <Table>
              <thead>
                <tr><Th>Task</Th><Th>Description</Th><Th className="text-right">Completed unaided</Th><Th className="text-right">Mean time (s)</Th><Th className="text-right">Errors</Th></tr>
              </thead>
              <tbody>
                {s.tasks.map((t) => (
                  <tr key={t.task} data-testid={`wt-${t.task}`}>
                    <Td>{t.task}</Td><Td>{t.description}</Td>
                    <Td className="text-right tabular-nums">{t.completed} of {t.participants}</Td>
                    <Td className="text-right tabular-nums">{t.mean_seconds ?? "–"}</Td>
                    <Td className="text-right tabular-nums">{t.errors}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Table>
              <thead>
                <tr><Th>Theme</Th><Th className="text-right">Participants</Th><Th>Representative comment</Th></tr>
              </thead>
              <tbody>
                {s.themes.map((t) => (
                  <tr key={t.theme}><Td>{t.label}</Td><Td className="text-right tabular-nums">{t.participants}</Td><Td>{t.comment ?? "–"}</Td></tr>
                ))}
              </tbody>
            </Table>
          </>
        )}
      </CardContent>
    </Card>
  );
}
