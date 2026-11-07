"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { api, ApiError } from "@/lib/client-api";
import type { TrainingJob, TrainingJobDetail, TrainingOptions } from "@/lib/types";

const mb = (b: number) => `${(b / 1e6).toFixed(0)} MB`;
const STATUS_STYLE: Record<string, string> = {
  queued: "bg-slate-500/15 text-slate-700 dark:text-slate-300",
  running: "bg-blue-600/15 text-blue-700 dark:text-blue-300",
  succeeded: "bg-green-600/15 text-green-700 dark:text-green-300",
  failed: "bg-red-600/15 text-red-700 dark:text-red-300",
  cancelled: "bg-amber-500/20 text-amber-800 dark:text-amber-300",
};
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "–");

function JobLog({ id, active }: { id: string; active: boolean }) {
  const q = useQuery({
    queryKey: ["training-job", id],
    queryFn: () => api<TrainingJobDetail>(`training/jobs/${id}`),
    refetchInterval: active ? 2000 : false,
  });
  return (
    <pre
      className="max-h-72 overflow-auto rounded-md bg-black/5 p-3 text-xs leading-relaxed dark:bg-white/10"
      data-testid="job-log"
    >
      {q.data?.log || "(no output yet)"}
    </pre>
  );
}

function JobRow({ job, onCancel }: { job: TrainingJob; onCancel: (id: string) => void }) {
  const [open, setOpen] = useState(job.status === "running");
  const active = job.status === "running" || job.status === "queued";
  return (
    <li className="py-3" data-testid="training-job">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <Badge className={STATUS_STYLE[job.status]}>{job.status}</Badge>
        <span className="font-medium">{job.kind === "download" ? `Download ${job.params.dataset}` : "Training run"}</span>
        {job.stage && <span className="text-black/60 dark:text-white/60">{job.stage}</span>}
        <span className="ml-auto text-xs text-black/55 dark:text-white/55">
          {job.created_by}, started {when(job.started_at ?? job.created_at)}
        </span>
        {active && (
          <Button size="sm" variant="outline" onClick={() => onCancel(job.id)}>
            Cancel
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          {open ? "Hide log" : "Show log"}
        </Button>
      </div>
      {job.error && <p className="mt-1 text-sm text-red-700 dark:text-red-400">{job.error}</p>}
      {job.result_version && (
        <p className="mt-1 text-sm">
          Model <span className="font-mono">{job.result_version}</span> was saved and registered.{" "}
          <Link href="/models" className="text-blue-700 underline dark:text-blue-300">
            See its results and make it the active model
          </Link>
        </p>
      )}
      {open && <div className="mt-2"><JobLog id={job.id} active={active} /></div>}
    </li>
  );
}

export function TrainingPanel() {
  const qc = useQueryClient();
  const opts = useQuery({
    queryKey: ["training-options"],
    queryFn: () => api<TrainingOptions>("training/options"),
    refetchInterval: 5000,
    retry: false,
  });
  const jobs = useQuery({
    queryKey: ["training-jobs"],
    queryFn: () => api<TrainingJob[]>("training/jobs"),
    refetchInterval: 3000,
    retry: false,
  });
  const [datasets, setDatasets] = useState<string[] | null>(null);
  const [models, setModels] = useState<string[] | null>(null);
  const [seed, setSeed] = useState(42);
  const [benignCap, setBenignCap] = useState(400000);
  const [classCap, setClassCap] = useState(150000);
  const [keep, setKeep] = useState(0.08);
  const [far, setFar] = useState(0.02);
  const [folds, setFolds] = useState(0);
  const [nJobs, setNJobs] = useState(3);
  const [cross, setCross] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["training-jobs"] });
    qc.invalidateQueries({ queryKey: ["training-options"] });
  };
  const start = useMutation({
    mutationFn: (body: unknown) => api<TrainingJob>("training/jobs", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: (e: Error) => setError(e.message),
  });
  const download = useMutation({
    mutationFn: (dataset: string) =>
      api<TrainingJob>("training/downloads", { method: "POST", body: JSON.stringify({ dataset }) }),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: (e: Error) => setError(e.message),
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api<TrainingJob>(`training/jobs/${id}/cancel`, { method: "POST" }),
    onSuccess: refresh,
    onError: (e: Error) => setError(e.message),
  });

  if (opts.error instanceof ApiError && opts.error.status === 403) {
    return (
      <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm" data-testid="training-denied">
        Training changes what every organisation is scored with, so only platform administrators can use it. Their
        emails are in PLATFORM_ADMIN_EMAILS in the server&apos;s .env file.
      </p>
    );
  }
  if (!opts.data) return <p className="text-sm">Loading…</p>;
  const o = opts.data;
  const chosenData = datasets ?? o.datasets.filter((d) => d.ready).map((d) => d.key);
  const chosenModels = models ?? o.algorithms.filter((a) => a.default && a.available).map((a) => a.key);
  const toggle = (list: string[], key: string) => (list.includes(key) ? list.filter((k) => k !== key) : [...list, key]);

  return (
    <div className="space-y-4">
      {error && (
        <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm">
          {error}
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>1. Datasets</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {o.datasets.map((d) => (
            <div key={d.key} className="flex flex-wrap items-center gap-3 text-sm" data-testid={`dataset-${d.key}`}>
              <span className="font-medium">{d.key}</span>
              <Badge className={d.ready ? STATUS_STYLE.succeeded : STATUS_STYLE.cancelled}>
                {d.ready ? `ready (${mb(d.bytes)})` : "not downloaded"}
              </Badge>
              <Button size="sm" variant="outline" disabled={o.busy || download.isPending} onClick={() => download.mutate(d.key)}>
                {d.ready ? "Download again and verify" : "Download and verify"}
              </Button>
              <span className="basis-full text-xs text-black/55 dark:text-white/55">
                Academic-use datasets from the University of Queensland (about 650 MB in total). Each file is checked
                against its recorded SHA-256. {d.citation}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>2. New training run</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Train on</legend>
            <div className="flex flex-wrap gap-4 text-sm">
              {o.datasets.map((d) => (
                <label key={d.key} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={chosenData.includes(d.key)}
                    disabled={!d.ready}
                    onChange={() => setDatasets(toggle(chosenData, d.key))}
                  />
                  {d.key}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Algorithms to compare</legend>
            <div className="flex flex-wrap gap-4 text-sm">
              {o.algorithms.map((a) => (
                <label key={a.key} className="flex items-center gap-2" title={a.note}>
                  <input
                    type="checkbox"
                    checked={chosenModels.includes(a.key)}
                    disabled={!a.available}
                    onChange={() => setModels(toggle(chosenModels, a.key))}
                  />
                  {a.label}
                </label>
              ))}
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <Button size="sm" variant="outline" onClick={() => setModels(["dt", "rf", "lgbm"])}>
                Default comparison
              </Button>
              <Button
                size="sm"
                variant="outline"
                title="LightGBM and XGBoost compute per-feature contributions, so alert pages can explain why a flow was flagged. A Random Forest cannot."
                onClick={() => setModels(["lgbm", "xgb"].filter((k) => o.algorithms.find((a) => a.key === k)?.available))}
                data-testid="preset-explainable"
              >
                Explainable only (boosted trees)
              </Button>
              <Button size="sm" variant="outline" onClick={() => setModels(o.algorithms.filter((a) => a.available).map((a) => a.key))}>
                Everything
              </Button>
            </div>
            <p className="mt-1 text-xs text-black/55 dark:text-white/55">
              The best model on the validation split (macro-F1) is exported; the test split is evaluated once, for it
              only. This rule is fixed and cannot be changed here.
            </p>
          </fieldset>
          <details>
            <summary className="cursor-pointer text-sm font-medium">Advanced</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              <div><Label htmlFor="t-seed">Random seed</Label><Input id="t-seed" type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-bcap">Benign cap in training</Label><Input id="t-bcap" type="number" value={benignCap} onChange={(e) => setBenignCap(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-ccap">Cap per attack class</Label><Input id="t-ccap" type="number" value={classCap} onChange={(e) => setClassCap(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-keep">Benign share kept (CSE-CIC)</Label><Input id="t-keep" type="number" step="0.01" value={keep} onChange={(e) => setKeep(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-far">False-alarm target</Label><Input id="t-far" type="number" step="0.001" value={far} onChange={(e) => setFar(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-folds">Cross-validation folds (0 = off)</Label><Input id="t-folds" type="number" value={folds} onChange={(e) => setFolds(Number(e.target.value))} /></div>
              <div><Label htmlFor="t-jobs">CPU cores</Label><Input id="t-jobs" type="number" value={nJobs} onChange={(e) => setNJobs(Number(e.target.value))} /></div>
              <label className="flex items-center gap-2 text-sm sm:col-span-2">
                <input type="checkbox" checked={cross} onChange={(e) => setCross(e.target.checked)} />
                Also measure dataset shift (train on one dataset, test on the other)
              </label>
            </div>
          </details>
          <div className="flex items-center gap-3">
            <Button
              data-testid="start-training"
              disabled={o.busy || start.isPending || chosenData.length === 0 || chosenModels.length === 0}
              onClick={() =>
                start.mutate({
                  datasets: chosenData,
                  models: chosenModels,
                  seed,
                  benign_cap: benignCap,
                  class_cap: classCap,
                  benign_keep: { "nf-cse-cic-ids2018-v2": keep },
                  target_far: far,
                  cv_folds: folds,
                  n_jobs: nJobs,
                  cross_dataset: cross,
                })
              }
            >
              Start training
            </Button>
            {o.busy && <span className="text-sm text-black/60 dark:text-white/60">Another job is queued or running.</span>}
          </div>
          <p className="text-xs text-black/55 dark:text-white/55">
            A full run on both datasets takes about 15 minutes on four cores and several GB of memory. The new model is
            registered but not switched on: you decide that on the Models page.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>3. Runs</CardTitle>
        </CardHeader>
        <CardContent>
          {(jobs.data ?? []).length === 0 ? (
            <p className="text-sm">Nothing has been run yet.</p>
          ) : (
            <ul className="divide-y divide-black/10 dark:divide-white/10">
              {(jobs.data ?? []).map((j) => (
                <JobRow key={j.id} job={j} onCancel={(id) => cancel.mutate(id)} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
