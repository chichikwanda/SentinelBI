"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api, ApiError } from "@/lib/client-api";
import type { BackupRow, TrainingJob } from "@/lib/types";

const mb = (b: number) => `${(b / 1e6).toFixed(1)} MB`;
// "20261105T100000Z" -> readable
const stamp = (n: string) => `${n.slice(0, 4)}-${n.slice(4, 6)}-${n.slice(6, 8)} ${n.slice(9, 11)}:${n.slice(11, 13)} UTC`;

export function BackupsPanel() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["backups"], queryFn: () => api<BackupRow[]>("training/backups"), retry: false, refetchInterval: 5000 });
  const jobs = useQuery({ queryKey: ["training-jobs"], queryFn: () => api<TrainingJob[]>("training/jobs"), refetchInterval: 3000, retry: false });
  const [error, setError] = useState<string | null>(null);
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["backups"] });
    qc.invalidateQueries({ queryKey: ["training-jobs"] });
  };
  const make = useMutation({
    mutationFn: () => api<TrainingJob>("training/backups", { method: "POST" }),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: (e: Error) => setError(e.message),
  });
  const check = useMutation({
    mutationFn: (folder: string) => api<TrainingJob>("training/backups/check", { method: "POST", body: JSON.stringify({ folder }) }),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: (e: Error) => setError(e.message),
  });

  if (list.error instanceof ApiError && list.error.status === 403) {
    return <p className="text-sm">Only platform administrators can make and check backups.</p>;
  }
  const recent = (jobs.data ?? []).filter((j) => j.kind === "backup" || j.kind === "check").slice(0, 5);
  const busy = (jobs.data ?? []).some((j) => j.status === "queued" || j.status === "running");

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backups</CardTitle>
        <Button data-testid="make-backup" disabled={busy || make.isPending} onClick={() => make.mutate()}>
          Back up now
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs text-black/60 dark:text-white/60">
          A backup is the database plus the trained models, with a checksum, saved in the <span className="font-mono">backups/</span>{" "}
          folder next to the project. It holds password hashes and every organisation&apos;s data, so keep it private. &quot;Check&quot; proves a
          backup works: it restores it into a scratch database, counts what came back and deletes the scratch copy. It never touches live data.
          Putting a backup back over the live database destroys current data, so that stays a deliberate step on the server (scripts/restore.sh
          with FORCE=1).
        </p>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-400">{error}</p>}
        {(list.data ?? []).length === 0 ? (
          <p className="text-sm">No backups yet.</p>
        ) : (
          <Table>
            <thead>
              <tr><Th>Made</Th><Th className="text-right">Size</Th><Th>Models</Th><Th /></tr>
            </thead>
            <tbody>
              {(list.data ?? []).map((b) => (
                <tr key={b.name}>
                  <Td>{stamp(b.name)}</Td>
                  <Td className="text-right tabular-nums">{mb(b.bytes)}</Td>
                  <Td>{b.has_models ? "included" : "–"}</Td>
                  <Td>
                    <Button size="sm" variant="outline" disabled={busy || check.isPending} onClick={() => check.mutate(b.name)}>
                      Check restore
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {recent.length > 0 && (
          <div>
            <h3 className="mb-1 text-sm font-semibold">Recent</h3>
            <ul className="space-y-1 text-sm">
              {recent.map((j) => (
                <li key={j.id} className="flex flex-wrap items-center gap-2">
                  <Badge className="bg-slate-500/15">{j.status}</Badge>
                  {j.kind === "backup" ? "Backup" : `Check ${String(j.params.folder ?? "")}`}
                  {j.stage && <span className="text-black/55 dark:text-white/55">{j.stage}</span>}
                  {j.error && <span className="text-red-700 dark:text-red-400">{j.error}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
