"use client";

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { RecommendationCard } from "@/components/recommendation-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { RecStatus, Recommendation } from "@/lib/types";

const FILTERS: { label: string; value: RecStatus | "active" }[] = [
  { label: "To do", value: "active" },
  { label: "In progress", value: "in_progress" },
  { label: "Done", value: "done" },
  { label: "Dismissed", value: "dismissed" },
];

export default function RecommendationsPage() {
  const [filter, setFilter] = useState<RecStatus | "active">("active");
  const { data, isError, error } = useQuery({
    queryKey: ["recommendations", "all", filter],
    queryFn: () =>
      api<Recommendation[]>(
        `recommendations?limit=200${filter === "active" ? "&status=open" : `&status=${filter}`}`,
      ),
    refetchInterval: 8000,
  });

  // identical actions raised by several alerts collapse into one card
  const groups = useMemo(() => {
    const byAction = new Map<string, Recommendation[]>();
    for (const r of data ?? []) byAction.set(r.action, [...(byAction.get(r.action) ?? []), r]);
    return [...byAction.values()];
  }, [data]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommended actions</CardTitle>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by status">
          {FILTERS.map((f) => (
            <Button
              key={f.value}
              size="sm"
              variant={filter === f.value ? "default" : "outline"}
              aria-pressed={filter === f.value}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-xs text-black/60 dark:text-white/60">
          Ranked by priority x alert severity x asset criticality. Rules live in YAML files and map to
          MITRE ATT&amp;CK mitigations, CIS Controls v8 and NIST CSF 2.0 (CIS and NIST titles are marked
          unverified in the repository until reviewed).
        </p>
        {isError ? (
          <p className="text-sm text-red-600" role="alert">
            {(error as Error).message}
          </p>
        ) : data && data.length === 0 ? (
          <p className="text-sm text-black/60 dark:text-white/60" data-testid="no-recommendations">
            Nothing here. Recommendations appear when an alert is raised.
          </p>
        ) : (
          <ul className="space-y-3">
            {groups.map(([first, ...rest]) => (
              <RecommendationCard key={first.id} rec={first} others={rest} showAlert />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
