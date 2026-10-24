"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/client-api";
import type { Alert, AlertStatus } from "@/lib/types";
import { AlertsTable } from "../dashboard/page";

const FILTERS: { label: string; value: AlertStatus | "all" }[] = [
  { label: "All", value: "all" },
  { label: "New", value: "new" },
  { label: "Acknowledged", value: "acknowledged" },
  { label: "False positive", value: "false_positive" },
  { label: "Resolved", value: "resolved" },
];

export default function AlertsPage() {
  const [status, setStatus] = useState<AlertStatus | "all">("all");
  const { data, isError, error } = useQuery({
    queryKey: ["alerts-list", status],
    queryFn: () => api<Alert[]>(`alerts?limit=200${status === "all" ? "" : `&status=${status}`}`),
    refetchInterval: 5000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alerts</CardTitle>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by status">
          {FILTERS.map((f) => (
            <Button
              key={f.value}
              size="sm"
              variant={status === f.value ? "default" : "outline"}
              aria-pressed={status === f.value}
              onClick={() => setStatus(f.value)}
            >
              {f.label}
            </Button>
          ))}
          <a href="/api/proxy/reports/alerts.csv" download>
            <Button size="sm" variant="ghost" type="button">
              Export CSV
            </Button>
          </a>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {isError ? (
          <p className="p-4 text-sm text-red-600" role="alert">
            {(error as Error).message}
          </p>
        ) : data && data.length === 0 ? (
          <p className="p-4 text-sm text-black/60 dark:text-white/60">No alerts match this filter.</p>
        ) : (
          <AlertsTable alerts={data ?? []} />
        )}
      </CardContent>
    </Card>
  );
}
