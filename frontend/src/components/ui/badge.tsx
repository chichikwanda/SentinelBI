import * as React from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const severityStyles: Record<Severity, string> = {
  Critical: "bg-red-600/15 text-red-700 dark:text-red-300",
  High: "bg-orange-500/15 text-orange-700 dark:text-orange-300",
  Medium: "bg-amber-500/20 text-amber-800 dark:text-amber-300",
  Low: "bg-slate-500/15 text-slate-700 dark:text-slate-300",
};

export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", className)}
      {...props}
    />
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={severityStyles[severity]}>{severity}</Badge>;
}
