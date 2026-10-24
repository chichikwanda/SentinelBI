import * as React from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-md border border-black/15 bg-transparent px-3 text-sm placeholder:text-black/40 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-white/20 dark:placeholder:text-white/40",
        className,
      )}
      {...props}
    />
  );
}

export function Select({ className, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "h-9 w-full rounded-md border border-black/15 bg-transparent px-3 text-sm focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-white/20 dark:[&>option]:bg-neutral-900",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("mb-1 block text-sm font-medium", className)} {...props} />;
}
