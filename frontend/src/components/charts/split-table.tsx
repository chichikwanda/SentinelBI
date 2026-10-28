"use client";

import { formatBytes, formatNumber } from "@/lib/format";

export interface SplitRow {
  label: string;
  sent: number;
  received: number;
  flows: number;
  /** extra words for the tooltip, e.g. a protocol */
  note?: string;
}

/** A ranked table that says what was SENT and what was RECEIVED for each row (two series on one
 *  scale: a stacked bar under each label, a legend because there are two, exact numbers beside it).
 *  Bars are scaled to the biggest row's total; a 2px gap keeps the two fills apart. */
export function SplitTable({
  rows,
  labelHeader,
  emptyText = "No traffic in this window.",
  testId,
}: {
  rows: SplitRow[];
  labelHeader: string;
  emptyText?: string;
  testId?: string;
}) {
  if (rows.length === 0) {
    return (
      <p className="viz-root text-sm" style={{ color: "var(--viz-ink-2)" }}>
        {emptyText}
      </p>
    );
  }
  const max = Math.max(...rows.map((r) => r.sent + r.received), 1);
  const head = "px-2 py-1 text-xs font-medium whitespace-nowrap";
  return (
    <div className="viz-root" data-testid={testId}>
      <div className="mb-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-4 rounded-sm" style={{ background: "var(--series-1)" }} />
          Sent by this host
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-4 rounded-sm" style={{ background: "var(--series-2)" }} />
          Received by this host
        </span>
      </div>
      <div className="w-full overflow-x-auto">
        <table className="w-full text-left text-sm tabular-nums">
          <thead>
            <tr style={{ color: "var(--viz-muted)" }}>
              <th className={`${head} w-full`}>{labelHeader}</th>
              <th className={`${head} text-right`}>Sent</th>
              <th className={`${head} text-right`}>Received</th>
              <th className={`${head} text-right`}>Total</th>
              <th className={`${head} text-right`}>Flows</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const total = r.sent + r.received;
              const width = Math.max(2, (total / max) * 100);
              return (
                <tr
                  key={`${r.label}|${r.note ?? ""}`}
                  data-testid="split-row"
                  title={`${r.label}${r.note ? ` (${r.note})` : ""}: sent ${formatBytes(r.sent)}, received ${formatBytes(r.received)}, ${formatNumber(r.flows)} flows`}
                  className="break-inside-avoid border-t"
                  style={{ borderColor: "var(--viz-grid)" }}
                >
                  <td className="px-2 py-1.5">
                    <div className="truncate font-mono text-xs" style={{ color: "var(--viz-ink)" }}>
                      {r.label}
                      {r.note && (
                        <span className="ml-1.5 font-sans" style={{ color: "var(--viz-muted)" }}>
                          {r.note}
                        </span>
                      )}
                    </div>
                    <div
                      className="mt-1 flex h-1.5 gap-[2px]"
                      style={{ width: `${width}%` }}
                      aria-hidden="true"
                    >
                      {r.sent > 0 && (
                        <div
                          className="h-1.5 rounded-l-[2px]"
                          style={{ flex: r.sent, background: "var(--series-1)" }}
                        />
                      )}
                      {r.received > 0 && (
                        <div
                          className="h-1.5 rounded-r-[4px]"
                          style={{ flex: r.received, background: "var(--series-2)" }}
                        />
                      )}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-right" style={{ color: "var(--viz-ink)" }}>
                    {formatBytes(r.sent)}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-right" style={{ color: "var(--viz-ink)" }}>
                    {formatBytes(r.received)}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-right" style={{ color: "var(--viz-ink)" }}>
                    {formatBytes(total)}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-right" style={{ color: "var(--viz-ink-2)" }}>
                    {formatNumber(r.flows)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
