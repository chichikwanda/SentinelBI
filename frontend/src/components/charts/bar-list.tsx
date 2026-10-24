"use client";

export interface BarItem {
  label: string;
  value: number;
  detail?: string;
}

/** Horizontal bars for a ranked magnitude (single series, so no legend box: the card title
 *  names it). Direct value labels, a 4px rounded data end, thin marks, native tooltips. */
export function BarList({
  items,
  format,
  emptyText = "No data in this window.",
}: {
  items: BarItem[];
  format: (v: number) => string;
  emptyText?: string;
}) {
  if (items.length === 0) {
    return <p className="text-sm" style={{ color: "var(--viz-ink-2)" }}>{emptyText}</p>;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="viz-root space-y-2">
      {items.map((item) => (
        <li key={item.label} title={item.detail ?? `${item.label}: ${format(item.value)}`}>
          <div className="mb-0.5 flex items-baseline justify-between gap-3 text-xs">
            <span className="truncate font-mono" style={{ color: "var(--viz-ink-2)" }}>
              {item.label}
            </span>
            <span className="shrink-0 tabular-nums" style={{ color: "var(--viz-ink)" }}>
              {format(item.value)}
            </span>
          </div>
          <div className="h-2 w-full rounded-r-[4px]" style={{ background: "var(--viz-grid)" }}>
            <div
              className="h-2 rounded-r-[4px]"
              style={{ width: `${Math.max(2, (item.value / max) * 100)}%`, background: "var(--series-1)" }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}
