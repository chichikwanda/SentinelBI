"use client";

import { useId, useMemo, useRef, useState } from "react";
import { formatBytes, formatClock, formatNumber, niceMax } from "@/lib/format";

export interface TrafficPoint {
  t: string;
  flows: number;
  bytes: number;
  alerts: number;
}

const W = 720;
const H = 230;
const M = { left: 48, right: 14, top: 12, bottom: 56 };
const PLOT_W = W - M.left - M.right;
const PLOT_H = H - M.top - M.bottom;
const STRIP_Y = H - 14; // alert event strip (no y-scale: events, not a second measure)

/** Flows per bucket as one area+line series; alert events are a separate strip beneath it,
 *  so there is a single y-axis (never dual-axis). Hover shows a crosshair and tooltip. */
export function TrafficChart({
  points,
  bucketMinutes,
}: {
  points: TrafficPoint[];
  bucketMinutes: number;
}) {
  const uid = useId();
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);

  const { max, xs, ys, line, area, ticksY, ticksX } = useMemo(() => {
    const n = points.length;
    const max = niceMax(Math.max(1, ...points.map((p) => p.flows)));
    const xs = points.map((_, i) => M.left + (n <= 1 ? PLOT_W / 2 : (i / (n - 1)) * PLOT_W));
    const ys = points.map((p) => M.top + PLOT_H - (p.flows / max) * PLOT_H);
    const line = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
    const base = M.top + PLOT_H;
    const area = n ? `${line} L${xs[n - 1].toFixed(1)},${base} L${xs[0].toFixed(1)},${base} Z` : "";
    const ticksY = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ v: Math.round(max * f), y: M.top + PLOT_H - f * PLOT_H }));
    const step = Math.max(1, Math.floor((n - 1) / 4));
    const ticksX = points.map((p, i) => ({ i, label: formatClock(p.t) })).filter(({ i }) => i % step === 0);
    return { max, xs, ys, line, area, ticksY, ticksX };
  }, [points]);

  const total = points.reduce((s, p) => s + p.flows, 0);
  const alertBuckets = points.filter((p) => p.alerts > 0);

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || points.length === 0) return;
    const x = ((e.clientX - rect.left) / rect.width) * W;
    const f = (x - M.left) / PLOT_W;
    setHover(Math.max(0, Math.min(points.length - 1, Math.round(f * (points.length - 1)))));
  }

  const hp = hover === null ? null : points[hover];

  return (
    <div className="viz-root relative">
      <div className="mb-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0.5 w-4 rounded" style={{ background: "var(--series-1)" }} />
          Flows per {bucketMinutes === 1 ? "minute" : `${bucketMinutes} minutes`}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--series-2)" }} />
          Alert raised
        </span>
        <span className="ml-auto">{formatNumber(total)} flows in view</span>
      </div>

      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Flows per bucket over time. ${formatNumber(total)} flows, ${alertBuckets.length} buckets with alerts.`}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id={`${uid}-fill`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--series-1)" stopOpacity="0.22" />
            <stop offset="100%" stopColor="var(--series-1)" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {ticksY.map((t) => (
          <g key={t.y}>
            <line x1={M.left} x2={W - M.right} y1={t.y} y2={t.y} stroke="var(--viz-grid)" strokeWidth={1} />
            <text x={M.left - 8} y={t.y + 3.5} textAnchor="end" fontSize={10} fill="var(--viz-muted)">
              {formatNumber(t.v)}
            </text>
          </g>
        ))}
        <line x1={M.left} x2={W - M.right} y1={M.top + PLOT_H} y2={M.top + PLOT_H} stroke="var(--viz-axis)" strokeWidth={1} />

        {area && <path d={area} fill={`url(#${uid}-fill)`} />}
        {line && <path d={line} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />}

        {ticksX.map(({ i, label }) => (
          <text
            key={i}
            x={xs[i]}
            y={M.top + PLOT_H + 16}
            textAnchor={xs[i] > W - M.right - 24 ? "end" : xs[i] < M.left + 24 ? "start" : "middle"}
            fontSize={10}
            fill="var(--viz-muted)"
          >
            {label}
          </text>
        ))}

        {/* alert event strip */}
        <line x1={M.left} x2={W - M.right} y1={STRIP_Y} y2={STRIP_Y} stroke="var(--viz-grid)" strokeWidth={1} />
        {points.map((p, i) =>
          p.alerts > 0 ? (
            <circle key={p.t} cx={xs[i]} cy={STRIP_Y} r={5} fill="var(--series-2)" stroke="var(--viz-surface)" strokeWidth={2} />
          ) : null,
        )}

        {hover !== null && hp && (
          <g pointerEvents="none">
            <line x1={xs[hover]} x2={xs[hover]} y1={M.top} y2={M.top + PLOT_H} stroke="var(--viz-axis)" strokeWidth={1} />
            <circle cx={xs[hover]} cy={ys[hover]} r={4} fill="var(--series-1)" stroke="var(--viz-surface)" strokeWidth={2} />
          </g>
        )}
        <rect x={M.left} y={M.top} width={PLOT_W} height={PLOT_H + 40} fill="transparent" />
      </svg>

      {hp && hover !== null && (
        <div
          className="pointer-events-none absolute z-10 rounded-md border px-2.5 py-1.5 text-xs shadow-sm"
          style={{
            left: `${Math.min(86, Math.max(2, (xs[hover] / W) * 100 - 6))}%`,
            top: 28,
            background: "var(--viz-surface)",
            borderColor: "var(--viz-axis)",
            color: "var(--viz-ink)",
          }}
        >
          <div className="font-medium">{formatClock(hp.t)}</div>
          <div style={{ color: "var(--viz-ink-2)" }}>
            {formatNumber(hp.flows)} flows, {formatBytes(hp.bytes)}
          </div>
          {hp.alerts > 0 && <div>{hp.alerts} alert{hp.alerts > 1 ? "s" : ""} raised</div>}
        </div>
      )}

      <details className="mt-2 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <summary className="cursor-pointer">View as table</summary>
        <div className="mt-2 max-h-56 overflow-auto">
          <table className="w-full text-left tabular-nums">
            <thead>
              <tr>
                <th className="pr-3">Time</th>
                <th className="pr-3">Flows</th>
                <th className="pr-3">Bytes</th>
                <th>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.t}>
                  <td className="pr-3">{formatClock(p.t)}</td>
                  <td className="pr-3">{formatNumber(p.flows)}</td>
                  <td className="pr-3">{formatBytes(p.bytes)}</td>
                  <td>{p.alerts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <span className="sr-only">y-axis maximum {formatNumber(max)}</span>
    </div>
  );
}
