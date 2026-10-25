"use client";

import { useMemo, useRef, useState } from "react";
import { formatBytes, formatClock, formatNumber, niceMax } from "@/lib/format";

export interface VolumePoint {
  t: string;
  sent: number;
  received: number;
  flows: number;
}

const W = 720;
const H = 230;
const M = { left: 56, right: 14, top: 12, bottom: 34 };
const PLOT_W = W - M.left - M.right;
const PLOT_H = H - M.top - M.bottom;

/** Data a host sent and received per bucket: two lines on ONE y-axis (the same unit), a legend
 *  because there are two series, a crosshair tooltip, and a table view for screen readers. */
export function VolumeChart({ points, bucketMinutes }: { points: VolumePoint[]; bucketMinutes: number }) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);

  const { max, xs, line, ticksY, ticksX } = useMemo(() => {
    const n = points.length;
    const max = niceMax(Math.max(1, ...points.map((p) => Math.max(p.sent, p.received))));
    const xs = points.map((_, i) => M.left + (n <= 1 ? PLOT_W / 2 : (i / (n - 1)) * PLOT_W));
    const y = (v: number) => M.top + PLOT_H - (v / max) * PLOT_H;
    const path = (pick: (p: VolumePoint) => number) =>
      points.map((p, i) => `${i === 0 ? "M" : "L"}${xs[i].toFixed(1)},${y(pick(p)).toFixed(1)}`).join(" ");
    const ticksY = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ v: max * f, y: M.top + PLOT_H - f * PLOT_H }));
    const step = Math.max(1, Math.floor((n - 1) / 4));
    const ticksX = points.map((p, i) => ({ i, label: formatClock(p.t) })).filter(({ i }) => i % step === 0);
    return {
      max,
      xs,
      line: { sent: path((p) => p.sent), received: path((p) => p.received), y },
      ticksY,
      ticksX,
    };
  }, [points]);

  const totalSent = points.reduce((s, p) => s + p.sent, 0);
  const totalReceived = points.reduce((s, p) => s + p.received, 0);

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || points.length === 0) return;
    const x = ((e.clientX - rect.left) / rect.width) * W;
    const f = (x - M.left) / PLOT_W;
    setHover(Math.max(0, Math.min(points.length - 1, Math.round(f * (points.length - 1)))));
  }
  const hp = hover === null ? null : points[hover];
  const per = bucketMinutes === 1 ? "minute" : `${bucketMinutes} minutes`;

  return (
    <div className="viz-root relative" data-testid="volume-chart">
      <div className="mb-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0.5 w-4 rounded" style={{ background: "var(--series-1)" }} />
          Sent per {per}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0.5 w-4 rounded" style={{ background: "var(--series-2)" }} />
          Received per {per}
        </span>
        <span className="ml-auto">
          {formatBytes(totalSent)} sent, {formatBytes(totalReceived)} received in view
        </span>
      </div>

      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Data sent and received per ${per}. ${formatBytes(totalSent)} sent, ${formatBytes(totalReceived)} received.`}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {ticksY.map((t) => (
          <g key={t.y}>
            <line x1={M.left} x2={W - M.right} y1={t.y} y2={t.y} stroke="var(--viz-grid)" strokeWidth={1} />
            <text x={M.left - 8} y={t.y + 3.5} textAnchor="end" fontSize={10} fill="var(--viz-muted)">
              {formatBytes(Math.round(t.v))}
            </text>
          </g>
        ))}
        <line x1={M.left} x2={W - M.right} y1={M.top + PLOT_H} y2={M.top + PLOT_H} stroke="var(--viz-axis)" strokeWidth={1} />

        <path d={line.received} fill="none" stroke="var(--series-2)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        <path d={line.sent} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

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

        {hover !== null && hp && (
          <g pointerEvents="none">
            <line x1={xs[hover]} x2={xs[hover]} y1={M.top} y2={M.top + PLOT_H} stroke="var(--viz-axis)" strokeWidth={1} />
            <circle cx={xs[hover]} cy={line.y(hp.sent)} r={4} fill="var(--series-1)" stroke="var(--viz-surface)" strokeWidth={2} />
            <circle cx={xs[hover]} cy={line.y(hp.received)} r={4} fill="var(--series-2)" stroke="var(--viz-surface)" strokeWidth={2} />
          </g>
        )}
        <rect x={M.left} y={M.top} width={PLOT_W} height={PLOT_H + 20} fill="transparent" />
      </svg>

      {hp && hover !== null && (
        <div
          className="pointer-events-none absolute z-10 rounded-md border px-2.5 py-1.5 text-xs shadow-sm"
          style={{
            left: `${Math.min(80, Math.max(2, (xs[hover] / W) * 100 - 6))}%`,
            top: 28,
            background: "var(--viz-surface)",
            borderColor: "var(--viz-axis)",
            color: "var(--viz-ink)",
          }}
        >
          <div className="font-medium">{formatClock(hp.t)}</div>
          <div style={{ color: "var(--viz-ink-2)" }}>
            Sent {formatBytes(hp.sent)}, received {formatBytes(hp.received)}
          </div>
          <div style={{ color: "var(--viz-ink-2)" }}>{formatNumber(hp.flows)} flows</div>
        </div>
      )}

      <details className="mt-2 text-xs" style={{ color: "var(--viz-ink-2)" }}>
        <summary className="cursor-pointer">View as table</summary>
        <div className="mt-2 max-h-56 overflow-auto">
          <table className="w-full text-left tabular-nums">
            <thead>
              <tr>
                <th className="pr-3">Time</th>
                <th className="pr-3">Sent</th>
                <th className="pr-3">Received</th>
                <th>Flows</th>
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.t}>
                  <td className="pr-3">{formatClock(p.t)}</td>
                  <td className="pr-3">{formatBytes(p.sent)}</td>
                  <td className="pr-3">{formatBytes(p.received)}</td>
                  <td>{formatNumber(p.flows)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <span className="sr-only">y-axis maximum {formatBytes(max)}</span>
    </div>
  );
}
