"use client";

import { useRef, useState } from "react";
import { formatClock } from "@/lib/format";

const W = 720;
const H = 180;
const M = { left: 40, right: 14, top: 10, bottom: 28 };
const PW = W - M.left - M.right;
const PH = H - M.top - M.bottom;

/** A single 0-100 series over time (organisation risk) with severity band guides. */
export function TrendChart({ points }: { points: { t: string; score: number }[] }) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const n = points.length;
  const xs = points.map((_, i) => M.left + (n <= 1 ? PW / 2 : (i / (n - 1)) * PW));
  const y = (v: number) => M.top + PH - (Math.min(100, Math.max(0, v)) / 100) * PH;
  const line = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y(points[i].score).toFixed(1)}`).join(" ");
  const step = Math.max(1, Math.floor((n - 1) / 4));

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || n === 0) return;
    const f = (((e.clientX - rect.left) / rect.width) * W - M.left) / PW;
    setHover(Math.max(0, Math.min(n - 1, Math.round(f * (n - 1)))));
  }

  return (
    <div className="viz-root relative">
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label="Organisation risk score over time"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {[0, 25, 50, 75, 100].map((v) => (
          <g key={v}>
            <line x1={M.left} x2={W - M.right} y1={y(v)} y2={y(v)} stroke="var(--viz-grid)" />
            <text x={M.left - 8} y={y(v) + 3.5} textAnchor="end" fontSize={10} fill="var(--viz-muted)">
              {v}
            </text>
          </g>
        ))}
        {line && <path d={line} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" />}
        {points.map((p, i) =>
          i % step === 0 ? (
            <text key={p.t} x={xs[i]} y={H - 8} textAnchor="middle" fontSize={10} fill="var(--viz-muted)">
              {formatClock(p.t)}
            </text>
          ) : null,
        )}
        {hover !== null && (
          <g pointerEvents="none">
            <line x1={xs[hover]} x2={xs[hover]} y1={M.top} y2={M.top + PH} stroke="var(--viz-axis)" />
            <circle cx={xs[hover]} cy={y(points[hover].score)} r={4} fill="var(--series-1)" stroke="var(--viz-surface)" strokeWidth={2} />
          </g>
        )}
        <rect x={M.left} y={M.top} width={PW} height={PH} fill="transparent" />
      </svg>
      {hover !== null && points[hover] && (
        <div
          className="pointer-events-none absolute top-2 rounded-md border px-2 py-1 text-xs shadow-sm"
          style={{
            left: `${Math.min(84, Math.max(2, (xs[hover] / W) * 100 - 6))}%`,
            background: "var(--viz-surface)",
            borderColor: "var(--viz-axis)",
          }}
        >
          {formatClock(points[hover].t)}: risk {points[hover].score.toFixed(1)}
        </div>
      )}
      {n < 2 && (
        <p className="mt-1 text-xs" style={{ color: "var(--viz-ink-2)" }}>
          The trend fills in as the worker records snapshots every minute while alerts are open.
        </p>
      )}
    </div>
  );
}
