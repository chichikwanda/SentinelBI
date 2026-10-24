import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";

const BANDS = [
  { label: "Low", from: 0, to: 25, color: "var(--sev-low)" },
  { label: "Medium", from: 25, to: 50, color: "var(--sev-medium)" },
  { label: "High", from: 50, to: 75, color: "var(--sev-high)" },
  { label: "Critical", from: 75, to: 100, color: "var(--sev-critical)" },
];

/** A 0-100 score as a hero figure plus a banded bar. Severity is always spelled out in text
 *  (and an icon), never carried by colour alone. */
export function RiskGauge({ score, severity }: { score: number; severity: string }) {
  const Icon = severity === "Low" ? ShieldCheck : severity === "Medium" ? ShieldQuestion : ShieldAlert;
  return (
    <div className="viz-root" data-testid="risk-gauge">
      <div className="flex items-baseline gap-2">
        <span className="text-4xl font-semibold tabular-nums" data-testid="risk-score">
          {score.toFixed(1)}
        </span>
        <span className="text-sm" style={{ color: "var(--viz-ink-2)" }}>
          / 100
        </span>
        <span className="ml-auto flex items-center gap-1 text-sm font-medium">
          <Icon size={16} aria-hidden /> {severity}
        </span>
      </div>
      <div className="relative mt-3" role="img" aria-label={`Risk ${score.toFixed(1)} of 100, ${severity}`}>
        <div className="flex h-2 gap-0.5">
          {BANDS.map((b) => (
            <div key={b.label} className="h-2 flex-1 rounded-sm" style={{ background: b.color, opacity: 0.35 }} />
          ))}
        </div>
        <div
          className="absolute -top-1 h-4 w-1 rounded"
          style={{ left: `calc(${Math.min(100, Math.max(0, score))}% - 2px)`, background: "var(--viz-ink)" }}
        />
        <div className="mt-1 flex justify-between text-[10px]" style={{ color: "var(--viz-muted)" }}>
          <span>0</span>
          <span>25</span>
          <span>50</span>
          <span>75</span>
          <span>100</span>
        </div>
      </div>
    </div>
  );
}
