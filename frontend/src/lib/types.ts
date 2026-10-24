// Hand-written for the vertical slice. A client generated from the FastAPI OpenAPI schema
// (openapi-typescript) replaces this next session, so the contract cannot drift.

export type Severity = "Low" | "Medium" | "High" | "Critical";
export type AlertStatus = "new" | "acknowledged" | "false_positive" | "resolved";
export type SourceMethod = "netflow" | "sensor" | "http" | "syslog" | "scan";

export interface Alert {
  id: string;
  attack_class: string;
  severity: Severity;
  risk_score: number;
  count: number;
  src_ip: string | null;
  dst_ip: string | null;
  first_seen: string;
  last_seen: string;
  status: AlertStatus;
  analyst_label: string | null;
  evidence: Record<string, unknown>;
}

export interface Source {
  id: string;
  name: string;
  cidr: string;
  method: SourceMethod;
  status: string;
  criticality: number;
  last_seen: string | null;
  created_at: string;
}

export interface Snippet {
  id: string;
  title: string;
  language: string;
  content: string;
}

export interface SourceCreated extends Source {
  api_key: string;
  setup: {
    collector_host: string;
    collector_port: number;
    api_url: string;
    snippets: Snippet[];
  };
}

export interface SourceHealth {
  source_id: string;
  state: "waiting" | "receiving" | "stale";
  first_flows_received: boolean;
  last_seen: string | null;
  flows_total: number;
  flows_last_minute: number;
}

// ---- analytics, risk, prescriptive, models, evaluation ----------------------------------

export interface Overview {
  flows_24h: number;
  open_alerts: number;
  open_by_severity: Record<Severity, number>;
  risk: { score: number; severity: Severity; peak_asset: number };
  sources_total: number;
  sources_receiving: number;
  top_attackers: { ip: string; alerts: number; flows: number; max_risk: number }[];
  model: { version: string | null; algo: string | null };
}

export interface TrafficSeries {
  bucket_minutes: number;
  minutes: number;
  points: { t: string; flows: number; bytes: number; alerts: number }[];
}
export interface TopTalker {
  ip: string;
  flows: number;
  bytes: number;
}
export interface ProtocolShare {
  protocol: string;
  flows: number;
  bytes: number;
}

export interface Reference {
  framework: "mitre" | "cis" | "nist";
  id: string;
  title: string | null;
  url: string | null;
}
export type RecStatus = "open" | "in_progress" | "done" | "dismissed";
export interface Recommendation {
  id: string;
  alert_id: string;
  rule_id: string;
  action: string;
  priority: number;
  effort: string | null;
  status: RecStatus;
  rank: number;
  compliance_note: string | null;
  references: Reference[];
  alert: {
    id: string;
    attack_class: string;
    severity: Severity;
    src_ip: string | null;
    last_seen: string;
  };
}

export interface AssetRisk {
  asset_id: string | null;
  label: string;
  ip: string | null;
  criticality: number;
  internet_facing: boolean;
  registered: boolean;
  score: number;
  severity: Severity;
  open_alerts: number;
}
export interface RiskOut {
  score: number;
  severity: Severity;
  peak_asset: number;
  assets: AssetRisk[];
}
export interface RiskTrend {
  hours: number;
  bucket_minutes: number;
  points: { t: string; score: number }[];
}

export interface TopFeature {
  feature: string;
  value: number;
  contribution: number;
}

export interface PerClassMetrics {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}
export interface EvalMetrics {
  n: number;
  accuracy: number;
  f1_macro: number;
  f1_weighted: number;
  precision_macro: number;
  recall_macro: number;
  roc_auc_ovr_macro: number;
  false_alarm_rate: number;
  attack_detection_rate: number;
  per_class: Record<string, PerClassMetrics>;
  train_seconds?: number;
  latency_ms_per_500_flows?: number;
}
export interface ModelRow {
  version: string;
  algo: string;
  dataset: string | null;
  active: boolean;
  created_at: string;
  features: string[];
  metrics: {
    test?: EvalMetrics;
    validation?: Record<string, EvalMetrics>;
    latency_ms_per_500_flows?: number | null;
    latency_conditions?: string | null;
    classes?: string[];
    limitations?: string[];
    training?: { splits?: Record<string, number>; not_done?: string[]; models_compared?: string[] };
  };
}

export interface Instruments {
  sus: { scale: [number, number]; items: string[]; benchmark: number };
  tam: { scale: [number, number]; items: { construct: string; text: string }[]; note: string };
}
export interface EvalSummary {
  sus: { n: number; mean: number | null; sd: number | null; benchmark: number; above_benchmark: boolean | null };
  tam: {
    n: number;
    means: Record<string, number> | null;
    cronbach_alpha: Record<string, number | null>;
  };
}
