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
  /** Other addresses of the same machine, reported by its sensor (the IPv6 ones). */
  extra_cidrs?: string[];
  method: SourceMethod;
  status: string;
  criticality: number;
  last_seen: string | null;
  created_at: string;
  /** The source is still learning what is normal until this moment. */
  baseline_until?: string | null;
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
export interface TrafficSummary {
  minutes: number;
  flows: number;
  total_bytes: number;
  monitored_hosts: number;
  monitored_sent_bytes: number;
  monitored_received_bytes: number;
}
export interface HostVolume {
  ip: string;
  sent_bytes: number;
  received_bytes: number;
  total_bytes: number;
  flows: number;
  /** null for a registered address with no traffic in the window */
  last_seen: string | null;
  source_id: string | null;
  source_name: string | null;
}
/** What one address sent to and received from a peer or over a service. */
export interface SplitVolume {
  sent_bytes: number;
  received_bytes: number;
  bytes: number;
  flows: number;
}
export interface HostDetail {
  ip: string;
  minutes: number;
  bucket_minutes: number;
  sent_bytes: number;
  received_bytes: number;
  total_bytes: number;
  flows: number;
  /** latest flow in the window; when the window is empty, the latest ever seen (or null) */
  last_seen: string | null;
  points: { t: string; sent: number; received: number; flows: number }[];
  peers: (SplitVolume & { ip: string })[];
  services: (SplitVolume & { service: string; protocol: string })[];
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
  alert_id: string | null;
  rule_id: string;
  action: string;
  priority: number;
  effort: string | null;
  status: RecStatus;
  rank: number;
  compliance_note: string | null;
  references: Reference[];
  /** null: the action comes from the self-assessment alone, not from an alert */
  alert: {
    id: string;
    attack_class: string;
    severity: Severity;
    src_ip: string | null;
    last_seen: string;
  } | null;
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
export interface DatasetSummary {
  n: number;
  accuracy: number;
  f1_macro: number;
  false_alarm_rate: number;
  attack_detection_rate: number;
  per_class_f1: Record<string, number>;
}
export interface AlertThreshold {
  value: number;
  calibration: {
    rule: string;
    target_met: boolean;
    chosen: { false_alarm_rate: number; attack_recall: number; far_max: number };
  };
  test: {
    false_alarm_rate: number;
    attack_recall: number;
    far_by_dataset: Record<string, number>;
    attack_recall_by_dataset: Record<string, number>;
  };
}
export interface ProbeResult {
  note: string;
  benign: number;
  total: number;
  flows: { flow: string; label: string; probability: number }[];
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
    per_dataset_test?: Record<string, DatasetSummary> | null;
    cross_dataset?: Record<string, DatasetSummary> | null;
    informal_probe?: ProbeResult | null;
    alert_threshold?: AlertThreshold | null;
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

// ---- devices, peer networks, quarantine -------------------------------------------------

export type DeviceState = "known" | "new" | "trusted" | "quarantined";
export type NetworkState = "baseline" | "new" | "approved" | "quarantined";

interface Tracked {
  id: string;
  source_id: string;
  first_seen: string;
  last_seen: string;
  state_reason: string | null;
  state_changed_at: string;
  /** "system", or the email of the person who decided */
  state_by: string;
  alert_id: string | null;
}
export interface Device extends Tracked {
  ip: string;
  mac: string | null;
  hostname: string | null;
  /** Who made the network card (from the MAC); "Randomised address" for a privacy MAC. */
  vendor: string | null;
  state: DeviceState;
}
export interface PeerNetwork extends Tracked {
  network: string;
  flows: number;
  bytes: number;
  flagged_ips: string[];
  state: NetworkState;
}
export interface InventorySummary {
  devices_total: number;
  devices_new: number;
  devices_quarantined: number;
  networks_total: number;
  networks_new: number;
  networks_quarantined: number;
}
export interface QuarantineItem {
  kind: "device" | "network";
  id: string;
  source_id: string;
  target: string;
  flagged_ips: string[];
  reason: string | null;
  since: string;
  alert_id: string | null;
  commands: { windows: string[]; linux: string[]; gateway: string[] };
}

// --- settings ------------------------------------------------------------------------------
export interface SettingItem {
  key: string;
  group: string;
  label: string;
  help: string;
  kind: "int" | "float" | "bool" | "choice" | "emails";
  min: number | null;
  max: number | null;
  choices: string[];
  unit: string;
  default: string | number | boolean;
  value: string | number | boolean;
  overridden: boolean;
}
export interface SettingsResponse {
  can_edit: boolean;
  items: SettingItem[];
}
export interface SystemHealth {
  checked_at: string;
  database: { ok: boolean; error?: string };
  schema_version?: string;
  active_model?: string | null;
  retention_days?: number;
  queue: {
    ok: boolean;
    error?: string;
    waiting?: number;
    dead_letters?: number;
    workers?: { name: string; idle_seconds: number; pending: number }[];
  };
  pipeline_lag?: { samples: number; median_ms?: number; p95_ms?: number; max_ms?: number };
}
export interface UserRow {
  id: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
}

// --- training ------------------------------------------------------------------------------
export interface TrainingOptions {
  algorithms: { key: string; label: string; available: boolean; default: boolean; note: string }[];
  datasets: { key: string; ready: boolean; bytes: number; citation: string; source: string }[];
  defaults: Record<string, unknown>;
  busy: boolean;
}
export interface TrainingJob {
  id: string;
  kind: "train" | "download" | "backup" | "check";
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  stage: string | null;
  params: Record<string, unknown>;
  result_version: string | null;
  error: string | null;
  created_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}
export interface TrainingJobDetail extends TrainingJob {
  log: string;
}

// --- self-assessment -----------------------------------------------------------------------
export type Maturity = "Low" | "Medium" | "High" | "Not assessed";
export interface AssessmentItem {
  id: string;
  area: string;
  question: string;
  source: string;
  weight: number;
  answer: number | null;
}
export interface AssessmentResponse {
  can_edit: boolean;
  items: AssessmentItem[];
  maturity: Record<string, { percent: number | null; level: Maturity; items: number; answered: number }>;
  governance: { id: string; question: string; source: string; status: string }[];
  disclaimer: string;
}

// --- rules and backups ---------------------------------------------------------------------
export interface RuleRow {
  id: string;
  attack_class: string | string[];
  min_severity: string;
  weak_area: string | null;
  max_level: string | null;
  profile_only: boolean;
  ports: number[] | null;
  enabled: boolean;
  changed: boolean;
  actions: {
    action: string;
    priority: number;
    effort: string;
    default: { action: string; priority: number; effort: string };
    refs: { framework: string; id: string; title: string | null }[];
  }[];
}
export interface RulesResponse {
  can_edit: boolean;
  rules: RuleRow[];
}
export interface BackupRow {
  name: string;
  bytes: number;
  has_models: boolean;
}
