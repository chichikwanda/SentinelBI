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
