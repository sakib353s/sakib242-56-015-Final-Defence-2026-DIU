export type Role = "SUPER_ADMIN" | "ANALYST" | "READ_ONLY";
export type Tone = "ok" | "warn" | "fail" | "info" | "dim";

export interface ProblemData {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string | null;
  audit_ref?: string | null;
  request_id?: string | null;
}

export interface Session {
  token: string;
  role: Role;
  username: string;
  user_id: string;
  session_id: string;
  audit_ref: string;
  since: number;
}

export interface LoginResult {
  access_token: string;
  role: Role;
  user_id: string;
  session_id: string;
  audit_ref: string;
}

export interface LoginUser {
  username: string;
  password: string;
  totp?: string;
}

export interface Me {
  id: string;
  username: string;
  role: Role;
  totp_ok: boolean;
  session_id: string;
}

export interface BootToken {
  boot_token: string;
  ttl_s: number;
}

export interface BootLine {
  seq: number;
  ts: string;
  label: string;
  status: "OK" | "WARN" | "FAIL" | "INFO" | "BAR" | "SPIN" | "RAW";
  detail: string;
}

export interface Health {
  ok: boolean;
  core: string;
  env: string;
  policy_hash: string;
  asgi_ready: boolean;
}

export interface ModuleHealth {
  module: string;
  display: string;
  status: string;
  detail: string;
}

export interface ModulesHealth {
  modules: ModuleHealth[];
}

export interface Warrant {
  id: string;
  kind: "pentest" | "vuln_scan" | "remediation" | "ipanon";
  scope_json?: string;      // full admin listing
  scope?: string[];         // analyst /available subset
  purpose: string;
  warrant_ref: string;
  owner_user_id?: string;
  subject_name: string | null;
  valid_from?: string;
  valid_until: string;
  revoked_at?: string | null;
  created_at?: string;
}

export interface LedgerList {
  warrants: Warrant[];
  as_of?: string;
}

export interface PentestSession {
  id: string;
  warrant_id: string;
  target: string;
  status: "CREATED" | "RUNNING" | "DONE" | "DONE_NO_REPORT" | "FAILED" | "ABORTED";
  phase: "recon" | "scan" | "post" | "report";
  progress: number;
  findings_count: number;
  risk_score: number | null;
  created_by: string;
  bound_session: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  aborted_reason: string | null;
  report_path: string | null;
}

export interface Finding {
  id: string;
  source: string;
  source_id: string;
  host: string;
  port: number | null;
  service: string | null;
  cve: string | null;
  severity: string;
  cvss: number | null;
  mitre: string | null;
  description: string;
  created_at: string;
  job_count?: number; // present on /remediation/findings
}

export interface PentestDetail {
  session: PentestSession;
  findings: Finding[];
}

export interface VulnScan {
  id: string;
  warrant_id: string;
  target: string;
  status: "PENDING" | "RUNNING" | "DONE" | "FAILED" | string;
  risk_score: number | null;
  findings_count: number;
  created_by: string;
  bound_session: string;
  created_at: string;
  finished_at: string | null;
  report_path: string | null;
}

export interface VulnDetail {
  scan: VulnScan | null;
  findings: Finding[];
}

export interface Alert {
  id: string;
  source: string;
  signature: string;
  category: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  src_ip: string | null;
  dest_ip: string | null;
  mitre: string | null;
  status: "new" | "acked" | string;
  ts: string;
  raw_json: string;
  ack_by: string | null;
  ack_at: string | null;
}

export interface BlockResult {
  block_id: string;
  ip: string;
  status: string;
}

export interface IpBlock {
  id: string;
  ip: string;
  rule: string | null;
  status: string;
  deployed_via: string | null;
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
  unblocked_at?: string | null;
}

export interface PlaybookStep {
  step: string;
  detail: string;
  auto?: boolean;
}

export interface PlaybookResult {
  incident_id: string;
  playbook: string;
  steps: PlaybookStep[];
}

export interface HoneypotResult {
  status: string;
  policy_note: string;
}

export type SagaState =
  | "DRAFT"
  | "CONSENTED"
  | "APPLIED"
  | "APPLIED_UNVERIFIED"
  | "ROLLED_BACK"
  | "ABORTED";

export interface RemediationJob {
  id: string;
  finding_id: string;
  host: string;
  state: SagaState;
  created_at: string;
  updated_at: string;
}

export interface RemediationDiff {
  job_id: string;
  state: SagaState;
  before: string[];
  after: string[];
  diff: string[];
  script: string;
}

export interface OsintEmailResult {
  case_id: string;
  mode?: string;
  domain?: string;
  registry_total?: number | null;
  breach_count: number;
  breaches: Array<{
    Name?: string;
    Title?: string;
    Domain?: string;
    BreachDate?: string;
    DataClasses?: string[];
    Verified?: boolean;
  }>;
}

export interface OsintPasswordResult {
  pwned: boolean;
  approximate_exposures: number;
  case_id: string;
}

export interface OsintDomainResult {
  case_id: string;
  domain: string;
  dns?: Record<string, string[]>;
  rdap?: { handle?: string; events?: Array<{ eventAction?: string; date?: string }>; error?: string };
  tls?: { subject?: Record<string, string>; issuer?: Record<string, string>; not_after?: string; expire_warning?: boolean; error?: string };
  subdomains?: string[];
  shodan?: { hosts?: (string | undefined)[]; data?: string[]; error?: string };
}

export interface OsintUrlResult {
  case_id: string;
  status: number;
  final_url: string;
  headers: Record<string, string>;
  redirects: string[];
}

export interface OsintProfileResult {
  username_hash: string;
  exposure_score: number;
  signals: Record<string, unknown>;
  rubric: Record<string, number>;
}

export interface LeakResults {
  results: Array<{
    watch_id: string;
    query: string;
    query_hash: string;
    public_repos_matched: number;
    checked_at: string;
  }>;
}

export interface DocIngest {
  id: string;
  sha256: string;
  md5: string;
  watermark_id: string;
  size: number;
  mime: string;
}

export interface DocRow {
  id: string;
  filename: string;
  sha256: string;
  md5: string;
  watermark_id: string;
  size: number;
  mime: string;
  created_at: string;
}

export interface CrawlCopy {
  url: string;
  verdict: string;
  found_at: string;
}

export interface DocDetail {
  document: DocRow;
  copies: CrawlCopy[];
}

export interface VictimCaseRow {
  id: string;
  case_type: string;
  status: string;
  created_at: string;
}

export interface TimelineEvent {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  evidence_ref: string | null;
  hash: string;
}

export interface VictimCaseDetail {
  case: { id: string; case_type: string; narrative: string; status: string; created_at: string };
  complainant: Record<string, string>;
  timeline: TimelineEvent[];
}

export interface ChainVerify {
  ok: boolean;
  events?: number;
  broken_at_seq?: number;
}

export interface ComplaintDrafts {
  case_id: string;
  drafts: Record<string, { report_id: string; download: string }>;
  note: string;
}

export interface Circuit {
  id: string;
  status: "building" | "active" | "stopped" | "failed" | string;
  masked_ip: string | null;
  started_at: string;
  last_heartbeat: string | null;
}

export interface TraceHop {
  ttl: number;
  ip: string;
  hostname: string | null;
  avg_ms: string | null;
  worst_ms: string | null;
  loss_pct: string | null;
  nat: unknown;
}

export interface TraceResult {
  target: { ip: string; hostname: string };
  started: string;
  engine: string;
  hops: TraceHop[];
}

export interface HwAsset {
  id: string;
  name: string;
  kind: string;
  host: string;
  ssh_port: number | null;
  ssh_user: string | null;
  disabled: number;
  last_check_at: string | null;
  created_at: string;
}

export interface HwAssetDetail extends HwAsset {
  last_check_json: string | null;
}

export interface HwCheckResult {
  checks: Record<string, Record<string, string>>;
  anomalies: string[];
  checked_at?: string;
}

export interface ReportRow {
  id: string;
  name: string;
  kind: string;
  ref_id: string | null;
  created_at: string;
  sha256: string;
}

export interface AuditEntry {
  seq: number;
  id: string;
  ts_ms: number;
  actor: string;
  action: string;
  object_ref: string;
  payload_json: string;
  payload_hash: string;
  prev_hash: string;
  hmac: string;
}

export interface AuditChainVerify {
  ok: boolean;
  verified?: number;
  broken_at?: number | null;
  [k: string]: unknown;
}

export interface PolicyResult {
  rulepack: Record<string, unknown>;
  sha256: string;
  ledger_active: string[];
}

export interface WsEnvelope<T = Record<string, unknown>> {
  channel: string;
  seq: number;
  ts: string;
  type: string;
  payload: T;
  hmac: string;
}

export type AssessmentStatus =
  | "CREATED" | "AUTHORIZED" | "PLANNED" | "QUEUED" | "DISPATCHED" | "RUNNING"
  | "PARSING" | "VERIFYING" | "COMPLETED" | "FAILED" | "CANCELLED"
  | "WORKER_LOST" | "UNKNOWN_RESULT" | "PARTIAL" | "BLOCKED_BY_POLICY";

export interface Assessment {
  id: string;
  warrant_id: string;
  target_raw: string;
  target_canonical: string;
  target_type: "ip" | "domain" | "url";
  profile: "quick" | "standard" | "deep";
  status: AssessmentStatus;
  current_stage: string | null;
  progress: number;
  findings_count: number;
  observations_count: number;
  risk_score: number | null;
  risk_version: string | null;
  created_by: string;
  bound_session: string;
  job_id: string | null;
  worker_id: string | null;
  policy_version: string | null;
  report_path: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  aborted_reason: string | null;
}

export interface AssessmentStage {
  id: string;
  assessment_id: string;
  seq: number;
  stage_key: string;
  label: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped" | "degraded" | "unknown";
  message: string | null;
  engine: string | null;
  engine_version: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Observation {
  id: string;
  assessment_id: string;
  kind: string;
  entity_type: string;
  entity_value: string;
  target: string;
  confidence: number;
  source_engine: string;
  source_version: string | null;
  provenance: string;
  payload_json: string;
  evidence_ids_json: string;
  state: "observed" | "inferred" | "correlated" | "declared";
  collected_at: string;
}

export type FindingLifecycle =
  | "detected" | "triaged" | "validating" | "confirmed" | "remediation_recommended"
  | "remediated" | "verified_fixed" | "false_positive" | "not_reproducible"
  | "unconfirmed" | "actioned_but_not_verified";

export interface AssessmentFinding {
  id: string;
  assessment_id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvss: number | null;
  confidence: number;
  detection_state: string;
  lifecycle: FindingLifecycle;
  cve: string | null;
  cwe: string | null;
  mitre: string | null;
  host: string | null;
  port: number | null;
  endpoint: string | null;
  parameter: string | null;
  technology: string | null;
  description: string;
  impact: string | null;
  remediation_hint: string | null;
  source_engine: string;
  source_version: string | null;
  evidence_ids_json: string | null;
  observation_ids_json: string | null;
  retest_def_json: string | null;
  before_snapshot_json: string | null;
  after_snapshot_json: string | null;
  verify_result: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  confirmed_by: string | null;
  confirmed_at: string | null;
  remediation_plan_json: string | null;
  remediated_at: string | null;
  last_retest_at: string | null;
  last_retest_job_id: string | null;
  retest_count: number | null;
  created_at: string;
  updated_at: string;
}

export interface FindingQueueRow {
  id: string;
  assessment_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: number;
  lifecycle: FindingLifecycle;
  host: string | null;
  endpoint: string | null;
  source_engine: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  assessment_id: string | null;
  finding_id: string | null;
  observation_id: string | null;
  kind: string;
  ref: string;
  sha256: string | null;
  size: number | null;
  mime: string | null;
  storage_path: string | null;
  redacted: number;
  description: string | null;
  produced_by: string;
  produced_version: string | null;
  captured_at: string;
}

export interface BrainDecision {
  id: string;
  assessment_id: string | null;
  finding_id: string | null;
  alert_id: string | null;
  incident_id: string | null;
  autonomy_level: "information_only" | "recommendation" | "preparation" | "approval_request" | "approved_automation" | "bounded_autonomous_defense";
  classification: string | null;
  risk: number | null;
  security_confidence: number | null;
  model_confidence: number | null;
  rationale_json: string;
  evidence_refs_json: string;
  missing_evidence_json: string;
  recommendations_json: string;
  selected_action: string | null;
  policy_result: string | null;
  authorization_result: string | null;
  verification_state: string;
  model_runtime: string | null;
  rule_pack_version: string | null;
  created_at: string;
}

export type TiStixType =
  | "indicator" | "malware" | "threat-actor" | "campaign" | "tool" | "attack-pattern"
  | "infrastructure" | "vulnerability" | "report" | "observed-data" | "intrusion-set"
  | "course-of-action" | "identity";

export interface TiObject {
  id: string;
  stix_type: TiStixType;
  stix_id: string | null;
  name: string;
  description: string | null;
  pattern: string | null;
  pattern_type: string | null;
  valid_from: string | null;
  valid_until: string | null;
  confidence: number | null;
  tlp: "CLEAR" | "GREEN" | "AMBER" | "RED" | null;
  labels_json: string;
  kill_chain_json: string;
  external_refs_json: string;
  source: string;
  trust: "internal" | "untrusted";
  provenance_json: string;
  first_seen: string | null;
  last_seen: string | null;
  revoked: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface TiRelationship {
  id: string;
  source_id: string;
  source_kind: string;
  source_type: string | null;
  source_name: string | null;
  relationship_type: string;
  target_id: string;
  target_kind: string;
  target_type: string | null;
  target_name: string | null;
  description: string | null;
  confidence: number;
  state: "declared" | "observed" | "inferred" | "correlated";
  created_by: string;
  created_at: string;
}

export interface TiObservable {
  observable_type: "ipv4" | "ipv6" | "domain" | "url" | "hash" | "email";
  value: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface TiObjectDetail {
  object: TiObject;
  relationships: TiRelationship[];
  observables: TiObservable[];
  decisions: { id: string; finding_id: string | null; rationale_json: string; recommendations_json: string; created_at: string }[];
}

export interface TiMatchResult {
  value: string;
  normalized: string | null;
  type: string | null;
  matches: (TiObject & { matched_type?: string; matched_value?: string })[];
}

export interface TiStats {
  by_type: { stix_type: string; n: number }[];
  total: number;
  untrusted: number;
  last_ingest: string | null;
  links: number;
  note: string;
}

export interface AssessmentDetail {
  assessment: Assessment;
  stages: AssessmentStage[];
  findings: AssessmentFinding[];
  observations_count: number;
  brain_decisions: BrainDecision[];
}

export interface FindingDetail {
  finding: AssessmentFinding;
  evidence: Evidence[];
  decision: BrainDecision | null;
}
