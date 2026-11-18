// Mirrors backend/app/api/* response shapes.

export type Role = "INVESTIGATOR" | "AUDITOR";
export type CheckStatus = "PASS" | "FAIL" | "INCONCLUSIVE";
export type C2PAStatus = "VALID" | "INVALID" | "ABSENT" | "ERROR" | "PENDING";
export type WitnessStatus = "PENDING" | "ACKNOWLEDGED" | "REJECTED" | "UNAVAILABLE";

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  role: Role;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: Role;
}

export interface Case {
  id: string;
  title: string;
  description: string | null;
  created_by: string;
  status: "OPEN" | "CLOSED" | "ARCHIVED";
  created_at: string;
}

export interface EvidenceSummary {
  id: string;
  case_id: string;
  original_filename: string;
  storage_key: string;
  sha256_digest: string;
  file_size: number;
  mime_type: string;
  phash: string | null;
  c2pa_status: C2PAStatus | null;
  uploaded_by: string;
  created_at: string;
  log_index?: number | null;
  checkpoint_tree_size?: number | null;
  witness_status?: WitnessStatus | null;
}

export interface C2PASummary {
  status: C2PAStatus;
  trusted: boolean | null;
  signer: string | null;
  issuer: string | null;
  signed_at: string | null;
  claim_generator: string | null;
  title: string | null;
  assertions: string[];
  validation_codes: string[];
  error: string | null;
}

export interface CustodyState {
  custodian_id: string | null;
  pending_transfer_to: string | null;
  pending_transfer_event: string | null;
}

export interface EvidenceDetail {
  id: string;
  case_id: string;
  original_filename: string;
  storage_key: string;
  sha256_digest: string;
  file_size: number;
  mime_type: string;
  phash: string | null;
  c2pa_status: C2PAStatus;
  c2pa_summary: C2PASummary | null;
  exif: Record<string, unknown> | null;
  uploaded_by: string;
  created_at: string | null;
  registration_log_index: number | null;
  custody: CustodyState;
}

export interface WitnessInfo {
  status: WitnessStatus;
  key_id: string | null;
  public_key: string | null;
  timestamp: string | null;
  signature: string | null;
  alert: string | null;
}

export interface Checkpoint {
  id: string;
  log_id: string;
  tree_size: number;
  root_hash: string;
  timestamp: string;
  key_id: string;
  signature: string;
  witness: WitnessInfo;
}

export interface CustodyEvent {
  id: string;
  evidence_id: string;
  actor_id: string;
  event_type: string;
  payload: Record<string, unknown> | null;
  timestamp: string | null;
  prev_event_hash: string | null;
  log_index: number | null;
  key_id: string | null;
  signature: string | null;
  canonical_bytes: string | null;
  signature_valid?: boolean;
  inclusion_valid?: boolean;
  inclusion_proof?: string[];
}

export interface CustodyTimeline {
  evidence_id: string;
  state: CustodyState;
  checkpoint: Checkpoint | null;
  events: CustodyEvent[];
}

export interface IntegrityResult {
  status: "PASS" | "FAIL" | "ERROR";
  stored_digest: string;
  computed_digest: string | null;
  log_index: number | null;
}

export interface Check {
  name: string;
  status: CheckStatus;
  detail: string;
  data: Record<string, unknown>;
}

export interface VerificationReport {
  evidence_id: string;
  overall: CheckStatus;
  checks: Check[];
  checkpoint: Checkpoint | null;
  events: CustodyEvent[];
}

export interface InclusionProof {
  event_id: string;
  event_type: string;
  log_index: number;
  tree_size: number;
  leaf_hash: string;
  root_hash: string;
  proof: string[];
}

export interface LogStats {
  log_id: string;
  tree_size: number;
  root_hash: string;
  latest_checkpoint: Checkpoint | null;
}

export interface OrbResult {
  query_keypoints: number;
  candidate_keypoints: number;
  good_matches: number;
  inliers: number;
  inlier_ratio: number;
  homography_found: boolean;
}

export interface TraceCandidate {
  evidence_id: string;
  hamming: number | null;
  phash_similarity: number | null;
  sha256_match: boolean;
  matched_by: string[];
  orb: OrbResult | null;
  evidence: EvidenceDetail;
}

export interface TraceSearchResult {
  query: {
    sha256: string;
    phash: string;
    mime_type: string;
    file_size: number;
    exif_present: boolean;
    width: number;
    height: number;
  };
  params: Record<string, unknown>;
  gallery_size: number;
  outcome: "CANDIDATES_FOUND" | "NO_MATCH";
  candidates: TraceCandidate[];
  notice: string;
  timings_ms: { hashing: number; search: number; total: number };
}

export type Assessment =
  | "VERIFIED_REGISTERED_ORIGINAL"
  | "CANDIDATE_ONLY"
  | "INTEGRITY_FAILURE"
  | "NO_MATCH";

export interface VerifyCandidateResult {
  assessment: Assessment;
  relationship: "BYTE_IDENTICAL" | "PERCEPTUAL_CANDIDATE" | "GEOMETRIC_CANDIDATE" | "NONE";
  explanation: string;
  query: { sha256: string; phash: string };
  similarity: { hamming: number | null; phash_threshold: number; orb: OrbResult | null };
  evidence: EvidenceDetail;
  verification: VerificationReport;
}

export interface ChartSpec {
  title: string;
  type: "line" | "bar";
  x: string;
  series: string[];
  x_label?: string;
  y_label?: string;
  data: Record<string, string | number | null>[];
}

export interface BenchmarkSpec {
  title: string;
  description: string;
  files: string[];
  charts: ChartSpec[];
  table?: Record<string, string | number | null>[];
}

export interface ExperimentManifest {
  run_id: string;
  name: string;
  status: string;
  started_at: string;
  finished_at: string;
  config: Record<string, unknown>;
  summary: Record<string, number>;
  files: string[];
  benchmarks: Record<string, BenchmarkSpec>;
}

export interface ExperimentRunSummary {
  id: string;
  db_id: string;
  name: string;
  created_at: string | null;
  config: Record<string, unknown>;
  summary: Record<string, number>;
  benchmarks: string[];
}

export interface ExperimentStatus {
  state: "idle" | "running" | "completed" | "failed";
  run_id: string | null;
  started_at: string | null;
  returncode: number | null;
  log_tail: string | null;
}
