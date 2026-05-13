pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS updates (
  update_id TEXT PRIMARY KEY,
  release_date TEXT,
  raw_sug_json TEXT,
  first_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  revision TEXT,
  title TEXT,
  description TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  exploited INTEGER,
  products_json TEXT,
  cwe TEXT,
  raw_sug_json TEXT,
  first_seen_at TEXT,
  last_revised_at TEXT
);

CREATE TABLE IF NOT EXISTS cve_kbs (
  cve_id TEXT,
  kb_id TEXT,
  PRIMARY KEY (cve_id, kb_id)
);

CREATE TABLE IF NOT EXISTS kb_enumerations (
  kb_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  csv_url TEXT,
  msu_path TEXT,
  tier1_fallback_reason TEXT,
  enumerated_at TEXT,
  file_list_hash TEXT
);

CREATE TABLE IF NOT EXISTS kb_files (
  kb_id TEXT,
  filename TEXT,
  arch TEXT,
  version TEXT,
  file_size INTEGER,
  date_stamp TEXT,
  source TEXT,
  PRIMARY KEY (kb_id, filename, arch),
  FOREIGN KEY (kb_id) REFERENCES kb_enumerations(kb_id)
);

CREATE TABLE IF NOT EXISTS cve_triage (
  cve_id TEXT,
  filename TEXT,
  confidence REAL,
  reasoning TEXT,
  cached_at TEXT,
  PRIMARY KEY (cve_id, filename)
);

-- One row per CVE-scoped diff run.  Fans out internally over all primary
-- binaries; per-pair ghidriff outputs live under ghidriff_output_dir.
CREATE TABLE IF NOT EXISTS diff_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  status TEXT,
    -- queued | fetching | awaiting_winbindex | diffing | synthesizing |
    -- deep_analyzing | reporting | done | failed
  started_at TEXT,
  finished_at TEXT,
  error TEXT,
  report_path TEXT,
  ghidriff_output_dir TEXT,
  created_by TEXT,
  UNIQUE (cve_id)
);

-- Stage 1 LLM synthesis output (one row per CVE)
CREATE TABLE IF NOT EXISTS cve_synthesis (
  cve_id TEXT PRIMARY KEY,
  diff_job_id INTEGER REFERENCES diff_jobs(id),
  primary_binaries_json TEXT,
  overall_summary TEXT,
  ranked_functions_json TEXT,
  created_at TEXT
);

-- Per-binary assessment from synthesis (one row per (cve, binary))
CREATE TABLE IF NOT EXISTS cve_synthesis_binaries (
  cve_id TEXT,
  filename TEXT,
  security_relevant INTEGER,
  confidence REAL,
  reasoning TEXT,
  PRIMARY KEY (cve_id, filename)
);

-- Stage 2 LLM deep-analysis findings (one row per (cve, binary, function))
CREATE TABLE IF NOT EXISTS function_findings (
  cve_id TEXT,
  filename TEXT,
  function_name TEXT,
  relevance REAL,
  summary TEXT,
  old_snippet TEXT,
  new_snippet TEXT,
  patch_summary TEXT,
  created_at TEXT,
  PRIMARY KEY (cve_id, filename, function_name)
);

CREATE TABLE IF NOT EXISTS triage_cache (
  cache_key TEXT PRIMARY KEY,
  response_json TEXT,
  created_at TEXT
);
"#;
