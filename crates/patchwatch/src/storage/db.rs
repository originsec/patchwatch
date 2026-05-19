use super::schema::DDL;
use crate::kb::types::{Arch, KbEnumeration, KbFile};
use crate::sug::types::Vulnerability;
use crate::triage::anthropic::Ranking;
use crate::triage::deep_analysis::DeepAnalysisResult;
use crate::triage::synthesis::{BinaryAssessment, SynthesisResult};
use anyhow::{anyhow, Result};
use deadpool_sqlite::Runtime;
use rusqlite::Connection;
use std::path::Path;

pub struct Db {
    pool: deadpool_sqlite::Pool,
}

// --- Status enum ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveStatus {
    New,
    Triaged,
    Analyzing,
    Analyzed,
    Failed,
}

impl CveStatus {
    pub fn from_str(s: &str) -> Self {
        match s {
            "triaged" => Self::Triaged,
            "done" => Self::Analyzed,
            "failed" => Self::Failed,
            "new" => Self::New,
            _ => Self::Analyzing,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Triaged => "triaged",
            Self::Analyzing => "analyzing",
            Self::Analyzed => "analyzed",
            Self::Failed => "failed",
        }
    }
}

// --- Query / result types ---

pub struct CveFilter {
    pub exploited_only: bool,
    pub min_cvss: Option<f64>,
    pub since_days: Option<u32>,
    pub search: Option<String>,
    pub sort: Option<String>,
    pub sort_dir: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for CveFilter {
    fn default() -> Self {
        Self {
            exploited_only: false,
            min_cvss: None,
            since_days: None,
            search: None,
            sort: None,
            sort_dir: None,
            limit: 50,
            offset: 0,
        }
    }
}

#[derive(Clone)]
pub struct CveListRow {
    pub cve_id: String,
    pub revision: Option<String>,
    pub title: Option<String>,
    pub cvss_score: Option<f64>,
    pub exploited: bool,
    pub kb_id: Option<String>,
    pub file_count: Option<i64>,
    pub status: CveStatus,
    pub last_revised_at: Option<String>,
}

pub struct CveDetail {
    pub cve_id: String,
    pub revision: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub exploited: bool,
    pub cwe: Option<String>,
    pub last_revised_at: Option<String>,
    pub kb_id: Option<String>,
    pub file_count: Option<i64>,
    pub enumeration_source: Option<String>,
}

pub struct SynthesisRow {
    pub cve_id: String,
    pub diff_job_id: Option<i64>,
    pub primary_binaries_json: String,
    pub overall_summary: String,
    pub ranked_functions_json: String,
    pub created_at: Option<String>,
}

pub struct FindingRow {
    pub cve_id: String,
    pub filename: String,
    pub function_name: String,
    pub relevance: f64,
    pub summary: String,
    pub old_snippet: String,
    pub new_snippet: String,
    pub patch_summary: String,
}

pub struct DiffJobRow {
    pub id: i64,
    pub cve_id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub report_path: Option<String>,
    pub ghidriff_output_dir: Option<String>,
}

impl DiffJobRow {
    pub fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "done" | "failed")
    }
}

// --- Db implementation ---

impl Db {
    pub fn open(path: &Path, pool_size: usize) -> Result<Self> {
        // Bootstrap schema synchronously on a direct connection before creating pool.
        let conn = Connection::open(path)?;
        conn.execute_batch(DDL)?;
        drop(conn);

        let cfg = deadpool_sqlite::Config::new(path);
        let mut pool_cfg = deadpool_sqlite::Pool::builder(
            deadpool_sqlite::Manager::from_config(&cfg, Runtime::Tokio1),
        );
        pool_cfg = pool_cfg.max_size(pool_size);
        let pool = pool_cfg.build().map_err(|e| anyhow!("pool build error: {e}"))?;
        Ok(Self { pool })
    }

    pub fn open_in_memory() -> Result<Self> {
        // Sync version for legacy tests only. Uses a direct connection for bootstrap,
        // then a single-slot pool so all interactions hit the same in-memory database.
        // NOTE: `:memory:` means each rusqlite connection is a separate DB, so we must
        // cap the pool at 1 to always reuse the same connection.
        let cfg = deadpool_sqlite::Config::new(":memory:");
        let pool = deadpool_sqlite::Pool::builder(
            deadpool_sqlite::Manager::from_config(&cfg, Runtime::Tokio1),
        )
        .max_size(1)
        .build()
        .map_err(|e| anyhow!("pool build error: {e}"))?;
        Ok(Self { pool })
    }

    pub async fn open_in_memory_async() -> Result<Self> {
        let db = Self::open_in_memory()?;
        db.with_conn(|c| c.execute_batch(DDL)).await?;
        Ok(db)
    }

    async fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.pool.get().await?;
        conn.interact(f)
            .await
            .map_err(|e| anyhow!("blocking task failed: {e}"))?
            .map_err(Into::into)
    }

    // --- CVE / KB upserts ---

    pub async fn upsert_cve(&self, cve: &Vulnerability, raw_json: String) -> Result<()> {
        let cve = cve.clone();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            c.execute(
                "INSERT INTO cves (cve_id, revision, title, description, cvss_score, cvss_vector, \
                 exploited, cwe, raw_sug_json, first_seen_at, last_revised_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
                 ON CONFLICT(cve_id) DO UPDATE SET \
                   revision=excluded.revision, title=excluded.title, \
                   description=excluded.description, cvss_score=excluded.cvss_score, \
                   cvss_vector=excluded.cvss_vector, exploited=excluded.exploited, \
                   cwe=excluded.cwe, raw_sug_json=excluded.raw_sug_json, \
                   last_revised_at=excluded.last_revised_at",
                rusqlite::params![
                    cve.cve_number,
                    cve.revision_number,
                    cve.cve_title,
                    cve.description,
                    cve.base_score,
                    cve.vector_string,
                    cve.exploited.as_deref().map(|s| if s.eq_ignore_ascii_case("yes") { 1i64 } else { 0 }),
                    cve.cwe_id(),
                    raw_json,
                    now,
                    cve.release_date,
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn upsert_cve_kb(&self, cve_id: &str, kb_id: &str) -> Result<()> {
        let (cve_id, kb_id) = (cve_id.to_owned(), kb_id.to_owned());
        self.with_conn(move |c| {
            c.execute(
                "INSERT OR IGNORE INTO cve_kbs (cve_id, kb_id) VALUES (?1, ?2)",
                rusqlite::params![cve_id, kb_id],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn upsert_kb_enumeration(&self, e: &KbEnumeration) -> Result<()> {
        let kb_id = e.kb_id.clone();
        let source = format!("{:?}", e.source).to_lowercase();
        let csv_url = e.csv_url.clone();
        let msu_path = e.msu_path.as_ref().map(|p| p.to_string_lossy().into_owned());
        let reason = e.fallback_reason.clone();
        let hash = e.file_list_hash();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            c.execute(
                "INSERT INTO kb_enumerations \
                 (kb_id, source, csv_url, msu_path, tier1_fallback_reason, enumerated_at, file_list_hash) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7) \
                 ON CONFLICT(kb_id) DO UPDATE SET \
                   source=excluded.source, csv_url=excluded.csv_url, msu_path=excluded.msu_path, \
                   tier1_fallback_reason=excluded.tier1_fallback_reason, \
                   enumerated_at=excluded.enumerated_at, file_list_hash=excluded.file_list_hash",
                rusqlite::params![kb_id, source, csv_url, msu_path, reason, now, hash],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn upsert_kb_files(&self, kb_id: &str, files: &[KbFile]) -> Result<()> {
        let kb_id = kb_id.to_owned();
        let files = files.to_vec();
        self.with_conn(move |c| {
            let tx = c.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO kb_files (kb_id, filename, arch, version, file_size, date_stamp, source) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7) \
                     ON CONFLICT(kb_id, filename, arch) DO UPDATE SET \
                       version=excluded.version, file_size=excluded.file_size, \
                       date_stamp=excluded.date_stamp, source=excluded.source",
                )?;
                for f in &files {
                    let arch_str = match f.arch {
                        Arch::X64 => "x64",
                        Arch::X86 => "x86",
                        Arch::Arm64 => "arm64",
                        Arch::Unknown => "unknown",
                    };
                    stmt.execute(rusqlite::params![
                        kb_id, f.filename, arch_str, f.version,
                        f.file_size.map(|s| s as i64), f.date_stamp, "csv"
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn list_cves(&self, filter: CveFilter) -> Result<Vec<CveListRow>> {
        self.with_conn(move |c| {
            let mut sql = String::from(
                "SELECT c.cve_id, c.revision, c.title, c.cvss_score, c.exploited, \
                 ck.kb_id, \
                 (SELECT COUNT(*) FROM kb_files kf WHERE kf.kb_id = ck.kb_id AND kf.arch = 'x64') as file_count, \
                 CASE \
                   WHEN dj.id IS NOT NULL THEN dj.status \
                   WHEN (SELECT COUNT(*) FROM cve_triage ct WHERE ct.cve_id = c.cve_id) > 0 THEN 'triaged' \
                   ELSE 'new' \
                 END as status, \
                 c.last_revised_at \
                 FROM cves c \
                 LEFT JOIN cve_kbs ck ON ck.cve_id = c.cve_id \
                 LEFT JOIN diff_jobs dj ON dj.cve_id = c.cve_id \
                 WHERE 1=1",
            );
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            if filter.exploited_only {
                sql.push_str(" AND c.exploited = 1");
            }
            if let Some(ref q) = filter.search {
                let pattern = format!("%{}%", q);
                sql.push_str(" AND (c.cve_id LIKE ? OR c.title LIKE ? OR c.description LIKE ?)");
                params.push(Box::new(pattern.clone()));
                params.push(Box::new(pattern.clone()));
                params.push(Box::new(pattern));
            }
            if let Some(min) = filter.min_cvss {
                sql.push_str(" AND c.cvss_score >= ?");
                params.push(Box::new(min));
            }
            if let Some(days) = filter.since_days {
                sql.push_str(&format!(" AND c.last_revised_at >= datetime('now', '-{} days')", days));
            }
            let order = match (filter.sort.as_deref(), filter.sort_dir.as_deref()) {
                (Some("cve"), Some("desc")) => "c.cve_id DESC",
                (Some("cve"), _) => "c.cve_id ASC",
                (Some("cvss"), Some("asc")) => "c.cvss_score ASC NULLS LAST",
                (Some("cvss"), _) => "c.cvss_score DESC NULLS LAST",
                (Some("kb"), Some("desc")) => "ck.kb_id DESC NULLS LAST",
                (Some("kb"), _) => "ck.kb_id ASC NULLS LAST",
                _ => "c.last_revised_at DESC",
            };
            sql.push_str(&format!(" ORDER BY {} LIMIT ? OFFSET ?", order));
            params.push(Box::new(filter.limit as i64));
            params.push(Box::new(filter.offset as i64));

            let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(params_refs.as_slice(), |row| {
                let exploited: Option<i64> = row.get(4)?;
                let status_str: String = row.get(7)?;
                Ok(CveListRow {
                    cve_id: row.get(0)?,
                    revision: row.get(1)?,
                    title: row.get(2)?,
                    cvss_score: row.get(3)?,
                    exploited: exploited.unwrap_or(0) != 0,
                    kb_id: row.get(5)?,
                    file_count: row.get(6)?,
                    status: CveStatus::from_str(&status_str),
                    last_revised_at: row.get(8)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
    }

    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<CveDetail>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT c.cve_id, c.revision, c.title, c.description, c.cvss_score, c.cvss_vector, \
                 c.exploited, c.cwe, c.last_revised_at, \
                 ck.kb_id, \
                 (SELECT COUNT(*) FROM kb_files kf WHERE kf.kb_id = ck.kb_id AND kf.arch = 'x64') as file_count, \
                 ke.source \
                 FROM cves c \
                 LEFT JOIN cve_kbs ck ON ck.cve_id = c.cve_id \
                 LEFT JOIN kb_enumerations ke ON ke.kb_id = ck.kb_id \
                 WHERE c.cve_id = ?1",
            )?;
            let mut rows = stmt.query_map([&cve_id], |row| {
                let exploited: Option<i64> = row.get(6)?;
                Ok(CveDetail {
                    cve_id: row.get(0)?,
                    revision: row.get(1)?,
                    title: row.get(2)?,
                    description: row.get(3)?,
                    cvss_score: row.get(4)?,
                    cvss_vector: row.get(5)?,
                    exploited: exploited.unwrap_or(0) != 0,
                    cwe: row.get(7)?,
                    last_revised_at: row.get(8)?,
                    kb_id: row.get(9)?,
                    file_count: row.get(10)?,
                    enumeration_source: row.get(11)?,
                })
            })?;
            match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn get_kb_files(&self, kb_id: &str) -> Result<Vec<KbFile>> {
        let kb_id = kb_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT filename, arch, version, file_size, date_stamp FROM kb_files \
                 WHERE kb_id = ?1 ORDER BY filename, arch",
            )?;
            let rows = stmt.query_map([&kb_id], |row| {
                let arch_str: String = row.get(1)?;
                let arch = match arch_str.as_str() {
                    "x64" => Arch::X64,
                    "x86" => Arch::X86,
                    "arm64" => Arch::Arm64,
                    _ => Arch::Unknown,
                };
                let file_size: Option<i64> = row.get(3)?;
                Ok(KbFile {
                    filename: row.get(0)?,
                    arch,
                    version: row.get(2)?,
                    file_size: file_size.map(|s| s as u64),
                    date_stamp: row.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
    }

    // --- Triage ---

    pub async fn upsert_triage(&self, cve_id: &str, rankings: &[Ranking]) -> Result<()> {
        let cve_id = cve_id.to_owned();
        let rankings = rankings.to_vec();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            let tx = c.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO cve_triage (cve_id, filename, confidence, reasoning, cached_at) \
                     VALUES (?1,?2,?3,?4,?5) \
                     ON CONFLICT(cve_id, filename) DO UPDATE SET \
                       confidence=excluded.confidence, reasoning=excluded.reasoning, \
                       cached_at=excluded.cached_at",
                )?;
                for r in &rankings {
                    stmt.execute(rusqlite::params![cve_id, r.filename, r.confidence, r.reasoning, now])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn get_triage(&self, cve_id: &str) -> Result<Vec<Ranking>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT filename, confidence, reasoning FROM cve_triage \
                 WHERE cve_id = ?1 ORDER BY confidence DESC",
            )?;
            let rows = stmt.query_map([&cve_id], |row| {
                Ok(Ranking { filename: row.get(0)?, confidence: row.get(1)?, reasoning: row.get(2)? })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
    }

    // --- Synthesis ---

    pub async fn upsert_synthesis(
        &self,
        cve_id: &str,
        job_id: i64,
        syn: &SynthesisResult,
    ) -> Result<()> {
        let cve_id = cve_id.to_owned();
        let primary_json = serde_json::to_string(&syn.primary_binaries)?;
        let ranked_json = serde_json::to_string(&syn.ranked_functions)?;
        let summary = syn.overall_summary.clone();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            c.execute(
                "INSERT INTO cve_synthesis \
                 (cve_id, diff_job_id, primary_binaries_json, overall_summary, ranked_functions_json, created_at) \
                 VALUES (?1,?2,?3,?4,?5,?6) \
                 ON CONFLICT(cve_id) DO UPDATE SET \
                   diff_job_id=excluded.diff_job_id, primary_binaries_json=excluded.primary_binaries_json, \
                   overall_summary=excluded.overall_summary, ranked_functions_json=excluded.ranked_functions_json, \
                   created_at=excluded.created_at",
                rusqlite::params![cve_id, job_id, primary_json, summary, ranked_json, now],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn upsert_synthesis_binaries(
        &self,
        cve_id: &str,
        per_binary: &[BinaryAssessment],
    ) -> Result<()> {
        let cve_id = cve_id.to_owned();
        let per_binary = per_binary.to_vec();
        self.with_conn(move |c| {
            let tx = c.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO cve_synthesis_binaries \
                     (cve_id, filename, security_relevant, confidence, reasoning) \
                     VALUES (?1,?2,?3,?4,?5) \
                     ON CONFLICT(cve_id, filename) DO UPDATE SET \
                       security_relevant=excluded.security_relevant, \
                       confidence=excluded.confidence, reasoning=excluded.reasoning",
                )?;
                for b in &per_binary {
                    stmt.execute(rusqlite::params![
                        cve_id, b.filename,
                        if b.security_relevant { 1i64 } else { 0 },
                        b.confidence, b.reasoning
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn get_synthesis(&self, cve_id: &str) -> Result<Option<SynthesisRow>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT cve_id, diff_job_id, primary_binaries_json, overall_summary, \
                 ranked_functions_json, created_at \
                 FROM cve_synthesis WHERE cve_id = ?1",
            )?;
            let mut rows = stmt.query_map([&cve_id], |row| {
                Ok(SynthesisRow {
                    cve_id: row.get(0)?,
                    diff_job_id: row.get(1)?,
                    primary_binaries_json: row.get(2)?,
                    overall_summary: row.get(3)?,
                    ranked_functions_json: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?;
            match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            }
        })
        .await
    }

    // --- Function findings ---

    pub async fn upsert_findings(
        &self,
        cve_id: &str,
        filename: &str,
        da: &DeepAnalysisResult,
    ) -> Result<()> {
        let cve_id = cve_id.to_owned();
        let filename = filename.to_owned();
        let findings = da.findings.clone();
        let patch_summary = da.patch_summary.clone();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            let tx = c.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO function_findings \
                     (cve_id, filename, function_name, relevance, summary, old_snippet, \
                      new_snippet, patch_summary, created_at) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
                     ON CONFLICT(cve_id, filename, function_name) DO UPDATE SET \
                       relevance=excluded.relevance, summary=excluded.summary, \
                       old_snippet=excluded.old_snippet, new_snippet=excluded.new_snippet, \
                       patch_summary=excluded.patch_summary, created_at=excluded.created_at",
                )?;
                for f in &findings {
                    stmt.execute(rusqlite::params![
                        cve_id, filename, f.name, f.relevance, f.summary,
                        f.old_snippet, f.new_snippet, patch_summary, now
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn get_findings(&self, cve_id: &str) -> Result<Vec<FindingRow>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT cve_id, filename, function_name, relevance, summary, \
                 old_snippet, new_snippet, patch_summary \
                 FROM function_findings \
                 WHERE cve_id = ?1 \
                 ORDER BY filename, relevance DESC",
            )?;
            let rows = stmt.query_map([&cve_id], |row| {
                Ok(FindingRow {
                    cve_id: row.get(0)?,
                    filename: row.get(1)?,
                    function_name: row.get(2)?,
                    relevance: row.get(3)?,
                    summary: row.get(4)?,
                    old_snippet: row.get(5)?,
                    new_snippet: row.get(6)?,
                    patch_summary: row.get(7)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
    }

    // --- diff_jobs lifecycle ---

    pub async fn create_diff_job(&self, cve_id: &str) -> Result<i64> {
        let cve_id = cve_id.to_owned();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            c.execute(
                "INSERT INTO diff_jobs (cve_id, status, started_at) VALUES (?1, 'queued', ?2) \
                 ON CONFLICT(cve_id) DO UPDATE SET \
                   status='queued', started_at=?2, finished_at=NULL, error=NULL, \
                   report_path=NULL, ghidriff_output_dir=NULL",
                rusqlite::params![cve_id, now],
            )?;
            // last_insert_rowid() returns 0 on a fresh connection when the upsert takes the
            // ON CONFLICT DO UPDATE path (pre-SQLite 3.38 behavior). Query by cve_id instead.
            c.query_row(
                "SELECT id FROM diff_jobs WHERE cve_id = ?1",
                rusqlite::params![cve_id],
                |row| row.get(0),
            )
        })
        .await
    }

    pub async fn update_diff_job_status(
        &self,
        id: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let status = status.to_owned();
        let error = error.map(|e| e.to_owned());
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            let finished_at: Option<String> = if matches!(status.as_str(), "done" | "failed") {
                Some(now.clone())
            } else {
                None
            };
            c.execute(
                "UPDATE diff_jobs SET status=?1, error=?2, finished_at=?3 WHERE id=?4",
                rusqlite::params![status, error, finished_at, id],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn list_diff_jobs(&self, cve_id: &str) -> Result<Vec<DiffJobRow>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, cve_id, status, started_at, finished_at, error, \
                 report_path, ghidriff_output_dir \
                 FROM diff_jobs WHERE cve_id = ?1 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map([&cve_id], |row| {
                Ok(DiffJobRow {
                    id: row.get(0)?,
                    cve_id: row.get(1)?,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    error: row.get(5)?,
                    report_path: row.get(6)?,
                    ghidriff_output_dir: row.get(7)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
    }

    pub async fn get_latest_diff_job(&self, cve_id: &str) -> Result<Option<DiffJobRow>> {
        let cve_id = cve_id.to_owned();
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, cve_id, status, started_at, finished_at, error, \
                 report_path, ghidriff_output_dir \
                 FROM diff_jobs WHERE cve_id = ?1 ORDER BY id DESC LIMIT 1",
            )?;
            let mut rows = stmt.query_map([&cve_id], |row| {
                Ok(DiffJobRow {
                    id: row.get(0)?,
                    cve_id: row.get(1)?,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    error: row.get(5)?,
                    report_path: row.get(6)?,
                    ghidriff_output_dir: row.get(7)?,
                })
            })?;
            match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn get_diff_job_by_id(&self, id: i64) -> Result<Option<DiffJobRow>> {
        self.with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, cve_id, status, started_at, finished_at, error, \
                 report_path, ghidriff_output_dir \
                 FROM diff_jobs WHERE id = ?1",
            )?;
            let mut rows = stmt.query_map([id], |row| {
                Ok(DiffJobRow {
                    id: row.get(0)?,
                    cve_id: row.get(1)?,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    error: row.get(5)?,
                    report_path: row.get(6)?,
                    ghidriff_output_dir: row.get(7)?,
                })
            })?;
            match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn fail_stale_diff_jobs(&self, reason: &str) -> Result<usize> {
        let reason = reason.to_owned();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(move |c| {
            let n = c.execute(
                "UPDATE diff_jobs SET status='failed', error=?1, finished_at=?2 \
                 WHERE status NOT IN ('done', 'failed')",
                rusqlite::params![reason, now],
            )?;
            Ok(n)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn opens_in_memory_and_creates_tables() {
        let db = Db::open_in_memory_async().await.expect("open");
        let count: i64 = db
            .with_conn(|c| {
                c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN \
                     ('updates','cves','cve_kbs','kb_enumerations','kb_files','cve_triage',\
                     'diff_jobs','triage_cache','cve_synthesis','cve_synthesis_binaries',\
                     'function_findings')",
                    [],
                    |row| row.get(0),
                )
            })
            .await
            .unwrap();
        assert_eq!(count, 11);
    }

    #[tokio::test]
    async fn round_trips_cve() {
        let db = Db::open_in_memory_async().await.expect("open");
        let cve = crate::sug::types::Vulnerability {
            cve_number: "CVE-2026-99999".into(),
            cve_title: Some("Test CVE".into()),
            base_score: Some(7.5),
            temporal_score: None,
            vector_string: Some("AV:N/AC:L".into()),
            severity: None,
            impact: None,
            issuing_cna: None,
            tag: None,
            exploited: Some("Yes".into()),
            publicly_disclosed: None,
            customer_action_required: None,
            is_mariner: None,
            release_number: None,
            release_date: Some("2026-04-08".into()),
            revision_number: Some("1.0".into()),
            description: Some("A test vulnerability".into()),
            cwe_list: Some(vec!["CWE-122".into()]),
        };
        db.upsert_cve(&cve, "{}".into()).await.unwrap();
        db.upsert_cve_kb("CVE-2026-99999", "KB5083768").await.unwrap();

        let detail = db.get_cve("CVE-2026-99999").await.unwrap();
        assert!(detail.is_some());
        let d = detail.unwrap();
        assert_eq!(d.cve_id, "CVE-2026-99999");
        assert_eq!(d.cvss_score, Some(7.5));
        assert!(d.exploited);
        assert_eq!(d.kb_id.as_deref(), Some("KB5083768"));
    }

    #[tokio::test]
    async fn diff_job_lifecycle() {
        let db = Db::open_in_memory_async().await.expect("open");
        let cve = crate::sug::types::Vulnerability {
            cve_number: "CVE-2026-11111".into(),
            cve_title: None, base_score: None, temporal_score: None, vector_string: None,
            severity: None, impact: None, issuing_cna: None, tag: None,
            exploited: None, publicly_disclosed: None, customer_action_required: None,
            is_mariner: None, release_number: None, release_date: None,
            revision_number: Some("1.0".into()), description: None, cwe_list: None,
        };
        db.upsert_cve(&cve, "{}".into()).await.unwrap();
        let job_id = db.create_diff_job("CVE-2026-11111").await.unwrap();
        assert!(job_id > 0);
        db.update_diff_job_status(job_id, "fetching", None).await.unwrap();
        db.update_diff_job_status(job_id, "done", None).await.unwrap();
        let job = db.get_latest_diff_job("CVE-2026-11111").await.unwrap().unwrap();
        assert_eq!(job.status, "done");
        assert!(job.is_terminal());
    }

    #[tokio::test]
    async fn fail_stale_jobs() {
        let db = Db::open_in_memory_async().await.expect("open");
        let cve = crate::sug::types::Vulnerability {
            cve_number: "CVE-2026-22222".into(),
            cve_title: None, base_score: None, temporal_score: None, vector_string: None,
            severity: None, impact: None, issuing_cna: None, tag: None,
            exploited: None, publicly_disclosed: None, customer_action_required: None,
            is_mariner: None, release_number: None, release_date: None,
            revision_number: Some("1.0".into()), description: None, cwe_list: None,
        };
        db.upsert_cve(&cve, "{}".into()).await.unwrap();
        let job_id = db.create_diff_job("CVE-2026-22222").await.unwrap();
        db.update_diff_job_status(job_id, "synthesizing", None).await.unwrap();
        let n = db.fail_stale_diff_jobs("process_restart").await.unwrap();
        assert_eq!(n, 1);
        let job = db.get_latest_diff_job("CVE-2026-22222").await.unwrap().unwrap();
        assert_eq!(job.status, "failed");
        assert_eq!(job.error.as_deref(), Some("process_restart"));
    }

    #[tokio::test]
    async fn create_diff_job_upsert_returns_existing_id() {
        let db = Db::open_in_memory_async().await.expect("open");
        let cve = crate::sug::types::Vulnerability {
            cve_number: "CVE-2026-33333".into(),
            cve_title: None, base_score: None, temporal_score: None, vector_string: None,
            severity: None, impact: None, issuing_cna: None, tag: None,
            exploited: None, publicly_disclosed: None, customer_action_required: None,
            is_mariner: None, release_number: None, release_date: None,
            revision_number: Some("1.0".into()), description: None, cwe_list: None,
        };
        db.upsert_cve(&cve, "{}".into()).await.unwrap();
        let first_id = db.create_diff_job("CVE-2026-33333").await.unwrap();
        assert!(first_id > 0);
        db.update_diff_job_status(first_id, "done", None).await.unwrap();
        // Re-trigger: ON CONFLICT DO UPDATE path must return the same (non-zero) id.
        let second_id = db.create_diff_job("CVE-2026-33333").await.unwrap();
        assert_eq!(second_id, first_id);
    }
}
