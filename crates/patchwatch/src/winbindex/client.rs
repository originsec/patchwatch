use super::types::WinbindexEntry;
use super::url::msdl_url;
use crate::cache::Cache;
use crate::http::get_with_retry;
use crate::kb::types::Arch;
use anyhow::Result;
use flate2::read::GzDecoder;
use reqwest::Client;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use tracing::info;

pub struct WinbindexClient {
    base_url: String,
    http: Client,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PairConfidence {
    /// Patched entry matched by KB number in Winbindex — exact.
    ExactKb,
    /// Patched entry matched by version string from KB CSV — KB not yet indexed.
    VersionFallback,
    /// Took the two most recent revisions — KB and version both unresolved.
    Approximate,
}

#[derive(Debug, Clone)]
pub struct PatchPair {
    pub patched: WinbindexEntry,
    pub previous: WinbindexEntry,
    pub confidence: PairConfidence,
}

#[derive(Debug, Clone)]
pub struct DownloadedBinary {
    pub path: PathBuf,
    pub sha256_hex: String,
    pub url: String,
    pub size: u64,
    /// File version string from Winbindex (e.g. "10.0.26100.1882"), if available.
    pub version: Option<String>,
}

impl WinbindexClient {
    pub fn new(base_url: impl Into<String>, http: Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    pub async fn fetch_file_data(
        &self,
        filename: &str,
    ) -> Result<HashMap<String, WinbindexEntry>> {
        let url = format!(
            "{}/data/by_filename_compressed/{}.json.gz",
            self.base_url.trim_end_matches('/'),
            filename.to_ascii_lowercase()
        );
        info!(%url, "fetching winbindex");
        let resp = get_with_retry(&self.http, &url, 3).await?;
        let bytes = resp.bytes().await?;
        let mut s = String::new();
        GzDecoder::new(&bytes[..]).read_to_string(&mut s)?;
        let map: HashMap<String, WinbindexEntry> = serde_json::from_str(&s)?;
        Ok(map)
    }

    pub async fn download_entry(
        &self,
        filename: &str,
        entry: &WinbindexEntry,
        cache: &Cache,
    ) -> Result<DownloadedBinary> {
        let timestamp = entry
            .timestamp()
            .ok_or_else(|| anyhow::anyhow!("no timestamp"))?;
        let virtual_size = entry
            .virtual_size()
            .ok_or_else(|| anyhow::anyhow!("no virtual_size"))?;
        let url = msdl_url(filename, timestamp, virtual_size);

        // If Winbindex provides a SHA256, check the content-addressable cache first.
        if let Some(known_sha) = entry.sha256() {
            let path = cache.binary_path(known_sha, filename);
            if path.exists() {
                let size = std::fs::metadata(&path)?.len();
                tracing::info!(%filename, "binary cache hit, skipping download");
                return Ok(DownloadedBinary {
                    path,
                    sha256_hex: known_sha.to_string(),
                    url,
                    size,
                    version: entry.version().map(|s| s.to_string()),
                });
            }
        }

        let resp = get_with_retry(&self.http, &url, 3).await?;
        let bytes = resp.bytes().await?;
        let sha = Cache::sha256_hex(&bytes);
        let path = cache.binary_path(&sha, filename);
        Cache::write_atomic(&path, &bytes)?;
        Ok(DownloadedBinary {
            path,
            sha256_hex: sha,
            url,
            size: bytes.len() as u64,
            version: entry.version().map(|s| s.to_string()),
        })
    }
}

/// Returns a patched/previous pair for the given filename, arch, and KB.
///
/// Three confidence levels, tried in order:
/// 1. KB number match in Winbindex index     → PairConfidence::ExactKb
/// 2. Version string match from KB CSV       → PairConfidence::VersionFallback
/// 3. Two most-recent revisions (approximate) → PairConfidence::Approximate
pub fn select_pair(
    entries: &HashMap<String, WinbindexEntry>,
    kb_id: &str,
    arch: Arch,
    fallback_version: Option<&str>,
) -> Option<PatchPair> {
    let arch_entries: Vec<&WinbindexEntry> = entries.values().filter(|v| v.arch() == arch).collect();

    // Level 1: KB number match
    if let Some(patched) = arch_entries.iter().find(|v| v.appears_in_kb(kb_id)).copied() {
        let patched_rev = parse_revision(patched.version()?)?;
        let prev = arch_entries.iter()
            .filter(|&&v| !std::ptr::eq(v, patched))
            .filter_map(|v| { let r = parse_revision(v.version()?)?; (r < patched_rev).then_some((r, *v)) })
            .max_by_key(|(r, _)| *r)
            .map(|(_, v)| v.clone())?;
        return Some(PatchPair { patched: patched.clone(), previous: prev, confidence: PairConfidence::ExactKb });
    }

    // Level 2: exact version match from KB CSV
    if let Some(ver) = fallback_version {
        if let Some(patched) = arch_entries.iter().find(|v| v.version() == Some(ver)).copied() {
            let patched_rev = parse_revision(patched.version()?)?;
            let prev = arch_entries.iter()
                .filter(|&&v| !std::ptr::eq(v, patched))
                .filter_map(|v| { let r = parse_revision(v.version()?)?; (r < patched_rev).then_some((r, *v)) })
                .max_by_key(|(r, _)| *r)
                .map(|(_, v)| v.clone())?;
            return Some(PatchPair { patched: patched.clone(), previous: prev, confidence: PairConfidence::VersionFallback });
        }
    }

    // Level 3: approximate — two most recent revisions
    let mut by_rev: Vec<(u64, &WinbindexEntry)> = arch_entries.iter()
        .filter_map(|v| Some((parse_revision(v.version()?)?, *v)))
        .collect();
    by_rev.sort_by_key(|(r, _)| std::cmp::Reverse(*r));
    if by_rev.len() >= 2 {
        let patched = by_rev[0].1.clone();
        let previous = by_rev[1].1.clone();
        return Some(PatchPair { patched, previous, confidence: PairConfidence::Approximate });
    }

    None
}

fn parse_revision(version: &str) -> Option<u64> {
    // Winbindex version strings look like "10.0.26100.4946 (WinBuild.160101.0800)".
    // Encode as (build_number << 32 | revision) so entries from newer OS branches always sort
    // above older branches even when the older branch has a higher bare revision number
    // (e.g. 10.0.10240.21161 must rank below 10.0.28000.2113).
    let mut parts = version.split('.');
    let _major = parts.next()?;
    let _minor = parts.next()?;
    let build: u64 = parts.next()?.parse().ok()?;
    let revision: u64 = parts
        .next()?
        .split_ascii_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((build << 32) | revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn gzip(input: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(input).unwrap();
        e.finish().unwrap()
    }

    #[tokio::test]
    async fn fetches_and_decodes_gz_json() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/winbindex_localspl_minimal.json"),
        )
        .unwrap();
        let gz = gzip(&raw);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data/by_filename_compressed/localspl.dll.json.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let c = WinbindexClient::new(server.uri(), http);
        let map = c.fetch_file_data("localspl.dll").await.unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn selects_patched_and_previous_by_revision() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/winbindex_localspl_minimal.json"),
        )
        .unwrap();
        let map: HashMap<String, WinbindexEntry> = serde_json::from_slice(&bytes).unwrap();
        let pair = select_pair(&map, "KB5034123", Arch::X64, None).expect("pair");
        assert_eq!(pair.patched.version(), Some("10.0.22631.4000"));
        assert_eq!(pair.previous.version(), Some("10.0.22631.3880"));
        assert_eq!(pair.confidence, PairConfidence::ExactKb);
    }

    #[test]
    fn newer_os_branch_beats_higher_revision_on_old_branch() {
        // 10.0.10240.21161 has a higher bare revision (21161) than 10.0.28000.2113 (2113),
        // but build 28000 is a newer OS. The approximate path must prefer the newer branch.
        use super::super::types::{FileInfo, WinbindexEntry};

        fn make_entry(version: &str, timestamp: u64) -> WinbindexEntry {
            WinbindexEntry {
                file_info: Some(FileInfo {
                    size: Some(1000),
                    md5: None,
                    sha1: None,
                    sha256: None,
                    machine_type: Some(34404), // x64
                    timestamp: Some(timestamp),
                    virtual_size: Some(0x1000),
                    version: Some(version.to_string()),
                    description: None,
                }),
                windows_versions: None,
            }
        }

        let mut map = HashMap::new();
        map.insert("old".to_string(), make_entry("10.0.10240.21161", 1000));
        map.insert("new".to_string(), make_entry("10.0.28000.2113", 2000));
        map.insert("prev".to_string(), make_entry("10.0.28000.2085", 1500));

        let pair = select_pair(&map, "KB9999999", Arch::X64, None).expect("pair");
        assert_eq!(pair.patched.version(), Some("10.0.28000.2113"),
            "newer OS branch should win even with lower revision");
        assert_eq!(pair.previous.version(), Some("10.0.28000.2085"));
        assert_eq!(pair.confidence, PairConfidence::Approximate);
    }
}
