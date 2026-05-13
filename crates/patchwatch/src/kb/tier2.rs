use crate::cache::Cache;
use crate::http::get_with_retry;
use crate::kb::types::{Arch, KbEnumeration, KbFile, KbSource};
use anyhow::{Result, anyhow};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tracing::info;

pub struct CatalogClient {
    base_url: String,
    http: Client,
}

#[derive(Debug, Clone)]
pub struct CatalogResult {
    pub update_id: String,
    pub title: String,
    pub arch: String,
}

fn extract_arch_from_title(title: &str) -> String {
    let t = title.to_ascii_lowercase();
    if t.contains("arm64") || t.contains("arm64-based") {
        "arm64".to_string()
    } else if t.contains("x64") || t.contains("x64-based") || t.contains("amd64") {
        "x64".to_string()
    } else if t.contains("x86") || t.contains("ia-32") {
        "x86".to_string()
    } else {
        String::new()
    }
}

impl CatalogClient {
    pub fn new(base_url: impl Into<String>, http: Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    /// Search the catalog for a KB number; returns rows matched by `goToDetails(<id>)`.
    pub async fn search(&self, kb_id: &str) -> Result<Vec<CatalogResult>> {
        let bare = kb_id.trim_start_matches(|c: char| !c.is_ascii_digit());
        let url = format!(
            "{}/Search.aspx?q=KB{}",
            self.base_url.trim_end_matches('/'),
            bare
        );
        info!(%url, "Catalog search");
        let resp = get_with_retry(&self.http, &url, 3).await?;
        let html = resp.text().await?;
        Self::parse_search_results(&html)
    }

    fn parse_search_results(html: &str) -> Result<Vec<CatalogResult>> {
        let doc = Html::parse_document(html);
        let row_sel = Selector::parse("table#ctl00_catalogBody_updateMatches tr").unwrap();
        let cell_sel = Selector::parse("td").unwrap();
        let input_sel = Selector::parse("input").unwrap();
        let onclick_re = Regex::new(r#"goToDetails\(['"]([0-9a-fA-F-]+)['"]\)"#).unwrap();

        let mut out = Vec::new();
        for row in doc.select(&row_sel) {
            let cells: Vec<_> = row.select(&cell_sel).collect();
            if cells.len() < 6 {
                continue;
            }
            let title = cells[0].text().collect::<String>().trim().to_string();
            // Column 3 is sometimes an explicit arch value but often just a date.
            // Prefer the column value when it looks like an arch; otherwise extract
            // from the title ("for x64-based Systems", "ARM64", etc.).
            let col3 = cells[3].text().collect::<String>().trim().to_string();
            let arch = if col3.to_ascii_lowercase().contains("x64")
                || col3.to_ascii_lowercase().contains("arm")
            {
                col3
            } else {
                extract_arch_from_title(&title)
            };
            let onclick = cells
                .last()
                .and_then(|c| c.select(&input_sel).next())
                .and_then(|i| i.value().attr("onclick"))
                .unwrap_or_default()
                .to_string();
            if let Some(cap) = onclick_re.captures(&onclick) {
                out.push(CatalogResult {
                    update_id: cap[1].to_string(),
                    title,
                    arch,
                });
            }
        }
        Ok(out)
    }

    /// Resolve the catalog `update_id` to the underlying .msu URL(s) by scraping the
    /// `DownloadDialog.aspx` JavaScript.
    pub async fn resolve_msu_urls(&self, update_id: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/DownloadDialog.aspx",
            self.base_url.trim_end_matches('/')
        );
        let body = format!(
            r#"[{{"size":0,"languages":"","uidInfo":"{0}","updateID":"{0}"}}]"#,
            update_id
        );
        info!(%url, %update_id, "Catalog DownloadDialog");
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("updateIDs={}", urlencoding::encode(&body)))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("DownloadDialog HTTP {}", resp.status());
        }
        let html = resp.text().await?;
        Ok(Self::parse_download_dialog(&html))
    }

    fn parse_download_dialog(html: &str) -> Vec<String> {
        // The dialog returns a script setting `downloadInformation[N].files = [{ url: "..."}]`.
        let re = Regex::new(r#"url['"]?\s*:\s*['"](https?://[^'"]+\.msu)['"]"#).unwrap();
        re.captures_iter(html).map(|c| c[1].to_string()).collect()
    }

    pub async fn download_msu(&self, msu_url: &str, dest: &Path) -> Result<u64> {
        info!(%msu_url, dest = %dest.display(), "downloading MSU");
        let resp = get_with_retry(&self.http, msu_url, 3).await?;
        let bytes = resp.bytes().await?;
        Cache::write_atomic(dest, &bytes)?;
        Ok(bytes.len() as u64)
    }

    /// Full Tier 2 path: search catalog → resolve → download MSU → expand → walk manifests.
    pub async fn enumerate(&self, kb_id: &str, msu_dir: &Path) -> Result<KbEnumeration> {
        let results = self.search(kb_id).await?;
        let pick = results
            .into_iter()
            .find(|r| r.arch.to_ascii_lowercase().contains("x64"))
            .ok_or_else(|| anyhow!("no x64 entry in catalog for {}", kb_id))?;
        let urls = self.resolve_msu_urls(&pick.update_id).await?;
        let url = urls.into_iter().next().ok_or_else(|| anyhow!("no msu url"))?;

        Cache::ensure_dir(msu_dir)?;
        let msu_path = msu_dir.join(format!("{}.msu", kb_id));
        if !msu_path.exists() {
            self.download_msu(&url, &msu_path).await?;
        }

        let extract_dir = msu_dir.join("extracted");
        if !extract_dir.exists() {
            extract_msu(&msu_path, &extract_dir).await?;
        }

        // Aggregate dedup by (filename, arch, version).
        let manifests = list_manifests(&extract_dir)?;
        let mut by_key: HashMap<(String, Arch, String), KbFile> = HashMap::new();
        for m in manifests {
            let bytes = std::fs::read(&m)?;
            let entries = parse_manifest(&bytes).unwrap_or_default();
            for f in entries {
                by_key
                    .entry((f.filename.clone(), f.arch, f.version.clone()))
                    .or_insert(f);
            }
        }
        let files: Vec<KbFile> = by_key.into_values().collect();

        Ok(KbEnumeration {
            kb_id: kb_id.to_string(),
            source: KbSource::Msu,
            csv_url: None,
            msu_path: Some(msu_path),
            fallback_reason: None,
            files,
        })
    }
}

pub async fn extract_msu(msu_path: &Path, out_dir: &Path) -> Result<()> {
    Cache::ensure_dir(out_dir)?;
    // First pass: extract outer container into out_dir.
    run_expand(msu_path, out_dir).await?;
    // The outer extraction produces *.cab files which themselves contain manifests.
    // Walk the dir once and re-expand any cab.
    for entry in walkdir(out_dir)? {
        if entry
            .extension()
            .and_then(OsStr::to_str)
            .map(|s| s.to_ascii_lowercase())
            == Some("cab".into())
        {
            let inner_out = out_dir.join(entry.file_stem().unwrap_or_default());
            Cache::ensure_dir(&inner_out)?;
            run_expand(&entry, &inner_out).await?;
        }
    }
    Ok(())
}

async fn run_expand(src: &Path, dest_dir: &Path) -> Result<()> {
    use tokio::process::Command;
    let out = Command::new("expand.exe")
        .arg("-F:*")
        .arg(src)
        .arg(dest_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "expand.exe failed (status {:?}) on {}: {}",
            out.status.code(),
            src.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(root)? {
        let e = e?;
        let p = e.path();
        if p.is_dir() {
            out.extend(walkdir(&p)?);
        } else {
            out.push(p);
        }
    }
    Ok(out)
}

pub fn list_manifests(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(walkdir(root)?
        .into_iter()
        .filter(|p| p.extension().and_then(OsStr::to_str) == Some("manifest"))
        .collect())
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Vec<KbFile>> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);

    let mut version = String::new();
    let mut arch = Arch::Unknown;
    let mut files: Vec<String> = Vec::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(anyhow!("xml: {}", e)),
            Ok(Event::Eof) => break,
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"assemblyIdentity" => {
                    for attr in e.attributes().flatten() {
                        let key = attr.key.as_ref().to_vec();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match key.as_slice() {
                            b"version" => version = val,
                            b"processorArchitecture" => arch = Arch::from_csv_platform(&val),
                            _ => {}
                        }
                    }
                }
                b"file" => {
                    let mut filename = String::new();
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" || attr.key.as_ref() == b"sourceName" {
                            filename = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                    if !filename.is_empty() {
                        files.push(filename);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }

    Ok(files
        .into_iter()
        .map(|filename| KbFile {
            filename,
            version: version.clone(),
            arch,
            file_size: None,
            date_stamp: None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn search_extracts_update_id() {
        let html = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/catalog_search_results.html"),
        )
        .unwrap();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/Search.aspx"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        let http = Client::builder().user_agent("test").build().unwrap();
        let c = CatalogClient::new(server.uri(), http);
        let r = c.search("5034123").await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].update_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(r[0].arch, "x64");
    }

    #[tokio::test]
    async fn resolve_msu_urls_extracts_msu() {
        let html = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/catalog_download_dialog.html"),
        )
        .unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/DownloadDialog.aspx"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        let http = Client::builder().user_agent("test").build().unwrap();
        let c = CatalogClient::new(server.uri(), http);
        let urls = c
            .resolve_msu_urls("11111111-1111-1111-1111-111111111111")
            .await
            .unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].ends_with(".msu"));
    }

    #[tokio::test]
    async fn download_msu_writes_file() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/foo.msu"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PRETEND_MSU".to_vec()))
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("kb.msu");
        let http = Client::builder().user_agent("test").build().unwrap();
        let c = CatalogClient::new(server.uri(), http);
        let n = c
            .download_msu(&format!("{}/foo.msu", server.uri()), &dest)
            .await
            .unwrap();
        assert_eq!(n, 11);
        assert_eq!(std::fs::read(&dest).unwrap(), b"PRETEND_MSU");
    }

    #[test]
    fn list_manifests_finds_xml_files() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("a/b");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("Microsoft-Windows-Print.manifest"), "<a/>").unwrap();
        std::fs::write(inner.join("update.mum"), "<m/>").unwrap();
        let v = list_manifests(tmp.path()).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].ends_with("Microsoft-Windows-Print.manifest"));
    }

    #[test]
    fn parses_manifest_fixture() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/Microsoft-Windows-Print.manifest"),
        )
        .unwrap();
        let files = parse_manifest(&bytes).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "localspl.dll");
        assert_eq!(files[0].version, "10.0.22621.4000");
        assert_eq!(files[0].arch, Arch::X64);
    }
}
