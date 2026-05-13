use crate::http::get_with_retry;
use crate::kb::csv::parse_kb_csv;
use crate::kb::types::{KbEnumeration, KbSource};
use anyhow::{Result, anyhow};
use reqwest::Client;
use scraper::{Html, Selector};
use tracing::{debug, info};

pub struct Tier1Client {
    /// Base URL for support.microsoft.com pages, e.g. `https://support.microsoft.com`.
    /// We append `/help/<kb>` to reach the topic page (Microsoft redirects from there
    /// to the canonical `/<lang>/topic/<title-with-guid>`).
    support_base: String,
    http: Client,
}

#[derive(Debug, Clone)]
pub struct KbArticle {
    pub url: String,
    pub html: String,
}

impl Tier1Client {
    /// `support_base` is typically `https://support.microsoft.com`.
    pub fn new(support_base: impl Into<String>, http: Client) -> Self {
        Self {
            support_base: support_base.into(),
            http,
        }
    }

    /// Builds the `/help/<kb>` URL. reqwest follows redirects, so this lands on the
    /// rendered topic page regardless of locale rewrites.
    fn article_url(&self, kb_number: &str) -> String {
        let bare = kb_number.trim_start_matches(|c: char| !c.is_ascii_digit());
        format!("{}/help/{}", self.support_base.trim_end_matches('/'), bare)
    }

    pub async fn fetch_article(&self, kb_number: &str) -> Result<KbArticle> {
        let url = self.article_url(kb_number);
        info!(%url, "fetching KB topic page");
        let resp = get_with_retry(&self.http, &url, 3).await?;
        let final_url = resp.url().to_string();
        let html = resp.text().await?;
        debug!(final_url = %final_url, bytes = html.len(), "topic page fetched");
        Ok(KbArticle {
            url: final_url,
            html,
        })
    }

    pub async fn enumerate(&self, kb_id: &str) -> Result<KbEnumeration> {
        let article = self.fetch_article(kb_id).await?;
        let csv_url = extract_file_information_csv_links(&article.html)
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no_csv_link"))?;
        info!(%csv_url, "downloading KB file-information CSV");
        let bytes = get_with_retry(&self.http, &csv_url, 3)
            .await?
            .bytes()
            .await?;
        let files = parse_kb_csv(&bytes)?;
        Ok(KbEnumeration {
            kb_id: kb_id.to_string(),
            source: KbSource::Csv,
            csv_url: Some(csv_url),
            msu_path: None,
            fallback_reason: None,
            files,
        })
    }
}

/// Extracts URLs of "file information" CSVs from a KB topic page HTML.
///
/// The signal is the link text — `download the file information for cumulative update <KB>`
/// is the main CSV; the SSU CSV uses similar text but with "servicing stack" or "SSU"; file
/// hashes use "hash". The actual href is typically a `go.microsoft.com/fwlink/?linkid=NNN`
/// redirector (which 302s to `download.microsoft.com/.../<kb>.csv`), so we must NOT filter
/// by `.csv` extension or hostname.
pub fn extract_file_information_csv_links(article_body_html: &str) -> Vec<String> {
    let doc = Html::parse_fragment(article_body_html);
    let sel = Selector::parse("a[href]").unwrap();
    let mut out = Vec::new();
    for el in doc.select(&sel) {
        let Some(href) = el.value().attr("href") else {
            continue;
        };
        let text = el.text().collect::<String>().to_ascii_lowercase();
        if !text.contains("file information") {
            continue;
        }
        if text.contains("hash") {
            continue;
        }
        if text.contains("ssu") || text.contains("servicing stack") {
            continue;
        }
        out.push(href.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn topic_fixture() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/support_kb_topic.html"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn fetch_article_lands_on_topic_html() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/help/5083769"))
            .respond_with(ResponseTemplate::new(200).set_body_string(topic_fixture()))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let c = Tier1Client::new(server.uri(), http);
        let art = c.fetch_article("KB5083769").await.unwrap();
        assert!(art.html.contains("File information"));
        assert!(art.html.contains("fwlink"));
    }

    #[test]
    fn extracts_main_cumulative_csv_and_skips_ssu_and_hashes() {
        let html = topic_fixture();
        let links = extract_file_information_csv_links(&html);
        assert_eq!(links.len(), 1, "got: {:?}", links);
        assert!(links[0].contains("linkid=2359592"));
    }

    #[test]
    fn extractor_accepts_fwlink_urls_without_csv_extension() {
        // fwlink URLs do not end in .csv; the extractor must not filter on extension.
        let html = r#"
            <a href="https://go.microsoft.com/fwlink/?linkid=2359592">download the file information for cumulative update 5083769</a>
        "#;
        let links = extract_file_information_csv_links(html);
        assert_eq!(links.len(), 1);
    }

    #[tokio::test]
    async fn enumerate_returns_kb_files_tagged_with_per_section_arch() {
        let server = MockServer::start().await;

        let csv_url = format!("{}/csv/file_information.csv", server.uri());
        let html = topic_fixture().replace(
            "https://go.microsoft.com/fwlink/?linkid=2359592",
            &csv_url,
        );

        Mock::given(method("GET"))
            .and(path("/help/5083769"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;

        let csv_bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/kb_file_information.csv"),
        )
        .unwrap();
        Mock::given(method("GET"))
            .and(path("/csv/file_information.csv"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(csv_bytes))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let c = Tier1Client::new(server.uri(), http);
        let e = c.enumerate("KB5083769").await.unwrap();
        assert_eq!(e.source, KbSource::Csv);
        // 2 arm64 + 3 x64 from the fixture.
        assert_eq!(e.files.len(), 5);

        use crate::kb::types::Arch;
        let x64_count = e.files.iter().filter(|f| f.arch == Arch::X64).count();
        let arm_count = e.files.iter().filter(|f| f.arch == Arch::Arm64).count();
        assert_eq!(x64_count, 3);
        assert_eq!(arm_count, 2);
    }
}
