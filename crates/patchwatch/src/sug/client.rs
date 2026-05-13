use super::types::{AffectedProduct, OdataPage, ReleaseNote, Vulnerability};
use crate::http::get_with_retry;
use anyhow::Result;
use reqwest::Client;
use tracing::info;

pub struct SugClient {
    base_url: String,
    language: String,
    http: Client,
}

impl SugClient {
    pub fn new(base_url: impl Into<String>, language: impl Into<String>, http: Client) -> Self {
        Self {
            base_url: base_url.into(),
            language: language.into(),
            http,
        }
    }

    fn root(&self) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), self.language)
    }

    pub async fn list_releases(&self) -> Result<Vec<ReleaseNote>> {
        let url = format!("{}/releaseNote", self.root());
        info!(%url, "SUG list_releases");
        let resp = get_with_retry(&self.http, &url, 3).await?;
        let page: OdataPage<ReleaseNote> = resp.json().await?;
        Ok(page.value)
    }

    pub async fn vulnerabilities_in_release(
        &self,
        release_number: &str,
    ) -> Result<Vec<Vulnerability>> {
        let raw = format!(
            "releaseNumber eq '{}' and isMariner eq false and issuingCna eq 'Microsoft'",
            release_number
        );
        let filt = urlencoding::encode(&raw);
        let url = format!("{}/vulnerability?$filter={}", self.root(), filt);
        self.fetch_all_pages(&url).await
    }

    pub async fn vulnerability_detail(&self, cve_id: &str) -> Result<Option<Vulnerability>> {
        let raw = format!("cveNumber eq '{}'", cve_id);
        let filt = urlencoding::encode(&raw);
        let url = format!("{}/vulnerability?$filter={}", self.root(), filt);
        let all = self.fetch_all_pages::<Vulnerability>(&url).await?;
        // The API can return one row per release a CVE appears in; later rows may not have
        // base_score populated. Pick the row with the highest score to ensure triage eligibility
        // is evaluated against the real severity, not a score-less revision row.
        Ok(all.into_iter().max_by(|a, b| {
            a.base_score
                .unwrap_or(0.0)
                .partial_cmp(&b.base_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }))
    }

    pub async fn affected_products(&self, cve_id: &str) -> Result<Vec<AffectedProduct>> {
        let raw = format!("cveNumber eq '{}'", cve_id);
        let filt = urlencoding::encode(&raw);
        let url = format!("{}/affectedProduct?$filter={}", self.root(), filt);
        self.fetch_all_pages(&url).await
    }

    async fn fetch_all_pages<T: serde::de::DeserializeOwned>(
        &self,
        start_url: &str,
    ) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut next = Some(start_url.to_string());
        while let Some(url) = next {
            let resp = get_with_retry(&self.http, &url, 3).await?;
            let page: OdataPage<T> = resp.json().await?;
            out.extend(page.value);
            next = page.next_link;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_releases_parses_fixture() {
        let body = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sug_release_notes.json"),
        )
        .unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sug/v2.0/en-US/releaseNote"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let client = SugClient::new(format!("{}/sug/v2.0", server.uri()), "en-US", http);
        let releases = client.list_releases().await.unwrap();
        assert_eq!(releases.len(), 3);
        assert_eq!(releases[0].release_number, "2026-Apr");
    }

    #[tokio::test]
    async fn vulnerabilities_in_release_paginates() {
        let server = MockServer::start().await;
        let mut p1 = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sug_vuln_page1.json"),
        )
        .unwrap();
        p1 = p1.replace("REPLACE_ME", &server.uri());
        let p2 = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sug_vuln_page2.json"),
        )
        .unwrap();

        Mock::given(method("GET"))
            .and(path("/sug/v2.0/en-US/vulnerability"))
            .respond_with(ResponseTemplate::new(200).set_body_string(p1))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/sug/v2.0/en-US/vulnerability"))
            .respond_with(ResponseTemplate::new(200).set_body_string(p2))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let client = SugClient::new(format!("{}/sug/v2.0", server.uri()), "en-US", http);
        let vulns = client.vulnerabilities_in_release("2026-Apr").await.unwrap();
        assert_eq!(vulns.len(), 3);
    }

    #[tokio::test]
    async fn affected_products_returns_kb_list() {
        let body = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sug_affected_products.json"),
        )
        .unwrap();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sug/v2.0/en-US/affectedProduct"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let http = Client::builder().user_agent("test").build().unwrap();
        let client = SugClient::new(format!("{}/sug/v2.0", server.uri()), "en-US", http);
        let products = client.affected_products("CVE-2026-00001").await.unwrap();
        assert_eq!(products.len(), 1);
        let kbs = products[0].kb_articles.as_ref().unwrap();
        assert_eq!(kbs[0].article_name.as_deref(), Some("5034123"));
    }
}
