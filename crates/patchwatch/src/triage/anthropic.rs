use crate::kb::types::KbFile;
use crate::sug::types::Vulnerability;
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::info;

/// Timeout for individual LLM requests. Large prompts (synthesis with thousands of function
/// names, deep analysis with full decompiled code) can take significantly longer than the
/// shared 60-second HTTP client timeout.
const LLM_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct AnthropicClient {
    api_key: String,
    base_url: String,
    model: String,
    http: Client,
}

#[derive(Debug, Serialize)]
struct MessageRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<RequestMessage<'a>>,
    system: &'a str,
}

#[derive(Debug, Serialize)]
struct RequestMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Deserialize)]
struct MessageResponse {
    content: Vec<ResponseBlock>,
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponseBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ranking {
    pub filename: String,
    pub confidence: f64,
    pub reasoning: String,
}

#[derive(Debug, Deserialize)]
struct RankingEnvelope {
    rankings: Vec<Ranking>,
}

pub const TRIAGE_SYSTEM_PROMPT: &str = "You are a Windows security expert. Given a CVE description and a list of binaries changed in the corresponding patch, rank each binary by the probability it contains the fix for this specific CVE. Output strict JSON with no extra text.";

impl AnthropicClient {
    pub fn new(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        http: Client,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into(),
            model: model.into(),
            http,
        }
    }

    pub async fn complete(&self, system: &str, user: &str, max_tokens: u32) -> Result<String> {
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        info!(%url, model = %self.model, "anthropic complete");
        let req = MessageRequest {
            model: &self.model,
            max_tokens,
            system,
            messages: vec![RequestMessage {
                role: "user",
                content: user,
            }],
        };
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .timeout(LLM_REQUEST_TIMEOUT)
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("anthropic HTTP {}: {}", s, t);
        }
        let parsed: MessageResponse = resp.json().await?;
        if parsed.stop_reason.as_deref() == Some("max_tokens") {
            tracing::warn!("anthropic response truncated at max_tokens");
        }
        let text = parsed
            .content
            .into_iter()
            .find(|b| b.block_type == "text")
            .and_then(|b| b.text)
            .ok_or_else(|| anyhow::anyhow!("no text block"))?;
        Ok(text)
    }

    pub async fn triage(
        &self,
        cve: &Vulnerability,
        kb_id: &str,
        files: &[KbFile],
        source: &str,
    ) -> Result<Vec<Ranking>> {
        let prompt = build_triage_prompt(cve, kb_id, files, source);
        let raw = self.complete(TRIAGE_SYSTEM_PROMPT, &prompt, 8192).await?;
        let json_start = raw.find('{').unwrap_or(0);
        let json_end = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());
        let json = &raw[json_start..json_end];
        let env: RankingEnvelope = serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("triage JSON parse failed ({e}); raw snippet: {}", &raw[..raw.len().min(200)]))?;
        Ok(env.rankings)
    }
}

pub fn build_triage_prompt(
    cve: &Vulnerability,
    kb_id: &str,
    files: &[KbFile],
    source: &str,
) -> String {
    // Dedup by filename, prefer x64.
    let mut by_name: BTreeMap<&str, Vec<&KbFile>> = BTreeMap::new();
    for f in files {
        by_name.entry(f.filename.as_str()).or_default().push(f);
    }
    let mut lines = String::new();
    for (name, group) in &by_name {
        let archs: Vec<String> = group
            .iter()
            .map(|g| format!("{:?}", g.arch).to_lowercase())
            .collect();
        let any = group[0];
        lines.push_str(&format!(
            "- {} (architectures: {}, version: {})\n",
            name,
            archs.join(","),
            any.version
        ));
    }
    format!(
        "CVE: {cve}\nTitle: {title}\nDescription: {desc}\nCWE: {cwe}\n\n\
         Files changed in {kb} ({n} unique filenames, source: {source}):\n{lines}\n\n\
         Respond with JSON:\n{{\"rankings\":[{{\"filename\":\"...\",\"confidence\":0.0,\"reasoning\":\"...\"}}]}}\n\
         Return the top 20 most security-relevant candidates, ordered by confidence descending. \
         Omit files that are clearly unrelated to this CVE.",
        cve = cve.cve_number,
        title = cve.cve_title.as_deref().unwrap_or("(no title)"),
        desc = cve.description.as_deref().unwrap_or("(no description)"),
        cwe = cve.cwe_id().as_deref().unwrap_or("(unknown)"),
        kb = kb_id,
        n = by_name.len(),
        source = source,
        lines = lines.trim_end(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb::types::Arch;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn empty_cve(num: &str) -> Vulnerability {
        Vulnerability {
            cve_number: num.into(),
            cve_title: None,
            base_score: None,
            temporal_score: None,
            vector_string: None,
            severity: None,
            impact: None,
            issuing_cna: None,
            tag: None,
            exploited: None,
            publicly_disclosed: None,
            customer_action_required: None,
            is_mariner: None,
            release_number: None,
            release_date: None,
            revision_number: None,
            description: None,
            cwe_list: None,
        }
    }

    #[tokio::test]
    async fn complete_returns_first_text_block() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [
                    { "type": "text", "text": "{\"rankings\":[]}" }
                ]
            })))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let c = AnthropicClient::new("key", server.uri(), "claude-sonnet-4-6", http);
        let s = c.complete("sys", "user", 1024).await.unwrap();
        assert!(s.contains("rankings"));
    }

    #[test]
    fn build_triage_prompt_includes_files_and_kb_source() {
        let cve = Vulnerability {
            cve_title: Some("Print Spooler EoP".into()),
            base_score: Some(8.8),
            description: Some("Bad thing".into()),
            cwe_list: Some(vec!["CWE-416".into()]),
            ..empty_cve("CVE-2026-12345")
        };
        let files = vec![
            KbFile {
                filename: "localspl.dll".into(),
                version: "10.0.22631.4000".into(),
                arch: Arch::X64,
                file_size: None,
                date_stamp: None,
            },
            KbFile {
                filename: "spoolsv.exe".into(),
                version: "10.0.22631.4000".into(),
                arch: Arch::X64,
                file_size: None,
                date_stamp: None,
            },
        ];
        let p = build_triage_prompt(&cve, "KB5034123", &files, "csv");
        assert!(p.contains("CVE-2026-12345"));
        assert!(p.contains("localspl.dll"));
        assert!(p.contains("spoolsv.exe"));
        assert!(p.contains("source: csv"));
    }

    #[tokio::test]
    async fn triage_parses_rankings_envelope() {
        let body = serde_json::json!({
            "content": [{"type": "text", "text": "{\"rankings\":[{\"filename\":\"localspl.dll\",\"confidence\":0.92,\"reasoning\":\"name match\"}]}"}]
        });
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let http = Client::builder().user_agent("test").build().unwrap();
        let c = AnthropicClient::new("k", server.uri(), "claude-opus-4-7", http);
        let cve = empty_cve("CVE-X");
        let r = c.triage(&cve, "KB1", &[], "csv").await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].filename, "localspl.dll");
        assert!((r[0].confidence - 0.92).abs() < 1e-6);
    }
}
