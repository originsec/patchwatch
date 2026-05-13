use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_score<'de, D>(d: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    // The MSRC API sometimes returns scores as JSON strings ("5.7") and sometimes
    // as bare numbers (5.7). Accept both.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ScoreRepr {
        Num(f64),
        Str(String),
    }
    match Option::<ScoreRepr>::deserialize(d)? {
        None => Ok(None),
        Some(ScoreRepr::Num(n)) => Ok(Some(n)),
        Some(ScoreRepr::Str(s)) => s
            .parse::<f64>()
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub cve_number: String,
    pub cve_title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_score")]
    pub base_score: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_score")]
    pub temporal_score: Option<f64>,
    pub vector_string: Option<String>,
    pub severity: Option<String>,
    pub impact: Option<String>,
    pub issuing_cna: Option<String>,
    pub tag: Option<String>,
    pub exploited: Option<String>,
    pub publicly_disclosed: Option<String>,
    pub customer_action_required: Option<bool>,
    pub is_mariner: Option<bool>,
    pub release_number: Option<String>,
    pub release_date: Option<String>,
    pub revision_number: Option<String>,
    pub description: Option<String>,
    pub cwe_list: Option<Vec<String>>,
}

impl Vulnerability {
    /// Returns the first CWE identifier (e.g. "CWE-416") from the cweList array.
    pub fn cwe_id(&self) -> Option<String> {
        let entry = self.cwe_list.as_ref()?.first()?;
        Some(entry.split(':').next()?.trim().to_owned())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KbArticle {
    pub article_name: Option<String>,
    pub article_url: Option<String>,
    pub fixed_build_number: Option<String>,
    pub reboot_required: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AffectedProduct {
    pub cve_number: String,
    pub product: Option<String>,
    pub kb_articles: Option<Vec<KbArticle>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseNote {
    pub release_number: String,
    pub release_date: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OdataPage<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_vulnerability_page() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sug_vuln_minimal.json"),
        )
        .unwrap();
        let page: OdataPage<Vulnerability> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(page.value.len(), 1);
        assert_eq!(page.value[0].cve_number, "CVE-2026-12345");
        assert_eq!(page.value[0].base_score, Some(8.8));
        assert_eq!(page.value[0].cwe_id().as_deref(), Some("CWE-416"));
    }
}
