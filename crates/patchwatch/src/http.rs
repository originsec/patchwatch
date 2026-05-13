use reqwest::{Client, Response};
use std::time::Duration;
use tracing::{debug, warn};

pub fn build_client(user_agent: &str) -> reqwest::Result<Client> {
    Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(60))
        .gzip(true)
        .build()
}

pub async fn get_with_retry(
    client: &Client,
    url: &str,
    max_attempts: u32,
) -> anyhow::Result<Response> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        debug!(url, attempt, "GET");
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) if resp.status().is_client_error() => {
                anyhow::bail!("HTTP {} for {}", resp.status(), url);
            }
            Ok(resp) => {
                warn!(status = %resp.status(), attempt, "retryable HTTP error");
                if attempt >= max_attempts {
                    anyhow::bail!("HTTP {} for {} after {} attempts", resp.status(), url, attempt);
                }
            }
            Err(err) => {
                warn!(?err, attempt, "transport error");
                if attempt >= max_attempts {
                    return Err(err.into());
                }
            }
        }
        let delay = Duration::from_secs(u64::from(attempt * attempt));
        tokio::time::sleep(delay).await;
    }
}
