//! Live tests against real Microsoft endpoints.
//! Gated behind `#[ignore]` — run with `cargo test -- --ignored`.

use patchwatch::config::Config;
use patchwatch::http::build_client;
use patchwatch::kb::tier1::Tier1Client;
use patchwatch::sug::SugClient;
use patchwatch::winbindex::client::WinbindexClient;

fn config() -> Config {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.yaml");
    Config::load(&p).unwrap()
}

#[tokio::test]
#[ignore = "live network: run with `cargo test -- --ignored`"]
async fn live_sug_lists_releases() {
    let cfg = config();
    let http = build_client("patchwatch-live-test").unwrap();
    let s = SugClient::new(&cfg.msrc.sug_base_url, &cfg.msrc.language, http);
    let releases = s.list_releases().await.unwrap();
    assert!(releases.iter().any(|r| r.release_number.starts_with("2026-")));
}

#[tokio::test]
#[ignore = "live network: run with `cargo test -- --ignored`"]
async fn live_tier1_for_known_2026_kb() {
    let cfg = config();
    let http = build_client("patchwatch-live-test").unwrap();
    let t1 = Tier1Client::new(&cfg.kb_enumeration.support_base_url, http);
    let kb = std::env::var("LIVE_KB").unwrap_or_else(|_| "5083769".into());
    let e = t1.enumerate(&kb).await.unwrap();
    assert!(!e.files.is_empty());
}

#[tokio::test]
#[ignore = "live network: run with `cargo test -- --ignored`"]
async fn live_winbindex_localspl() {
    let cfg = config();
    let http = build_client("patchwatch-live-test").unwrap();
    let c = WinbindexClient::new(&cfg.winbindex.base_url, http);
    let map = c.fetch_file_data("localspl.dll").await.unwrap();
    assert!(map.len() > 100);
}
