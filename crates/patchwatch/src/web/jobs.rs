use crate::analyze::orchestrator::analyze_cve;
use crate::config::Config;
use crate::storage::Db;
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

pub enum JobMsg {
    Run { cve_id: String, job_id: i64, override_binary: Option<String> },
    Shutdown,
}

pub struct AnalyzeService {
    sender: mpsc::Sender<JobMsg>,
}

impl AnalyzeService {
    pub fn spawn(cfg: Arc<Config>, db: Arc<Db>, http: Client) -> Self {
        let (tx, mut rx) = mpsc::channel::<JobMsg>(64);
        tokio::spawn(async move {
            info!("analyze worker started");
            while let Some(msg) = rx.recv().await {
                match msg {
                    JobMsg::Run { cve_id, job_id, override_binary } => {
                        info!(%cve_id, job_id, "analyze worker: starting job");
                        let cfg2 = Arc::clone(&cfg);
                        let db2 = Arc::clone(&db);
                        let http2 = http.clone();
                        let cve2 = cve_id.clone();
                        let res = tokio::spawn(async move {
                            analyze_cve(&cfg2, &db2, &http2, &cve2, job_id, override_binary.as_deref()).await
                        })
                        .await;
                        match res {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                error!(%cve_id, job_id, %e, "analyze worker: job failed");
                                let _ = db.update_diff_job_status(job_id, "failed", Some(&e.to_string())).await;
                            }
                            Err(join_err) => {
                                error!(job_id, %join_err, "analyze worker: job panicked");
                                let _ = db.update_diff_job_status(job_id, "failed", Some("internal panic")).await;
                            }
                        }
                    }
                    JobMsg::Shutdown => {
                        info!("analyze worker shutting down");
                        break;
                    }
                }
            }
        });
        AnalyzeService { sender: tx }
    }

    pub async fn enqueue(
        &self,
        cve_id: String,
        job_id: i64,
        override_binary: Option<String>,
    ) -> Result<()> {
        self.sender
            .send(JobMsg::Run { cve_id, job_id, override_binary })
            .await
            .map_err(|_| anyhow!("analyze worker shut down"))
    }
}
