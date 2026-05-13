use thiserror::Error;

#[derive(Debug, Error)]
pub enum PatchWatchError {
    #[error("HTTP {status} for {url}")]
    Http { status: u16, url: String },

    #[error("expected field `{0}` missing")]
    MissingField(&'static str),

    #[error("could not parse {what}: {detail}")]
    Parse { what: &'static str, detail: String },

    #[error("external command `{cmd}` failed (exit {code:?}): {stderr}")]
    Command { cmd: String, code: Option<i32>, stderr: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PatchWatchError>;
