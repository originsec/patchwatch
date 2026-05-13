use crate::kb::types::Arch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub size: Option<u64>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub machine_type: Option<u32>,
    pub timestamp: Option<u64>,
    pub virtual_size: Option<u64>,
    pub version: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub release_date: Option<String>,
    pub release_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMeta {
    #[serde(default)]
    pub update_info: Option<UpdateInfo>,
}

pub type Builds = HashMap<String, HashMap<String, UpdateMeta>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WinbindexEntry {
    #[serde(default)]
    pub file_info: Option<FileInfo>,
    #[serde(default)]
    pub windows_versions: Option<Builds>,
}

impl WinbindexEntry {
    pub fn arch(&self) -> Arch {
        match self.file_info.as_ref().and_then(|f| f.machine_type) {
            Some(34404) => Arch::X64,
            Some(332) => Arch::X86,
            Some(43620) => Arch::Arm64,
            _ => Arch::Unknown,
        }
    }
    pub fn version(&self) -> Option<&str> {
        self.file_info.as_ref().and_then(|f| f.version.as_deref())
    }
    pub fn timestamp(&self) -> Option<u64> {
        self.file_info.as_ref().and_then(|f| f.timestamp)
    }
    pub fn virtual_size(&self) -> Option<u64> {
        self.file_info.as_ref().and_then(|f| f.virtual_size)
    }
    pub fn sha256(&self) -> Option<&str> {
        self.file_info.as_ref().and_then(|f| f.sha256.as_deref())
    }
    pub fn appears_in_kb(&self, kb_number: &str) -> bool {
        let bare = kb_number.trim_start_matches(|c: char| !c.is_ascii_digit());
        let with_kb = format!("KB{}", bare);
        let Some(builds) = &self.windows_versions else {
            return false;
        };
        builds
            .values()
            .any(|kbs| kbs.keys().any(|k| k.eq_ignore_ascii_case(&with_kb)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/winbindex_localspl_minimal.json"),
        )
        .unwrap();
        let map: HashMap<String, WinbindexEntry> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(map.len(), 2);
        let abc = &map["abc123"];
        assert_eq!(abc.arch(), Arch::X64);
        assert_eq!(abc.version(), Some("10.0.22631.4000"));
        assert!(abc.appears_in_kb("KB5034123"));
        assert!(!abc.appears_in_kb("KB9999999"));
    }
}
