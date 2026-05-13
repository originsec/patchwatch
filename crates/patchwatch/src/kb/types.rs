use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X64,
    Arm64,
    Unknown,
}

impl Arch {
    pub fn from_csv_platform(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "x64" | "amd64" => Self::X64,
            "x86" => Self::X86,
            "arm64" => Self::Arm64,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KbSource {
    Csv,
    Msu,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KbFile {
    pub filename: String,
    pub version: String,
    pub arch: Arch,
    pub file_size: Option<u64>,
    pub date_stamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KbEnumeration {
    pub kb_id: String,
    pub source: KbSource,
    pub csv_url: Option<String>,
    pub msu_path: Option<std::path::PathBuf>,
    pub fallback_reason: Option<String>,
    pub files: Vec<KbFile>,
}

impl KbEnumeration {
    pub fn file_list_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut sorted: Vec<_> = self.files.iter().collect();
        sorted.sort_by(|a, b| {
            (a.filename.as_str(), a.version.as_str(), a.arch).cmp(&(
                b.filename.as_str(),
                b.version.as_str(),
                b.arch,
            ))
        });
        let mut h = Sha256::new();
        h.update(format!("{:?}", self.source).as_bytes());
        for f in sorted {
            h.update(f.filename.as_bytes());
            h.update(b"|");
            h.update(f.version.as_bytes());
            h.update(b"|");
            h.update(format!("{:?}", f.arch).as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_from_csv_platform_handles_common_variants() {
        assert_eq!(Arch::from_csv_platform("x64"), Arch::X64);
        assert_eq!(Arch::from_csv_platform("AMD64"), Arch::X64);
        assert_eq!(Arch::from_csv_platform("arm64"), Arch::Arm64);
        assert_eq!(Arch::from_csv_platform("Itanium"), Arch::Unknown);
    }

    #[test]
    fn file_list_hash_is_order_independent() {
        let f1 = KbFile {
            filename: "a.dll".into(),
            version: "1".into(),
            arch: Arch::X64,
            file_size: None,
            date_stamp: None,
        };
        let f2 = KbFile {
            filename: "b.dll".into(),
            version: "2".into(),
            arch: Arch::X64,
            file_size: None,
            date_stamp: None,
        };
        let e1 = KbEnumeration {
            kb_id: "K".into(),
            source: KbSource::Csv,
            csv_url: None,
            msu_path: None,
            fallback_reason: None,
            files: vec![f1.clone(), f2.clone()],
        };
        let e2 = KbEnumeration {
            kb_id: "K".into(),
            source: KbSource::Csv,
            csv_url: None,
            msu_path: None,
            fallback_reason: None,
            files: vec![f2, f1],
        };
        assert_eq!(e1.file_list_hash(), e2.file_list_hash());
    }
}
