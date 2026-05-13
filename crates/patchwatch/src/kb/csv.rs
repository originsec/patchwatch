use crate::kb::types::{Arch, KbFile};
use anyhow::Result;

/// Parses a Microsoft "File information" CSV.
///
/// Real KB CSVs are concatenated multi-section files. Each section starts with a
/// single-cell descriptive banner row that encodes the architecture, e.g.
///
///   Windows 11, version 24H2 LCU arm64-based
///   "File name","File version","Date","Time","File size"
///   "localspl.dll","10.0.26100.8246","11-Apr-2026","21:53","805,376"
///   ...
///   Windows 11, version 24H2 LCU x64-based
///   "File name",...
///   ...
///
/// The parser walks records, treats single-cell rows as section banners (sets the
/// current arch), skips header rows, and emits one [`KbFile`] per data row tagged
/// with the current section's arch. Unknown rows are skipped.
pub fn parse_kb_csv(bytes: &[u8]) -> Result<Vec<KbFile>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(bytes);

    let mut current_arch = Arch::Unknown;
    let mut out = Vec::new();
    for rec in rdr.records() {
        let r = rec?;
        if r.is_empty() {
            continue;
        }

        // Detect banner rows by content: real Microsoft KB CSVs contain a
        // descriptive title row before each section, e.g.
        // `Windows 11, version 24H2 LCU x64-based`. The comma means csv splits
        // it across multiple cells, so we re-join and scan for arch keywords.
        let joined = r.iter().collect::<Vec<_>>().join(",");
        if let Some(arch) = arch_from_banner(&joined) {
            current_arch = arch;
            continue;
        }

        // Column header row (5 cells starting with "File name").
        let first = r.get(0).unwrap_or_default();
        if first.eq_ignore_ascii_case("File name") {
            continue;
        }

        // Data row — must have at least filename + version.
        if first.is_empty() || r.len() < 2 {
            continue;
        }
        let filename = first.to_string();
        let version = r.get(1).unwrap_or_default().to_string();
        let date_stamp = r.get(2).map(str::to_string);
        let file_size = r.get(4).and_then(parse_size);
        out.push(KbFile {
            filename,
            version,
            arch: current_arch,
            file_size,
            date_stamp,
        });
    }
    Ok(out)
}

fn arch_from_banner(banner: &str) -> Option<Arch> {
    let lower = banner.to_ascii_lowercase();
    if lower.contains("arm64-based") || lower.contains("arm64 based") {
        Some(Arch::Arm64)
    } else if lower.contains("x64-based") || lower.contains("x64 based") {
        Some(Arch::X64)
    } else if lower.contains("x86-based") || lower.contains("x86 based") {
        Some(Arch::X86)
    } else {
        None
    }
}

/// Parses Microsoft's quoted, comma-grouped size strings ("805,376" → 805376).
fn parse_size(raw: &str) -> Option<u64> {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.is_empty() {
        None
    } else {
        cleaned.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_section_fixture() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/kb_file_information.csv"),
        )
        .unwrap();
        let rows = parse_kb_csv(&bytes).unwrap();

        // 2 arm64 + 3 x64
        assert_eq!(rows.len(), 5);

        let arm: Vec<_> = rows.iter().filter(|r| r.arch == Arch::Arm64).collect();
        let x64: Vec<_> = rows.iter().filter(|r| r.arch == Arch::X64).collect();
        assert_eq!(arm.len(), 2);
        assert_eq!(x64.len(), 3);

        let local_x64 = x64
            .iter()
            .find(|r| r.filename == "localspl.dll")
            .expect("localspl.dll x64");
        assert_eq!(local_x64.version, "10.0.26100.8246");
        assert_eq!(local_x64.file_size, Some(805376));

        assert!(x64.iter().any(|r| r.filename == "win32k.sys"));
        assert!(arm.iter().all(|r| r.filename != "win32k.sys"));
    }

    #[test]
    fn arch_from_banner_recognizes_microsoft_titles() {
        assert_eq!(
            arch_from_banner("Windows 11, version 24H2 LCU x64-based"),
            Some(Arch::X64)
        );
        assert_eq!(
            arch_from_banner("Windows 11, version 24H2 LCU arm64-based"),
            Some(Arch::Arm64)
        );
        assert_eq!(
            arch_from_banner("Windows Server 2019 x86-based"),
            Some(Arch::X86)
        );
        assert_eq!(arch_from_banner("Mystery section"), None);
    }

    #[test]
    fn parse_size_strips_commas() {
        assert_eq!(parse_size("805,376"), Some(805376));
        assert_eq!(parse_size("\"805,376\""), Some(805376));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("Not versioned"), None);
    }
}
