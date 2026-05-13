/// Builds the Microsoft symbol-server URL for a PE file.
/// Format: https://msdl.microsoft.com/download/symbols/<filename>/<TIMESTAMP_HEX_8><IMAGE_SIZE_HEX>/<filename>
/// Where TIMESTAMP is uppercase hex zero-padded to 8, and image_size is lowercase hex unpadded.
pub fn msdl_url(filename: &str, timestamp: u64, image_size: u64) -> String {
    let ts = format!("{:08X}", timestamp);
    let sz = format!("{:x}", image_size);
    format!(
        "https://msdl.microsoft.com/download/symbols/{0}/{1}{2}/{0}",
        filename, ts, sz
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_url() {
        let url = msdl_url("localspl.dll", 0x66130A80, 0x140000);
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/localspl.dll/66130A80140000/localspl.dll"
        );
    }

    #[test]
    fn pads_short_timestamp() {
        let url = msdl_url("a.dll", 0x1, 0x1000);
        assert!(url.contains("/000000011000/"));
    }
}
