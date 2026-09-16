//! Small helpers that are security relevant on their own.

use std::path::{Path, PathBuf};

/// Characters that are illegal in Windows file names, plus the path separators.
const ILLEGAL: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Device names reserved by Windows; using them as a file name is refused.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Maximum length (in bytes) of a sanitized file name.
const MAX_NAME_LEN: usize = 120;

/// Turn an attacker-controlled file name into something safe to create inside
/// the download directory.
///
/// The remote peer fully controls this string, so we must defend against
/// directory traversal (`../../`), absolute paths, NTFS alternate data streams
/// (`file.txt:evil`), Windows reserved device names, control characters and
/// trailing dots/spaces (which Windows silently strips, enabling `foo.exe.` to
/// become `foo.exe`).
pub fn sanitize_filename(raw: &str) -> String {
    // 1. Keep only the final path component, whatever separator was used.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();

    // 2. Drop control characters and characters illegal on Windows.
    let mut cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !ILLEGAL.contains(c))
        .collect();

    // 3. Windows strips trailing dots and spaces; do it ourselves so the name
    //    we validate is the name that ends up on disk.
    while cleaned.ends_with('.') || cleaned.ends_with(' ') {
        cleaned.pop();
    }
    let cleaned = cleaned.trim_start().to_string();

    // 4. Refuse the special directory entries.
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "received_file".to_string();
    }

    // 5. Refuse reserved device names (with or without extension).
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return format!("_{cleaned}");
    }

    // 6. Clamp the length, keeping the extension when possible.
    truncate_keeping_extension(&cleaned, MAX_NAME_LEN)
}

fn truncate_keeping_extension(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && name.len() - i <= 16 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let budget = max.saturating_sub(ext.len());
    let mut cut = budget.min(stem.len());
    while cut > 0 && !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    if cut == 0 {
        return "received_file".to_string();
    }
    format!("{}{}", &stem[..cut], ext)
}

/// Return a path inside `dir` that does not exist yet, appending ` (n)` to the
/// stem if needed. Never overwrites an existing file.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1..10_000u32 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{stem}.{}.{ext}", std::process::id()))
}

/// Human readable byte size, for the UI and logs only.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Reject peers that are not on a private / link-local network.
///
/// SyncMob is a LAN tool: refusing routable addresses means a misconfigured
/// port forward cannot expose the node to the open internet.
pub fn is_lan_addr(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback() || is_cgnat(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Truncate a remote-supplied string before it ever reaches a log line or the
/// UI, so a peer cannot flood the interface.
pub fn clamp_str(s: &str, max: usize) -> String {
    let s = s.replace(['\r', '\n', '\0'], " ");
    if s.chars().count() <= max {
        s
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_is_stripped() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(
            sanitize_filename(r"..\..\windows\system32\evil.dll"),
            "evil.dll"
        );
        assert_eq!(sanitize_filename("/absolute/path.txt"), "path.txt");
        assert_eq!(sanitize_filename(".."), "received_file");
        assert_eq!(sanitize_filename("."), "received_file");
        assert_eq!(sanitize_filename(""), "received_file");
    }

    #[test]
    fn ads_and_illegal_chars_are_removed() {
        assert_eq!(sanitize_filename("report.txt:$DATA"), "report.txt$DATA");
        assert_eq!(sanitize_filename("a<b>c|d?e*f.txt"), "abcdef.txt");
        assert_eq!(sanitize_filename("bad\u{0}name.txt"), "badname.txt");
    }

    #[test]
    fn trailing_dots_are_removed() {
        assert_eq!(sanitize_filename("payload.exe."), "payload.exe");
        assert_eq!(sanitize_filename("payload.exe   "), "payload.exe");
    }

    #[test]
    fn reserved_names_are_escaped() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_filename("com1.log"), "_com1.log");
    }

    #[test]
    fn long_names_keep_extension() {
        let long = "x".repeat(400) + ".tar.gz";
        let out = sanitize_filename(&long);
        assert!(out.len() <= MAX_NAME_LEN);
        assert!(out.ends_with(".gz"));
    }

    #[test]
    fn lan_filter() {
        use std::net::IpAddr;
        assert!(is_lan_addr("192.168.1.5".parse::<IpAddr>().unwrap()));
        assert!(is_lan_addr("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_lan_addr("172.16.9.9".parse::<IpAddr>().unwrap()));
        assert!(!is_lan_addr("8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_lan_addr("172.32.0.1".parse::<IpAddr>().unwrap()));
    }
}
