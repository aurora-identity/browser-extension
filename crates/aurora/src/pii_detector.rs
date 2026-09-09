use once_cell::sync::Lazy;
use regex::Regex;

// --- STATIC REGEX COMPILATION ---
static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?x)
        [a-zA-Z0-9._%+\-]+   # Greedy local part
        @
        [a-zA-Z0-9.\-]+      # Greedy domain part
        \.
        [a-zA-Z]{2,6}        # Common TLD lengths
    ").unwrap()
});

static RE_SSN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b").unwrap()
});

static RE_PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?x)
        (?:(?:\+|00)(?:49|47)) # Mandatory CC prefix
        [\d\s().-]{7,20}       # Linear scan for valid chars
    ").unwrap()
});

// --- CORE LOGIC ---

pub fn detect_pii(body: &[u8]) -> Vec<String> {
    let mut detected = Vec::with_capacity(3);
    
    // UPDATED FAST-PATH:
    // We check for '@', digits, AND '%' or '+' (to account for encoded data)
    let has_at = body.contains(&b'@');
    let has_digits = body.iter().any(|b: &u8| b.is_ascii_digit());
    let has_encoding = body.contains(&b'%') || body.contains(&b'+');

    // If none of these exist, there is zero chance of PII or encoded PII
    if !has_at && !has_digits && !has_encoding {
        return detected;
    }

    let raw = String::from_utf8_lossy(body).to_string();
    let decoded = percent_decode_lossy(&raw);

    let mut found_email = false;
    let mut found_ssn = false;
    let mut found_phone = false;

    // We run the checks if the character exists OR if there was encoding present
    if (has_at || has_encoding) && (contains_email(&raw) || contains_email(&decoded)) {
        found_email = true;
    }

    if (has_digits || has_encoding) && (contains_valid_ssn(&raw) || contains_valid_ssn(&decoded)) {
        found_ssn = true;
    }

    if (has_digits || has_encoding) && (contains_phone(&raw) || contains_phone(&decoded)) {
        found_phone = true;
    }

    if found_email { detected.push("email detected".to_string()); }
    if found_ssn { detected.push("ssn detected".to_string()); }
    if found_phone { detected.push("phone detected".to_string()); }

    detected
}

fn contains_email(text: &str) -> bool {
    RE_EMAIL.is_match(text)
}

fn contains_valid_ssn(text: &str) -> bool {
    for cap in RE_SSN.captures_iter(text) {
        let area = cap.get(1).map_or("", |m| m.as_str());
        let group = cap.get(2).map_or("", |m| m.as_str());
        let serial = cap.get(3).map_or("", |m| m.as_str());

        if is_valid_us_ssn(area, group, serial) {
            return true;
        }
    }
    false
}

fn is_valid_us_ssn(area: &str, group: &str, serial: &str) -> bool {
    let area_num: u16 = area.parse().unwrap_or(0);
    let group_num: u16 = group.parse().unwrap_or(0);
    let serial_num: u16 = serial.parse().unwrap_or(0);

    if area_num == 0 || area_num == 666 || (900..=999).contains(&area_num) {
        return false;
    }
    if group_num == 0 || serial_num == 0 {
        return false;
    }
    true
}

fn contains_phone(text: &str) -> bool {
    for m in RE_PHONE.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c: &char| c.is_ascii_digit()).collect();
        if (10..=15).contains(&digits.len()) {
            return true;
        }
    }
    false
}

fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    if !bytes.contains(&b'%') && !bytes.contains(&b'+') {
        return s.to_string();
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(a), Some(b)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                    out.push((a << 4) | b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(out: &[String], s: &str) -> bool {
        out.iter().any(|x| x == s)
    }

    #[test]
    fn returns_empty_when_no_pii() {
        let out = detect_pii(b"hello=world&count=123");
        assert!(out.is_empty());
    }

    #[test]
    fn detects_email() {
        let out = detect_pii(b"contact me at alice.smith+test@example.com");
        assert!(has(&out, "email detected"));
    }

    #[test]
    fn detects_various() {
        let out = detect_pii(br#"{"user":{"email":"alice.smith@example.com"},"plan":"plus"}"#);
        assert!(has(&out, "email detected"));
        let out = detect_pii(br#"{"event":"Pasted to Composer","ts":"2026-02-17T20:59:25.377Z"}"#);
        assert!(out.is_empty());
        let out = detect_pii(br#"{"event":"connectors.selected","count":0,"ts":1771361967471}"#);
        assert!(out.is_empty());
        let out = detect_pii(br#"{"event":"contact.shared","recipient":"bob.jones@example.org"}"#);
        assert!(has(&out, "email detected"));
        let out = detect_pii(br#"{"event":"turn.finish","ms":2035,"tools":0}"#);
        assert!(out.is_empty());
        let out = detect_pii(br#"{"event":"attribution","thread_id":"WEB:abc123"}"#);
        assert!(out.is_empty());
        let out = detect_pii(br#"{"event":"Create New Thread","version":144}"#);
        assert!(out.is_empty());
        let out = detect_pii(br#"%7B%22from%22%3A%20%22carol.doe%40example.net%22%7D"#);
        assert!(has(&out, "email detected"));
    }

    #[test]
    fn detects_valid_ssn() {
        let out = detect_pii(b"ssn=123-45-6789");
        assert!(has(&out, "ssn detected"));
    }

    #[test]
    fn does_not_detect_invalid_ssn_ranges() {
        assert!(!has(&detect_pii(b"ssn=000-12-3456"), "ssn detected"));
        assert!(!has(&detect_pii(b"ssn=666-12-3456"), "ssn detected"));
    }

    #[test]
    fn detects_phone() {
        let out = detect_pii(b"call me at +49 55532671");
        assert!(has(&out, "phone detected"));
    }

    #[test]
    fn detects_multiple() {
        let out = detect_pii(b"email=john@example.com ssn=123-45-6789 phone=+49 4155552671");
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn detects_urlencoded_percent_decoded_content() {
        // "email%3Da%40b.com" contains '%', so the fast-path will now allow it through
        let body = b"email%3Da%40b.com%26ssn%3D123-45-6789";
        let out = detect_pii(body);
        assert!(has(&out, "email detected"), "Encoded email failed to detect");
        assert!(has(&out, "ssn detected"), "Encoded SSN failed to detect");
    }
}