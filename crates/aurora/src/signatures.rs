pub fn identify_format(bytes: &[u8]) -> &'static str {
    match bytes {
        b if b.starts_with(&[0x4D, 0x5A]) => "Windows Executable (EXE/DLL)",
        b if b.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) => "Linux Executable (ELF)",
        b if b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) => "Java Class File",
        
        // --- DOCUMENTS ---
        b if b.starts_with(&[0x25, 0x50, 0x44, 0x46]) => "PDF Document",
        b if b.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) => "Legacy Office / MSI",
        b if b.starts_with(b"{\\rtf1") => "RTF Document",
        
        // --- ARCHIVES ---
        b if b.starts_with(&[0x50, 0x4B, 0x03, 0x04]) => "ZIP/Modern Office",
        b if b.starts_with(&[0x52, 0x61, 0x72, 0x21]) => "RAR Archive",
        b if b.starts_with(&[0x37, 0x7A, 0xBC, 0xAF]) => "7-Zip Archive",

        // --- IMAGES ---
        b if b.starts_with(&[0x89, 0x50, 0x4E, 0x47]) => "PNG Image",
        b if b.starts_with(&[0xFF, 0xD8, 0xFF])       => "JPEG Image",
        b if b.len() > 12 && &b[8..12] == b"WEBP"    => "WebP Image",

        // --- WEB / TEXT ---
        b if b.starts_with(b"{") || b.starts_with(b"[") => "JSON",
        b if b.starts_with(b"<?xml")                  => "XML Document",

        // --- VIDEO FORMATS ---
        b if b.len() > 8 && &b[4..8] == b"ftyp" => "MP4/MOV Video",
        b if b.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) => "MKV/WebM Video",
        b if b.starts_with(b"RIFF") && b.len() > 12 && &b[8..12] == b"AVI " => "AVI Video",
        b if b.starts_with(&[0x46, 0x4C, 0x56, 0x01]) => "Flash Video (FLV)",
        
        _ => "Unknown/Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executables() {
        assert_eq!(identify_format(&[0x4D, 0x5A, 0x90]), "Windows Executable (EXE/DLL)");
        assert_eq!(identify_format(&[0x7F, 0x45, 0x4C, 0x46]), "Linux Executable (ELF)");
    }

    #[test]
    fn test_videos() {
        let mut mp4 = vec![0u8; 10];
        mp4[4..8].copy_from_slice(b"ftyp");
        assert_eq!(identify_format(&mp4), "MP4/MOV Video");
        assert_eq!(identify_format(&[0x1A, 0x45, 0xDF, 0xA3]), "MKV/WebM Video");
    }

    #[test]
    fn test_office_zip() {
        assert_eq!(identify_format(&[0x50, 0x4B, 0x03, 0x04]), "ZIP/Modern Office");
    }
}