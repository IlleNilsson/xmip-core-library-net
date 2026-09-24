//! A filesystem path as the path of a URI, and back: what a transport or an
//! archive writes after `file://`, `sqlite://` or `unix://` when the thing
//! it names is a file.
//!
//! A URI uses forward slashes on every platform and its path opens with a
//! slash, so a Windows path is converted rather than printed: `C:\in\a.edi`
//! is `/C:/in/a.edi`, and `file://` before it reads `file:///C:/in/a.edi`.
//! Until 2026-09-24 the file, SQLite and Unix-socket transports and the
//! file, SQL-script and SQLite archives each wrote this, and the file
//! transport put a fourth slash before a Unix path.

use std::path::{Path, PathBuf};

/// A backslash, the Windows separator.
const BACKSLASH: char = '\\';

/// `path` as the path part of a URI: forward slashes, and a leading slash
/// so a Windows drive reads `/C:/...` after the authority.
#[must_use]
pub fn path_of(path: &Path) -> String {
    let text = path.display().to_string().replace(BACKSLASH, "/");
    if text.starts_with('/') {
        text
    } else {
        format!("/{text}")
    }
}

/// The filesystem path a URI's path names: [`path_of`] undone, the slash
/// before a drive letter dropped. Forward slashes are kept; Windows reads
/// them as separators.
#[must_use]
pub fn file_of(uri_path: &str) -> PathBuf {
    let bytes = uri_path.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':';
    PathBuf::from(if drive { &uri_path[1..] } else { uri_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_of_either_platform_is_one_uri_path_and_comes_back() {
        assert_eq!(path_of(Path::new("/var/xmip/in")), "/var/xmip/in");
        assert_eq!(path_of(Path::new("C:\\in\\a.edi")), "/C:/in/a.edi");
        assert_eq!(path_of(Path::new("relative/a")), "/relative/a");
        assert_eq!(file_of("/C:/in/a.edi"), PathBuf::from("C:/in/a.edi"));
        assert_eq!(file_of("/var/xmip/in"), PathBuf::from("/var/xmip/in"));
        assert_eq!(file_of("/1:/x"), PathBuf::from("/1:/x"), "not a drive");
    }
}
