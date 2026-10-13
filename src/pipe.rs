//! Where a named local endpoint is on this system: the one rule for every
//! part of Xmip that names one — the named pipe transport and a node's
//! local operate listener (ADR-0014, amendment 2026-10-13).
//!
//! On Windows a named pipe is a kernel object under `\\.\pipe\`; on Unix
//! it is a file — a FIFO for the transport, a Unix domain socket for the
//! operate listener — and a bare name is a file in the temporary
//! directory. A name that already is a path is taken as one.

use std::path::PathBuf;

/// The operating system's path for an endpoint called `name`: as given
/// where it already is a path, `\\.\pipe\<name>` on Windows otherwise, and
/// a file in the temporary directory on Unix otherwise.
#[must_use]
pub fn path_of(name: &str) -> PathBuf {
    if name.contains('/') || name.contains(char::from(92)) {
        return PathBuf::from(name);
    }
    if cfg!(windows) {
        PathBuf::from(format!("\\\\.\\pipe\\{name}"))
    } else {
        std::env::temp_dir().join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_becomes_the_systems_path_and_a_path_stays() {
        let bare = path_of("orders");
        if cfg!(windows) {
            assert_eq!(bare, PathBuf::from("\\\\.\\pipe\\orders"));
        } else {
            assert_eq!(bare, std::env::temp_dir().join("orders"));
        }
        assert_eq!(
            path_of("/run/xmip/orders"),
            PathBuf::from("/run/xmip/orders")
        );
        assert_eq!(
            path_of("\\\\server\\pipe\\orders"),
            PathBuf::from("\\\\server\\pipe\\orders")
        );
    }
}
