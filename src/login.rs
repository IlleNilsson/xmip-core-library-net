//! A login a server is offered — a user and the secret it presents — and
//! the check the server is handed to admit it or not (open problem 59).
//!
//! Identity presentation is a security responsibility, not a transport's
//! (`architecture.toml`), so a server that logs a client in — Xmip's SSH
//! server and FTP server, the loopbacks' and the Playground's far ends —
//! links no authenticator: it asks the [`Check`] it was handed. The one
//! that proves a password is `authenticate/password`'s; [`only`] and
//! [`nobody`] are what a loopback that knows its one client is handed.
//!
//! One home: SSH and FTP each admitted any password until 2026-11-01.

use std::sync::Arc;

use codec::constant_time;

/// What a client offered to log in with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Offered<'a> {
    /// The user it asked to be.
    pub user: &'a str,
    /// The secret it presented: a password.
    pub secret: &'a str,
}

impl std::fmt::Debug for Offered<'_> {
    /// The user alone: a secret is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offered").field("user", &self.user).finish()
    }
}

/// Whether an offered login is admitted: what a server is handed.
pub type Check = Arc<dyn Fn(&Offered<'_>) -> bool + Send + Sync>;

/// A check that admits `user` with `secret` alone, compared in constant
/// time: a loopback's, whose far end knows the one client it serves.
#[must_use]
pub fn only(user: impl Into<String>, secret: impl Into<String>) -> Check {
    let (user, secret) = (user.into(), secret.into());
    Arc::new(move |offered: &Offered<'_>| {
        // Both compared, so the time says nothing of which was wrong.
        let named = constant_time::equal(offered.user.as_bytes(), user.as_bytes());
        let proven = constant_time::equal(offered.secret.as_bytes(), secret.as_bytes());
        named & proven
    })
}

/// A check that admits no one: a server whose every client presents a
/// key, or none.
#[must_use]
pub fn nobody() -> Check {
    Arc::new(|_: &Offered<'_>| false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered<'a>(user: &'a str, secret: &'a str) -> Offered<'a> {
        Offered { user, secret }
    }

    #[test]
    fn only_admits_its_one_pair() {
        let check = only("party", "pencil");
        assert!(check(&offered("party", "pencil")));
        assert!(!check(&offered("party", "pen")), "a shorter secret");
        assert!(!check(&offered("party", "pencils")), "a longer one");
        assert!(!check(&offered("parts", "pencil")), "another user");
        assert!(!check(&offered("", "")));
    }

    #[test]
    fn nobody_admits_no_one() {
        assert!(!nobody()(&offered("xmip", "xmip")));
    }

    #[test]
    fn an_offer_never_prints_its_secret() {
        let printed = format!("{:?}", offered("party", "pencil"));
        assert!(printed.contains("party"), "{printed}");
        assert!(!printed.contains("pencil"), "{printed}");
    }
}
