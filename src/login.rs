//! A login a server is offered — a user and the password or the public key
//! it presents — and the check the server is handed to admit it or not
//! (open problem 59).
//!
//! Identity presentation is a security responsibility, not a transport's
//! (`architecture.toml`), so a server that logs a client in — Xmip's SSH
//! server and FTP server, the loopbacks' and the Essentials' far ends —
//! links no authenticator: it asks the [`Check`] it was handed. The one
//! that proves a password is `authenticate/password`'s, the one that says
//! whether a key is the user's `authenticate/ssh-key`'s; [`only`],
//! [`only_key`] and [`nobody`] are what a loopback that knows its one
//! client is handed.
//!
//! One home: SSH and FTP each admitted any password, and SSH any key whose
//! signature verified, until 2026-11-01.

use std::sync::Arc;

use codec::constant_time;

/// A password a client offered to log in with.
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

/// A public key a client offered to log in with, its signature already
/// verified by the server: what is left to ask is whether the key is the
/// user's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferedKey<'a> {
    /// The user it asked to be.
    pub user: &'a str,
    /// The public key, as its blob travels on the wire (RFC 4253 section
    /// 6.6).
    pub key: &'a [u8],
}

/// What a client offered: a password or a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer<'a> {
    /// A user and a password.
    Password(Offered<'a>),
    /// A user and a public key whose signature verified.
    Key(OfferedKey<'a>),
}

/// Whether an offered login is admitted: what a server is handed.
pub type Check = Arc<dyn Fn(&Offer<'_>) -> bool + Send + Sync>;

/// A check that admits `user` with the password `secret` alone, compared
/// in constant time, and no key: a loopback's, whose far end knows the one
/// client it serves.
#[must_use]
pub fn only(user: impl Into<String>, secret: impl Into<String>) -> Check {
    let (user, secret) = (user.into(), secret.into());
    Arc::new(move |offer: &Offer<'_>| match offer {
        // Both compared, so the time says nothing of which was wrong.
        Offer::Password(offered) => {
            let named = constant_time::equal(offered.user.as_bytes(), user.as_bytes());
            let proven = constant_time::equal(offered.secret.as_bytes(), secret.as_bytes());
            named & proven
        }
        Offer::Key(_) => false,
    })
}

/// A check that admits `user` with the public key `key` alone, its blob
/// compared in constant time, and no password: a loopback's whose near end
/// presents a key.
#[must_use]
pub fn only_key(user: impl Into<String>, key: impl Into<Vec<u8>>) -> Check {
    let (user, key) = (user.into(), key.into());
    Arc::new(move |offer: &Offer<'_>| match offer {
        Offer::Key(offered) => {
            let named = constant_time::equal(offered.user.as_bytes(), user.as_bytes());
            let held = constant_time::equal(offered.key, &key);
            named & held
        }
        Offer::Password(_) => false,
    })
}

/// A check that admits no one: a server whose every client presents
/// nothing.
#[must_use]
pub fn nobody() -> Check {
    Arc::new(|_: &Offer<'_>| false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password<'a>(user: &'a str, secret: &'a str) -> Offer<'a> {
        Offer::Password(Offered { user, secret })
    }

    fn key<'a>(user: &'a str, key: &'a [u8]) -> Offer<'a> {
        Offer::Key(OfferedKey { user, key })
    }

    #[test]
    fn only_admits_its_one_password_and_no_key() {
        let check = only("party", "pencil");
        assert!(check(&password("party", "pencil")));
        assert!(!check(&password("party", "pen")), "a shorter secret");
        assert!(!check(&password("party", "pencils")), "a longer one");
        assert!(!check(&password("parts", "pencil")), "another user");
        assert!(!check(&password("", "")));
        assert!(!check(&key("party", b"pencil")), "a key");
    }

    #[test]
    fn only_key_admits_its_one_key_for_its_one_user_and_no_password() {
        let check = only_key("party", b"blob".to_vec());
        assert!(check(&key("party", b"blob")));
        assert!(!check(&key("party", b"blot")), "another key");
        assert!(!check(&key("parts", b"blob")), "another user");
        assert!(!check(&password("party", "blob")), "a password");
    }

    #[test]
    fn nobody_admits_no_one() {
        assert!(!nobody()(&password("xmip", "xmip")));
        assert!(!nobody()(&key("xmip", b"xmip")));
    }

    #[test]
    fn an_offer_never_prints_its_secret() {
        let printed = format!("{:?}", password("party", "pencil"));
        assert!(printed.contains("party"), "{printed}");
        assert!(!printed.contains("pencil"), "{printed}");
    }
}
