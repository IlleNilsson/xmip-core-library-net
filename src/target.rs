//! A target as a URI writes it (RFC 3986 section 3):
//! `scheme://user@host:port/path?query#fragment` — the scheme, the
//! authority with its user information, the path, the query decoded into
//! pairs, and the fragment — read once, for every technology whose send
//! names where it goes and every origin a technology is handed.
//!
//! A read borrows the text and allocates nothing until a caller asks for a
//! decoded part, so a target read per message costs a scan of it. The
//! authority is kept as written: a bus, a MAC address or a hex address is
//! an authority some technologies write, and is not a host and a port
//! until [`Target::host_and_port`] is asked for one.
//!
//! One reading. Until 2026-09-28 the transport capability split a target
//! on its first slash and left the query in the path, twenty technologies
//! stripped their scheme by hand, the two Azure brokers cut a token's
//! resource twice, and ten read a query again, most without
//! percent-decoding it.

use crate::NetError;
use crate::authority;
use crate::percent::{decode, decode_pairs};

/// A target as a URI writes it, borrowed from the text it was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Target<'a> {
    text: &'a str,
    scheme: &'a str,
    /// What follows `scheme://`, fragment and all.
    rest: &'a str,
    /// `scheme://`, the user information and the authority.
    root: &'a str,
    user: Option<&'a str>,
    authority: &'a str,
    path: &'a str,
    query: &'a str,
    fragment: Option<&'a str>,
}

impl<'a> Target<'a> {
    /// Read `text` as `scheme://` and the rest.
    ///
    /// # Errors
    ///
    /// Where `text` does not open with a scheme — a letter, then letters,
    /// digits, `+`, `-` or `.` — and `://`.
    pub fn parse(text: &'a str) -> Result<Self, NetError> {
        let (scheme, rest) = text
            .split_once("://")
            .filter(|(scheme, _)| is_scheme(scheme))
            .ok_or_else(|| NetError::new(format!("'{text}' is not scheme://…")))?;
        Ok(Self::split(text, scheme, rest))
    }

    /// Read `text` where it opens with one of `schemes` and `://`, in any
    /// case: the schemes a technology declares it accepts. `None` where it
    /// opens with no scheme or another, so the caller falls back to what it
    /// was configured with.
    #[must_use]
    pub fn under(schemes: &[&str], text: &'a str) -> Option<Self> {
        Self::parse(text).ok().filter(|target| target.is(schemes))
    }

    /// Read `text` as a target without a scheme — `host:port/path?query` —
    /// which some technologies take beside their scheme's form.
    #[must_use]
    pub fn bare(text: &'a str) -> Self {
        Self::split(text, "", text)
    }

    /// Read `text` where it names its own server: under one of `schemes`,
    /// or bare as `host:port/path` — an authority with a port, then a
    /// slash. `None` where it names neither, and is a path on the server
    /// the technology was configured with ([`Self::relative`]).
    #[must_use]
    pub fn naming_server(schemes: &[&str], text: &'a str) -> Option<Self> {
        if text.contains("://") {
            return Self::under(schemes, text);
        }
        let bare = Self::bare(text);
        (bare.authority().contains(':') && text[bare.root().len()..].starts_with('/'))
            .then_some(bare)
    }

    /// Read `text` as a relative reference (RFC 3986 section 4.2): a path
    /// alone — `table/column` — with its query and fragment, and no
    /// authority, for a target on the server a technology was configured
    /// with.
    #[must_use]
    pub fn relative(text: &'a str) -> Self {
        let path = text.split(['?', '#']).next().unwrap_or_default();
        let after = &text[path.len()..];
        Self {
            rest: text,
            root: "",
            path,
            ..Self::split(text, "", after)
        }
    }

    fn split(text: &'a str, scheme: &'a str, rest: &'a str) -> Self {
        let (hier, fragment) = match rest.split_once('#') {
            Some((hier, fragment)) => (hier, Some(fragment)),
            None => (rest, None),
        };
        let (hier, query) = hier.split_once('?').unwrap_or((hier, ""));
        let (written, path) = hier.split_once('/').unwrap_or((hier, ""));
        let (user, authority) = match written.rsplit_once('@') {
            Some((user, authority)) => (Some(user), authority),
            None => (None, written),
        };
        let root = &text[..text.len() - rest.len() + written.len()];
        Self {
            text,
            scheme,
            rest,
            root,
            user,
            authority,
            path,
            query,
            fragment,
        }
    }

    /// Whether the scheme is one of `schemes`, in any case.
    #[must_use]
    pub fn is(&self, schemes: &[&str]) -> bool {
        schemes
            .iter()
            .any(|scheme| scheme.eq_ignore_ascii_case(self.scheme))
    }

    /// The scheme, as written; empty for a [`Self::bare`] target.
    #[must_use]
    pub const fn scheme(&self) -> &'a str {
        self.scheme
    }

    /// The authority as written — `host:port`, `[::1]:4840`, a bus name —
    /// without its user information; empty where the target names none.
    #[must_use]
    pub const fn authority(&self) -> &'a str {
        self.authority
    }

    /// The host, brackets off an IPv6 literal, and the port where the
    /// authority names one.
    ///
    /// # Errors
    ///
    /// An authority [`authority::parse`] refuses: no host, an unclosed
    /// bracket, a port that is not one.
    pub fn host_and_port(&self) -> Result<(&'a str, Option<u16>), NetError> {
        authority::parse(self.authority)
            .map_err(|refused| NetError::new(format!("'{}': {refused}", self.text)))
    }

    /// The user name the authority carries before `@`, decoded.
    #[must_use]
    pub fn user(&self) -> Option<String> {
        self.user
            .map(|user| decode(user.split_once(':').map_or(user, |(name, _)| name)))
    }

    /// The password the user information carries after `:`, decoded.
    #[must_use]
    pub fn password(&self) -> Option<String> {
        self.user
            .and_then(|user| user.split_once(':'))
            .map(|(_, password)| decode(password))
    }

    /// The path after the slash that ends the authority, still encoded,
    /// without the query and the fragment: `a/b` of `mqtt://h/a/b?x`.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// The path's segments, still encoded; none where there is no path.
    ///
    /// # Errors
    ///
    /// A segment that is empty — `a//b`, `a/` — which names nothing.
    pub fn segments(&self) -> Result<Vec<&'a str>, NetError> {
        if self.path.is_empty() {
            return Ok(Vec::new());
        }
        let segments: Vec<&str> = self.path.split('/').collect();
        if segments.contains(&"") {
            return Err(NetError::new(format!(
                "'{}' has an empty path segment",
                self.text
            )));
        }
        Ok(segments)
    }

    /// The query's pairs, each name and value decoded; a pair without `=`
    /// has an empty value.
    #[must_use]
    pub fn query(&self) -> Vec<(String, String)> {
        decode_pairs(self.query)
    }

    /// The first value the query gives `name`, decoded.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<String> {
        self.query()
            .into_iter()
            .find_map(|(candidate, value)| (candidate == name).then_some(value))
    }

    /// The fragment after `#`, as written: an OPC UA node id.
    #[must_use]
    pub const fn fragment(&self) -> Option<&'a str> {
        self.fragment
    }

    /// `scheme://`, the user information and the authority: what the path
    /// hangs under — the namespace an Azure resource lives in.
    #[must_use]
    pub const fn root(&self) -> &'a str {
        self.root
    }

    /// The target without its fragment (RFC 3986 section 4.3): the
    /// endpoint an OPC UA target names its node under.
    #[must_use]
    pub fn absolute(&self) -> &'a str {
        match self.fragment {
            Some(fragment) => &self.text[..self.text.len() - fragment.len() - 1],
            None => self.text,
        }
    }

    /// Everything after `scheme://`, whole: the authority and the path
    /// together, for a scheme whose target is a filesystem path or a
    /// pipe's name rather than a host.
    #[must_use]
    pub const fn after_scheme(&self) -> &'a str {
        self.rest
    }
}

/// Whether `text` is a scheme (RFC 3986 section 3.1).
fn is_scheme(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Target<'_> {
        Target::parse(text).expect("a target")
    }

    #[test]
    fn a_target_is_a_scheme_an_authority_a_path_a_query_and_a_fragment() {
        let target = read("opc.tcp://plant:4840/line/a?x=1#ns=2;s=Orders");

        assert_eq!(target.scheme(), "opc.tcp");
        assert_eq!(target.authority(), "plant:4840");
        assert_eq!(target.host_and_port().expect("host"), ("plant", Some(4840)));
        assert_eq!(target.path(), "line/a");
        assert_eq!(target.segments().expect("segments"), ["line", "a"]);
        assert_eq!(target.query_value("x").as_deref(), Some("1"));
        assert_eq!(target.fragment(), Some("ns=2;s=Orders"));
        assert_eq!(target.absolute(), "opc.tcp://plant:4840/line/a?x=1");
        assert_eq!(target.root(), "opc.tcp://plant:4840");
        assert_eq!(target.after_scheme(), "plant:4840/line/a?x=1#ns=2;s=Orders");
    }

    #[test]
    fn the_query_is_taken_off_even_where_there_is_no_path() {
        let target = read("cotp://plc:102?src-tsap=0100&dst-tsap=0102");

        assert_eq!(target.authority(), "plc:102");
        assert_eq!(target.path(), "");
        assert!(target.segments().expect("none").is_empty());
        assert_eq!(target.query_value("dst-tsap").as_deref(), Some("0102"));
        assert_eq!(target.query_value("absent"), None);
    }

    #[test]
    fn the_query_is_percent_decoded() {
        let target = read("dns://ns/a.example?type=TXT&text=a%20b%26c&flag");

        assert_eq!(
            target.query(),
            [
                ("type".to_string(), "TXT".to_string()),
                ("text".to_string(), "a b&c".to_string()),
                ("flag".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn an_ipv6_host_is_read_inside_its_brackets() {
        let target = read("amqp://[::1]:5672/exchange/key");

        assert_eq!(target.authority(), "[::1]:5672");
        assert_eq!(target.host_and_port().expect("host"), ("::1", Some(5672)));
        assert_eq!(
            read("coap://[fe80::1]/x").host_and_port().expect("host").0,
            "fe80::1"
        );
        assert!(
            read("amqp://[::1:5672/x").host_and_port().is_err(),
            "unclosed"
        );
    }

    #[test]
    fn user_information_is_taken_off_the_authority_and_decoded() {
        let target = read("amqp://guest:p%40ss@broker:5672/x");

        assert_eq!(target.user().as_deref(), Some("guest"));
        assert_eq!(target.password().as_deref(), Some("p@ss"));
        assert_eq!(target.authority(), "broker:5672");
        assert_eq!(target.root(), "amqp://guest:p%40ss@broker:5672");
        let bare = read("amqp://only@broker");
        assert_eq!(
            (bare.user().as_deref(), bare.password()),
            (Some("only"), None)
        );
        assert_eq!(read("amqp://broker").user(), None);
    }

    #[test]
    fn an_empty_segment_is_refused() {
        for text in ["sql://h/db//c", "sql://h/t/", "sql://h//t"] {
            let refused = read(text).segments().expect_err(text);
            assert!(refused.message.contains("empty path segment"), "{text}");
        }
    }

    #[test]
    fn a_scheme_is_matched_in_any_case_and_what_has_none_is_refused() {
        assert!(Target::under(&["mqtt"], "MQTT://h/a").is_some());
        assert!(Target::under(&["as2", "as2s"], "as2s://h/a").is_some());
        assert!(Target::under(&["mqtt"], "nats://h/a").is_none());
        assert!(Target::under(&["mqtt"], "a/b").is_none());
        for text in ["a/b", "://h", "1x://h", "a b://h", "host:1883/a"] {
            assert!(Target::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_bare_target_is_an_authority_and_the_rest() {
        let target = Target::bare("nms:162/1.3.6?community=ops");

        assert_eq!((target.scheme(), target.authority()), ("", "nms:162"));
        assert_eq!(target.path(), "1.3.6");
        assert_eq!(target.query_value("community").as_deref(), Some("ops"));
    }

    #[test]
    fn a_target_names_its_server_by_its_scheme_or_as_host_and_port() {
        let named = |text| Target::naming_server(&["mq", "ibm-mq"], text);

        assert_eq!(
            named("mq://h:1414/QM1/Q").expect("scheme").authority(),
            "h:1414"
        );
        assert_eq!(named("h:1414/QM1/Q").expect("peer").path(), "QM1/Q");
        assert!(named("QM1/Q").is_none(), "a path alone");
        assert!(named("h:1414").is_none(), "no slash after the port");
        assert!(named("other://h:1/Q").is_none(), "another scheme");
    }

    #[test]
    fn a_target_read_per_message_costs_a_scan_of_it() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        let began = Instant::now();
        for _ in 0..10_000 {
            let target = Target::under(&["mqtt"], black_box("mqtt://[::1]:1883/a/b?x=1#f"));
            black_box(target.expect("read").segments().expect("segments"));
        }
        let took = began.elapsed();
        // Generous for a debug build under load: five microseconds a read.
        assert!(took < Duration::from_millis(50), "{took:?}");
    }

    #[test]
    fn a_relative_target_is_a_path_alone() {
        let target = Target::relative("orders/payload?x=1");

        assert_eq!((target.authority(), target.root()), ("", ""));
        assert_eq!(target.segments().expect("segments"), ["orders", "payload"]);
        assert_eq!(target.query_value("x").as_deref(), Some("1"));
        assert!(Target::relative("db//c").segments().is_err());
    }

    #[test]
    fn a_file_scheme_keeps_its_path_whole_after_the_scheme() {
        let target = read("unix:///var/run/xmip.sock");

        assert_eq!(target.authority(), "");
        assert_eq!(target.after_scheme(), "/var/run/xmip.sock");
    }
}
