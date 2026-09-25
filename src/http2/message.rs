//! A request and its answer as HTTP/2 carries them (RFC 9113 section 8):
//! the pseudo-header fields first, every name in lowercase, and none of
//! the fields that belong to an HTTP/1.1 connection. The same `Request`
//! and `Response` HTTP/1.1 writes and reads, so a caller does not care
//! which version carried them.

use super::error::Violation;
use crate::http::{Request, Response, reason, split_target};

/// The fields that name an HTTP/1.1 connection and never travel in
/// HTTP/2 (section 8.2.2); `te` travels only as `trailers`.
const CONNECTION_SPECIFIC: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// What a field costs against `SETTINGS_MAX_HEADER_LIST_SIZE`.
const OVERHEAD: usize = 32;

/// Refuse a header list that is malformed (section 8.2): larger than
/// `limit`, a name empty or not lowercase, or a pseudo-field after a
/// regular one.
///
/// # Errors
///
/// A `PROTOCOL_ERROR` for the stream it arrived on.
pub fn check(fields: &[(String, String)], limit: usize) -> Result<(), Violation> {
    let size: usize = fields
        .iter()
        .map(|(name, value)| name.len() + value.len() + OVERHEAD)
        .sum();
    if size > limit {
        return Err(Violation::protocol(format!(
            "a header list of {size} octets, over the {limit} announced"
        )));
    }
    let mut regular = false;
    for (name, _) in fields {
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Violation::protocol(format!("a field name {name:?}")));
        }
        let pseudo = name.starts_with(':');
        if pseudo && regular {
            return Err(Violation::protocol(format!("{name} after a regular field")));
        }
        regular |= !pseudo;
    }
    Ok(())
}

/// `request` as the fields of its head: `:method`, `:scheme`,
/// `:authority` from its `Host`, `:path`, and its own headers.
#[must_use]
pub fn request_fields(scheme: &str, request: &Request) -> Vec<(String, String)> {
    let target = request.target();
    let mut fields = vec![
        (":method".to_string(), request.method.clone()),
        (":scheme".to_string(), scheme.to_string()),
    ];
    if let Some(host) = request.header_value("host") {
        fields.push((":authority".to_string(), host.to_string()));
    }
    let path = if target.is_empty() {
        "/".to_string()
    } else {
        target
    };
    fields.push((":path".to_string(), path));
    fields.extend(carried(&request.headers));
    fields
}

/// The request a head and a body carry; `:authority` is its `Host`.
///
/// # Errors
///
/// A `PROTOCOL_ERROR` where `:method`, `:scheme` or `:path` is missing, a
/// pseudo-field is not a request's, or a `content-length` disagrees with
/// the body.
pub fn request_of(fields: Vec<(String, String)>, body: Vec<u8>) -> Result<Request, Violation> {
    let (mut method, mut scheme, mut path) = (None, None, None);
    let mut headers = Vec::new();
    for (name, value) in fields {
        match name.as_str() {
            ":method" => method = Some(value),
            ":scheme" => scheme = Some(value),
            ":path" => path = Some(value).filter(|path| !path.is_empty()),
            ":authority" => headers.insert(0, ("host".to_string(), value)),
            other if other.starts_with(':') => {
                return Err(Violation::protocol(format!("{other} in a request")));
            }
            _ => headers.push((name, value)),
        }
    }
    let (Some(method), Some(_), Some(target)) = (method, scheme, path) else {
        return Err(Violation::protocol(
            "a request without :method, :scheme or :path",
        ));
    };
    let (path, query) = split_target(&target);
    let request = Request {
        method,
        path,
        query,
        headers,
        body,
    };
    if let Some(length) = request.header_value("content-length")
        && length.parse::<usize>().ok() != Some(request.body.len())
    {
        return Err(Violation::protocol(
            "a content-length the body does not have",
        ));
    }
    Ok(request)
}

/// `response` as the fields of its head: `:status` and its own headers.
#[must_use]
pub fn response_fields(response: &Response) -> Vec<(String, String)> {
    let mut fields = vec![(":status".to_string(), response.status.to_string())];
    fields.extend(carried(&response.headers));
    fields
}

/// The answer a head, a body and trailers carry.
///
/// # Errors
///
/// A `PROTOCOL_ERROR` where `:status` is missing or not three digits.
pub fn response_of(
    fields: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
) -> Result<Response, Violation> {
    let mut status = None;
    let mut headers = Vec::new();
    for (name, value) in fields {
        if name == ":status" {
            status = Some(value)
                .filter(|code| code.len() == 3)
                .and_then(|code| code.parse().ok());
        } else if !name.starts_with(':') {
            headers.push((name, value));
        }
    }
    let status: u16 = status.ok_or_else(|| Violation::protocol("an answer without a :status"))?;
    Ok(Response {
        status,
        reason: reason(status).to_string(),
        headers,
        body,
        trailers,
    })
}

/// `headers` as HTTP/2 carries them: lowercase, without the fields of an
/// HTTP/1.1 connection.
#[must_use]
pub fn carried(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .filter(|(name, value)| {
            !CONNECTION_SPECIFIC.contains(&name.as_str()) && (name != "te" || value == "trailers")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_request_travels_as_pseudo_fields_then_its_own_in_lowercase() {
        let request = Request::new("POST", "/orders.OrderService/Get")
            .query("a", "b c")
            .header("Host", "example:50051")
            .header("Content-Type", "application/grpc")
            .header("Connection", "keep-alive")
            .header("TE", "trailers");
        let head = request_fields("https", &request);
        assert_eq!(
            head,
            fields(&[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "example:50051"),
                (":path", "/orders.OrderService/Get?a=b%20c"),
                ("content-type", "application/grpc"),
                ("te", "trailers"),
            ])
        );
        check(&head, 4096).expect("well formed");
        let back = request_of(head, Vec::new()).expect("read");
        assert_eq!(back.path, "/orders.OrderService/Get");
        assert_eq!(back.query_value("a"), Some("b c"));
        assert_eq!(back.header_value("host"), Some("example:50051"));
    }

    #[test]
    fn a_malformed_head_is_refused() {
        assert!(check(&fields(&[("Upper", "x")]), 4096).is_err());
        assert!(check(&fields(&[("a", "1"), (":path", "/")]), 4096).is_err());
        assert!(check(&fields(&[("a", "1")]), 10).is_err());
        assert!(request_of(fields(&[(":method", "GET")]), Vec::new()).is_err());
        let head = fields(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":status", "200"),
        ]);
        assert!(request_of(head, Vec::new()).is_err());
        let lying = fields(&[
            (":method", "PUT"),
            (":scheme", "http"),
            (":path", "/"),
            ("content-length", "3"),
        ]);
        assert!(request_of(lying, b"ab".to_vec()).is_err());
        assert!(response_of(fields(&[(":status", "2000")]), Vec::new(), Vec::new()).is_err());
        let answer = response_of(fields(&[(":status", "404")]), Vec::new(), Vec::new());
        assert_eq!(answer.expect("read").reason, "Not Found");
    }
}
