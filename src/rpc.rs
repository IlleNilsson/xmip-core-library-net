//! JSON-RPC 2.0, once (<https://www.jsonrpc.org/specification>): what a
//! message says — an answer, a refusal with its code, a notification — and
//! what one read says it is, a request or a notification, or the refusal
//! it is answered with; and the two ways a message is framed on a stream,
//! by a `Content-Length` header as the Language Server Protocol frames it
//! ([`content_length`]) and one message a line as the Model Context
//! Protocol's standard input and output frame it ([`line`]).
//!
//! The VS Code language server and `xmip mcp` speak it. Until 2026-11-17
//! the language server held its messages and framing itself and the C#
//! command line's MCP server held them again.

pub mod content_length;
pub mod line;

use serde_json::{Value, json};

/// The codes JSON-RPC 2.0 reserves, section 5.1. A server's own codes,
/// from -32000 to -32099, are that server's.
pub mod code {
    /// The text is not JSON.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON is not a request.
    pub const INVALID_REQUEST: i64 = -32600;
    /// No such method.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The method's parameters are wrong.
    pub const INVALID_PARAMS: i64 = -32602;
    /// The server could not answer.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// The answer to the request `id`; a null id where there is none.
#[must_use]
pub fn response(id: Option<&Value>, result: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.cloned().unwrap_or(Value::Null), "result": result })
}

/// The refusal of the request `id`, with its code and its words; a null id
/// where the request's could not be read.
#[must_use]
pub fn error(id: Option<&Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": { "code": code, "message": message },
    })
}

/// A notification of `method` with its `params`, which is never answered.
#[must_use]
pub fn notification(method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

/// What one message read is: a request, answered, or a notification,
/// never answered.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Incoming<'a> {
    /// A request: its `id`, a string or a number as the client gave it.
    Request {
        id: &'a Value,
        method: &'a str,
        params: Option<&'a Value>,
    },
    /// A notification: no `id`, or one that is neither a string nor a
    /// number.
    Notification {
        method: &'a str,
        params: Option<&'a Value>,
    },
}

/// `text` read as one message, or the parse error it is answered with.
///
/// # Errors
///
/// Where `text` is not JSON: the answer to send, its id null.
pub fn parse(text: &str) -> Result<Value, Value> {
    serde_json::from_str(text)
        .map_err(|unread| error(None, code::PARSE_ERROR, &format!("Parse error: {unread}")))
}

/// What `message` is: a request or a notification, or the refusal of
/// something that is neither.
///
/// # Errors
///
/// Where `message` is not an object with `jsonrpc` `"2.0"` and a `method`
/// string: the answer to send, with the message's id where it has one.
pub fn incoming(message: &Value) -> Result<Incoming<'_>, Value> {
    let id = message
        .get("id")
        .filter(|id| id.is_string() || id.is_number());
    let method = message.get("method").and_then(Value::as_str);

    match (message.get("jsonrpc").and_then(Value::as_str), method) {
        (Some("2.0"), Some(method)) => {
            let params = message.get("params");
            Ok(id.map_or(Incoming::Notification { method, params }, |id| {
                Incoming::Request { id, method, params }
            }))
        }
        _ => Err(error(
            id,
            code::INVALID_REQUEST,
            "Invalid Request: a JSON-RPC 2.0 request is an object with jsonrpc \"2.0\" and a \
             method.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_and_a_refusal_carry_the_id_as_given_and_null_without_one() {
        let id = json!("seven");

        assert_eq!(
            response(Some(&id), &json!({"ok": true})),
            json!({"jsonrpc": "2.0", "id": "seven", "result": {"ok": true}})
        );
        assert_eq!(
            error(None, code::METHOD_NOT_FOUND, "no"),
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32601, "message": "no"}})
        );
        assert_eq!(
            notification("ping", &json!({})),
            json!({"jsonrpc": "2.0", "method": "ping", "params": {}})
        );
    }

    #[test]
    fn a_request_has_a_string_or_number_id_and_anything_else_is_a_notification() {
        let request = json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});
        let notified = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let odd = json!({"jsonrpc": "2.0", "id": {"no": 1}, "method": "ping", "params": [1]});

        assert_eq!(
            incoming(&request),
            Ok(Incoming::Request {
                id: &json!(3),
                method: "ping",
                params: None
            })
        );
        assert_eq!(
            incoming(&notified),
            Ok(Incoming::Notification {
                method: "notifications/initialized",
                params: None
            })
        );
        assert!(matches!(
            incoming(&odd),
            Ok(Incoming::Notification {
                method: "ping",
                params: Some(_)
            })
        ));
    }

    #[test]
    fn what_is_no_request_is_refused_with_its_id_and_text_no_json_with_none() {
        let refused =
            incoming(&json!({"jsonrpc": "1.0", "id": 4, "method": "ping"})).expect_err("not 2.0");

        assert_eq!(refused["id"], 4);
        assert_eq!(refused["error"]["code"], code::INVALID_REQUEST);
        assert!(incoming(&json!([1, 2])).is_err(), "an array is no request");

        let unread = parse("{not json").expect_err("no JSON");

        assert_eq!(unread["id"], Value::Null);
        assert_eq!(unread["error"]["code"], code::PARSE_ERROR);
        assert!(
            unread["error"]["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("Parse error: "))
        );
    }
}
