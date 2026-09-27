# xmip-core-library-net

Network primitives the capabilities share. What an address means to a gate
is the gate's; how it is written and read is here.

| Item | What it is |
| --- | --- |
| `address::parse` | An address as a transport writes it: bare, with a port, or IPv6 in brackets |
| `Network` | A network in prefix notation, and whether an address is inside it |
| `authority` | An authority as a URI writes it: `parse` into host and port, `host_of`, `with_default_port`, and `bracketed` for an IPv6 host in a `Host` header |
| `mac` | A hardware address in IEEE 802 notation: `parse` reads colons, hyphens, the dotted form or the digits alone, `notation` writes lowercase with colons |
| `percent` | Percent-encoding, RFC 3986's unreserved set: `encode`, and `encode_keeping` for a standard whose set is another (an event's wire attributes in HTTP headers), a lenient `decode` that leaves a broken escape as written, and `decode_strict` that refuses it where it is |
| `uri` | A filesystem path as the path of a URI and back: `path_of` writes forward slashes and a leading slash (`/C:/in/a.edi`), `file_of` drops the slash before a drive. The file, SQLite and Unix-socket transports and the file, SQL-script and SQLite archives each wrote `path_of` until 2026-09-24 |
| `head` | A head as the line-oriented protocols write it — lines, then a blank line: `read_head` bounded at `MAX_HEADERS`, each line read by `read::line`, and `header` that never searches the first line. HTTP and a WebSocket handshake read with it; the transport capability held it until 2026-09-25 |
| `read` | Reading off a connection, never more than Xmip holds: `until` a delimiter and `to_end` under a ceiling the caller names, and `line`, one line under `MAX_LINE` (64 KiB), its one CRLF or LF taken off, refused — never repaired — where it is not UTF-8. The head reader, the chunked body, STOMP, FTP, IMAP, SMTP, POP3, NATS, RESP, the SSH identification, syslog, MLLP and the dot-stuffed block read their lines through it, and TCP, a Unix socket, a named pipe and FTP's data connection read to the end through it; until 2026-09-27 each did it itself, unbounded, under three UTF-8 policies |
| `reply::code` | The code a line-oriented server's reply opens with — three digits, 100 to 599, then a space, a hyphen where the reply continues, or nothing. FTP and SMTP read it here; until 2026-09-27 each read it itself, and only FTP checked the range |
| `MAX_BODY` | The largest single Stream, body or message Xmip reads off one connection, 64 MiB. HTTP, the transport capability and every technology whose protocol states no maximum of its own read under it; until 2026-09-27 eleven places restated it, five of them as 16 MiB |
| `Endpoint` | An `http://` or `https://` URL: host, port — the scheme's, or `or_port`'s where it names none — and path; `authority` as a `Host` header writes it, `address` to connect or bind to, `plain` to refuse TLS where the caller has none. The http transport read its targets with a parser of its own until 2026-09-25 |
| `http` | HTTP/1.1 on the wire, both halves: `Request` and `Response`, `write_request`, `read_response`, `read_request`, `write_response`, and `exchange` of one for the other over whatever connection it is handed — a socket, or one the http transport wrapped in TLS. An answer is read by its length, its chunks or its end, a connection kept where a message names its own `Connection`. What the capabilities ask a service beside them with, and what every technology riding on HTTP calls; the http transport carried a second codec, which refused a chunked answer, until 2026-09-25. An answer carries its `trailers`, a chunked one written and read with them, and `Version` names what a connection speaks and the ALPN identifier it is agreed by. A body is bytes; `Response::text` reads an answer a protocol writes as text — a service's XML or JSON, an error's detail — as UTF-8, and refuses a body that is not, never replacing a byte (ADR-0038). No TLS here: the connection is the caller's |
| `http2` | HTTP/2 on the wire, RFC 9113, both halves, over the same `Request` and `Response`: a `Client` that sends each request on a stream of its own and reads its answer, head, body and trailers; a `Server` that takes requests off their streams and answers them, and `serve` for a whole connection; `exchange` for one request on a connection of its own. The preface and `sniff`, which tells it from an HTTP/1.1 request line and hands back what it read (`Replayed`); every frame type of section 6, SETTINGS and its acknowledgement, the stream states, flow control on the connection and per stream — a body waits at a shut window and resumes on `WINDOW_UPDATE` — `PING`, `RST_STREAM`, and `GOAWAY` sent and honoured. HPACK, RFC 7541 (`http2::hpack`): the static table, the dynamic table with eviction, Huffman coding, the integer and string representations, held to every example of Appendix C. Synchronous and hand-written; server push off; no `Upgrade`, which RFC 9113 removed |

Until 2026-09-22 identification and authorization each carried their own
network type, and authorization read the peer's address under a name no one
wrote, so an address rule never matched a peer identified by name. The name
the peer's address travels under was declared here until 2026-09-24 and is
`context::property::PEER_ADDRESS` now, with every other name one layer writes
and another reads.

Until 2026-09-24 the authority was read by the transport capability and again
by two clients; the Open Policy Agent client, the OAuth 2.0 introspection
client and the Redpanda Admin API client each wrote HTTP/1.1 by hand; the
Ethernet frame, the DHCP message and the MAC identifier each read a MAC
address with a different set of spellings; and the http transport, the
API-key identifier, the form shape and the introspection client each
percent-encoded, three of the readers taking `%+f` as a byte. Each has one
copy here now, and the callers call it.

Moving a Stream over HTTP is the http transport's
([xmip-core-transport-http](https://github.com/IlleNilsson/xmip-core-transport-http)),
not this client's.

`architecture.toml` carries the maturity.
