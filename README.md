# xmip-core-library-net

Network primitives the capabilities share. What an address means to a gate
is the gate's; how it is written and read is here.

| Item | What it is |
| --- | --- |
| `address::parse` | An address as a transport writes it: bare, with a port, or IPv6 in brackets |
| `Network` | A network in prefix notation, and whether an address is inside it |
| `authority` | An authority as a URI writes it: `parse` into host and port, `host_of`, `with_default_port`, and `bracketed` for an IPv6 host in a `Host` header |
| `mac` | A hardware address in IEEE 802 notation: `parse` reads colons, hyphens, the dotted form or the digits alone, `notation` writes lowercase with colons |
| `percent` | Percent-encoding, RFC 3986's unreserved set: `encode`, a lenient `decode` that leaves a broken escape as written, and `decode_strict` that refuses it where it is |
| `uri` | A filesystem path as the path of a URI and back: `path_of` writes forward slashes and a leading slash (`/C:/in/a.edi`), `file_of` drops the slash before a drive. The file, SQLite and Unix-socket transports and the file, SQL-script and SQLite archives each wrote `path_of` until 2026-09-24 |
| `Endpoint`, `http` | The minimal HTTP/1.1 client a capability asks a service beside it with: an `http://` URL, one request over one connection, the answer read by its length, its chunks or its end. No TLS |

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
