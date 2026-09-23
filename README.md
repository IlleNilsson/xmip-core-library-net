# xmip-core-library-net

Network primitives the capabilities share. What an address means to a gate
is the gate's; how it is written and read is here.

| Item | What it is |
| --- | --- |
| `PEER_ADDRESS` | The name the socket peer's address travels under: the property a transport writes, the evidence identification records, the fact authorization checks |
| `address::parse` | An address as a transport writes it: bare, with a port, or IPv6 in brackets |
| `Network` | A network in prefix notation, and whether an address is inside it |

Until 2026-09-22 identification and authorization each carried their own
network type, and authorization read the peer's address under a name no one
wrote, so an address rule never matched a peer identified by name.

`architecture.toml` carries the maturity.
