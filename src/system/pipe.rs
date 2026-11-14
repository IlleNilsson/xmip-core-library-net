//! The named pipe's calls into Windows, which `crate::pipe`'s Windows half
//! makes, accepts, connects to, reads and writes its pipes through: the
//! accounts its descriptor admits and its client runs as (`account`), the
//! client end (`client`), the server end and its instances (`instance`),
//! and the overlapped operations of either (`io`).

pub(crate) mod account;
pub(crate) mod client;
pub(crate) mod instance;
pub(crate) mod io;
