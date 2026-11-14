//! `net`'s calls to the operating system, Windows': the crate's one folder
//! of unsafe code (ADR-0050, amendments 2026-10-21 and 2026-11-14), each
//! file under `src/system/` lowering the lint at its top and saying of
//! every block why it is sound. The named pipe's (`pipe`, which
//! `crate::pipe` makes its pipes through), the TCP connect's (`connect`,
//! which `crate::connect` makes its sockets through), and the one
//! overlapped wait both take (`overlapped`). Every other file of the crate
//! writes no unsafe code; on Unix the crate calls the system only through
//! the standard library and `nix`.

pub(crate) mod connect;
pub(crate) mod overlapped;
pub(crate) mod pipe;
