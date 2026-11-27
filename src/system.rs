//! `net`'s calls to the operating system: the crate's one folder of unsafe
//! code (ADR-0050, amendments 2026-10-21, 2026-11-14 and 2026-11-27), each
//! file under `src/system/` lowering the lint at its top and saying of
//! every block why it is sound. Windows': the named pipe's (`pipe`, which
//! `crate::pipe` makes its pipes through), the TCP connect's (`connect`,
//! which `crate::connect` makes its sockets through), and the one
//! overlapped wait both take (`overlapped`), public for every other call
//! into Windows in the estate that waits on an overlapped operation — a
//! serial port's (ADR-0064, amendment 2026-11-15). Linux's: an IEEE
//! 802.15.4 interface's socket (`ieee802154`, which `crate::ieee802154`
//! opens, sends and reads through). Every other file of the crate writes no
//! unsafe code; otherwise on Unix the crate calls the system only through
//! the standard library and `nix`.

#[cfg(windows)]
pub(crate) mod connect;
#[cfg(target_os = "linux")]
pub(crate) mod ieee802154;
#[cfg(windows)]
pub mod overlapped;
#[cfg(windows)]
pub(crate) mod pipe;
