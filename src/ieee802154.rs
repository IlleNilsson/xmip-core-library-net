//! An IEEE 802.15.4 interface of the kernel's: the one boundary Thread,
//! Zigbee and `WirelessHART` reach a radio through (ADR-0051, amendment
//! 2026-11-27). A datagram socket of `AF_IEEE802154` on one named interface
//! — `wpan0`, as Linux names its first — bound to the interface's own PAN
//! and short address, which the interface is asked for. The kernel's MAC
//! writes each frame's header, a data frame from that address to the short
//! address a send names on the same PAN, and its check sequence; what is
//! handed in and read out is the frame's payload, with the short address it
//! goes to or came from ([`Heard`]).
//!
//! **A user opens it.** A datagram socket asks for no capability, where a
//! raw one, which writes the MAC header itself, asks for `CAP_NET_RAW`.
//! Every socket bound to an interface's address hears every frame sent to
//! it, and only an interface of the first network namespace is heard at
//! all, so a network namespace of a test's own makes none.
//!
//! **Linux's alone**, its calls in this crate's one folder of unsafe code
//! (`src/system/ieee802154.rs`, ADR-0050). Elsewhere, and on a Linux whose
//! kernel carries no 802.15.4 sockets, [`Interface::open`] refuses in
//! words, naming what is missing.

use std::time::Duration;

use crate::NetError;

/// The most a PHY packet holds: `aMaxPhyPacketSize`.
pub const MAX_FRAME: usize = 127;

/// A data frame's MAC header between two short addresses on one PAN — two
/// of frame control, a sequence, the PAN, two addresses — and the two-byte
/// check sequence at its end.
const MAC_OVERHEAD: usize = 9 + 2;

/// What one frame carries above the MAC: [`MAX_FRAME`] less its header and
/// check sequence, 116 bytes.
pub const MAX_PAYLOAD: usize = MAX_FRAME - MAC_OVERHEAD;

/// The short address every node on a PAN hears.
pub const BROADCAST: u16 = 0xffff;

/// Where an interface is on the air: its PAN and its short address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub pan: u16,
    pub short: u16,
}

/// One frame's payload as it was heard, and the short address that sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub source: u16,
    pub payload: Vec<u8>,
}

/// An interface of the kernel's, its socket bound to its own address.
#[derive(Debug)]
pub struct Interface {
    name: String,
    address: Address,
    #[cfg(target_os = "linux")]
    socket: std::os::fd::OwnedFd,
}

impl Interface {
    /// The interface called `name`, its datagram socket bound to the PAN
    /// and short address the interface is on.
    ///
    /// # Errors
    /// Not Linux; a kernel without 802.15.4 sockets; no 802.15.4 interface
    /// of that name; one not yet given a PAN and a short address; or a
    /// socket the kernel refuses — each said in words.
    pub fn open(name: &str) -> Result<Self, NetError> {
        cfg_select! {
            target_os = "linux" => {
                let (socket, address) = crate::system::ieee802154::opened(name)
                    .map_err(|error| refused(name, &error))?;
                Ok(Self {
                    name: name.to_string(),
                    address,
                    socket,
                })
            }
            _ => Err(NetError::new(format!(
                "{name:?} is no interface this system has: an IEEE 802.15.4 interface is \
                 Linux's, its kernel's MAC under an AF_IEEE802154 socket"
            ))),
        }
    }

    /// The interface's name, as its Location names it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the interface is on the air, as it was opened.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// `payload` in one frame to the short address `destination` on the
    /// interface's PAN, from the interface's own.
    ///
    /// # Errors
    /// A payload over [`MAX_PAYLOAD`], or a send the kernel refused.
    pub fn send(&self, destination: u16, payload: &[u8]) -> Result<(), NetError> {
        crate::ceiling::within(payload.len(), MAX_PAYLOAD, "one 802.15.4 frame carries")?;
        cfg_select! {
            target_os = "linux" => {
                let to = Address {
                    pan: self.address.pan,
                    short: destination,
                };
                crate::system::ieee802154::sent(&self.socket, to, payload).map_err(|error| {
                    NetError::from_io(&format!("sending on {}", self.name), &error)
                })
            }
            _ => {
                let _ = destination;
                Err(NetError::new("no interface is open on this system"))
            }
        }
    }

    /// The next frame sent to the interface, waiting at most `timeout`;
    /// `None` where none came. A wait of zero looks once.
    ///
    /// # Errors
    /// A read the kernel refused.
    pub fn receive(&self, timeout: Duration) -> Result<Option<Heard>, NetError> {
        cfg_select! {
            target_os = "linux" => {
                let mut buffer = [0; MAX_FRAME];
                let read = crate::system::ieee802154::received(&self.socket, &mut buffer, timeout)
                    .map_err(|error| {
                        NetError::from_io(&format!("reading {}", self.name), &error)
                    })?;
                Ok(read.map(|(length, source)| Heard {
                    source,
                    payload: buffer[..length].to_vec(),
                }))
            }
            _ => {
                let _ = timeout;
                Err(NetError::new("no interface is open on this system"))
            }
        }
    }
}

/// Why `name` could not be opened, in words: the kernel's own where they
/// name what is missing plainly, the estate's where they do not.
#[cfg(target_os = "linux")]
fn refused(name: &str, error: &std::io::Error) -> NetError {
    use std::io::ErrorKind;
    let said = match error.raw_os_error() {
        Some(libc::EAFNOSUPPORT) => "the kernel makes no IEEE 802.15.4 socket here: its \
                                     module ieee802154_socket is not loaded — Ubuntu's \
                                     /etc/modprobe.d/blacklist-rare-network.conf keeps it \
                                     from loading on demand, and `modprobe \
                                     ieee802154_socket` loads it — or this process is in a \
                                     network namespace other than the first"
            .to_string(),
        Some(libc::ENODEV) => "no interface of that name on this machine".to_string(),
        Some(libc::ENOTTY) => "not an IEEE 802.15.4 interface".to_string(),
        Some(libc::EADDRNOTAVAIL) => "the interface has no PAN and short address yet \
                                      (`iwpan dev <name> set pan_id` and `short_addr` give \
                                      it them)"
            .to_string(),
        _ if error.kind() == ErrorKind::InvalidInput => {
            "not an interface's name: one to fifteen bytes, no NUL".to_string()
        }
        _ => error.to_string(),
    };
    NetError {
        message: format!("{name:?}: {said}"),
        io: Some(error.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_carries_what_the_phy_holds_less_the_mac() {
        assert_eq!(MAX_PAYLOAD, 116);
        let address = Address {
            pan: 0xbeef,
            short: 1,
        };
        assert_eq!(address.short, 1);
    }

    /// An interface this machine has not is refused, naming it: on Linux
    /// as the kernel answers — no such interface, or no 802.15.4 sockets
    /// at all — and elsewhere as no interface the system has.
    #[test]
    fn an_interface_not_on_this_machine_is_refused_by_name() {
        let refused = Interface::open("xmip-absent").expect_err("no such interface");
        assert!(refused.message.contains("\"xmip-absent\""), "{refused}");
        let refused = Interface::open("a-name-past-fifteen").expect_err("too long");
        assert!(refused.message.contains("a-name-past-fifteen"), "{refused}");
    }

    /// On a machine with two radios on one PAN — Linux's `mac802154_hwsim`
    /// makes them, `wpan0` and `wpan1` — a frame sent on one is heard on
    /// the other, from the sender's short address, and one over a frame is
    /// refused before it is sent. Where they are not, the test says so and
    /// holds nothing more.
    #[test]
    fn a_frame_sent_on_one_interface_is_heard_on_the_other() {
        let (near, far) = match (Interface::open("wpan0"), Interface::open("wpan1")) {
            (Ok(near), Ok(far)) => (near, far),
            (near, far) => {
                let why = near.err().or(far.err()).map(|why| why.message);
                println!("wpan0 and wpan1: SKIPPED: {}", why.unwrap_or_default());
                return;
            }
        };
        assert_eq!(near.address().pan, far.address().pan, "one PAN");
        let nonce = format!("xmip-{:?}", std::time::Instant::now()).into_bytes();
        near.send(far.address().short, &nonce).expect("sent");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let heard = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let heard = far
                .receive(left)
                .expect("read")
                .expect("a frame within 5 s");
            // Another test on the same air may send to it too.
            if heard.payload == nonce {
                break heard;
            }
        };
        assert_eq!(heard.source, near.address().short);
        assert!(near.send(far.address().short, &[0; MAX_PAYLOAD]).is_ok());
        let over = near
            .send(far.address().short, &[0; MAX_PAYLOAD + 1])
            .expect_err("over");
        assert!(over.message.contains("over the 116"), "{over}");
        assert!(
            near.receive(Duration::ZERO).is_ok(),
            "a look returns at once"
        );
    }
}
