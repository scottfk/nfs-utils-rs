//! `utils/statd/rmtcall.c`: the socket statd calls lockd back on, and the callback list
//! (`notify`): asking the local portmapper for lockd's port, then making the call.

use support::bfmt;
use support::nsm_file::Mon;
use support::nsm_rpc::{NSM_MAXMSGSIZE, nsm_parse_reply, nsm_recv_getport, nsm_xmit_getport, nsm_xmit_nlmcall};
use support::sys::{self, Fd, FdSet};
use support::xlog::{D_GENERAL, L_ERROR, m, xlog, xlog_warn};
use tirpc::xdr::XdrMem;

use super::State;
use super::notlist::{Ix, nlist_free, nlist_insert_timer, nlist_remove};

/// `MAX_BRP_RETRIES`.
const MAX_BRP_RETRIES: usize = 100;
/// `NOTIFY_TIMEOUT`.
pub const NOTIFY_TIMEOUT: i64 = 5;

/// A `sockaddr_in` for 127.0.0.1 at `port` (host order).
fn loopback_sin(port: u16) -> Vec<u8> {
    let mut sin = vec![0u8; size_of::<libc::sockaddr_in>()];
    sin[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    sin[2..4].copy_from_slice(&port.to_be_bytes());
    sin[4..8].copy_from_slice(&[127, 0, 0, 1]);
    sin
}

impl State {
    /// `statd_get_socket()`: a UDP socket on 127.0.0.1 at a reserved port that isn't a
    /// known service. Returns the descriptor or -1.
    pub fn statd_get_socket(&mut self) -> Fd {
        if self.sockfd >= 0 {
            return self.sockfd;
        }
        let mut prevsocks: Vec<Fd> = Vec::new();
        loop {
            self.sockfd = sys::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
            if self.sockfd < 0 {
                xlog(L_ERROR, &bfmt!("statd_get_socket: Can't create socket: {}", m()));
                break;
            }
            let mut sin = loopback_sin(0);
            if tirpc::clnt::bindresvport_sa(&mut self.lib, self.sockfd, Some(&mut sin)) < 0 {
                // QUIRK: the socket is kept, unbound.
                xlog(D_GENERAL, b"statd_get_socket: can't bind to reserved port");
                break;
            }
            // sin.sin_port, in network order, as getservbyport() wants it.
            if !sys::getservbyport_raw(i32::from(u16::from_ne_bytes([sin[2], sin[3]])), b"udp") {
                break;
            }
            if prevsocks.len() == MAX_BRP_RETRIES {
                xlog(D_GENERAL, b"statd_get_socket: No unused privileged ports");
                break;
            }
            prevsocks.push(self.sockfd);
        }
        while let Some(fd) = prevsocks.pop() {
            sys::close(fd);
        }
        if self.sockfd < 0 {
            return -1;
        }
        self.sockfd
    }

    /// `recv_rply()`: the pending callback a reply on the socket is for (and, if it was
    /// waiting for lockd's port, the port), or `None`.
    fn recv_rply(&mut self, portp: &mut u64) -> Option<Ix> {
        let mut msgbuf = [0u8; NSM_MAXMSGSIZE];
        let (msglen, sin) = sys::recvfrom(self.sockfd, &mut msgbuf, size_of::<libc::sockaddr_in>());
        if msglen == -1 {
            xlog_warn(&bfmt!("recv_rply: recvfrom failed: {}", m()));
            return None;
        }
        let mut x = XdrMem::new(&mut msgbuf[..msglen as usize]);
        let xid = nsm_parse_reply(&mut x);
        if xid == 0 {
            return None;
        }
        if sin[4..8] != [127, 0, 0, 1] {
            let a = std::net::Ipv4Addr::new(sin[4], sin[5], sin[6], sin[7]).to_string();
            xlog_warn(&bfmt!("recv_rply: Unrecognized reply from {}", a));
            return None;
        }
        let mut lp = self.l.notify;
        while let Some(i) = lp {
            if self.l.nodes[i].xid == xid {
                if self.l.nodes[i].port == 0 {
                    *portp = nsm_recv_getport(&mut x);
                }
                return Some(i);
            }
            lp = self.l.nodes[i].next;
        }
        None
    }

    /// `process_entry()`: send the next call for a callback (the port query, or the
    /// callback itself). 0 once it has run out of tries.
    fn process_entry(&mut self, i: Ix) -> i32 {
        if self.l.nodes[i].times == 0 {
            xlog(D_GENERAL, b"process_entry: Cannot notify localhost, giving up");
            return 0;
        }
        let n = &self.l.nodes[i];
        let sin = loopback_sin(n.port);
        let xid = if n.port == 0 {
            nsm_xmit_getport(self.sockfd, &sin, n.my_prog as u32, n.my_vers as u32)
        } else {
            let mon = Mon {
                mon_name: n.mon_name.clone(),
                my_name: Vec::new(),
                my_prog: n.my_prog as u32,
                my_vers: n.my_vers as u32,
                my_proc: n.my_proc as u32,
                priv_: n.priv_,
            };
            nsm_xmit_nlmcall(self.sockfd, &sin, &mon, n.state)
        };
        self.l.nodes[i].xid = xid;
        if xid == 0 {
            xlog_warn(&bfmt!("process_entry: failed to notify port {}", self.l.nodes[i].port));
        }
        self.l.nodes[i].times -= 1;
        1
    }

    /// `process_reply()`: handle a datagram on the callback socket, if `rfds` has it.
    /// Returns 1 if it did.
    pub fn process_reply(&mut self, rfds: &mut FdSet) -> i32 {
        if self.sockfd == -1 || !sys::fd_isset(self.sockfd, rfds) {
            return 0;
        }
        sys::fd_clr(self.sockfd, rfds);
        let mut port: u64 = 0;
        let Some(lp) = self.recv_rply(&mut port) else {
            return 1;
        };
        if self.l.nodes[lp].port == 0 {
            if port != 0 {
                self.l.nodes[lp].port = port as u16;
                self.process_entry(lp);
                self.l.nodes[lp].when = sys::time() + NOTIFY_TIMEOUT;
                nlist_remove(&mut self.l.nodes, &mut self.l.notify, lp);
                nlist_insert_timer(&mut self.l.nodes, &mut self.l.notify, lp);
                return 1;
            }
            xlog_warn(&bfmt!("process_reply: service {} not registered on localhost", self.l.nodes[lp].my_prog));
        } else {
            let n = &self.l.nodes[lp];
            xlog(D_GENERAL, &bfmt!("process_reply: Callback to {} (for {}) succeeded", n.my_name, n.mon_name));
        }
        nlist_free(&mut self.l.nodes, Some(&mut self.l.notify), lp);
        1
    }

    /// `process_notify_list()`: send what's due (strictly before now).
    pub fn process_notify_list(&mut self) {
        while let Some(e) = self.l.notify {
            if self.l.nodes[e].when >= sys::time() {
                break;
            }
            if self.process_entry(e) != 0 {
                self.l.nodes[e].when = sys::time() + NOTIFY_TIMEOUT;
                nlist_remove(&mut self.l.nodes, &mut self.l.notify, e);
                nlist_insert_timer(&mut self.l.nodes, &mut self.l.notify, e);
            } else {
                let n = &self.l.nodes[e];
                xlog(
                    L_ERROR,
                    &bfmt!(
                        "process_notify_list: Can't callback {} ({},{}), giving up",
                        n.my_name,
                        n.my_prog,
                        n.my_vers
                    ),
                );
                nlist_free(&mut self.l.nodes, Some(&mut self.l.notify), e);
            }
        }
    }
}
