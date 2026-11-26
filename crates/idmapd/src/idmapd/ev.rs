//! What rpc.idmapd uses of libevent 2.1 (`event_base_new()`, `event_new()`,
//! `evsignal_new()`, `evtimer_new()`, `event_add()`, `event_free()`,
//! `event_base_loopexit()` and `event_base_dispatch()`), with its epoll backend's
//! behavior: the same descriptors, opened in the same order, the same `epoll_ctl()` and
//! `epoll_wait()` calls, the self-pipe its signal handler writes to, and the order in
//! which ready events run.
//!
//! One pass of the loop: `epoll_wait()` (with no timeout when a timer is due), then the
//! ready descriptors' events in the order the kernel reported them, then the due
//! timers, all run first in, first out from one queue; an event that becomes active
//! during the pass (a signal, read from the pipe) joins the end of the queue. Freeing an
//! event takes it off the queue. Signals arrive through the pipe and run their event
//! once per delivery, the lowest signal number first when several came in together.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::Relaxed};

use support::sys::{self, Fd};

pub const EV_TIMEOUT: i16 = 0x01;
pub const EV_READ: i16 = 0x02;
pub const EV_SIGNAL: i16 = 0x08;

/// `INITIAL_NEVENT` and `MAX_NEVENT`.
const INITIAL_NEVENT: usize = 32;
const MAX_NEVENT: usize = 4096;

/// `evsig_base_fd`: the pipe's write end, for the handler.
static SIG_W: AtomicI32 = AtomicI32::new(-1);
/// Set by [`loopexit`] (from a signal handler): `event_base_loopexit()`'s once-event,
/// which joins the active queue.
static LOOPEXIT: AtomicBool = AtomicBool::new(false);

/// `evsig_handler()`: one byte, the signal number, down the pipe.
extern "C" fn evsig_handler(sig: libc::c_int) {
    let saved = sys::errno();
    let _ = sys::write(SIG_W.load(Relaxed), &[sig as u8]);
    sys::set_errno(saved);
}

/// `event_base_loopexit(base, NULL)`: safe to call from a signal handler.
pub fn loopexit() {
    LOOPEXIT.store(true, Relaxed);
}

/// libevent's `event_log()` with no log function set: `[severity] msg` on stderr.
fn event_log(severity: &str, msg: &[u8]) {
    let mut m = format!("[{severity}] ").into_bytes();
    m.extend_from_slice(msg);
    m.push(b'\n');
    sys::stderr(&m);
}

/// `event_warn()`: the message, `: strerror(errno)`.
fn event_warn(msg: &[u8]) {
    let mut m = msg.to_vec();
    m.extend_from_slice(b": ");
    m.extend_from_slice(&sys::strerror(sys::errno()));
    event_log("warn", &m);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read(Fd),
    Signal(i32),
    Timer,
}

#[derive(Debug)]
struct Event<T> {
    kind: Kind,
    tok: T,
    /// `EVLIST_INSERTED` (or, for a timer, on the timer list).
    added: bool,
    /// On the active queue.
    active: bool,
    /// Signal deliveries still to run.
    ncalls: u32,
}

/// An event handle (`struct event *`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvId(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Active {
    Ev(usize),
    /// The internal event on the pipe's read end.
    SigPipe,
    /// `event_base_loopexit()`'s once-event.
    LoopExit,
}

/// What `event_base_dispatch()` returned when the loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    /// Asked to (`event_base_loopexit()`): 0.
    Exit,
    /// No events left: 1.
    Empty,
    /// The backend failed: -1.
    Failed,
}

/// `struct event_base` with its epoll backend.
#[derive(Debug)]
pub struct Base<T> {
    epfd: Fd,
    sig_r: Fd,
    sig_w: Fd,
    nevents: usize,
    events: Vec<Option<Event<T>>>,
    queue: VecDeque<Active>,
    /// Timers due now (`evtimer_add()` with a zero timeout), in the order added.
    timers: Vec<usize>,
    sig_added: bool,
    gotterm: bool,
    /// The read ends whose events are registered with epoll, by descriptor.
    registered: Vec<(Fd, usize)>,
}

impl<T: Copy> Base<T> {
    /// `event_base_new()`: `epoll_create1(EPOLL_CLOEXEC)` (else `epoll_create()`), then
    /// the signal pipe with `pipe2(O_NONBLOCK|O_CLOEXEC)` (else `pipe()`). Without
    /// descriptors for both, libevent would fall back to `poll()`, whose set-up needs
    /// the pipe too and exits.
    pub fn new() -> Base<T> {
        let mut epfd = sys::epoll_create1(libc::EPOLL_CLOEXEC);
        if epfd == -1 {
            epfd = sys::epoll_create(32000);
            if epfd == -1 {
                if sys::errno() != libc::ENOSYS {
                    event_warn(b"epoll_create");
                }
            } else {
                sys::set_cloexec(epfd);
            }
        }
        let (r, w) = match sys::pipe2(libc::O_NONBLOCK | libc::O_CLOEXEC) {
            Some(p) => p,
            None => match sys::pipe() {
                Some((r, w)) => {
                    for fd in [r, w] {
                        sys::setfl(fd, sys::getfl(fd) | libc::O_NONBLOCK);
                        sys::set_cloexec(fd);
                    }
                    (r, w)
                }
                None => {
                    event_warn(b"evutil_make_internal_pipe_: pipe");
                    let mut m = b"evsig_init_: socketpair: ".to_vec();
                    m.extend_from_slice(&sys::strerror(sys::errno()));
                    event_log("err", &m);
                    sys::exit(1);
                }
            },
        };
        Base {
            epfd,
            sig_r: r,
            sig_w: w,
            nevents: INITIAL_NEVENT,
            events: Vec::new(),
            queue: VecDeque::new(),
            timers: Vec::new(),
            sig_added: false,
            gotterm: false,
            registered: Vec::new(),
        }
    }

    fn push(&mut self, kind: Kind, tok: T) -> EvId {
        self.events.push(Some(Event { kind, tok, added: false, active: false, ncalls: 0 }));
        EvId(self.events.len() - 1)
    }

    /// `event_new(base, fd, EV_READ | EV_PERSIST, cb, arg)`.
    pub fn new_read(&mut self, fd: Fd, tok: T) -> EvId {
        self.push(Kind::Read(fd), tok)
    }

    /// `evsignal_new(base, sig, cb, arg)` (persistent).
    pub fn new_signal(&mut self, sig: i32, tok: T) -> EvId {
        self.push(Kind::Signal(sig), tok)
    }

    /// `evtimer_new(base, cb, arg)`.
    pub fn new_timer(&mut self, tok: T) -> EvId {
        self.push(Kind::Timer, tok)
    }

    /// `event_add(ev, NULL)` (a timer: `event_add(ev, &zero)`): 0, or -1 when epoll
    /// refused the descriptor (libevent says so on stderr).
    pub fn add(&mut self, id: EvId) -> i32 {
        let Some(ev) = self.events[id.0].as_ref() else { return -1 };
        if ev.added {
            return 0;
        }
        match ev.kind {
            Kind::Read(fd) => {
                if self.ctl_add(fd) != 0 {
                    return -1;
                }
                self.registered.push((fd, id.0));
            }
            Kind::Signal(sig) => {
                SIG_W.store(self.sig_w, Relaxed);
                sys::sigaction_blocking_all(sig, evsig_handler);
                if !self.sig_added {
                    if self.ctl_add(self.sig_r) != 0 {
                        return -1;
                    }
                    self.sig_added = true;
                }
            }
            Kind::Timer => self.timers.push(id.0),
        }
        if let Some(ev) = self.events[id.0].as_mut() {
            ev.added = true;
        }
        0
    }

    /// `epoll_apply_one_change()` for an add: `EPOLL_CTL_ADD`, retried as
    /// `EPOLL_CTL_MOD` on `EEXIST`.
    fn ctl_add(&mut self, fd: Fd) -> i32 {
        let events = libc::EPOLLIN as u32;
        if sys::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, events) == 0 {
            return 0;
        }
        if sys::errno() == libc::EEXIST {
            if sys::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, events) == -1 {
                event_warn(&support::bfmt!("Epoll ADD({}) on {} retried as MOD; that failed too", events as i32, fd));
                return -1;
            }
            return 0;
        }
        event_warn(&support::bfmt!(
            "Epoll ADD({}) on fd {} failed. Old events were 0; read change was 1 (add); write change was 0 (none); close change was 0 (none)",
            events as i32,
            fd
        ));
        -1
    }

    /// `event_free(ev)`: deleted (`EPOLL_CTL_DEL` for a descriptor, whose failures
    /// libevent ignores), off the active queue, and gone.
    pub fn free(&mut self, id: EvId) {
        let Some(ev) = self.events[id.0].take() else { return };
        if ev.added {
            match ev.kind {
                Kind::Read(fd) => {
                    self.registered.retain(|&(_, i)| i != id.0);
                    sys::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, fd, 0);
                }
                Kind::Timer => self.timers.retain(|&i| i != id.0),
                // rpc.idmapd frees its signal events only on the way out.
                Kind::Signal(_) => {}
            }
        }
        if ev.active {
            self.queue.retain(|a| *a != Active::Ev(id.0));
        }
    }

    fn activate(&mut self, idx: usize, ncalls: u32) {
        if let Some(ev) = self.events[idx].as_mut() {
            if ev.active {
                return;
            }
            ev.active = true;
            ev.ncalls = ncalls;
            self.queue.push_back(Active::Ev(idx));
        }
    }

    /// `event_haveevents()`: any non-internal event added.
    fn have_events(&self) -> bool {
        self.events.iter().flatten().any(|e| e.added)
    }

    /// The top of `event_base_loop()`'s pass, then `dispatch()` and
    /// `timeout_process()`: fills the active queue. `Some` when the loop ends.
    pub fn wait(&mut self) -> Option<Done> {
        if self.gotterm {
            return Some(Done::Exit);
        }
        if !self.have_events() && self.queue.is_empty() {
            return Some(Done::Empty);
        }
        let timeout = if self.timers.is_empty() { -1 } else { 0 };
        match sys::epoll_wait(self.epfd, self.nevents, timeout) {
            Err(e) if e == libc::EINTR => {}
            Err(_) => {
                event_warn(b"epoll_wait");
                return Some(Done::Failed);
            }
            Ok(ready) => {
                let n = ready.len();
                for (what, fd) in ready {
                    let what = what as i32;
                    let readable = what & (libc::EPOLLERR | libc::EPOLLHUP | libc::EPOLLIN) != 0;
                    if !readable {
                        continue;
                    }
                    if fd == self.sig_r && self.sig_added {
                        if !self.queue.contains(&Active::SigPipe) {
                            self.queue.push_back(Active::SigPipe);
                        }
                    } else if let Some(&(_, idx)) = self.registered.iter().find(|&&(f, _)| f == fd) {
                        self.activate(idx, 0);
                    }
                }
                if n == self.nevents && self.nevents < MAX_NEVENT {
                    self.nevents *= 2;
                }
            }
        }
        // timeout_process(): due timers are deleted, then activated.
        for idx in std::mem::take(&mut self.timers) {
            if let Some(ev) = self.events[idx].as_mut() {
                ev.added = false;
            }
            self.activate(idx, 0);
        }
        None
    }

    /// The next callback to run from the active queue: its token, the `fd` argument
    /// libevent passes (the descriptor, the signal number, or -1 for a timer) and the
    /// result flags. Internal events run here.
    pub fn next(&mut self) -> Option<(T, Fd, i16)> {
        loop {
            if LOOPEXIT.swap(false, Relaxed) {
                self.queue.push_back(Active::LoopExit);
            }
            let a = *self.queue.front()?;
            match a {
                Active::LoopExit => {
                    self.queue.pop_front();
                    self.gotterm = true;
                }
                Active::SigPipe => {
                    self.queue.pop_front();
                    self.evsig_cb();
                }
                Active::Ev(idx) => {
                    let Some(ev) = self.events[idx].as_mut() else {
                        self.queue.pop_front();
                        continue;
                    };
                    match ev.kind {
                        Kind::Signal(sig) => {
                            if ev.ncalls <= 1 {
                                ev.active = false;
                                self.queue.pop_front();
                            } else {
                                ev.ncalls -= 1;
                            }
                            return Some((ev.tok, sig, EV_SIGNAL));
                        }
                        Kind::Read(fd) => {
                            ev.active = false;
                            self.queue.pop_front();
                            return Some((ev.tok, fd, EV_READ));
                        }
                        Kind::Timer => {
                            ev.active = false;
                            self.queue.pop_front();
                            return Some((ev.tok, -1, EV_TIMEOUT));
                        }
                    }
                }
            }
        }
    }

    /// `evsig_cb()`: drain the pipe, then activate each signal's events with the
    /// number of deliveries, lowest signal first.
    fn evsig_cb(&mut self) {
        let mut ncaught = [0u32; 65];
        let mut buf = [0u8; 1024];
        loop {
            let n = sys::read(self.sig_r, &mut buf);
            if n <= 0 {
                break;
            }
            for &b in &buf[..n as usize] {
                if (b as usize) < ncaught.len() {
                    ncaught[b as usize] += 1;
                }
            }
        }
        for (sig, &n) in ncaught.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let ids: Vec<usize> = self
                .events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| e.as_ref().filter(|e| e.added && e.kind == Kind::Signal(sig as i32)).map(|_| i))
                .collect();
            for i in ids {
                self.activate(i, n);
            }
        }
    }
}
