//! `utils/statd/notlist.c`: the doubly linked notify lists, kept as in C (an entry's
//! links are its own `next`/`prev` fields, and a list is a head), in an arena.
//!
//! Entries are never reused: C frees an entry's strings in `nlist_free()` but leaks the
//! entry itself in most paths, so nothing ever points at a recycled one. A freed entry's
//! strings are emptied.

use support::nsm_file::SM_PRIV_SIZE;

use super::hostname::statd_matchhostname;

/// `MAX_TRIES`.
pub const MAX_TRIES: i16 = 5;

/// An index into [`Lists::nodes`].
pub type Ix = usize;

/// `struct notify_list`.
#[derive(Debug, Clone, Default)]
pub struct Node {
    pub mon_name: Vec<u8>,
    pub my_name: Vec<u8>,
    pub my_prog: i32,
    pub my_vers: i32,
    pub my_proc: i32,
    pub priv_: [u8; SM_PRIV_SIZE],
    /// The callback port, host order (C keeps it in network order).
    pub port: u16,
    pub times: i16,
    pub state: i32,
    pub dns_name: Option<Vec<u8>>,
    pub next: Option<Ix>,
    pub prev: Option<Ix>,
    pub xid: u32,
    pub when: i64,
}

/// The entries, and the two lists' heads.
#[derive(Debug, Default)]
pub struct Lists {
    pub nodes: Vec<Node>,
    /// `rtnl`: the run-time monitor list.
    pub rtnl: Option<Ix>,
    /// `notify`: pending callbacks, by time.
    pub notify: Option<Ix>,
}

/// `nlist_new()`.
pub fn nlist_new(nodes: &mut Vec<Node>, my_name: &[u8], mon_name: &[u8], state: i32) -> Ix {
    nodes.push(Node {
        times: MAX_TRIES,
        state,
        my_name: my_name.to_vec(),
        mon_name: mon_name.to_vec(),
        ..Node::default()
    });
    nodes.len() - 1
}

/// `nlist_insert()`: put `entry` in front of `*head` (which may be inside a list).
pub fn nlist_insert(nodes: &mut [Node], head: &mut Option<Ix>, entry: Ix) {
    if let Some(h) = *head {
        nodes[entry].next = Some(h);
        nodes[entry].prev = nodes[h].prev;
        nodes[h].prev = Some(entry);
    }
    *head = Some(entry);
}

/// `nlist_insert_timer()`: insert `entry` before the first entry due later.
pub fn nlist_insert_timer(nodes: &mut [Node], head: &mut Option<Ix>, entry: Ix) {
    let mut spot = *head;
    let mut back: Option<Ix> = None;
    while let Some(s) = spot {
        if nodes[s].when > nodes[entry].when {
            break;
        }
        back = Some(s);
        spot = nodes[s].next;
    }
    if spot == *head {
        nlist_insert(nodes, head, entry);
    } else {
        nlist_insert(nodes, &mut spot, entry);
        // nlist_insert() always leaves spot at entry, so this always runs.
        if spot == Some(entry)
            && let Some(b) = back
        {
            nodes[b].next = Some(entry);
            nodes[entry].prev = Some(b);
        }
    }
}

/// `nlist_remove()`.
pub fn nlist_remove(nodes: &mut [Node], head: &mut Option<Ix>, entry: Ix) {
    let prev = nodes[entry].prev;
    let next = nodes[entry].next;
    if let Some(n) = next {
        nodes[n].prev = prev;
    }
    match prev {
        Some(p) => nodes[p].next = next,
        None => *head = next,
    }
    nodes[entry].next = None;
    nodes[entry].prev = None;
}

/// `nlist_clone()`.
pub fn nlist_clone(nodes: &mut Vec<Node>, entry: Ix) -> Ix {
    let (my_name, mon_name, state) = (nodes[entry].my_name.clone(), nodes[entry].mon_name.clone(), nodes[entry].state);
    let new = nlist_new(nodes, &my_name, &mon_name, state);
    nodes[new].my_prog = nodes[entry].my_prog;
    nodes[new].my_vers = nodes[entry].my_vers;
    nodes[new].my_proc = nodes[entry].my_proc;
    nodes[new].priv_ = nodes[entry].priv_;
    new
}

/// `nlist_free()`: unlink `entry` from `head` (if given and not empty) and free its
/// strings.
pub fn nlist_free(nodes: &mut [Node], head: Option<&mut Option<Ix>>, entry: Ix) {
    if let Some(h) = head
        && h.is_some()
    {
        nlist_remove(nodes, h, entry);
    }
    nodes[entry].my_name = Vec::new();
    nodes[entry].mon_name = Vec::new();
    nodes[entry].dns_name = None;
}

/// `nlist_kill()`.
pub fn nlist_kill(nodes: &mut [Node], head: &mut Option<Ix>) {
    while let Some(h) = *head {
        let next = nodes[h].next;
        nlist_free(nodes, Some(head), h);
        *head = next;
    }
}

/// `nlist_gethost()`: the first entry from `list` on whose `mon_name` (or `my_name`)
/// `host` matches.
pub fn nlist_gethost(nodes: &[Node], list: Option<Ix>, host: &[u8], myname: bool) -> Option<Ix> {
    let mut lp = list;
    while let Some(l) = lp {
        let name = if myname { &nodes[l].my_name } else { &nodes[l].mon_name };
        if statd_matchhostname(host, name) {
            return Some(l);
        }
        lp = nodes[l].next;
    }
    None
}
