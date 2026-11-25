//! The parts of nfs-utils 2.8.5's `support/` that `rpc.statd`, `sm-notify` and the
//! id-mapping programs use: `xlog.c`, `conffile.c`, `support/nsm` (the on-disk monitor
//! records and the hand-built NSM calls), and the helpers they need from
//! `support/misc` and `support/nfs`. Each module names the file it ports.

/// Format bytes like C's `printf("%s ...")`: `bfmt!("a {} b {}", x, y)` with each
/// argument a [`Piece`] (byte strings, strings, integers). Each `{}` takes the next
/// argument.
#[macro_export]
macro_rules! bfmt {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        let pieces: &[&dyn $crate::Piece] = &[$(&$arg),*];
        $crate::format_pieces($fmt, pieces)
    }};
}

pub mod conffile;
pub mod misc;
pub mod nsm_file;
pub mod nsm_rpc;
pub mod sockaddr;
pub mod sys;
pub mod xlog;

/// Something [`bfmt!`] can print.
pub trait Piece {
    fn put(&self, out: &mut Vec<u8>);
}

impl Piece for [u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &[u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl<const N: usize> Piece for &[u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self[..]);
    }
}
impl Piece for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl Piece for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
macro_rules! int_piece {
    ($($t:ty),*) => {$(
        impl Piece for $t {
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(self.to_string().as_bytes());
            }
        }
    )*};
}
int_piece!(i32, u32, i64, u64, usize, u16, u8);

/// [`bfmt!`]'s worker.
pub fn format_pieces(fmt: &str, pieces: &[&dyn Piece]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len() + 32);
    let mut rest = fmt;
    let mut i = 0;
    while let Some(p) = rest.find("{}") {
        out.extend_from_slice(&rest.as_bytes()[..p]);
        if let Some(a) = pieces.get(i) {
            a.put(&mut out);
        }
        i += 1;
        rest = &rest[p + 2..];
    }
    out.extend_from_slice(rest.as_bytes());
    out
}
