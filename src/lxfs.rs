use std::borrow::Cow;

use ntapi::winapi::shared::minwindef::*;
use winapi::shared::basetsd::ULONG64;

pub const LXATTRB: &'static str = "LXATTRB";
pub const LXXATTR: &'static str = "LXXATTR";

pub struct LxfsParsed<'a> {
    lxattrb: Option<Cow<'a, EaLxattrbV1>>,
    lxxattr: Option<LxxattrParsed<'a>>,
}

pub struct LxxattrParsed<'a> {
    entries: Vec<LxxattrEntry<'a>>,
    changed: bool,
}

struct LxxattrEntry<'a> {
    pub name: Cow<'a, str>,
    pub value: Cow<'a, [u8]>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EaLxattrbV1 {
    flags: USHORT,        // 0
    version: USHORT,      // 1

    pub st_mode: ULONG,       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    pub st_uid: ULONG,        // Numeric identifier of user who owns file (Linux-specific).
    pub st_gid: ULONG,        // Numeric identifier of group that owns the file (Linux-specific)
    pub st_rdev: ULONG,       // Drive number of the disk containing the file.
    pub st_atime_nsec: ULONG, // Time of last access of file (nano-seconds).
    pub st_mtime_nsec: ULONG, // Time of last modification of file (nano-seconds).
    pub st_ctime_nsec: ULONG, // Time of creation of file (nano-seconds).
    pub st_atime: ULONG64,    // Time of last access of file.
    pub st_mtime: ULONG64,    // Time of last modification of file.
    pub st_ctime: ULONG64,    // Time of creation of file.
}

impl Default for EaLxattrbV1 {
    fn default() -> Self {
        Self {
            flags: 0,
            version: 1,
            st_mode: 0o0644,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_atime_nsec: 0,
            st_mtime_nsec: 0,
            st_ctime_nsec: 0,
            st_atime: 0,
            st_mtime: 0,
            st_ctime: 0,
        }
    }
}
