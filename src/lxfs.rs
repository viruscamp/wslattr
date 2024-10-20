use std::mem::transmute_copy;

use ntapi::winapi::shared::minwindef::*;
use winapi::shared::basetsd::ULONG64;

pub const LXATTRB: &'static str = "LXATTRB";

#[derive(Copy, Clone, Default, Debug)]
pub struct EaLxattrbV1 {
    flags: USHORT,
    version: USHORT,

    st_mode: ULONG,       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    st_uid: ULONG,        // Numeric identifier of user who owns file (Linux-specific).
    st_gid: ULONG,        // Numeric identifier of group that owns the file (Linux-specific)
    st_rdev: ULONG,       // Drive number of the disk containing the file.
    st_atime_nsec: ULONG, // Time of last access of file (nano-seconds).
    st_mtime_nsec: ULONG, // Time of last modification of file (nano-seconds).
    st_ctime_nsec: ULONG, // Time of creation of file (nano-seconds).
    st_atime: ULONG64,    // Time of last access of file.
    st_mtime: ULONG64,    // Time of last modification of file.
    st_ctime: ULONG64,    // Time of creation of file.
}

pub unsafe fn lxattrb_from_ea_value(data: &[u8]) -> EaLxattrbV1 {
    assert!(data.len() >= size_of::<EaLxattrbV1>());
    *(data.as_ptr() as *const EaLxattrbV1)
}