//! FILETIME, 64bit, 100ns, since 1601-01-01 00:00::00
//! tv_sec, unix time_t 64bit, 1sec, since 1970-01-01 00:00:00 UTC
//! tv_nsec, 32bit, 1ns, Nano seconds of access time

use std::fmt::Display;
use std::sync::LazyLock;

use time::{format_description, Duration, OffsetDateTime};
use windows::Win32::Foundation::FILETIME;

/// a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
//pub type WinFileTime = i64;

#[derive(Clone, Copy, Debug)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct LxfsTime {
    pub tv_sec: u64,
    pub tv_nsec: u32,
}

impl LxfsTime {
    pub fn new(tv_sec: u64, tv_nsec: u32) -> Self {
        Self { tv_sec, tv_nsec }
    }
}

impl Display for LxfsTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let odt = OffsetDateTime::from_unix_timestamp(self.tv_sec as i64).map_err(|_| std::fmt::Error)?;
        let odt = odt + Duration::nanoseconds(self.tv_nsec as i64);
        f.write_str(&odt.format(&FILE_TIME_FORMAT).map_err(|_| std::fmt::Error)?)?;
        Ok(())
    }
}

impl From<(u64, u32)> for LxfsTime {
    fn from((tv_sec, tv_nsec): (u64, u32)) -> Self {
        LxfsTime { tv_sec, tv_nsec }
    }
}

impl Into<(u64, u32)> for LxfsTime {
    fn into(self) -> (u64, u32) {
        (self.tv_sec, self.tv_nsec)
    }
}

impl From<u64> for LxfsTime {
    fn from(t64: u64) -> Self {
        u64_to_lxfs_time(t64)
    }
}

impl From<FILETIME> for LxfsTime {
    fn from(ft: FILETIME) -> Self {
        filetime_to_lxfs_time(ft)
    }
}

impl Into<FILETIME> for LxfsTime {
    fn into(self) -> FILETIME {
        lxfs_time_to_filetime(self)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UlargeIntegerS {
    low_part: u32,
    high_part: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
union ULARGE_INTEGER {
    s: UlargeIntegerS,
    u: UlargeIntegerS,
    quad_part: u64,
}

pub fn u64_to_filetime(t64: u64) -> FILETIME {
    let mut ull = ULARGE_INTEGER { quad_part: t64 };
    let s = unsafe { &mut ull.s };
    FILETIME {
        dwLowDateTime: s.low_part,
        dwHighDateTime: s.high_part,
    }
}

pub fn filetime_to_u64(ft: FILETIME) -> u64 {
    let mut ull = ULARGE_INTEGER { quad_part: 0 };
    let s = unsafe { &mut ull.s };
    s.low_part = ft.dwLowDateTime;
    s.high_part = ft.dwHighDateTime;
    let t64 = unsafe { ull.quad_part };
    return t64;
}

pub fn lxfs_time_to_filetime(lt: LxfsTime) -> FILETIME {
    let t64 = lxfs_time_to_u64(lt);
    u64_to_filetime(t64)
}

pub fn filetime_to_lxfs_time(ft: FILETIME) -> LxfsTime {
    let t64 = filetime_to_u64(ft);
    u64_to_lxfs_time(t64)
}

pub fn lxfs_time_to_u64(lt: LxfsTime) -> u64 {
    (lt.tv_sec * 10000000u64) + 116444736000000000u64 + (lt.tv_nsec as u64/100)
}

pub fn u64_to_lxfs_time(t64: u64) -> LxfsTime {
    let (sec, ns100) = ( t64 / 10000000u64, t64 % 10000000u64);
    LxfsTime {
        tv_sec: sec - 11644473600u64,
        tv_nsec: (ns100 as u32) * 100u32,
    }
}

pub const FILE_TIME_FORMAT_STR: &'static str = "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:7] UTC";

pub static FILE_TIME_FORMAT: LazyLock<Vec<format_description::FormatItem<'static>>> = LazyLock::new(|| {
    format_description::parse(FILE_TIME_FORMAT_STR).unwrap()
});

#[test]
fn test_convert() {
    let tv = LxfsTime {
        tv_sec: 1729741525,
        tv_nsec: 3480100,
    };
    let ft = lxfs_time_to_filetime(tv);

    assert_eq!(tv, filetime_to_lxfs_time(ft));
}

#[test]
fn test_display() {
    let tv_sec: u64 = 1729741525;
    let tv_nsec: u32 = 3480100;

    let odt = OffsetDateTime::from_unix_timestamp(tv_sec as i64).unwrap() + Duration::nanoseconds(tv_nsec as i64);
    println!("myformat: {}", odt.format(&FILE_TIME_FORMAT).unwrap());
    println!("default: {}", odt);

    assert_eq!("2024-10-24 03:45:25.0034801 UTC", odt.format(&FILE_TIME_FORMAT).unwrap());
}
