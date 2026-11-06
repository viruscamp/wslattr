//! FILETIME, 64bit, 100ns, since 1601-01-01 00:00::00
//! tv_sec, unix time_t 64bit, 1sec, since 1970-01-01 00:00:00 UTC
//! tv_nsec, 32bit, 1ns, Nano seconds of access time

use std::fmt::Display;

use time::{Duration, OffsetDateTime};
use time::format_description::StaticFormatDescription;
use time::macros::format_description;
use windows::Win32::Foundation::FILETIME;

/// a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
/// value < 0 is invalid
pub type WinFileTime = i64;

/// POSIX timespec actually
#[derive(Clone, Copy, Debug)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct LxfsTime {
    pub tv_sec: i64,
    pub tv_nsec: i32,
}

impl LxfsTime {
    pub fn new(tv_sec: i64, tv_nsec: i32) -> Self {
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

impl From<(i64, i32)> for LxfsTime {
    fn from((tv_sec, tv_nsec): (i64, i32)) -> Self {
        LxfsTime { tv_sec, tv_nsec }
    }
}

impl Into<(i64, i32)> for LxfsTime {
    fn into(self) -> (i64, i32) {
        (self.tv_sec, self.tv_nsec)
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

pub fn i64_to_filetime(mut t64: i64) -> FILETIME {
    if t64 < 0 {
        t64 = 0;
    }
    FILETIME {
        dwLowDateTime: t64 as u32,
        dwHighDateTime: (t64 >> 32) as u32,
    }
}

pub fn filetime_to_u64(ft: FILETIME) -> u64 {
    ft.dwHighDateTime as u64 * 0x100000000u64 + ft.dwLowDateTime as u64
}

pub const SECS_1601_TO_1970: i64 = 60 * 60 * 24 * (365 * (1970-1601) + 89);

/// overrange value will be set to 0(1601-01-01 00:00:00)
pub fn lxfs_time_to_filetime(lt: LxfsTime) -> FILETIME {
    let t64 = (lt.tv_sec + SECS_1601_TO_1970) * 10000000 + (lt.tv_nsec as i64 / 100);
    i64_to_filetime(t64)
}

pub fn filetime_to_lxfs_time(ft: FILETIME) -> LxfsTime {
    let t64 = filetime_to_u64(ft);
    let (sec, ns100) = (t64 / 10000000, t64 % 10000000);
    LxfsTime {
        tv_sec: sec as i64 - SECS_1601_TO_1970,
        tv_nsec: (ns100 as i32) * 100,
    }
}

pub fn i64_to_lxfs_time(t64: i64) -> LxfsTime {
    filetime_to_lxfs_time(i64_to_filetime(t64))
}

pub const FILE_TIME_FORMAT: StaticFormatDescription = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:7] UTC");

#[test]
fn test_convert() {
    let lxtv = LxfsTime {
        tv_sec: 1729741525,
        tv_nsec: 3480100,
    };
    let ft = lxfs_time_to_filetime(lxtv);

    assert_eq!(lxtv, filetime_to_lxfs_time(ft));
}

#[test]
fn test_display() {
    let lxtv = LxfsTime {
        tv_sec: 1729741525,
        tv_nsec: 3480100,
    };

    assert_eq!("2024-10-24 03:45:25.0034801 UTC", lxtv.to_string());

    let odt = OffsetDateTime::from_unix_timestamp(lxtv.tv_sec as i64).unwrap() + Duration::nanoseconds(lxtv.tv_nsec as i64);
    println!("myformat: {}", odt.format(FILE_TIME_FORMAT).unwrap());
    println!("default: {}", odt);

    assert_eq!("2024-10-24 03:45:25.0034801 UTC", odt.format(FILE_TIME_FORMAT).unwrap());
}

#[test]
fn test_filetime() {
    //let ft = u64_to_filetime(1);
    //let lxtv = filetime_to_lxfs_time(ft);

    let d1 = time::macros::datetime!(1601-02-03 04:05:06.789000000 UTC);
    println!("d1: {}", d1.format(FILE_TIME_FORMAT).unwrap());
    assert_eq!(
        d1.format(FILE_TIME_FORMAT).unwrap(),
        "1601-02-03 04:05:06.7890000 UTC"
    );

    let odt = OffsetDateTime::from_unix_timestamp(-3).unwrap();
    println!("myformat: {}", odt.format(FILE_TIME_FORMAT).unwrap());
    println!("default: {}", odt);
}