//! FILETIME, 64bit, 100ns, since 1601-01-01 00:00::00
//! tv_sec, unix time_t 64bit, 1sec, since 1970-01-01 00:00:00 UTC
//! tv_nsec, 32bit, 1ns, Nano seconds of access time

use std::fmt::Display;
use std::time::SystemTime;

use time::{Duration, OffsetDateTime};
use time::format_description::StaticFormatDescription;
use time::macros::format_description;
use windows::Win32::Foundation::FILETIME;

/// a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
/// value < 0 is invalid
pub type WinFileTime = i64;

/// POSIX timespec actually
#[derive(Clone, Copy, Debug)]
#[derive(PartialEq, PartialOrd)]
pub struct LxfsTime {
    pub tv_sec: i64,
    /// 0 ~ 999_999_999
    pub tv_nsec: i32,
}

impl LxfsTime {
    pub fn new(tv_sec: i64, tv_nsec: i32) -> Self {
        Self { tv_sec, tv_nsec }
    }
}

pub const FILE_TIME_FORMAT: StaticFormatDescription = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:9] UTC");

impl Display for LxfsTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(odt) = OffsetDateTime::from_unix_timestamp(self.tv_sec) {
            let odt = odt + Duration::nanoseconds(self.tv_nsec as i64);
            f.write_str(&odt.format(&FILE_TIME_FORMAT).map_err(|_| std::fmt::Error)?)?;
        } else {
            f.write_fmt(format_args!("Invalid {:?}", self))?;
        }
        Ok(())
    }
}

impl From<(i64, i32)> for LxfsTime {
    fn from((tv_sec, tv_nsec): (i64, i32)) -> Self {
        LxfsTime { tv_sec, tv_nsec }
    }
}

impl From<LxfsTime> for (i64, i32) {
    fn from(t: LxfsTime) -> Self {
        (t.tv_sec, t.tv_nsec)
    }
}

impl From<FILETIME> for LxfsTime {
    fn from(ft: FILETIME) -> Self {
        filetime_to_lxfs_time(ft)
    }
}

impl From<LxfsTime> for FILETIME {
    fn from(lt: LxfsTime) -> FILETIME {
        lxfs_time_to_filetime(lt)
    }
}

pub const fn i64_to_filetime(mut t64: i64) -> FILETIME {
    if t64 < 0 {
        t64 = 0;
    }
    FILETIME {
        dwLowDateTime: t64 as u32,
        dwHighDateTime: (t64 >> 32) as u32,
    }
}

pub const fn filetime_to_i64(ft: FILETIME) -> i64 {
    // check ft >= 0
    ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64
}

pub const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;
pub const SECS_1601_TO_1970: i64 = 60 * 60 * 24 * (365 * (1970-1601) + 89);

pub const FILETIME_MIN: FILETIME = i64_to_filetime(0);
pub const FILETIME_MAX: FILETIME = i64_to_filetime(i64::MAX);

pub const FILETIME_MIN_LXFS_TIME: LxfsTime = filetime_to_lxfs_time(FILETIME_MIN);
pub const FILETIME_MAX_LXFS_TIME: LxfsTime = filetime_to_lxfs_time(FILETIME_MAX);

pub const fn lxfs_time_to_filetime(lt: LxfsTime) -> FILETIME {
    if lt.tv_sec < FILETIME_MIN_LXFS_TIME.tv_sec
        || (lt.tv_sec == FILETIME_MIN_LXFS_TIME.tv_sec
            && lt.tv_nsec < FILETIME_MIN_LXFS_TIME.tv_nsec)
    {
        return FILETIME_MIN;
    }
    if lt.tv_sec > FILETIME_MAX_LXFS_TIME.tv_sec
        || (lt.tv_sec == FILETIME_MAX_LXFS_TIME.tv_sec
            && lt.tv_nsec > FILETIME_MAX_LXFS_TIME.tv_nsec)
    {
        return FILETIME_MAX;
    }
    let t64 = (lt.tv_sec + SECS_1601_TO_1970) * FILETIME_TICKS_PER_SEC + (lt.tv_nsec as i64 / 100);
    i64_to_filetime(t64)
}

pub const fn filetime_to_lxfs_time(ft: FILETIME) -> LxfsTime {
    let t64 = filetime_to_i64(ft);
    let (sec, ns100) = (t64 / FILETIME_TICKS_PER_SEC, t64 % FILETIME_TICKS_PER_SEC);
    LxfsTime {
        tv_sec: sec as i64 - SECS_1601_TO_1970,
        tv_nsec: (ns100 as i32) * 100,
    }
}

pub const fn i64_to_lxfs_time(t64: i64) -> LxfsTime {
    filetime_to_lxfs_time(i64_to_filetime(t64))
}

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
        tv_nsec: 3480101,
    };

    let a:SystemTime;

    assert_eq!("2024-10-24 03:45:25.003480101 UTC", lxtv.to_string());

    let odt = OffsetDateTime::from_unix_timestamp(lxtv.tv_sec as i64).unwrap() + Duration::nanoseconds(lxtv.tv_nsec as i64);
    println!("myformat: {}", odt.format(FILE_TIME_FORMAT).unwrap());
    println!("default: {}", odt);

    assert_eq!("2024-10-24 03:45:25.003480101 UTC", odt.format(FILE_TIME_FORMAT).unwrap());
}

#[test]
fn test_filetime() {
    let d1 = time::macros::datetime!(1601-02-03 04:05:06.789000001 UTC);
    println!("d1: {}", d1.format(FILE_TIME_FORMAT).unwrap());
    assert_eq!(
        d1.format(FILE_TIME_FORMAT).unwrap(),
        "1601-02-03 04:05:06.789000001 UTC"
    );

    let ft1 = lxfs_time_to_filetime(LxfsTime {
        tv_sec: d1.unix_timestamp(),
        tv_nsec: d1.nanosecond() as i32,
    });
    let lxtv1 = filetime_to_lxfs_time(ft1);
    assert_eq!(lxtv1.tv_sec, d1.unix_timestamp());
    assert_eq!(lxtv1.tv_nsec, d1.nanosecond() as i32 - 1);

    let odt = OffsetDateTime::from_unix_timestamp(-3).unwrap();
    println!("myformat: {}", odt.format(FILE_TIME_FORMAT).unwrap());
}

#[test]
fn filetime_min_max() {
    let ft_min = FILETIME_MIN;
    let ft_max = FILETIME_MAX;

    assert_eq!(filetime_to_i64(ft_min), 0);
    assert_eq!(filetime_to_i64(ft_max), i64::MAX);

    let lxtm1 = filetime_to_lxfs_time(ft_min);
    let lxtm2 = filetime_to_lxfs_time(ft_max);

    println!("filetime_min: {}", &lxtm1);
    println!("filetime_max: {}", &lxtm2);

    assert_eq!(lxtm1.to_string(), "1601-01-01 00:00:00.000000000 UTC");
    assert_eq!(lxtm2.to_string(), "+30828-09-14 02:48:05.477580700 UTC");
}

#[test]
fn lxfs_time_min_max() {
    let lxtv_min = LxfsTime { tv_sec: i64::MIN, tv_nsec: 0 };
    let lxtv_max = LxfsTime { tv_sec: i64::MAX, tv_nsec: 999_999_999 };

    // crate `time` does not support
    println!("lxtv_min: {}", &lxtv_min);
    println!("lxtv_max: {}", &lxtv_max);

    let ft_min = lxfs_time_to_filetime(lxtv_min);
    let ft_max = lxfs_time_to_filetime(lxtv_max);

    assert_eq!(ft_min, FILETIME_MIN);
    assert_eq!(ft_max, FILETIME_MAX);
}
