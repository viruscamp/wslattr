//! FILETIME, 64bit, 100ns, since 1601-01-01 00:00::00
//! tv_sec, 64bit, 1sec, since 1970-01-01 00:00:00 UTC
//! tv_nsec, 32bit, 1ns, Nano seconds of access time

use std::fmt::Display;
use std::sync::LazyLock;

use time::{format_description, Duration, OffsetDateTime};

use winapi::shared::minwindef::FILETIME;
use winapi::um::winnt::ULARGE_INTEGER;

#[derive(Clone, Copy, Debug)]
pub struct TimeTWithNano {
    pub tv_sec: u64,
    pub tv_nsec: u32,
}

impl TimeTWithNano {
    pub fn new(tv_sec: u64, tv_nsec: u32) -> Self {
        TimeTWithNano {
            tv_sec,
            tv_nsec,
        }
    }
}

impl Display for TimeTWithNano {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let odt = OffsetDateTime::from_unix_timestamp(self.tv_sec as i64).map_err(|_| std::fmt::Error)?;
        let odt = odt + Duration::nanoseconds(self.tv_nsec as i64);
        f.write_str(&odt.format(&FILE_TIME_FORMAT).map_err(|_| std::fmt::Error)?)?;
        Ok(())
    }
}

impl From<(u64, u32)> for TimeTWithNano {
    fn from(x: (u64, u32)) -> Self {
        TimeTWithNano {
            tv_sec: x.0,
            tv_nsec: x.1,
        }
    }
}

impl From<FILETIME> for TimeTWithNano {
    fn from(ft: FILETIME) -> Self {
        filetime_to_timet64(ft).into()
    }
}

impl Into<FILETIME> for TimeTWithNano {
    fn into(self) -> FILETIME {
        timet64_to_filetime(self.tv_sec, self.tv_nsec)
    }
}

pub fn timet64_to_filetime(tv_sec: u64, tv_nsec: u32) -> FILETIME {
    let mut ull = ULARGE_INTEGER::default();
    *unsafe { ull.QuadPart_mut() } = (tv_sec * 10000000u64) + 116444736000000000u64 + (tv_nsec as u64/100);

    let s = unsafe { ull.s() };
    FILETIME {
        dwLowDateTime: s.LowPart,
        dwHighDateTime: s.HighPart,
    }
}

pub fn filetime_to_timet64(ft: FILETIME) -> (u64, u32) {
    let mut ull = ULARGE_INTEGER::default();
    let s = unsafe { ull.s_mut() };
    s.LowPart = ft.dwLowDateTime;
    s.HighPart = ft.dwHighDateTime;

    let qp = unsafe { ull.QuadPart() };
    let (sec, ns100) = ( qp / 10000000u64, qp % 10000000u64);
    return ((sec - 11644473600u64), (ns100 as u32) * 100u32);
}

pub const FILE_TIME_FORMAT_STR: &'static str = "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:7] UTC";

pub static FILE_TIME_FORMAT: LazyLock<Vec<format_description::FormatItem<'static>>> = LazyLock::new(|| {
    format_description::parse(FILE_TIME_FORMAT_STR).unwrap()
});

#[test]
fn test_convert() {
    let tv_sec: u64 = 1729741525;
    let tv_nsec: u32 = 3480100;

    let ft = timet64_to_filetime(tv_sec, tv_nsec);

    assert_eq!((tv_sec, tv_nsec), filetime_to_timet64(ft));
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
