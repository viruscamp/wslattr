use std::fmt::Display;
use std::mem::transmute;
use std::io::{Error, Result};

use ntapi::ntioapi::REPARSE_DATA_BUFFER;
use ntapi::winapi::shared::minwindef::*;
use ntapi::winapi::shared::ntdef::{NULL, NULL64, TRUE, FALSE};
use ntapi::winapi::um::ioapiset::DeviceIoControl;
use winapi::shared::winerror::ERROR_MORE_DATA;
use winapi::um::winioctl::FSCTL_GET_REPARSE_POINT;
use winapi::um::winnt::REPARSE_GUID_DATA_BUFFER;

use crate::ea_parse::EaEntry;

pub type HANDLE = *mut ntapi::winapi::ctypes::c_void;

pub const LXUID: &'static str = "$LXUID";
pub const LXGID: &'static str = "$LXGID";
pub const LXMOD: &'static str = "$LXMOD";
pub const LXDEV: &'static str = "$LXDEV";

/// prefix of linux extended file attribute saved as ntfs ea
pub const LX_DOT: &'static str = "LX.";

#[repr(C)]
#[derive(Debug)]
pub struct Lxdev {
    pub type_major: ULONG,
    pub type_minor: ULONG,
}

#[derive(Default)]
pub struct WslfsParsed<'a> {
    pub lxuid: Option<ULONG>,
    pub lxgid: Option<ULONG>,
    pub lxmod: Option<ULONG>,
    pub lxdev: Option<Lxdev>,
    pub reparse_tag: Option<WslfsReparseTag>,

    pub lx_ea: Vec<EaEntry<'a>>,
}

#[derive(Debug)]
pub enum WslfsReparseTag {
    LxSymlink(String),
    LxFifo,
    LxChr,
    LxBlk,
    AfUnix,

    Unknown,
}
impl Display for WslfsReparseTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WslfsReparseTag::LxSymlink(s) => f.write_fmt(format_args!("SYMLINK -> {s}")),
            WslfsReparseTag::LxFifo => f.write_str("FIFO"),
            WslfsReparseTag::LxChr => f.write_str("CHR"),
            WslfsReparseTag::LxBlk => f.write_str("BLK"),
            WslfsReparseTag::AfUnix => f.write_str("AF_UNIX"),
            WslfsReparseTag::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

pub const IO_REPARSE_TAG_LX_SYMLINK: DWORD = 0xA000001D;
pub const IO_REPARSE_TAG_AF_UNIX: DWORD = 0x80000023;
pub const IO_REPARSE_TAG_LX_FIFO: DWORD = 0x80000024;
pub const IO_REPARSE_TAG_LX_CHR: DWORD = 0x80000025;
pub const IO_REPARSE_TAG_LX_BLK: DWORD = 0x80000026;

pub fn parse_reparse_tag(reparse_tag: DWORD, file_handle: HANDLE) -> Result<WslfsReparseTag> {
    Ok(match reparse_tag {
        IO_REPARSE_TAG_LX_SYMLINK => {
            WslfsReparseTag::LxSymlink(unsafe { read_lx_symlink(file_handle) }?)
        },
        IO_REPARSE_TAG_AF_UNIX => WslfsReparseTag::AfUnix,
        IO_REPARSE_TAG_LX_FIFO => WslfsReparseTag::LxFifo,
        IO_REPARSE_TAG_LX_CHR => WslfsReparseTag::LxChr,
        IO_REPARSE_TAG_LX_BLK => WslfsReparseTag::LxBlk,
        _ => WslfsReparseTag::Unknown,
    })
}

unsafe fn read_reparse_point_inner(file_handle: HANDLE, buf: &mut Vec<u8>) -> Option<Error> {
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        transmute(buf.as_mut_ptr()),
        buf.len() as DWORD,
        &mut bytes_returned,
        transmute(NULL),
    ) != 0 {
        //dbg!(buf.len(), bytes_returned);
        buf.truncate(bytes_returned as usize);
        return None;
    }
    let err = Error::last_os_error();
    //dbg!(err.raw_os_error());
    return Some(err);
}

unsafe fn read_reparse_point(file_handle: HANDLE) -> Result<Vec<u8>> {
    // a reasonable init buf size 64
    let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + 36;
    let mut buf = vec![0; buf_size];
    match read_reparse_point_inner(file_handle, &mut buf) {
        None => return Ok(buf),
        Some(err) => {
            match err.raw_os_error() {
                Some(os_error) if os_error == ERROR_MORE_DATA as i32 => {
                    // retry with new buf
                    let reparse_buf = buf.as_ptr() as *const REPARSE_GUID_DATA_BUFFER;
                    // larger in most case
                    let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + (*reparse_buf).ReparseDataLength as usize;
                    let mut buf = vec![0; buf_size];
                    match read_reparse_point_inner(file_handle, &mut buf) {
                        None => return Ok(buf),
                        Some(err) => {
                            println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                            return Err(err);
                        }
                    }
                },
                _ => {
                    println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                    return Err(err);
                }
            }
        },
    }
}

unsafe fn read_lx_symlink(file_handle: HANDLE) -> Result<String> {
    let link_buf = read_reparse_point(file_handle)?;

    let reparse_buf: &REPARSE_DATA_BUFFER = transmute(link_buf.as_ptr());

    //1d 00 00 a0 // ReparseTag = 0xA000001D
    //05 00 00 00 // ReparseDataLength = 5, Reserved = 0x0000
    //02 00 00 00 // Tag = 0x00000002
    //78          // link_name = 'x' UTF-8 no null

    let data_idx = size_of_val(&reparse_buf.ReparseTag) + size_of_val(&reparse_buf.ReparseDataLength) + size_of_val(&reparse_buf.Reserved);
    let data_len = reparse_buf.ReparseDataLength as usize;
    let str_idx = data_idx + 4;
    
    //println!("data_len={}, bytes_len={}", data_len, bytes_len);
    assert_eq!(reparse_buf.ReparseTag, IO_REPARSE_TAG_LX_SYMLINK);
    assert!(data_idx + data_len <= link_buf.len());
    assert_eq!(&link_buf[data_idx..str_idx], [2, 0, 0, 0]);

    let data_str = &link_buf[str_idx..(data_idx + data_len)];
    let link_name = String::from_utf8_lossy(data_str).to_string();

    return Ok(link_name);
}


