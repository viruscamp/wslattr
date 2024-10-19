use std::fmt::Display;
use std::mem::transmute;
use std::io::{Error, Result};

use ntapi::ntioapi::REPARSE_DATA_BUFFER;
use ntapi::winapi::shared::minwindef::*;
use ntapi::winapi::shared::ntdef::*;
use ntapi::winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::FSCTL_GET_REPARSE_POINT;
use winapi::um::winnt::MAXIMUM_REPARSE_DATA_BUFFER_SIZE;

pub type HANDLE = *mut ntapi::winapi::ctypes::c_void;

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

unsafe fn read_lx_symlink(file_handle: HANDLE) -> Result<String> {
    let mut link_buf = vec![0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize];
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        transmute(link_buf.as_mut_ptr()),
        MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
        &mut bytes_returned,
        transmute(NULL),
    ) == 0 {
        println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
        return Err(Error::last_os_error());
    }
    let bytes_len = bytes_returned as usize;

    let reparse_buf: &REPARSE_DATA_BUFFER = transmute(link_buf.as_ptr());

    //1d 00 00 a0 // ReparseTag = 0xA000001D
    //05 00 00 00 // ReparseDataLength = 5, Reserved = 0x0000
    //02 00 00 00 // Tag = 0x00000002  or ReparseGuid.Data1: ulong = 2
    //78          // link_name = 'x' UTF-8 no null

    let data_len: usize = reparse_buf.ReparseDataLength as usize;
    let data_str = &link_buf[12..(8 + data_len)];
    
    //println!("data_len={}, bytes_len={}", data_len, bytes_len);
    assert!(data_len + 8 <= bytes_len);
    assert_eq!(reparse_buf.ReparseTag, IO_REPARSE_TAG_LX_SYMLINK);
    //assert_eq!(reparse_buf.ReparseGuid.Data1, 2);
    assert_eq!(&link_buf[8..12], [2, 0, 0, 0]);

    let link_name = String::from_utf8_lossy(data_str).to_string();

    return Ok(link_name);
}

pub const LXUID: &'static str = "$LXUID";
pub const LXGID: &'static str = "$LXGID";
pub const LXMOD: &'static str = "$LXMOD";
pub const LXDEV: &'static str = "$LXDEV";


pub fn ulong_from_ea_value(ea_value: &[u8]) -> Option<winapi::shared::minwindef::ULONG> {
    TryInto::<[u8; 4]>::try_into(ea_value)
        .map(u32::from_le_bytes)
        .ok()
}
