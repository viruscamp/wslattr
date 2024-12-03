use std::borrow::Cow;
use std::fmt::Display;
use std::mem::{offset_of, transmute};
use std::io::Result;

use winapi::shared::minwindef::{DWORD, UCHAR, ULONG, USHORT};
use winapi::shared::ntdef::HANDLE;

use crate::ea_parse::{EaEntryCow, EaEntryRaw};
use crate::ntfs_io::{delete_reparse_point, write_reparse_point};
use crate::wsl_file::{open_file_inner, WslFile, WslFileAttributes};

pub const LXUID: &'static str = "$LXUID";
pub const LXGID: &'static str = "$LXGID";
pub const LXMOD: &'static str = "$LXMOD";
pub const LXDEV: &'static str = "$LXDEV";

/// prefix of linux extended file attribute saved as ntfs ea
pub const LX_DOT: &'static str = "LX.";

// 从 EaParsed 借用会导致不能修改 EaParsed, 即使是只 push
// EaParsed.push 可能扩容, 导致所有借用数据错误
// 直接从 WslFile.ea_buf 借用才行
#[derive(Default)]
pub struct WslfsParsed<'a> {
    pub lxuid: Option<Cow<'a, u32>>,
    pub lxgid: Option<Cow<'a, u32>>,
    pub lxmod: Option<Cow<'a, u32>>,
    pub lxdev: Option<Cow<'a, Lxdev>>,

    pub lx_dot_ea: Vec<EaEntryCow<'a>>,

    pub reparse_tag: Option<WslfsReparseTag>,
}

impl<'a> Display for WslfsParsed<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //Symlink:                   -> target
        //$LXUID:                    Uid: (0 / )
        //$LXGID:                    Gid: (0 / )
        //$LXMOD:                    Mode: 100755 Access: (0755) -rwxr-xr-x
        //$LXDEV:                    Device type: 37,13
        //Linux extended attributes(LX.*):
        //  user.xdg.origin.url:     http://example.url

        match &self.reparse_tag {
            Some(t) => {
                f.write_fmt(format_args!("{:28}{}\n", "File Type(Reparse Tag):", &t.type_name()))?;
                if let WslfsReparseTag::LxSymlink(s) = t {
                    f.write_fmt(format_args!("{:28}-> {}\n", "Symlink:", s))?;
                }
            },
            None => {},
        };

        if let Some(l) = &self.lxuid {
            f.write_fmt(format_args!("{:28}{}\n", "$LXUID:", *l))?;
        }
        if let Some(l) = &self.lxgid {
            f.write_fmt(format_args!("{:28}{}\n", "$LXGID:", *l))?;
        }
        if let Some(l) = &self.lxmod {
            f.write_fmt(format_args!("{:28}{:o}\n", "$LXMOD:", l.as_ref()))?;
        }
        if let Some(l) = &self.lxdev {
            f.write_fmt(format_args!("{:28}Device type: {}, {}\n", "$LXDEV:", l.major, l.minor))?;
        }

        if self.lx_dot_ea.len() > 0 {
            f.write_str("Linux extended attributes(LX.*):\n")?;
            for l in &self.lx_dot_ea {
                let name = lx_dot_ea_name_display(&l.name);
                let value_str = lx_dot_ea_value_display(&l.value);
                f.write_fmt(format_args!("  {:26}{}\n", name.as_ref(), value_str))?;
            }
        }
        Ok(())
    }
}

impl<'a> WslFileAttributes<'a> for WslfsParsed<'a> {
    fn maybe(&self) -> bool {
        self.lxuid.is_some() ||
        self.lxgid.is_some() ||
        self.lxmod.is_some() ||
        self.lxdev.is_some() ||
        self.reparse_tag.is_some() ||
        !self.lx_dot_ea.is_empty()
    }

    fn try_load<'b: 'a>(wsl_file: &'a WslFile, ea_parsed: &'b Vec<EaEntryRaw<'a>>) -> Result<Self> {
        let mut p = Self::default();
        p.reparse_tag = if let Some(t) = wsl_file.reparse_tag {
            Some(parse_reparse_tag(t, wsl_file.file_handle)?)
        } else {
            None
        };

        p.lx_dot_ea = vec![];

        for ea in ea_parsed {
            if ea.name == LXUID.as_bytes() {
                p.lxuid = Some(Cow::Owned(ea.get_ea::<u32>().to_owned()));
            } else if ea.name == LXGID.as_bytes() {
                p.lxgid = Some(Cow::Owned(ea.get_ea::<u32>().to_owned()));
            } else if ea.name == LXMOD.as_bytes() {
                p.lxmod = Some(Cow::Owned(ea.get_ea::<u32>().to_owned()));
            } else if ea.name == LXDEV.as_bytes() {
                p.lxdev = Some(Cow::Owned(ea.get_ea::<Lxdev>().to_owned()));
            } else if ea.name.starts_with(LX_DOT.as_bytes()) {
                p.lx_dot_ea.push(EaEntryCow {
                    flags: ea.flags,
                    name: ea.name.to_owned().into(),
                    value: ea.value.to_owned().into(),
                });
            }
        }

        Ok(p)
    }

    fn get_uid(&self) -> Option<u32> {
        self.lxuid.as_ref().map(|l| *l.as_ref())
    }

    fn get_gid(&self) -> Option<u32> {
        self.lxgid.as_ref().map(|l| *l.as_ref())
    }

    fn get_mode(&self) -> Option<u32> {
        self.lxmod.as_ref().map(|l| *l.as_ref())
    }

    fn get_dev_major(&self) -> Option<u32> {
        self.lxdev.as_ref().map(|lxdev| lxdev.major)
    }

    fn get_dev_minor(&self) -> Option<u32> {
        self.lxdev.as_ref().map(|lxdev| lxdev.minor)
    }

    fn set_uid(&mut self, uid: u32) {
        self.lxuid = Some(Cow::Owned(uid));
    }

    fn set_gid(&mut self, gid: u32) {
        self.lxgid = Some(Cow::Owned(gid));
    }

    fn set_mode(&mut self, mode: u32) {
        self.lxmod = Some(Cow::Owned(mode));
    }

    fn set_dev_major(&mut self, dev_major: u32) {
        let mut lxdev = self.lxdev.take().unwrap_or_default();
        lxdev.to_mut().major = dev_major;
        self.lxdev = Some(lxdev);
    }

    fn set_dev_minor(&mut self, dev_minor: u32) {
        let mut lxdev = self.lxdev.take().unwrap_or_default();
        lxdev.to_mut().minor = dev_minor;
        self.lxdev = Some(lxdev);
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Lxdev {
    pub major: ULONG,
    pub minor: ULONG,
}

#[derive(Clone, Debug)]
pub enum WslfsReparseTag {
    LxSymlink(String),
    LxFifo,
    LxChr,
    LxBlk,
    AfUnix,

    Unknown,
}
impl WslfsReparseTag {
    pub fn type_name(&self) -> &'static str {
        match self {
            WslfsReparseTag::LxSymlink(_) => "SYMLINK",
            WslfsReparseTag::LxFifo => "FIFO",
            WslfsReparseTag::LxChr => "CHR",
            WslfsReparseTag::LxBlk => "BLK",
            WslfsReparseTag::AfUnix => "AF_UNIX",
            WslfsReparseTag::Unknown => "UNKNOWN",
        }
    }

    pub fn tag_id(&self) -> DWORD {
        match self {
            WslfsReparseTag::LxSymlink(_) => IO_REPARSE_TAG_LX_SYMLINK,
            WslfsReparseTag::LxFifo => IO_REPARSE_TAG_LX_FIFO,
            WslfsReparseTag::LxChr => IO_REPARSE_TAG_LX_CHR,
            WslfsReparseTag::LxBlk => IO_REPARSE_TAG_LX_BLK,
            WslfsReparseTag::AfUnix => IO_REPARSE_TAG_AF_UNIX,
            WslfsReparseTag::Unknown => 0,
        }
    }
}
impl Display for WslfsReparseTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_name = self.type_name();
        if let WslfsReparseTag::LxSymlink(s) = self {
            f.write_fmt(format_args!("{type_name} -> {s}"))
        } else {
            f.write_str(type_name)
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

const LX_SYMLINK_SIG: ULONG = 0x00000002;

#[derive(Debug, Default)]
#[repr(C)]
struct ReparseDataBufferLxSymlink {
    reparse_tag: ULONG,
    reparse_data_length: USHORT,
    reserved: USHORT,
    lx_symlink_sig: ULONG,
    link: [UCHAR; 1],
}

unsafe fn read_lx_symlink(file_handle: HANDLE) -> Result<String> {
    let raw_buf = crate::ntfs_io::read_reparse_point(file_handle)?;

    let data_idx = offset_of!(ReparseDataBufferLxSymlink, lx_symlink_sig);
    let link_idx = offset_of!(ReparseDataBufferLxSymlink, link);

    // min size is 12, with a empty link, do not use `size_of::<REPARSE_DATA_BUFFER_LX_SYMLINK>()`
    //dbg!(raw_buf.len(), offset_of!(REPARSE_DATA_BUFFER_LX_SYMLINK, Link));
    assert!(raw_buf.len() >= link_idx);

    //1d 00 00 a0 // ReparseTag = 0xA000001D
    //05 00 00 00 // ReparseDataLength = 5, Reserved = 0x0000
    //02 00 00 00 // Tag = 0x00000002
    //78          // link_name = 'x' UTF-8 no null
    
    let reparse_buf: &ReparseDataBufferLxSymlink = transmute(raw_buf.as_ptr());

    let data_len = reparse_buf.reparse_data_length as usize;

    //println!("data_len={}, bytes_len={}", data_len, bytes_len);
    assert_eq!(reparse_buf.reparse_tag, IO_REPARSE_TAG_LX_SYMLINK);
    assert!(data_idx + data_len <= raw_buf.len());
    assert_eq!(reparse_buf.lx_symlink_sig, LX_SYMLINK_SIG); // QUESTION: how about a BE machine?

    let link_buf = &raw_buf[link_idx..(data_idx + data_len)];
    let link = String::from_utf8_lossy(link_buf).to_string();

    return Ok(link);
}

// only for wslfs -> lxfs
pub unsafe fn delete_wslfs_reparse_point(wsl_file: &mut WslFile) -> Result<()> {
    assert!(wsl_file.writable);
    assert!(wsl_file.reparse_tag.is_some());
    delete_reparse_point(wsl_file.file_handle, wsl_file.reparse_tag.unwrap())?;
    wsl_file.reparse_tag = None;
    open_file_inner(wsl_file, true)?; // open as normal file
    Ok(())
}

// only for change wslfs file type
pub unsafe fn set_wslfs_reparse_point(wsl_file: &mut WslFile, tag: WslfsReparseTag) -> Result<()> {
    assert!(wsl_file.writable);

    let reparse_tag_id = tag.tag_id();
    if let Some(t) = wsl_file.reparse_tag {
        if t != reparse_tag_id {
            delete_reparse_point(wsl_file.file_handle, t)?;
            wsl_file.reparse_tag = None;
        }
    } else {
        // TODO: reopen with reparse data
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "cannot add reparse point"));
    }

    let mut buf = match &tag {
        WslfsReparseTag::LxSymlink(s) => {
            let data_len = s.bytes().len() + size_of::<ULONG>();
            let buf_len = offset_of!(ReparseDataBufferLxSymlink, lx_symlink_sig) + data_len;
            let mut buf = vec![0u8; buf_len];
            let reparse_data: &mut ReparseDataBufferLxSymlink = transmute(buf.as_mut_ptr());
            reparse_data.reparse_tag = reparse_tag_id;
            reparse_data.reparse_data_length = data_len as u16;
            reparse_data.lx_symlink_sig = LX_SYMLINK_SIG;
            core::ptr::copy(s.as_ptr(), reparse_data.link.as_mut_ptr(), s.bytes().len());
            buf
        },
        _ => {
            let buf_len = offset_of!(ReparseDataBufferLxSymlink, lx_symlink_sig);
            let mut buf = vec![0u8; buf_len];
            let reparse_data: &mut ReparseDataBufferLxSymlink = transmute(buf.as_mut_ptr());
            reparse_data.reparse_tag = reparse_tag_id;
            reparse_data.reparse_data_length = 0;
            buf
        },
    };

    write_reparse_point(wsl_file.file_handle, buf.as_mut_slice())?;
    wsl_file.reparse_tag = Some(reparse_tag_id);
    Ok(())
}

// TODO:  Upper ASCII, should be converted before display
fn lx_dot_ea_name_display<'x>(name: &'x [u8]) -> impl AsRef<str> + 'x {
    String::from_utf8_lossy(&name[LX_DOT.len()..]).to_ascii_lowercase()  
}

fn lx_dot_ea_value_display<'a>(value: &'a [u8]) -> Cow<'a, str> {
    let bytes = &value[4..];
    match std::str::from_utf8(bytes) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(bytes.escape_ascii().to_string()),
    }
}
