use std::borrow::Cow;
use std::fmt::Display;
use std::mem::{offset_of, transmute};
use std::io::Result;
use std::ops::Deref;

use winapi::shared::minwindef::{DWORD, UCHAR, ULONG, USHORT};
use winapi::shared::ntdef::HANDLE;

use crate::ea_parse::{EaEntry, EaParsed};
use crate::wsl_file::{WslFile, WslFileAttributes};

pub const LXUID: &'static str = "$LXUID";
pub const LXGID: &'static str = "$LXGID";
pub const LXMOD: &'static str = "$LXMOD";
pub const LXDEV: &'static str = "$LXDEV";

/// prefix of linux extended file attribute saved as ntfs ea
pub const LX_DOT: &'static str = "LX.";

#[derive(Default)]
pub struct WslfsParsed<'a> {
    pub lxuid: Option<Cow<'a, u32>>,
    pub lxgid: Option<Cow<'a, u32>>,
    pub lxmod: Option<Cow<'a, u32>>,
    pub lxdev: Option<Cow<'a, Lxdev>>,
    pub reparse_tag: Option<WslfsReparseTag>,

    pub lx_dot_ea: Vec<EaEntry<'a>>,
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
            f.write_fmt(format_args!("{:28}{:o}\n", "$LXMOD:", l.deref()))?;
        }
        if let Some(l) = &self.lxdev {
            f.write_fmt(format_args!("{:28}Device type: {}, {}\n", "$LXDEV:", l.major, l.minor))?;
        }

        if self.lx_dot_ea.len() > 0 {
            f.write_str("Linux extended attributes(LX.*):\n")?;
            for l in &self.lx_dot_ea {
                let name = lx_dot_ea_name_display(&l.name);
                let value = lx_dot_ea_value_display(&l.value);
                f.write_fmt(format_args!("  {:26}{}\n", name, value))?;
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

    fn try_load(wsl_file: &'a WslFile, ea_parsed: &'a EaParsed) -> Result<Self> {
        let mut p = Self::default();
        p.reparse_tag = if let Some(t) = wsl_file.reparse_tag {
            Some(parse_reparse_tag(t, wsl_file.file_handle)?)
        } else {
            None
        };

        p.lx_dot_ea = vec![];

        for ea in ea_parsed {
            if ea.name == LXUID {
                p.lxuid = Some(Cow::Borrowed(ea.get_ea::<ULONG>()));
            } else if ea.name == LXGID {
                p.lxgid = Some(Cow::Borrowed(ea.get_ea::<ULONG>()));
            } else if ea.name == LXMOD {
                p.lxmod = Some(Cow::Borrowed(ea.get_ea::<ULONG>()));
            } else if ea.name == LXDEV {
                p.lxdev = Some(Cow::Borrowed(ea.get_ea::<Lxdev>()));
            } else if ea.name.starts_with(LX_DOT) {
                // TODO convert
                p.lx_dot_ea.push(EaEntry {
                    flags: ea.flags,
                    name: ea.name[LX_DOT.len()..].into(),
                    value: ea.value[4..].into(),
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

#[derive(Debug, Default)]
#[repr(C)]
struct ReparseDataBufferLxSymlink {
    reparse_tag: ULONG,
    reparse_data_length: USHORT,
    reserved: USHORT,
    tag: ULONG,
    link: [UCHAR; 1],
}

unsafe fn read_lx_symlink(file_handle: HANDLE) -> Result<String> {
    let raw_buf = crate::ntfs_io::read_reparse_point(file_handle)?;

    let data_idx = offset_of!(ReparseDataBufferLxSymlink, tag);
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
    assert_eq!(reparse_buf.tag, 0x00000002); // QUESTION: how about a BE machine?

    let link_buf = &raw_buf[link_idx..(data_idx + data_len)];
    let link = String::from_utf8_lossy(link_buf).to_string();

    return Ok(link);
}

// TODO:  Upper aSCII, should be converted before display
fn lx_dot_ea_name_display(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn lx_dot_ea_value_display<'a>(value: &'a [u8]) -> Cow<'a, str> {
    match std::str::from_utf8(value) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(value.escape_ascii().to_string()),
    }
}
