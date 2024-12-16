use std::borrow::Cow;
use std::fmt::Display;
use std::mem::{offset_of, transmute};
use std::io::Result;

use windows::Win32::Foundation::HANDLE;

use crate::distro::Distro;
use crate::ea_parse::{EaEntryCow, EaEntryRaw};
use crate::ntfs_io::{delete_reparse_point, write_reparse_point};
use crate::posix::{lsperms, StModeType};
use crate::wsl_file::{open_file_inner, WslFile, WslFileAttributes};

pub const LXUID: &'static str = "$LXUID";
pub const LXGID: &'static str = "$LXGID";
pub const LXMOD: &'static str = "$LXMOD";
pub const LXDEV: &'static str = "$LXDEV";

/// prefix of linux extended file attribute saved as ntfs ea
pub const LX_DOT: &'static str = "LX.";

#[derive(Default)]
pub struct WslfsParsed<'a, 'd> {
    pub lxuid: Option<Cow<'a, u32>>,
    pub lxgid: Option<Cow<'a, u32>>,
    pub lxmod: Option<Cow<'a, u32>>,
    pub lxdev: Option<Cow<'a, Lxdev>>,

    pub lx_dot_ea: Vec<EaEntryCow<'a>>,

    pub reparse_tag: Option<StModeType>,

    pub symlink: Option<String>,

    pub distro: Option<&'d Distro>,
}

impl<'a, 'd> Display for WslfsParsed<'a, 'd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //Symlink:                   -> target
        //$LXUID:                    Uid: 0 / user1
        //$LXGID:                    Gid: 0
        //$LXMOD:                    Mode: 100755 Access: (0755) -rwxr-xr-x
        //$LXDEV:                    Device type: 37,13
        //Linux extended attributes(LX.*):
        //  user.xdg.origin.url:     http://example.url

        match &self.reparse_tag {
            Some(t) => {
                f.write_fmt(format_args!("{:28}{}\n", "File Type(Reparse Tag):", &t.name().0))?;
                if *t == StModeType::LNK {
                    f.write_fmt(format_args!("{:28}-> {}\n", "Symlink:", self.symlink.as_ref().map_or("", String::as_str)))?;
                }
            },
            None => {},
        };

        if let Some(l) = &self.lxuid {
            let uid: u32 = **l;
            if let Some(user_name) = self.distro.and_then(|d| d.user_name(uid)) {
                f.write_fmt(format_args!("{:28}Uid: {} / {}\n", "$LXUID:", uid, user_name))?;
            } else {
                f.write_fmt(format_args!("{:28}Uid: {}\n", "$LXUID:", uid))?;
            }
        }
        if let Some(l) = &self.lxgid {
            let gid: u32 = **l;
            if let Some(group_name) = self.distro.and_then(|d| d.group_name(gid)) {
                f.write_fmt(format_args!("{:28}Gid: {} / {}\n", "$LXGID:", gid, group_name))?;
            } else {
                f.write_fmt(format_args!("{:28}Gid: {}\n", "$LXGID:", gid))?;
            }
        }
        if let Some(l) = &self.lxmod {
            let mode = *l.as_ref();
            let access = lsperms(mode);
            f.write_fmt(format_args!("{:28}Mode: {:06o} Access: {}\n", "$LXMOD:", mode, access))?;
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

impl<'a, 'd> WslFileAttributes<'a> for WslfsParsed<'a, 'd> {
    fn maybe(&self) -> bool {
        self.lxuid.is_some() ||
        self.lxgid.is_some() ||
        self.lxmod.is_some() ||
        self.lxdev.is_some() ||
        self.reparse_tag.is_some() ||
        !self.lx_dot_ea.is_empty()
    }

    fn load<'b: 'a, 'c>(wsl_file: &'c WslFile, ea_parsed: &'b Option<Vec<EaEntryRaw<'a>>>) -> Self {
        let mut p = Self::default();

        p.reparse_tag = wsl_file.reparse_tag.map(WslfsReparseTag::from_tag_id);
        if wsl_file.reparse_tag == Some(IO_REPARSE_TAG_LX_SYMLINK) {
            p.symlink = read_lx_symlink(wsl_file.file_handle).ok();
        }

        p.lx_dot_ea = vec![];

        if let Some(ea_parsed) = ea_parsed {
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
        }

        p
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
    pub major: u32,
    pub minor: u32,
}

pub trait WslfsReparseTag {
    fn tag_id(&self) -> u32;
    fn from_tag_id(tag_id: u32) -> Self;
}

impl WslfsReparseTag for StModeType {
    fn tag_id(&self) -> u32 {
        use StModeType::*;
        match *self {
            LNK => IO_REPARSE_TAG_LX_SYMLINK,
            FIFO => IO_REPARSE_TAG_LX_FIFO,
            CHR => IO_REPARSE_TAG_LX_CHR,
            BLK => IO_REPARSE_TAG_LX_BLK,
            SOCK => IO_REPARSE_TAG_AF_UNIX,
            _ => 0,
        }
    }

    fn from_tag_id(tag_id: u32) -> Self {
        use StModeType::*;
        match tag_id {
            IO_REPARSE_TAG_LX_SYMLINK => LNK,
            IO_REPARSE_TAG_AF_UNIX => SOCK,
            IO_REPARSE_TAG_LX_FIFO => FIFO,
            IO_REPARSE_TAG_LX_CHR => CHR,
            IO_REPARSE_TAG_LX_BLK => BLK,
            _ => UNKNOWN,
        }
    }
}

pub const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xA000001D;
pub const IO_REPARSE_TAG_AF_UNIX: u32 = 0x80000023;
pub const IO_REPARSE_TAG_LX_FIFO: u32 = 0x80000024;
pub const IO_REPARSE_TAG_LX_CHR: u32 = 0x80000025;
pub const IO_REPARSE_TAG_LX_BLK: u32 = 0x80000026;

const LX_SYMLINK_SIG: u32 = 0x00000002;

#[derive(Debug, Default)]
#[repr(C)]
struct ReparseDataBufferLxSymlink {
    reparse_tag: u32,
    reparse_data_length: u16,
    reserved: u16,
    lx_symlink_sig: u32,
    link: [u8; 1],
}

fn read_lx_symlink(file_handle: HANDLE) -> Result<String> {
    let raw_buf = unsafe { crate::ntfs_io::read_reparse_point(file_handle)? };

    let data_idx = offset_of!(ReparseDataBufferLxSymlink, lx_symlink_sig);
    let link_idx = offset_of!(ReparseDataBufferLxSymlink, link);

    // min size is 12, with a empty link, do not use `size_of::<REPARSE_DATA_BUFFER_LX_SYMLINK>()`
    //dbg!(raw_buf.len(), offset_of!(REPARSE_DATA_BUFFER_LX_SYMLINK, Link));
    assert!(raw_buf.len() >= link_idx);

    //1d 00 00 a0 // ReparseTag = 0xA000001D
    //05 00 00 00 // ReparseDataLength = 5, Reserved = 0x0000
    //02 00 00 00 // Tag = 0x00000002
    //78          // link_name = 'x' UTF-8 no null
    
    let reparse_buf: &ReparseDataBufferLxSymlink = unsafe { transmute(raw_buf.as_ptr()) };

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
pub unsafe fn set_wslfs_reparse_point(wsl_file: &mut WslFile, tag: StModeType, symlink: Option<&str>) -> Result<()> {
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
        StModeType::LNK => {
            let s = symlink.unwrap();
            let data_len = s.bytes().len() + size_of::<u32>();
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
