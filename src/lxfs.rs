use std::{borrow::Cow, fmt::Display, mem::{offset_of, transmute}, ptr::{addr_of, slice_from_raw_parts}};

use crate::ea_parse::{force_cast, EaEntry, EaEntryRaw};
use crate::ntfs_io::read_data;
use crate::time_utils::TimeTWithNano; 
use crate::wsl_file::{WslFile, WslFileAttributes};

pub const LXATTRB: &'static str = "LXATTRB";
pub const LXXATTR: &'static str = "LXXATTR";

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EaLxattrbV1 {
    flags: u16,            // 0
    version: u16,          // 1

    pub st_mode: u32,       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    pub st_uid: u32,        // Numeric identifier of user who owns file (Linux-specific).
    pub st_gid: u32,        // Numeric identifier of group that owns the file (Linux-specific)
    pub st_rdev: u32,       // Drive number of the disk containing the file.
    pub st_atime_nsec: u32, // Time of last access of file (nano-seconds).
    pub st_mtime_nsec: u32, // Time of last modification of file (nano-seconds).
    pub st_ctime_nsec: u32, // Time of creation of file (nano-seconds).
    pub st_atime: u64,    // Time of last access of file.
    pub st_mtime: u64,    // Time of last modification of file.
    pub st_ctime: u64,    // Time of creation of file.
}

impl Default for EaLxattrbV1 {
    fn default() -> Self {
        Self {
            flags: 0,
            version: 1,
            st_mode: 0o0644,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_atime_nsec: 0,
            st_mtime_nsec: 0,
            st_ctime_nsec: 0,
            st_atime: 0,
            st_mtime: 0,
            st_ctime: 0,
        }
    }
}

#[derive(Default)]
pub struct LxfsParsed<'a> {
    lxattrb: Option<Cow<'a, EaLxattrbV1>>,
    lxxattr: Option<LxxattrParsed<'a>>,
    symlink: Option<String>,
}

impl<'a> Display for LxfsParsed<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //Symlink:                   -> target
        //LXATTRB:
        //  Flags:                   0
        //  Version:                 1
        //  Ownership:               Uid: (0 / ), Gid: (0 / )
        //  Mode:                    100755
        //  Access:                  (0755) -rwxr-xr-x
        //  Device type:             37, 13
        //  Last status change:      2019-11-19 18:29:52.102270300 +0800
        //  Last file access:        2019-11-19 18:29:52.000000000 +0800
        //  Last file modification:  2019-11-14 01:57:46.000000000 +0800
        //Linux extended attributes(LXXATTR):
        //  user.xdg.origin.url:      http://example.url
        
        if let Some(s) = &self.symlink {
            f.write_fmt(format_args!("{:28}-> {}\n", "Symlink:", s))?;
        }

        if let Some(l) = &self.lxattrb {
            f.write_str("LXATTRB:\n")?;
            f.write_fmt(format_args!("{:28}{}\n", "  Flags:", l.flags))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Version:", l.version))?;
            f.write_fmt(format_args!("{:28}{} {}\n", "  Ownership:", l.st_uid, l.st_gid))?;
            f.write_fmt(format_args!("{:28}{:o}\n", "  Mode:", l.st_mode))?;
            f.write_fmt(format_args!("{:28}{:o}\n", "  Access:", l.st_mode))?;
            if l.st_rdev != 0 {
                f.write_fmt(format_args!("{:28}{}, {}\n", "  Device type:", dev_major(l.st_rdev), dev_minor(l.st_rdev)))?;
            }
            f.write_fmt(format_args!("{:28}{}\n", "  Last status change:", TimeTWithNano::new(l.st_ctime, l.st_ctime_nsec)))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Last file access:", TimeTWithNano::new(l.st_atime, l.st_atime_nsec)))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Last file modification:", TimeTWithNano::new(l.st_mtime, l.st_mtime_nsec)))?;
        }

        if let Some(lxxattr) = &self.lxxattr {
            f.write_str("Linux extended attributes(LXXATTR):\n")?;
            for l in &lxxattr.entries {
                let name = lxxattr_name_display(&l.name);
                let value = lxxattr_value_display(&l.value);
                f.write_fmt(format_args!("  {:26}{}\n", name, value))?;
            }
        }
        Ok(())
    }
}

const MINORBITS: usize = 20;
const MINORMASK: u32 = (1u32 << MINORBITS) - 1;

const fn dev_major(dev: u32) -> u32 {
    dev >> MINORBITS
}
const fn dev_minor(dev: u32) -> u32 {
    dev & MINORMASK
}
const fn make_dev(ma: u32, mi: u32) -> u32 {
    (ma << MINORBITS) | mi
}

const S_IFLNK: u32 = 0o0120000;		/* symbolic link */

/* symbolic link */
const fn S_ISLNK(m: u32) -> bool {
    (m & 0o0170000) == S_IFLNK
}

impl<'a> WslFileAttributes<'a> for LxfsParsed<'a> {
    fn maybe(&self) -> bool {
        self.lxattrb.is_some() ||
        self.lxxattr.is_some()
    }

    fn try_load<'b: 'a>(wsl_file: &'a WslFile, ea_parsed: &'b Vec<EaEntryRaw<'a>>) -> std::io::Result<Self> {
        let mut p = Self::default();

        for EaEntry { name, value, flags: _ } in ea_parsed {
            let name = name.as_ref();
            if name == LXATTRB.as_bytes() {
                p.lxattrb = Some(Cow::Borrowed(force_cast(value.as_ref())));
                
                if let Some(mode) = p.get_mode() {
                    if S_ISLNK(mode) {
                        let buf = unsafe { read_data(wsl_file.file_handle) }.unwrap();                
                        let symlink = String::from_utf8(buf).unwrap();
                        p.symlink = Some(symlink);
                    }
                }
            } else if name == LXXATTR.as_bytes() {
                let lxxattr_parsed = unsafe { parse_lxxattr(value.as_ref()) };
                p.lxxattr = Some(lxxattr_parsed);
            }
        }

        Ok(p)
    }
    
    fn get_uid(&self) -> Option<u32> {
        self.lxattrb.as_ref().map(|l| l.st_uid)
    }
    
    fn get_gid(&self) -> Option<u32> {
        self.lxattrb.as_ref().map(|l| l.st_gid)
    }
    
    fn get_mode(&self) -> Option<u32> {
        self.lxattrb.as_ref().map(|l| l.st_mode)
    }
    
    fn get_dev_major(&self) -> Option<u32> {
        self.lxattrb.as_ref().map(|l| dev_major(l.st_rdev))
    }
    
    fn get_dev_minor(&self) -> Option<u32> {
        self.lxattrb.as_ref().map(|l| dev_minor(l.st_rdev))
    }
    
    fn set_uid(&mut self, uid: u32) {
        let mut lxattrb = self.lxattrb.take().unwrap_or_default();
        lxattrb.to_mut().st_uid = uid;
        self.lxattrb = Some(lxattrb);
    }
    
    fn set_gid(&mut self, gid: u32) {
        let mut lxattrb = self.lxattrb.take().unwrap_or_default();
        lxattrb.to_mut().st_gid = gid;
        self.lxattrb = Some(lxattrb);
    }
    
    fn set_mode(&mut self, mode: u32) {
        let mut lxattrb = self.lxattrb.take().unwrap_or_default();
        lxattrb.to_mut().st_mode = mode;
        self.lxattrb = Some(lxattrb);
    }
    
    fn set_dev_major(&mut self, ma: u32) {
        let mut lxattrb = self.lxattrb.take().unwrap_or_default();
        let st_rdev = lxattrb.st_rdev;
        lxattrb.to_mut().st_rdev = make_dev(ma, dev_minor(st_rdev));
        self.lxattrb = Some(lxattrb);
    }
    
    fn set_dev_minor(&mut self, mi: u32) {
        let mut lxattrb = self.lxattrb.take().unwrap_or_default();
        let st_rdev = lxattrb.st_rdev;
        lxattrb.to_mut().st_rdev = make_dev(dev_major(st_rdev), mi);
        self.lxattrb = Some(lxattrb);
    }
}

#[derive(Default)]
pub struct LxxattrParsed<'a> {
    entries: Vec<LxxattrEntry<'a>>,
}

struct LxxattrEntry<'a> {
    pub name: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
}

/// |Offset      |Size|Note|
/// |------------|----|----|
/// |0           |4   |Always 00 00 01 00|
/// |4           |4   |Next entry relative offset. Zero if last. (A)|
/// |8           |2   |Length of xattr value. (B)|
/// |10          |1   |Length of xattr name. (C)|
/// |11          |C   |xattr name. UTF-8. No null terminator.|
/// |11 + C      |B   |xattr value.|
/// |11 + B + C  |1   |Unknown. Even if change to a random value, WSL does not worry. should be aligned|
/// |4 + A       |    |Repeat above six elements.|
struct LxxattrEntryRaw {
    next_entry_offset: u32,
    value_length: u16,
    name_length: u8,
    /// xattr name. UTF-8. No null terminator.
    name: [u8; 0],
    /// xattr value.
    value: [u8; 0],
}

#[repr(C)]
struct LxxattrRaw {
    flags: u16,            // 0
    version: u16,          // 1
    entries: LxxattrEntryRaw,
}

const LXXATTR_ALIGN: usize = size_of::<u32>();

fn lxxattr_entry_size(pea: &LxxattrEntryRaw) -> usize {
    lxxattr_entry_size_inner(pea.name_length, pea.value_length)
}

fn lxxattr_entry_size_inner(name_len: u8, value_len: u16) -> usize {
    let data_len = offset_of!(LxxattrEntryRaw, name) + name_len as usize + value_len as usize;
    let full_len = (data_len + 1) / LXXATTR_ALIGN * LXXATTR_ALIGN;
    return full_len;
}

pub unsafe fn parse_lxxattr<'a>(buf: &'a [u8]) -> LxxattrParsed<'a> {
    let buf = buf.as_ref();

    let mut entries = vec![];

    assert!(buf.len() >= size_of::<LxxattrRaw>());

    let buf_range = buf.as_ptr_range();
    let praw: &LxxattrRaw = transmute(buf.as_ptr());
    assert_eq!(praw.flags, 0);
    assert_eq!(praw.version, 1);
    let mut ea_ptr = addr_of!(praw.entries) as *const u8;
    
    loop {
        assert!(ea_ptr.add(size_of::<LxxattrEntryRaw>()) <= buf_range.end);
        let pea: &LxxattrEntryRaw = transmute(ea_ptr);
        let pea_end = ea_ptr.add(lxxattr_entry_size(pea));

        // invalid ea data may cause read overflow
        assert!(pea_end <= buf_range.end);

        let pname = &pea.name as *const u8;
        let name = &*slice_from_raw_parts(pname, pea.name_length as usize);

        let pvalue =  pname.add(pea.name_length as usize);
        let value = &*slice_from_raw_parts(pvalue, pea.value_length as usize);

        entries.push(LxxattrEntry {
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(value),
        });

        if pea.next_entry_offset == 0 {
            break;
        }
        ea_ptr = ea_ptr.add(pea.next_entry_offset as usize);
    }
    
    LxxattrParsed {
        entries,
    }
}

// TODO:  Upper ASCII, should be converted before display
fn lxxattr_name_display(name: impl AsRef<[u8]>) -> String {
    String::from_utf8_lossy(name.as_ref()).to_ascii_lowercase()
}

fn lxxattr_value_display<'a>(value: &'a [u8]) -> Cow<'a, str> {
    match std::str::from_utf8(value) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(value.escape_ascii().to_string()),
    }
}
