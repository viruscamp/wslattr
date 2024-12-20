use std::{borrow::Cow, fmt::Display, mem::{offset_of, transmute}, ptr::{addr_of, slice_from_raw_parts}};

use crate::{distro::Distro, ea_parse::{force_cast, EaEntry, EaEntryRaw}, posix::{lsperms, StModeType}};
use crate::ntfs_io::read_data;
use crate::time_utils::LxfsTime; 
use crate::wsl_file::{WslFile, WslFileAttributes};

pub const LXATTRB: &'static str = "LXATTRB";
pub const LXXATTR: &'static str = "LXXATTR";

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EaLxattrbV1 {
    flags: u16,             // 0
    version: u16,           // 1

    pub st_mode: u32,       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    pub st_uid: u32,        // Numeric identifier of user who owns file (Linux-specific).
    pub st_gid: u32,        // Numeric identifier of group that owns the file (Linux-specific)
    pub st_rdev: u32,       // Drive number of the disk containing the file.
    pub st_atime_nsec: u32, // Time of last access of file (nano-seconds).
    pub st_mtime_nsec: u32, // Time of last modification of file (nano-seconds).
    pub st_ctime_nsec: u32, // Time of change of file (nano-seconds).
    pub st_atime: u64,      // Time of last access of file.
    pub st_mtime: u64,      // Time of last modification of file.
    pub st_ctime: u64,      // Time of change of file.
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
pub struct LxfsParsed<'a, 'd> {
    pub lxattrb: Option<Cow<'a, EaLxattrbV1>>,
    pub lxxattr: Option<LxxattrParsed<'a>>,
    pub symlink: Option<String>,

    pub distro: Option<&'d Distro>,
}

impl<'a, 'd> Display for LxfsParsed<'a, 'd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //Symlink:                   -> target
        //LXATTRB:
        //  Flags:                   0
        //  Version:                 1
        //  Ownership:               Uid: (0 / root), Gid: (0 / video)
        //  Mode:                    100755
        //  Access:                  -rwxr-xr-x
        //  Device type:             37, 13
        //  Last file access:        2019-11-19 18:29:52.000000000 +0800
        //  Last file modification:  2019-11-14 01:57:46.000000000 +0800
        //  Last status change:      2019-11-19 18:29:52.102270300 +0800
        //Linux extended attributes(LXXATTR):
        //  user.xdg.origin.url:      http://example.url
        
        if let Some(s) = &self.symlink {
            f.write_fmt(format_args!("{:28}-> {}\n", "Symlink:", s))?;
        }

        if let Some(l) = &self.lxattrb {
            f.write_str("LXATTRB:\n")?;
            f.write_fmt(format_args!("{:28}{}\n", "  Flags:", l.flags))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Version:", l.version))?;

            let uid = l.st_uid;
            if let Some(user_name) = self.distro.and_then(|d| d.user_name(uid)) {
                f.write_fmt(format_args!("{:28}{} / {}\n", "  User:", uid, user_name))?;
            } else {
                f.write_fmt(format_args!("{:28}{}\n", "  User:", uid))?;
            }

            let gid = l.st_gid;
            if let Some(group_name) = self.distro.and_then(|d| d.group_name(gid)) {
                f.write_fmt(format_args!("{:28}{} / {}\n", "  Group:", gid, group_name))?;
            } else {
                f.write_fmt(format_args!("{:28}{}\n", "  Group:", l.st_gid))?;
            }

            let mode = l.st_mode;
            let access = lsperms(mode);
            f.write_fmt(format_args!("{:28}Mode: {:06o} Access: {}\n", "  Mode:", mode, access))?;

            if l.st_rdev != 0 {
                f.write_fmt(format_args!("{:28}{}, {}\n", "  Device type:", dev_major(l.st_rdev), dev_minor(l.st_rdev)))?;
            }
            f.write_fmt(format_args!("{:28}{}\n", "  Last file access:", LxfsTime::new(l.st_atime, l.st_atime_nsec)))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Last file modification:", LxfsTime::new(l.st_mtime, l.st_mtime_nsec)))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Last status change:", LxfsTime::new(l.st_ctime, l.st_ctime_nsec)))?;
        }

        if let Some(lxxattr) = &self.lxxattr {
            f.write_str("Linux extended attributes(LXXATTR):\n")?;
            for l in &lxxattr.entries {
                f.write_fmt(format_args!("  {:26}{}\n", l.name_display(), l.value_display()))?;
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
pub const fn make_dev(ma: u32, mi: u32) -> u32 {
    (ma << MINORBITS) | mi
}

impl<'a, 'd> WslFileAttributes<'a> for LxfsParsed<'a, 'd> {
    fn maybe(&self) -> bool {
        self.lxattrb.is_some() ||
        self.lxxattr.is_some()
    }

    fn load<'b: 'a, 'c>(wsl_file: &'c WslFile, ea_parsed: &'b Option<Vec<EaEntryRaw<'a>>>)-> Self {
        let mut p = Self::default();

        if let Some(ea_parsed) = ea_parsed {
            for EaEntry { name, value, flags: _ } in ea_parsed {
                let name = name.as_ref();
                if name == LXATTRB.as_bytes() {
                    p.lxattrb = Some(Cow::Borrowed(force_cast(value.as_ref())));
                    
                    if let Some(mode) = p.get_mode() {
                        if StModeType::from_mode(mode) == StModeType::LNK {
                            let buf = unsafe { read_data(wsl_file.file_handle) }.unwrap();                
                            let symlink = String::from_utf8(buf).unwrap();
                            p.symlink = Some(symlink);
                        }
                    }
                } else if name == LXXATTR.as_bytes() {
                    let lxxattr_parsed = unsafe { parse_lxxattr(value.as_ref()) };
                    p.lxxattr = Some(lxxattr_parsed);

                    /*
                    let mut out = LxxattrOut::default();
                    for e in &p.lxxattr.as_ref().unwrap().entries {
                        out.add(e);
                    }
                    assert_eq!(value, &out.buff);
                    */
                }
            }
        }

        p
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

pub struct LxxattrEntry<'a> {
    pub name: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
}

impl<'a> LxxattrEntry<'a> {
    fn name_display(&self) -> String {
        String::from_utf8_lossy(self.name.as_ref()).to_ascii_lowercase()
    }

    fn value_display(&'a self) -> String {
        use std::fmt::Write;

        let bytes = self.value.as_ref();
        let mut out = String::with_capacity(bytes.len() + 16);

        write!(&mut out, "\"").unwrap();
        crate::escape_utils::escape_bytes_octal(bytes, &mut out, true).unwrap();
        write!(&mut out, "\"").unwrap();

        out
    }
}

/// |Offset     |Size|Note|
/// |-----------|----|----|
/// |0          |4   |Next entry relative offset. Zero if last. (A)|
/// |4          |2   |Length of xattr value. (B)|
/// |6          |1   |Length of xattr name. (C)|
/// |7          |C   |xattr name. UTF-8. No null terminator.|
/// |7 + C      |B   |xattr value.|
/// |7 + B + C  |1   |Unknown. Even if change to a random value, WSL does not worry.|
/// |A          |    |Repeat above six elements.|
#[repr(C)]
struct LxxattrEntryRaw {
    next_entry_offset: u32,
    value_length: u16,
    name_length: u8,
    /// xattr name. UTF-8. No null terminator.
    name: [u8; 0],
    /// xattr value.
    value: [u8; 0],
    _byte: u8,
}

impl LxxattrEntryRaw {
    fn size(&self) -> usize {
        Self::size_inner(self.name_length, self.value_length)
    }

    fn size_inner(name_len: u8, value_len: u16) -> usize {
        let data_len = size_of::<LxxattrEntryRaw>() + name_len as usize + value_len as usize;
        //let full_len = (data_len + LXXATTR_ALIGN - 1) / LXXATTR_ALIGN * LXXATTR_ALIGN;
        // not aligned
        return data_len;
    }
}

/// |Offset     |Size|Note|
/// |-----------|----|----|
/// |0          |4   |Always 00 00 01 00|
/// |4          |4   |LxxattrEntryRaw+|
#[repr(C)]
struct LxxattrRaw {
    flags: u16,            // 0
    version: u16,          // 1
    entries: [LxxattrEntryRaw; 1],
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
        let pea_end = ea_ptr.add(pea.size());

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


#[derive(Default)]
pub struct LxxattrOut {
    pub buff: Vec<u8>,

    // pos, size
    last_attr_info: Option<(usize, usize)>,
}

impl LxxattrOut {
    pub fn add(&mut self, name: &[u8], value: &[u8]) {
        if self.buff.is_empty() {
            // TODO how about big endian?
            self.buff = vec![0, 0, 1, 0];
        }
        unsafe {
            let this_size = LxxattrEntryRaw::size_inner(name.len() as u8, value.len() as u16);
            self.buff.resize(self.buff.len() + this_size, 0);

            let this_pos = if let Some(last_attr_info) = self.last_attr_info {                
                let last_attr_ptr = self.buff.as_mut_ptr().add(last_attr_info.0);
                let last_attr: &mut LxxattrEntryRaw = transmute(last_attr_ptr);
                last_attr.next_entry_offset = last_attr_info.1 as u32;
                last_attr_info.0 + last_attr_info.1
            } else {
                4
            };

            let pea: *mut u8 = self.buff.as_mut_ptr().add(this_pos);
            let ea: &mut LxxattrEntryRaw = transmute(pea);
            ea.next_entry_offset = 0;

            ea.name_length = name.len() as u8;
            let pname: *mut u8 = pea.add(offset_of!(LxxattrEntryRaw, name));
            std::ptr::copy_nonoverlapping(name.as_ptr(), pname, ea.name_length as usize);

            ea.value_length = value.as_ref().len() as u16;
            let pvalue: *mut u8 = pname.add(ea.name_length as usize);
            std::ptr::copy_nonoverlapping(value.as_ptr(), pvalue, ea.value_length as usize);

            self.last_attr_info = Some((this_pos, this_size));
        }
    }
}
