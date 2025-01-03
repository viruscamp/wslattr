use std::borrow::Cow;
use std::mem::{offset_of, transmute};
use std::ptr::{addr_of, slice_from_raw_parts};

use windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION;

use crate::distro::{Distro, FsType};
use crate::ea_parse::{force_cast, EaEntry, EaEntryRaw};
use crate::posix::{lsperms, StModeType, DEFAULT_MODE};
use crate::ntfs_io::read_data;
use crate::time_utils::{u64_to_lxfs_time, LxfsTime}; 
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

impl EaLxattrbV1 {
    pub fn new(basic_file_info: &Option<FILE_BASIC_INFORMATION>) -> Self {
        let mut lxattrb = Self {
            flags: 0,
            version: 1,
            st_mode: DEFAULT_MODE,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_atime_nsec: 0,
            st_mtime_nsec: 0,
            st_ctime_nsec: 0,
            st_atime: 0,
            st_mtime: 0,
            st_ctime: 0,
        };

        if let Some(fbi) = basic_file_info {
            (lxattrb.st_atime, lxattrb.st_atime_nsec) = u64_to_lxfs_time(fbi.LastAccessTime as u64).into();
            (lxattrb.st_mtime, lxattrb.st_mtime_nsec) = u64_to_lxfs_time(fbi.LastWriteTime as u64).into();
            (lxattrb.st_ctime, lxattrb.st_ctime_nsec) = u64_to_lxfs_time(fbi.ChangeTime as u64).into();
        }

        return lxattrb;
    }
}

#[derive(Default)]
pub struct LxfsParsed<'a> {
    pub lxattrb: Option<Cow<'a, EaLxattrbV1>>,
    lxxattr: Option<Vec<LxxattrEntry<'a>>>,
    pub symlink: Option<String>,

    pub basic_file_info: Option<FILE_BASIC_INFORMATION>,
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

impl<'a> LxfsParsed<'a> {
    pub fn load<'b: 'a, 'c>(wsl_file: &'c WslFile, ea_parsed: &'b Option<Vec<EaEntryRaw<'a>>>)-> Self {
        let mut p = Self::default();
        p.basic_file_info = wsl_file.basic_file_info;

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
                }
            }
        }

        p
    }

    fn lxattrb_mut(&mut self) -> &mut EaLxattrbV1 {
        let lxattrb = self.lxattrb.take().unwrap_or_else(|| {
            Cow::Owned(EaLxattrbV1::new(&self.basic_file_info))
        });
        self.lxattrb = Some(lxattrb);
        self.lxattrb.as_mut().unwrap().to_mut()
    }
}

impl<'a> WslFileAttributes<'a> for LxfsParsed<'a> {
    fn fs_type(&self) -> FsType {
        FsType::Lxfs
    }

    fn maybe(&self) -> bool {
        self.lxattrb.is_some() ||
        self.lxxattr.is_some()
    }
    
    fn fmt(&self, f: &mut dyn std::io::Write, distro: Option<&Distro>) -> std::io::Result<()> {
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
            f.write("LXATTRB:\n".as_bytes())?;
            f.write_fmt(format_args!("{:28}{}\n", "  Flags:", l.flags))?;
            f.write_fmt(format_args!("{:28}{}\n", "  Version:", l.version))?;

            let uid = l.st_uid;
            if let Some(user_name) = distro.and_then(|d| d.user_name(uid)) {
                f.write_fmt(format_args!("{:28}{} / {}\n", "  User:", uid, user_name))?;
            } else {
                f.write_fmt(format_args!("{:28}{}\n", "  User:", uid))?;
            }

            let gid = l.st_gid;
            if let Some(group_name) = distro.and_then(|d| d.group_name(gid)) {
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
            f.write("Linux extended attributes(LXXATTR):\n".as_bytes())?;
            for l in lxxattr {
                f.write_fmt(format_args!("  {:26}{}\n", l.name_display(), l.value_display()))?;
            }
        }
        Ok(())
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
        self.lxattrb_mut().st_uid = uid;
    }
    
    fn set_gid(&mut self, gid: u32) {
        self.lxattrb_mut().st_gid = gid;
    }
    
    fn set_mode(&mut self, mode: u32) {
        self.lxattrb_mut().st_mode = mode;
    }
    
    fn set_dev_major(&mut self, ma: u32) {
        let mut lxattrb = self.lxattrb_mut();
        let st_rdev = lxattrb.st_rdev;
        lxattrb.st_rdev = make_dev(ma, dev_minor(st_rdev));
    }
    
    fn set_dev_minor(&mut self, mi: u32) {
        let mut lxattrb = self.lxattrb_mut();
        let st_rdev = lxattrb.st_rdev;
        lxattrb.st_rdev = make_dev(dev_major(st_rdev), mi);
    }

    fn set_attr(&mut self, name: &str, value: &[u8]) {
        let mut lxxattr = self.lxxattr.take().unwrap_or_default();
        if let Some(x) = lxxattr.iter_mut()
            .filter(|x| x.name.as_ref() == name.as_bytes())
            .next()
        {
            x.value = Some(Cow::Owned(value.to_owned()));
        } else {
            let name = Cow::Owned(name.as_bytes().to_owned());
            let value = Some(Cow::Owned(value.to_owned()));
            lxxattr.push(LxxattrEntry { name, value });
        }
        self.lxxattr = Some(lxxattr);
    }

    fn rm_attr(&mut self, name: &str) {
        let mut lxxattr = self.lxxattr.take().unwrap_or_default();
        if let Some(x) = lxxattr.iter_mut()
            .filter(|x| x.name.as_ref() == name.as_bytes())
            .next()
        {
            x.value = None;
        }
        self.lxxattr = Some(lxxattr);
    }

    fn save(&mut self, wsl_file: &mut WslFile) -> std::io::Result<()>  {
        use crate::ea_parse::{EaOut, get_buffer};
        use crate::ntfs_io::write_ea;

        let mut ea_out = EaOut::default();

        if let Some(Cow::Owned(ref x)) = self.lxattrb {
            ea_out.add(LXATTRB.as_bytes(), get_buffer(x));
        }

        if let Some(x) = self.lxxattr.take() {            
            let mut lxxattr_out = LxxattrOut::default();
            let t = x.into_iter().filter(|attr| {
                if let Some(ref value) = attr.value {
                    lxxattr_out.add(&attr.name, value);
                    true
                } else {
                    false
                }
            }).collect();
            ea_out.add(LXXATTR.as_bytes(), &lxxattr_out.buffer);
            self.lxxattr = Some(t);
        }

        unsafe { write_ea(wsl_file.file_handle, &ea_out.buffer) }
    }
}

struct LxxattrEntry<'a> {
    pub name: Cow<'a, [u8]>,
    /// None means will be deleted in save
    pub value: Option<Cow<'a, [u8]>>,
}

impl<'a> LxxattrEntry<'a> {
    fn name_display(&self) -> String {
        String::from_utf8_lossy(self.name.as_ref()).to_ascii_lowercase()
    }

    fn value_display(&'a self) -> String {
        use std::fmt::Write;

        if let Some(x) = &self.value {
            let bytes = x.as_ref();
            let mut out = String::with_capacity(bytes.len() + 16);
            write!(&mut out, "\"").unwrap();
            crate::escape_utils::escape_bytes_octal(bytes, &mut out, true).unwrap();
            write!(&mut out, "\"").unwrap();

            out
        } else {
            "TO_RM".to_owned()
        }
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

unsafe fn parse_lxxattr<'a>(buffer: &'a [u8]) -> Vec<LxxattrEntry<'a>> {
    let mut entries = vec![];

    assert!(buffer.len() >= size_of::<LxxattrRaw>());

    let buf_range = buffer.as_ptr_range();
    let praw: &LxxattrRaw = transmute(buffer.as_ptr());
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
            value: Some(Cow::Borrowed(value)),
        });

        if pea.next_entry_offset == 0 {
            break;
        }
        ea_ptr = ea_ptr.add(pea.next_entry_offset as usize);
    }
    
    entries
}

#[derive(Default)]
pub struct LxxattrOut {
    pub buffer: Vec<u8>,

    // pos, size
    last_attr_info: Option<(usize, usize)>,

    count: usize,
}

impl LxxattrOut {
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn add(&mut self, name: &[u8], value: &[u8]) {
        if self.buffer.is_empty() {
            // TODO how about big endian?
            self.buffer = vec![0, 0, 1, 0];
        }
        unsafe {
            let this_size = LxxattrEntryRaw::size_inner(name.len() as u8, value.len() as u16);
            self.buffer.resize(self.buffer.len() + this_size, 0);

            let this_pos = if let Some(last_attr_info) = self.last_attr_info {                
                let last_attr_ptr = self.buffer.as_mut_ptr().add(last_attr_info.0);
                let last_attr: &mut LxxattrEntryRaw = transmute(last_attr_ptr);
                last_attr.next_entry_offset = last_attr_info.1 as u32;
                last_attr_info.0 + last_attr_info.1
            } else {
                4
            };

            let pea: *mut u8 = self.buffer.as_mut_ptr().add(this_pos);
            let ea: &mut LxxattrEntryRaw = transmute(pea);
            ea.next_entry_offset = 0;

            ea.name_length = name.len() as u8;
            let pname: *mut u8 = pea.add(offset_of!(LxxattrEntryRaw, name));
            std::ptr::copy_nonoverlapping(name.as_ptr(), pname, ea.name_length as usize);

            ea.value_length = value.as_ref().len() as u16;
            let pvalue: *mut u8 = pname.add(ea.name_length as usize);
            std::ptr::copy_nonoverlapping(value.as_ptr(), pvalue, ea.value_length as usize);

            self.last_attr_info = Some((this_pos, this_size));
            self.count += 1;
        }
    }
}
