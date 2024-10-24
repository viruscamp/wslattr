use std::{borrow::Cow, fmt::Display};

use ntapi::winapi::shared::minwindef::*;
use winapi::shared::basetsd::ULONG64;

use crate::{ea_parse::EaParsed, time_utils::TimeTWithNano, wsl_file::{WslFile, WslFileAttributes}};

pub const LXATTRB: &'static str = "LXATTRB";
pub const LXXATTR: &'static str = "LXXATTR";

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
            f.write_fmt(format_args!("{:28}-> {}\n", "  Flags:", l.flags))?;
            f.write_fmt(format_args!("{:28}-> {}\n", "  Version:", l.version))?;
            f.write_fmt(format_args!("{:28}-> {} {}\n", "  Ownership:", l.st_uid, l.st_gid))?;
            f.write_fmt(format_args!("{:28}-> {:o}\n", "  Mode:", l.st_mode))?;
            f.write_fmt(format_args!("{:28}-> {:o}\n", "  Access:", l.st_mode))?;
            if l.st_rdev != 0 {
                f.write_fmt(format_args!("{:28}-> {}, {}\n", "  Device type:", dev_major(l.st_rdev), dev_minor(l.st_rdev)))?;
            }
            f.write_fmt(format_args!("{:28}-> {}\n", "  Last status change:", TimeTWithNano::new(l.st_ctime, l.st_ctime_nsec)))?;
            f.write_fmt(format_args!("{:28}-> {}\n", "  Last file access:", TimeTWithNano::new(l.st_atime, l.st_atime_nsec)))?;
            f.write_fmt(format_args!("{:28}-> {}\n", "  Last file modification:", TimeTWithNano::new(l.st_mtime, l.st_mtime_nsec)))?;
        }

        if let Some(l) = &self.lxxattr {
            f.write_str("Linux extended attributes(LXXATTR):\n")?;
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

impl<'a> WslFileAttributes<'a> for LxfsParsed<'a> {
    fn try_load(wsl_file: &'a WslFile, ea_parsed: &'a EaParsed) -> std::io::Result<Self> {
        let mut p = Self::default();

        p.lxattrb = ea_parsed.get_ea::<EaLxattrbV1>(LXATTRB).map(|x| Cow::Borrowed(x));

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

pub struct LxxattrParsed<'a> {
    entries: Vec<LxxattrEntry<'a>>,
    changed: bool,
}

struct LxxattrEntry<'a> {
    pub name: Cow<'a, str>,
    pub value: Cow<'a, [u8]>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EaLxattrbV1 {
    flags: USHORT,            // 0
    version: USHORT,          // 1

    pub st_mode: ULONG,       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    pub st_uid: ULONG,        // Numeric identifier of user who owns file (Linux-specific).
    pub st_gid: ULONG,        // Numeric identifier of group that owns the file (Linux-specific)
    pub st_rdev: ULONG,       // Drive number of the disk containing the file.
    pub st_atime_nsec: ULONG, // Time of last access of file (nano-seconds).
    pub st_mtime_nsec: ULONG, // Time of last modification of file (nano-seconds).
    pub st_ctime_nsec: ULONG, // Time of creation of file (nano-seconds).
    pub st_atime: ULONG64,    // Time of last access of file.
    pub st_mtime: ULONG64,    // Time of last modification of file.
    pub st_ctime: ULONG64,    // Time of creation of file.
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
