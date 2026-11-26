use std::path::{Path, PathBuf};

use clap::ValueEnum;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::core::{Error, HRESULT, Result};
use windows_registry::{Key, CURRENT_USER};

use crate::posix::{load_groups, load_users, PosixIdentifier};
use crate::path_utils::{is_path_prefix_disk, normalize_path, try_get_abs_path_prefix, try_get_distro_from_unc_path};

#[derive(Clone, Copy, ValueEnum, Debug)]
#[derive(PartialEq, Eq)]
pub enum FsType {
    Lxfs = 1,
    Wslfs = 2,
}

#[derive(Debug, Clone, Copy)]
#[derive(PartialEq, Eq)]
pub enum DistroSource {
    Unknown,
    Arg,
    Default,
    CurrentDirUNC,
    CurrentDirDisk,
    FilePathUNC,
    FilePathDisk,
}

#[derive(Debug)]
pub struct Distro {
    pub guid: String,
    pub name: String,
    pub base_path: PathBuf,
    pub fs_type: Option<FsType>, // None means WSL2

    pub source: DistroSource,

    pub users: Option<Vec<PosixIdentifier>>,
    pub groups: Option<Vec<PosixIdentifier>>,
}

const REG_LXSS: &'static str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";

#[allow(non_upper_case_globals)]
const DefaultDistribution: &str = "DefaultDistribution";

#[allow(non_upper_case_globals)]
const DistributionName: &str = "DistributionName";

#[allow(non_upper_case_globals)]
const BasePath: &str = "BasePath";

// Flags, from wslapi.h
// Valid but overridden by /etc/wsl.conf after Windows Build 17093 and later.
// WSL_DISTRIBUTION_FLAGS_NONE = 0x0,
// WSL_DISTRIBUTION_FLAGS_ENABLE_INTEROP = 0x1,
// WSL_DISTRIBUTION_FLAGS_APPEND_NT_PATH = 0x2,
// WSL_DISTRIBUTION_FLAGS_ENABLE_DRIVE_MOUNTING = 0x4
// LXSS_DISTRO_FLAGS_VM_MODE = 0x8 // only in https://github.com/microsoft/WSL/blob/6e43d804/src/windows/service/inc/wslservice.idl#L105-L111
#[allow(non_upper_case_globals)]
const Flags: &str = "Flags";

#[allow(non_upper_case_globals)]
const Version: &str = "Version";

pub fn try_load_from_reg_default() -> Result<Distro> {
    let lxss = CURRENT_USER.open(REG_LXSS)?;
    let default_distro_guid = lxss.get_string(DefaultDistribution)?;
    let dist_key = lxss.open(&default_distro_guid)?;
    let mut d = try_load_from_reg_key(default_distro_guid, dist_key)?;
    d.source = DistroSource::Default;
    return Ok(d);
}

pub fn try_load_reg<S: AsRef<str>>(name: S) -> Result<(String, Key)> {
    let lxss = CURRENT_USER.open(REG_LXSS)?;
    for guid in lxss.keys()? {
        if let Ok(k) = lxss.open(&guid) {
            if let Ok(s) = k.get_string(DistributionName) {
                if s.as_str() == name.as_ref() {
                    return Ok((guid, k));
                }
            }
        }
    }
    Err(ERROR_FILE_NOT_FOUND.to_hresult().into())
}

pub fn try_load<S: AsRef<str>>(name: S) -> Result<Distro> {
    try_load_reg(name)
    .and_then(|(guid, k)| try_load_from_reg_key(guid, k))
}

pub fn try_load_from_absolute_path<P: AsRef<Path>>(path: P) -> Result<Distro> {
    if let Some(n) = try_get_distro_from_unc_path(path.as_ref()) {
        if let Ok(mut distro) = try_load(&n.to_string_lossy()) {
            distro.source = DistroSource::FilePathUNC;
            return Ok(distro);
        }
    }

    if is_path_prefix_disk(&try_get_abs_path_prefix(path.as_ref())) {
        let path = normalize_path(path.as_ref())?;
        let lxss = CURRENT_USER.open(REG_LXSS)?;

        for guid in lxss.keys()? {
            if let Ok(k) = lxss.open(&guid) {
                if let Ok(s) = k.get_string(BasePath) {
                    if let Ok(base_path) = normalize_path(&PathBuf::from(&s)) {
                        if path.starts_with(base_path) {
                            let mut distro = try_load_from_reg_key(guid, k)?;
                            distro.source = DistroSource::FilePathDisk;
                            return Ok(distro);
                        }
                    }
                }
            }
        }
    }

    return Err(ERROR_FILE_NOT_FOUND.to_hresult().into());
}

pub fn try_load_from_current_dir() -> Result<Distro> {
    std::env::current_dir()
    .map_or_else(
        |_| Err(ERROR_FILE_NOT_FOUND.to_hresult().into()), 
        |p| {
            let mut distro = try_load_from_absolute_path(p)?;
            distro.source = match distro.source {
                DistroSource::FilePathUNC => DistroSource::CurrentDirUNC,
                DistroSource::FilePathDisk => DistroSource::CurrentDirDisk,
                other => other,
            };
            Ok(distro)
        }
    )
}

pub fn try_load_from_reg_key(guid: String, distro_key: Key) -> Result<Distro> {
    let name: String = distro_key.get_string(DistributionName)?;
    let base_path: String = distro_key.get_string(BasePath)?;
    let base_path = PathBuf::from(&base_path);

    // & 0x08 = 0 -> WSL1
    let is_wsl2 = if let Ok(flags) = distro_key.get_u32(Flags) {
        (flags & 0x08) != 0
    } else {
        false
    };

    let fs_type = if !is_wsl2 {
        match distro_key.get_u32(Version) {
            Ok(1) => Some(FsType::Lxfs),
            Ok(2) => Some(FsType::Wslfs),
            _ => None,
        }
    } else {
        None
    };

    let groups = load_groups(&base_path.join("rootfs"));
    let users = load_users(&base_path.join("rootfs"));

    return Ok(Distro {
        guid,
        name,
        base_path,
        fs_type,
        source: DistroSource::Unknown,
        users,
        groups,
    });
}

impl Distro {
    pub fn set_fs_type(&mut self, fs_type: Option<FsType>) -> Result<()> {
        let lxss = CURRENT_USER.open(REG_LXSS)?;
        let dist_key = lxss.create(&self.guid)?;
        match fs_type {
            None => dist_key.remove_value(Version),
            Some(FsType::Lxfs) => dist_key.set_u32(Version, FsType::Lxfs as u32),
            Some(FsType::Wslfs) => dist_key.set_u32(Version, FsType::Wslfs as u32),
        }?;
        self.fs_type = fs_type;
        Ok(())
    }

    pub fn uid(&self, user_name: &str) -> Option<u32> {
        self.users.as_ref()
        .and_then(|users|
            users.iter()
            .find(|u| u.name == user_name)
            .and_then(|u| Some(u.id))
        )
    }

    pub fn gid(&self, group_name: &str) -> Option<u32> {
        self.groups.as_ref()
        .and_then(|groups|
            groups.iter()
            .find(|u| u.name == group_name)
            .and_then(|u| Some(u.id))
        )
    }

    pub fn user_name(&self, uid: u32) -> Option<&str> {
        self.users.as_ref()
        .and_then(|users|
            users.iter()
            .find(|u| u.id == uid)
            .and_then(|u| Some(u.name.as_str()))
        )
    }

    pub fn group_name(&self, gid: u32) -> Option<&str> {
        self.groups.as_ref()
        .and_then(|groups|
            groups.iter()
            .find(|u| u.id == gid)
            .and_then(|u| Some(u.name.as_str()))
        )
    }
}
