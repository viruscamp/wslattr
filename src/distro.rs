use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::ValueEnum;
use windows_registry::{Key, CURRENT_USER};

use crate::posix::{load_groups, load_users, Group, User};
use crate::{is_path_prefix_disk, normalize_path, try_get_abs_path_prefix, try_get_distro_from_unc_path};

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
    CurrentDir,
    FilePath,
}

#[derive(Debug)]
pub struct Distro {
    pub name: String,
    pub base_path: PathBuf,
    pub fs_type: Option<FsType>, // None means WSL2

    pub source: DistroSource,

    pub users: Option<Vec<User>>,
    pub groups: Option<Vec<Group>>,
}

const REG_LXSS: &'static str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";

#[allow(non_upper_case_globals)]
const DefaultDistribution: &str = "DefaultDistribution";

#[allow(non_upper_case_globals)]
const DistributionName: &str = "DistributionName";
#[allow(non_upper_case_globals)]
const BasePath: &str = "BasePath";
#[allow(non_upper_case_globals)]
const Flags: &str = "Flags";
#[allow(non_upper_case_globals)]
const Version: &str = "Version";

pub fn try_load_from_reg_default() -> Option<Distro> {
    let lxss = CURRENT_USER.open(REG_LXSS).ok()?;
    let default_distro_guid = lxss.get_string(DefaultDistribution).ok()?;
    let mut d = try_load_from_reg_key(lxss.open(default_distro_guid).ok()?)?;
    d.source = DistroSource::Default;
    return Some(d);
}

pub fn try_load_reg<S: AsRef<str>>(name: S) -> Option<Key> {
    let lxss = CURRENT_USER.open(REG_LXSS).ok()?;
    lxss.keys().ok()?
    .filter_map(|k| lxss.open(k).ok())
    .filter(|k| {
        if let Ok(s) = k.get_string(DistributionName) {
            s.as_str() == name.as_ref()
        } else {
            false
        }
    })
    .nth(0)
}

pub fn try_load<S: AsRef<str>>(name: S) -> Option<Distro> {
    try_load_reg(name)
    .and_then(try_load_from_reg_key)
}

pub fn try_load_from_absolute_path<P: AsRef<Path>>(path: P) -> Option<Distro> {
    if let Some(n) = try_get_distro_from_unc_path(path.as_ref()) {
        return try_load(&n.to_string_lossy());
    }

    if is_path_prefix_disk(&try_get_abs_path_prefix(path.as_ref())) {
        let path = normalize_path(path.as_ref()).ok()?;

        let lxss = CURRENT_USER.open(REG_LXSS).ok()?;
        return lxss.keys().ok()?
        .filter_map(|k| lxss.open(k).ok())
        .filter(|k| {
            if let Ok(s) = k.get_string(BasePath) {
                if let Ok(base_path) = PathBuf::from_str(&s) {
                    if let Ok(base_path) = normalize_path(&base_path) {
                        return path.starts_with(base_path);
                    }
                }
            }
            return false;
        })
        .nth(0)
        .and_then(try_load_from_reg_key);
    }

    return None;
}

pub fn try_load_from_reg_key(distro_key: Key) -> Option<Distro> {
    let name: String = distro_key.get_string(DistributionName).ok()?;
    let base_path: String = distro_key.get_string(DistributionName).ok()?;
    let base_path = PathBuf::from_str(&base_path).ok()?;

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

    return Some(Distro {
        name,
        base_path,
        fs_type,
        source: DistroSource::Unknown,
        users,
        groups,
    });
}

impl Distro {
    pub fn set_fs_type(&mut self, fs_type: Option<FsType>) {
        try_load_reg(&self.name).and_then(|k| {
            match fs_type {
                None => k.remove_value(Version),
                Some(FsType::Lxfs) => k.set_u32(Version, FsType::Lxfs as u32),
                Some(FsType::Wslfs) => k.set_u32(Version, FsType::Wslfs as u32),
            }.unwrap();
            self.fs_type = fs_type;            
            Some(())
        });
    }

    pub fn uid(&self, user_name: &str) -> Option<u32> {
        self.users.as_ref()
        .and_then(|users|
            users.iter()
            .find(|u| u.name == user_name).and_then(|u| Some(u.uid))
        )
    }

    pub fn gid(&self, group_name: &str) -> Option<u32> {
        self.groups.as_ref()
        .and_then(|groups|
            groups.iter()
            .find(|u| u.name == group_name).and_then(|u| Some(u.gid))
        )
    }

    pub fn user_name(&self, uid: u32) -> Option<&str> {
        self.users.as_ref()
        .and_then(|users|
            users.iter()
            .find(|u| u.uid == uid).and_then(|u| Some(u.name.as_str()))
        )
    }

    pub fn group_name(&self, gid: u32) -> Option<&str> {
        self.groups.as_ref()
        .and_then(|groups|
            groups.iter()
            .find(|u| u.gid == gid).and_then(|u| Some(u.name.as_str()))
        )
    }
}