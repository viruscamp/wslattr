use std::path::PathBuf;
use std::str::FromStr;

use clap::ValueEnum;
use windows_registry::{Key, CURRENT_USER};

#[derive(Clone, Copy, ValueEnum, Debug)]
pub enum FsType {
    Lxfs,
    Wslfs,
}

#[derive(Debug)]
pub struct Distro {
    pub name: String,
    pub base_path: PathBuf,
    pub fs_type: Option<FsType>, // None means WSL2
}

const REG_LXSS: &'static str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";

pub fn default() -> Option<Distro> {
    let lxss = CURRENT_USER.open(REG_LXSS).ok()?;
    let default_distro_guid = lxss.get_string("DefaultDistribution").ok()?;
    return try_load_from_reg_key(lxss.open(default_distro_guid).ok()?); 
}

pub fn try_load<S: AsRef<str>>(name: S) -> Option<Distro> {
    let lxss = CURRENT_USER.open(REG_LXSS).ok()?;
    lxss.keys().ok()?
    .filter_map(|k| lxss.open(k).ok())
    .filter(|k| {
        if let Ok(s) = k.get_string("DistributionName") {
            s.as_str() == name.as_ref()
        } else {
            false
        }
    })
    .nth(0)
    .and_then(try_load_from_reg_key)
}

pub fn try_load_from_reg_key(distro_key: Key) -> Option<Distro> {
    let name: String = distro_key.get_string("DistributionName").ok()?;
    let base_path: String = distro_key.get_string("BasePath").ok()?;
    let base_path = PathBuf::from_str(&base_path).ok()?;

    // & 0x08 = 0 -> WSL1
    let is_wsl2 = if let Ok(flags) = distro_key.get_u32("Flags") {
        (flags & 0x08) != 0
    } else {
        false
    };

    let fs_type = if !is_wsl2 {
        match distro_key.get_u32("Version") {
            Ok(1) => Some(FsType::Lxfs),
            Ok(2) => Some(FsType::Wslfs),
            _ => None,
        }
    } else {
        None
    };

    return Some(Distro {
        name,
        base_path,
        fs_type,
    });
}
