use std::path::PathBuf;

use registry::{Data, Hive, RegKey, Security};

use clap::ValueEnum;
use utfx::{U16CStr, U16CString};

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
    let lxss = Hive::CurrentUser.open(REG_LXSS, Security::Read).ok()?;
    if let Data::String(s) = lxss.value("DefaultDistribution").ok()? {
        try_load_from_reg_key(lxss.open(s, Security::Read).ok()?)
    } else {
        None
    }    
}

pub fn try_load<S: AsRef<str>>(name: S) -> Option<Distro> {
    try_load_from_u16cstr(U16CString::from_str(name.as_ref()).expect("invalid u16 string for distro name"))
}

pub fn try_load_from_u16cstr<S: AsRef<U16CStr>>(name: S) -> Option<Distro> {
    Hive::CurrentUser.open(REG_LXSS, Security::Read).ok()?.keys()
    .filter_map(|k| k.ok())
    .filter_map(|k| k.open(Security::Read).ok())
    .filter(|k| {
        if let Ok(Data::String(s)) = k.value("DistributionName") {
            s.as_ucstr() == name.as_ref()
        } else {
            false
        }
    })
    .nth(0)
    .and_then(try_load_from_reg_key)
}

pub fn try_load_from_reg_key(distro_key: RegKey) -> Option<Distro> {
    let name = if let Ok(Data::String(s)) = distro_key.value("DistributionName") {
        Some(s.to_string_lossy())
    } else {
        None
    }?;
    let base_path = if let Ok(Data::String(s)) = distro_key.value("BasePath") {
        Some(s.to_os_string().into())
    } else {
        None
    }?;

    // & 0x08 = 0 -> WSL1
    let is_wsl2 = if let Ok(Data::U32(flags)) = distro_key.value("Flags") {
        (flags & 0x08) != 0
    } else {
        false
    };

    let fs_type = if !is_wsl2 {
        match distro_key.value("Version") {
            Ok(Data::U32(1)) => Some(FsType::Lxfs),
            Ok(Data::U32(2)) => Some(FsType::Wslfs),
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
