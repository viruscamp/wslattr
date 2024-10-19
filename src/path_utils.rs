use std::env::current_dir;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, Prefix};

pub fn is_unix_absolute<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().starts_with("/")
}

pub fn try_get_abs_path_prefix(abs_path: &Path) -> Option<Prefix> {
    if let Some(Component::Prefix(ref prefix)) = abs_path.components().nth(0) {
        Some(prefix.kind())
    } else {
        None
    }
}

pub fn is_path_prefix_disk(prefix: &Option<Prefix>) -> bool {
    match prefix {
        Some(Prefix::VerbatimDisk(_)) => true,
        Some(Prefix::Disk(_)) => true,
        _ => false,
    }
}

pub fn try_get_distro_from_unc_path_prefix<'a>(prefix: &'a Prefix<'a>) -> Option<&'a OsStr> {
    let is_wsl = |unc_server: &OsStr| unc_server.to_ascii_lowercase() == "wsl$";
    match *prefix {
        Prefix::VerbatimUNC(unc_server, unc_share) if is_wsl(unc_server) => {
            Some(unc_share)
        }
        Prefix::UNC(unc_server, unc_share) if is_wsl(unc_server)  => {
            Some(unc_share)
        }
        _ => None,
    }
}

/// only r"\\wsl$\{distro}\**" will return Some("{distro}")
pub fn try_get_distro_from_unc_path(abs_path: &Path) -> Option<OsString> {
    try_get_abs_path_prefix(abs_path)
        .as_ref()
        .and_then(try_get_distro_from_unc_path_prefix)
        .map(|s| s.to_owned())
}

pub fn try_get_distro_from_current_dir() -> Option<OsString> {
    try_get_distro_from_unc_path(&current_dir().expect("invalid current dir"))
}
