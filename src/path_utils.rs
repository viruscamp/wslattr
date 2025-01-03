use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf, Prefix};

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

pub fn normalize_path(path: &Path) -> std::io::Result<PathBuf> {
    use normpath::PathExt;
    use dunce::simplified;

    let p = path.normalize_virtually()?;
    Ok(simplified(p.as_path()).to_path_buf())
}

pub fn is_server_wsl(server: &OsStr) -> bool {
    let s = server.to_ascii_lowercase();
    s == "wsl$" || s == "wsl.localhost"
}

pub fn try_get_distro_from_unc_prefix<'a>(prefix: &'a Prefix<'a>) -> Option<&'a OsStr> {
    match *prefix {
        Prefix::VerbatimUNC(unc_server, unc_share) if is_server_wsl(unc_server) => {
            Some(unc_share)
        }
        Prefix::UNC(unc_server, unc_share) if is_server_wsl(unc_server)  => {
            Some(unc_share)
        }
        _ => None,
    }
}

/// only `r"\\wsl$\{distro}\**"` and `r"\\wsl.localhost\{distro}\**"` return `Some("{distro}")`
pub fn try_get_distro_from_unc_path(abs_path: &Path) -> Option<OsString> {
    try_get_abs_path_prefix(abs_path)
        .as_ref()
        .and_then(try_get_distro_from_unc_prefix)
        .map(|s| s.to_owned())
}
