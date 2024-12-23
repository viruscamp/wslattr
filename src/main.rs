use std::path::{absolute, Path, PathBuf};
use clap::{arg, command, Parser, Subcommand};

use ea_parse::{EaEntry, EaEntryRaw, EaOut};
use lxfs::{EaLxattrbV1, LxfsParsed, LxxattrOut, LXATTRB, LXXATTR};
use ntfs_io::{delete_reparse_point, query_file_basic_infomation, write_data};
use path_utils::*;
use distro::{Distro, DistroSource, FsType};
use posix::{chmod_all, lsperms, StModeType, DEFAULT_MODE};
use time_utils::LxfsTime;
use windows::Win32::Foundation::HANDLE;
use wsl_file::{open_handle, WslFile, WslFileAttributes};
use wslfs::WslfsParsed;

mod distro;
mod path_utils;
mod wsl_file;
mod ntfs_io;
mod ea_parse;
mod lxfs;
mod wslfs;
mod time_utils;
mod posix;
mod escape_utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[clap(flatten)]
    args_view: Option<ArgsView>,
}

#[derive(Parser, Debug)]
struct ArgsView {
    /// file to view
    path: PathBuf,

    /// WSL distro from registry, for user and group name
    #[arg(long, short)]
    distro: Option<String>,
}

#[derive(Parser, Debug)]
struct ArgsChange {
    /// file to change
    path: PathBuf,

    /// WSL1 fs type, if provided ignore fs type from `--distro`
    #[arg(long, short = 't')]
    fs_type: Option<distro::FsType>,

    /// WSL distro from registry, to get WSL1 fs type
    #[arg(long, short)]
    distro: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    View(ArgsView),
    Chown {
        /// uid or user name(with valid distro)
        user: String,
        #[clap(flatten)]
        
        args_change: ArgsChange,
    },
    Chgrp {
        /// gid or group name(with valid distro)
        group: String,
        #[clap(flatten)]

        args_change: ArgsChange,
    },
    Chmod {
        /// posix modes string, "0844", "u+x,g-t"
        modes: String,
        #[clap(flatten)]

        args_change: ArgsChange,
    },
    Downgrade {
        /// file to change
        #[clap(conflicts_with("distro"))]
        path: Option<PathBuf>,

        /// WSL distro from registry, to get WSL1 fs type
        #[clap(conflicts_with("path"))]
        #[arg(long, short)]
        distro: Option<String>,
    },
    SetEa {
        /// file to change
        path: PathBuf,

        #[arg(long, short)]
        name: String,
    
        #[arg(long, short)]
        value: Option<String>,
    },
}

/// inspect WSL1 lxfs or wslfs attributes from windows
fn main() {
    use Command::*;

    let args = Args::parse();
    println!("args: {:?}!", args);

    if let Some(cmd) = args.command {
        match cmd {
            View(args_view) => view(args_view),
            Chown { args_change, user } => chown(args_change, user),
            Chgrp { args_change, group } => chgrp(args_change, group),
            Chmod { args_change, modes } => chmod(args_change, modes),
            Downgrade { path, distro } => {
                if path.is_some() && distro.is_some() {
                    println!("[ERROR] path and distro args are conflicted");
                    return;
                }
                if path.is_none() && distro.is_none() {
                    println!("[ERROR] there must be one of path or distro args");
                    return;
                }
                if let Some(name) = distro {
                    if let Some(d) = distro::try_load(&name) {
                        if d.fs_type.is_none() {
                            // TODO should panic
                            print!("[ERROR] WSL distro: {} is WSL2", &d.name);
                            return;
                        }
                        downgrade_distro(&d);
                    } else {
                        println!("[ERROR] there must be one of path or distro args");
                        return;
                    }
                } else if let Some(path) = path {
                    open_to_view(ArgsView { path, distro: None }, |mut wsl_file, _distro, wslfs, lxfs| {
                        downgrade(&mut wsl_file, &wslfs, &lxfs);
                    });
                }
            },
            SetEa { path, name, value } => {
                let wsl_file = unsafe { open_handle(&path, true) }.unwrap();
                let value_bytes = value.map(|v| escape_utils::unescape(&v).expect("invalid value"));
                set_ea(wsl_file.file_handle, name.as_bytes(), value_bytes.as_ref().map(|v| v.as_slice()));
            },
        }

    } else if let Some(args_view) = args.args_view {
        view(args_view);
    } else {
        // fail
        print!("argument <PATH> or command must be provided")
    }
}

fn open_to_view(args: ArgsView, f: impl FnOnce(WslFile, Option<Distro>, WslfsParsed, LxfsParsed) -> ()) {
    let distro = try_load_distro(args.distro.as_ref(), Some(&args.path));

    if let Some(wsl_file) = load_wsl_file(&args.path, distro.as_ref()) {
        let ea_buffer = wsl_file.read_ea().unwrap_or(None);

        if ea_buffer.is_none() {
            println!("no EAs exists");
        }
        
        let ea_parsed = ea_buffer.as_ref()
        .map(|ea_buffer| {
            ea_parse::parse_ea(&ea_buffer)
        });

        let wslfs = wslfs::WslfsParsed::load(&wsl_file, &ea_parsed);
    
        let lxfs = lxfs::LxfsParsed::load(&wsl_file, &ea_parsed);

        f(wsl_file, distro, wslfs, lxfs)
    } else {
        println!("[ERROR] load file failed");
    }
}

fn view(args_view: ArgsView) {
    open_to_view(args_view, |wsl_file, distro, wslfs, lxfs| {        
        print_file_time(wsl_file.file_handle);

        wslfs.fmt(&mut std::io::stdout().lock(), distro.as_ref()).unwrap();
        lxfs.fmt(&mut std::io::stdout().lock(), distro.as_ref()).unwrap();
    });
}

fn open_to_change(args: ArgsChange, f: impl FnOnce(WslFile, Option<Distro>, &mut dyn WslFileAttributes ) -> ()) {
    let distro = try_load_distro(args.distro.as_ref(), Some(&args.path));

    if let Some(mut wsl_file) = load_wsl_file(&args.path, distro.as_ref()) {
        let ea_buffer = wsl_file.read_ea().unwrap_or(None);

        if ea_buffer.is_none() {
            println!("no EAs exists");
        }
        
        let ea_parsed = ea_buffer.as_ref()
        .map(|ea_buffer| {
            ea_parse::parse_ea(&ea_buffer)
        });

        let mut wslfs = wslfs::WslfsParsed::load(&wsl_file, &ea_parsed);
    
        let mut lxfs = lxfs::LxfsParsed::load(&wsl_file, &ea_parsed);

        let wsl_attrs: &mut dyn WslFileAttributes = if let Some(fs_type) = args.fs_type {
            println!("use fs_type: {:?} from arg --fs_type", fs_type);
            match fs_type {
                FsType::Lxfs => &mut lxfs,
                FsType::Wslfs => &mut wslfs,
            }
        } else if let Some(d) = distro.as_ref().filter(|d| d.source == DistroSource::Arg && d.fs_type.is_some()) {
            let fs_type = d.fs_type.unwrap();
            println!("use fs_type: {:?} from arg --distro {}", fs_type, &d.name);
            match fs_type {
                FsType::Lxfs => &mut lxfs,
                FsType::Wslfs => &mut wslfs,
            }
        } else if wslfs.maybe() && lxfs.maybe() {
            println!("[ERROR] cannot determine fs_type, cause both wslfs and lxfs metadata exist");
            return;
        } else if wslfs.maybe() {
            &mut wslfs
        } else if lxfs.maybe() {
            &mut lxfs
        } else {
            println!("[ERROR] cannot determine fs_type, cause no wslfs nor lxfs metadata exists");
            return;
        };

        wsl_file.reopen_to_write().unwrap();
        f(wsl_file, distro, wsl_attrs)
    } else {
        println!("[ERROR] load file failed");
    }
}

fn chown(args: ArgsChange, user: String) {
    open_to_change(args, |mut wsl_file, distro, wsl_attrs| {
        let uid = if let Ok(uid) = u32::from_str_radix(&user, 10) {
            uid
        } else if let Some(distro) = &distro {
            if let Some(uid) = distro.uid(&user) {
                uid
            } else {
                println!("[ERROR] no user: {} in distro: {}", &user, &distro.name);
                return;
            }
        } else {
            println!("[ERROR] user: {} without -d <distro>", &user);
            return;
        };

        let olduid = wsl_attrs.get_uid();

        wsl_attrs.set_uid(uid);
        if let Err(ex) = wsl_attrs.save(&mut wsl_file) {
            println!("[ERROR] chown for {:?} {:?} --> {}, error: {ex:?}", wsl_attrs.fs_type(), olduid, uid);
        } else {
            println!("chown for {:?} {:?} --> {}", wsl_attrs.fs_type(), olduid, uid);
        }
    });
}

fn chgrp(args: ArgsChange, group: String) {
    open_to_change(args, |mut wsl_file, distro, wsl_attrs| {
        let gid = if let Ok(gid) = u32::from_str_radix(&group, 10) {
            gid
        } else if let Some(distro) = &distro {
            if let Some(gid) = distro.gid(&group) {
                gid
            } else {
                println!("[ERROR] no group: {} in distro: {}", &group, &distro.name);
                return;
            }
        } else {
            println!("[ERROR] group: {} without -d <distro>", &group);
            return;
        };

        let oldgid = wsl_attrs.get_gid();

        wsl_attrs.set_gid(gid);
        if let Err(ex) = wsl_attrs.save(&mut wsl_file) {
            println!("[ERROR] chgrp for {:?} {:?} --> {}, error: {ex:?}", wsl_attrs.fs_type(), oldgid, gid);
        } else {
            println!("chgrp for {:?} {:?} --> {}", wsl_attrs.fs_type(), oldgid, gid);
        }
    });
}

fn chmod(args: ArgsChange, modes: String) {
    open_to_change(args, |mut wsl_file, _distro, wsl_attrs| {
        let mode = wsl_attrs.get_mode().unwrap_or(DEFAULT_MODE);
        if let Ok(newmode) = chmod_all(mode, &modes) {
            wsl_attrs.set_mode(newmode);
            if let Err(ex) = wsl_attrs.save(&mut wsl_file) {
                println!("[ERROR] chmod for {:?}: {:06o} / {} --> {:06o} / {} {ex:?}", wsl_attrs.fs_type(), mode, lsperms(mode), newmode, lsperms(newmode));
            } else {
                println!("chmod for {:?}: {:06o} / {} --> {:06o} / {}", wsl_attrs.fs_type(), mode, lsperms(mode), newmode, lsperms(newmode));
            }
        } else {
            println!("[ERROR] invalid mode: {}", modes);
        }
    });
}

fn test_ea_write(ea_buffer: &Option<Vec<u8>>, ea_parsed: &Option<Vec<EaEntry<&[u8]>>>) {
    if let Some(ea_parsed) = ea_parsed {
        let ea_buffer = ea_buffer.as_ref().unwrap();

        let mut ea_out = EaOut::default();
        for ea in ea_parsed {
            ea_out.add_entry(&ea);
        }

        // read ea and construct a new buffer, they should be same

        println!("read_ea_len={} out_ea_len={}", ea_buffer.len(), ea_out.buff.len());
        assert_eq!(ea_buffer, &ea_out.buff);
    }
}

fn set_ea(file_handle: HANDLE, name: &[u8], value: Option<&[u8]>) {
    // add, change, delete
    let mut ea_out = EaOut::default();
    ea_out.add(name, value.unwrap_or(&[0;0]));
    unsafe {
        let _ = ntfs_io::write_ea(file_handle, &ea_out.buff);
    }
}

fn try_load_distro<S: AsRef<str>, P: AsRef<Path>>(arg_distro: Option<S>, path: Option<P>) -> Option<Distro> {
    // try load distro fron argument
    if let Some(distro_name) = arg_distro {
        let distro_name = distro_name.as_ref();
        //println!("try load distro fron arg: {}", distro_name);
        let distro = distro::try_load(distro_name);
        if let Some(mut d) = distro {
            d.source = DistroSource::Arg;
            if d.fs_type.is_none() {
                // TODO should panic
                print!("[ERROR] WSL distro: {} is WSL2", &d.name);
                return None;
            }
            println!("distro: {} loaded from arg", distro_name);
            return Some(d);
        } else {
            // TODO should panic
            print!("[ERROR] cannot load WSL distro: {}", distro_name);
            return None;
        }
    }

    // try load distro fron file path
    if let Some(p) = path {
        let in_path = p.as_ref();
        if !is_unix_absolute(in_path) && in_path.is_absolute() {
            //println!("try load distro fron file path: {}", in_path.display());
            let distro = distro::try_load_from_absolute_path(in_path);
            if let Some(mut d) = distro {
                d.source = DistroSource::FilePath;
                if d.fs_type.is_none() {
                    // TODO should panic
                    print!("[ERROR] WSL distro: {} is WSL2", &d.name);
                    return None;
                }
                println!("distro: {} loaded from file path: {}", &d.name, in_path.display());
                return Some(d);
            }
        }
    }    

    // try load distro fron current path
    if let Ok(cd) = std::env::current_dir() {
        //println!("try load distro from current dir: {}", &cd.display());
        let distro = distro::try_load_from_absolute_path(&cd);
        if let Some(mut d) = distro {
            d.source = DistroSource::CurrentDir;
            if d.fs_type.is_none() {
                // TODO should panic
                print!("[ERROR] WSL distro: {} is WSL2", &d.name);
                return None;
            }
            println!("distro: {} loaded from current dir: {}", &d.name, cd.display());
            return Some(d);
        }
    }

    // try load default WSL distro in registry
    if let Some(d) = distro::default() {
        if d.fs_type.is_none() {
            // TODO should panic
            print!("[ERROR] WSL distro: {} is WSL2", &d.name);
            return None;
        }
        println!("distro: {} loaded from default WSL distro in registry", &d.name);
        return Some(d);
    }

    println!("no distro loaded");
    return None;
}

fn load_wsl_file(in_path: &Path, distro: Option<&Distro>) -> Option<WslFile> {
    let full_path;
    let real_path;

    if is_unix_absolute(in_path) {
        // unix path with root like r"/usr/bin"
        println!("unix path: {:?}", in_path);

        let d = distro.expect("argument --distro is needed for unix path");
        //println!("distro: {:?}", d);

        let mut unix_path_comps = in_path.components();
        unix_path_comps.next(); // RootDir
        real_path = d.base_path.join("rootfs").join(unix_path_comps); // .skip(1)

        full_path = in_path.to_path_buf();
    } else {
        let abs_path = absolute(in_path).expect(&format!("invalid path: {:?}", in_path));
        let path_prefix = try_get_abs_path_prefix(&abs_path);
        if let Some(distro_name) = path_prefix.as_ref().and_then(try_get_distro_from_unc_prefix) {
            // wsl UNC path like r"\\wsl$\Arch\file"
            println!("try load distro from wsl path: {:?}!", distro_name);

            // TODO distro has been loaded
            let distro = distro::try_load(&distro_name.to_str()?);
            let d = distro.as_ref().expect(&format!("invalid distro: {:?}", distro_name));
            //println!("distro: {:?}", d);

            let mut abs_path_comps = abs_path.components();
            abs_path_comps.next(); // Prefix
            abs_path_comps.next(); // RootDir
            real_path = d.base_path.join("rootfs").join(abs_path_comps); // .skip(2)

            full_path = abs_path;
        } else if is_path_prefix_disk(&path_prefix) {
            // normal path like r"D:\file"
            real_path = abs_path.clone();
            full_path = abs_path;
        } else {
            dbg!(path_prefix);
            // unsupported path like r"\\remote\share\"
            panic!("unsupported path {:?}", abs_path);
        }
    }

    println!("full_path: {}", &full_path.display());
    println!("real_path: {}", &real_path.display());

    unsafe {
        let wsl_file = wsl_file::open_handle(&real_path, false).expect("failed to open file");
        return Some(wsl_file);
    }
}

fn downgrade_distro(distro: &Distro) {
    for entry in walkdir::WalkDir::new(&distro.base_path) {
        if let Ok(entry) = entry {
            if let Ok(_) = downgrade_path(&entry.path().join("rootfs")) {
                println!("downgrade success: {}", entry.path().display());
            } else {
                println!("downgrade failed: {}", entry.path().display());
            }
        }
    }
}

fn downgrade_path(real_path: &Path) -> std::io::Result<()> {
    let mut wsl_file = unsafe { wsl_file::open_handle(&real_path, false)? };
    let ea_buffer = wsl_file.read_ea().unwrap_or(None);
    
    let ea_parsed = ea_buffer.as_ref()
    .map(|ea_buffer| {
        ea_parse::parse_ea(&ea_buffer)
    });

    let wslfs = wslfs::WslfsParsed::load(&wsl_file, &ea_parsed);
    let lxfs = lxfs::LxfsParsed::load(&wsl_file, &ea_parsed);

    downgrade(&mut wsl_file, &wslfs, &lxfs);

    Ok(())
}

fn downgrade(wsl_file: &mut WslFile,  wslfs: &WslfsParsed, lxfs: &LxfsParsed) {
    if lxfs.maybe() {
        println!("{} maybe lxfs already", unsafe { wsl_file.full_path.Buffer.display() });
        return;
    }
    let mut ea_to_remove = vec![
        wslfs::LXUID.as_bytes(),        
        wslfs::LXGID.as_bytes(),
        wslfs::LXMOD.as_bytes(),
        wslfs::LXDEV.as_bytes()
    ];

    let mut ea_out = EaOut::default();

    // 1. for all files, set LXATTRB
    let mut lxattrb = EaLxattrbV1::default();

    lxattrb.st_uid = wslfs.get_uid().unwrap_or(0);
    lxattrb.st_gid = wslfs.get_gid().unwrap_or(0);
    lxattrb.st_mode = wslfs.get_mode().unwrap_or(0);

    let dev_major = wslfs.get_dev_major().unwrap_or(0);
    let dev_minor = wslfs.get_dev_minor().unwrap_or(0);
    lxattrb.st_rdev = lxfs::make_dev(dev_major, dev_minor);

    if let Ok(fbi) = query_file_basic_infomation(wsl_file.file_handle) {
        (lxattrb.st_atime, lxattrb.st_atime_nsec) = time_utils::u64_to_lxfs_time(fbi.LastAccessTime as u64).into();
        (lxattrb.st_mtime, lxattrb.st_mtime_nsec) = time_utils::u64_to_lxfs_time(fbi.LastWriteTime as u64).into();
        (lxattrb.st_ctime, lxattrb.st_ctime_nsec) = time_utils::u64_to_lxfs_time(fbi.ChangeTime as u64).into();
    }

    let lxattrb_bytes = unsafe {
		std::slice::from_raw_parts(
			&lxattrb as *const _ as *const u8,
			std::mem::size_of_val(&lxattrb)
		)
	};
    ea_out.add(LXATTRB.as_bytes(), lxattrb_bytes);

    // 2. for all files, set LXXATTR, from LX.*
    let mut lxxattr_out = LxxattrOut::default();
    for dot_ea in &wslfs.lx_dot_ea {
        ea_to_remove.push(&dot_ea.name_ea());
        lxxattr_out.add(&dot_ea.name(), &dot_ea.value());
    }
    ea_out.add(LXXATTR.as_bytes(), &lxxattr_out.buff);

    // write EA
    for ea in ea_to_remove {
        ea_out.add(ea,"".as_bytes());
    }
    unsafe {
        let _ = wsl_file.reopen_to_write();
        let _ = ntfs_io::write_ea(wsl_file.file_handle, &ea_out.buff);
    }

    // 3. special files, remove sparse point
    if let Some(t) = wslfs.reparse_tag {
        if  t != StModeType::UNKNOWN {
            use wslfs::WslfsReparseTag;
            unsafe {
                let _ = delete_reparse_point(wsl_file.file_handle, t.tag_id());
            }
        }
    }

    // 4. symlink files, write file content
    if let Some(ref symlink) = wslfs.symlink {
        unsafe {
            let _ = write_data(wsl_file.file_handle, symlink.as_bytes());
        }
    }
}

fn print_file_time(file_handle: HANDLE) {
    if let Ok(fbi) = query_file_basic_infomation(file_handle) {
        let creation_time: LxfsTime = (fbi.CreationTime as u64).into();
        println!("{:28}{}", "CreationTime:", creation_time);
        let last_access_time: LxfsTime = (fbi.LastAccessTime as u64).into();
        println!("{:28}{}", "LastAccessTime:", last_access_time);
        let last_write_time: LxfsTime = (fbi.LastWriteTime as u64).into();
        println!("{:28}{}", "LastWriteTime:", last_write_time);
        let change_time: LxfsTime = (fbi.ChangeTime as u64).into();
        println!("{:28}{}", "ChangeTime:", change_time);
    } else {
        println!("[ERROR] cannot query file times")
    }
}