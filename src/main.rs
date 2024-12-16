use std::path::{absolute, Path, PathBuf};
use clap::{arg, command, Parser, Subcommand};

use ea_parse::{EaEntry, EaEntryRaw, EaOut};
use lxfs::{EaLxattrbV1, LxfsParsed, LXATTRB};
use ntfs_io::{delete_reparse_point, query_file_basic_infomation, write_data};
use path_utils::*;
use distro::Distro;
use posix::{chmod, lsperms, StModeType};
use time_utils::LxfsTime;
use windows::Win32::Foundation::HANDLE;
use wsl_file::{WslFile, WslFileAttributes};
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// file path
    path: PathBuf,

    #[arg(long, short)]
    distro: Option<String>,

    #[arg(long, short)]
    fs_type: Option<distro::FsType>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, PartialEq, Debug)]
enum Command {
    Chown,
    Chgrp,
    Chmod {
        modes: String,
    },
    Downgrade,
    SetEa {
        #[arg(long, short)]
        name: String,
    
        #[arg(long, short)]
        value: Option<String>,
    },
}

/// inspect WSL1 lxfs or wslfs attributes from windows
fn main() {
    let args = Args::parse();
    println!("args: {:?}!", args);

    let distro = try_load_distro(args.distro.as_ref());

    if let Some(mut wsl_file) = load_wsl_file(&args.path, &distro) {
        let ea_buffer = wsl_file.read_ea().unwrap_or(None);

        if ea_buffer.is_none() {
            println!("no EAs exist");
        }
        
        let ea_parsed = ea_buffer.as_ref()
        .map(|ea_buffer| {
            ea_parse::parse_ea(&ea_buffer)
        });

        print_file_time(wsl_file.file_handle);

        let mut wslfs = wslfs::WslfsParsed::load(&wsl_file, &ea_parsed);
        wslfs.distro = distro.as_ref();
        println!("{wslfs}");
    
        let mut lxfs = lxfs::LxfsParsed::load(&wsl_file, &ea_parsed);
        lxfs.distro = distro.as_ref();
        println!("{lxfs}");

        if let Some(cmd) = args.command {
            match cmd {
                Command::Chown => todo!(),
                Command::Chgrp => todo!(),
                Command::Chmod { modes } => {
                    if let Some(mode) = wslfs.get_mode() {
                        if let Ok(newmode) = chmod(mode, &modes) {
                            println!("new mode: {:06o} , {}", newmode, lsperms(newmode));
                        } else {
                            println!("invalid modes: {}", modes);
                        }
                    }

                    if let Some(mode) = lxfs.get_mode() {
                        if let Ok(newmode) = chmod(mode, &modes) {
                            println!("new mode: {:06o} , {}", newmode, lsperms(newmode));
                        } else {
                            println!("invalid modes: {}", modes);
                        }
                    }              
                },
                Command::Downgrade => {
                    if let Some(d) = &distro {
                        downgrade_distro(d);
                    } else {
                        downgrade(&mut wsl_file, &wslfs, &lxfs);
                    }
                },
                Command::SetEa { name, value } => {
                    //test_ea_write(&ea_buffer, &ea_parsed);
                    set_ea(&mut wsl_file, &name, value.as_ref().map(String::as_str));
                }
            }
        }
    }
}

fn test_ea_write(ea_buffer: &Option<Vec<u8>>, ea_parsed: &Option<Vec<EaEntry<&[u8]>>>) {
    if let Some(ea_parsed) = ea_parsed {
        let ea_buffer = ea_buffer.as_ref().unwrap();

        let mut ea_out = EaOut::default();
        for ea in ea_parsed {
            ea_out.add(&ea);
        }

        // read ea and construct a new buffer, they should be same

        println!("read_ea_len={} out_ea_len={}", ea_buffer.len(), ea_out.buff.len());
        assert_eq!(ea_buffer, &ea_out.buff);
    }
}

fn set_ea(wsl_file: &mut WslFile, name: &str, value: Option<&str>) {
    // add, change, delete
    let mut ea_out = EaOut::default();
    ea_out.add(&EaEntryRaw {
        flags: 0,
        name: name.as_bytes(),
        value: value.unwrap_or("").as_bytes(),
    });
    unsafe {
        let _ = wsl_file.reopen_to_write();
        let _ = ntfs_io::write_ea(wsl_file.file_handle, &ea_out.buff);
    }
}

pub fn try_load_distro<S: AsRef<str>>(distro_from_arg: Option<S>) -> Option<Distro> {
    None
    .or(distro_from_arg.and_then(|name| {
        println!("try load distro from arg: {}", name.as_ref());
        distro::try_load(&name).or_else(|| {
            panic!("failed to load distro from arg: {}", name.as_ref())
        })
    }))
    .or_else(|| {
        match std::env::current_dir() {
            Ok(cd) => {
                println!("try load distro from current dir: {}", &cd.display());
                try_get_distro_from_unc_path(&cd)
                .and_then(|n| distro::try_load(&n.to_string_lossy()))                
            },
            Err(_) => None,
        }
    })
    .or_else(|| {
        println!("try load distro from reg");
        distro::default()
    })
    .inspect(|d| {
        if d.fs_type.is_none() {
            panic!("WSL2 distro {} is not supported", d.name);
        }
    })
}

fn load_wsl_file(in_path: &Path, distro_from_arg: &Option<Distro>) -> Option<WslFile> {
    let full_path;
    let real_path;

    if is_unix_absolute(in_path) {
        // unix path with root like r"/usr/bin"
        println!("unix path: {:?}", in_path);

        let d = distro_from_arg.as_ref().expect("argument --distro is needed for unix path");
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
    let ea_to_remove = vec![wslfs::LXUID, wslfs::LXGID, wslfs::LXMOD, wslfs::LXDEV];
    let mut ea_out = EaOut::default();

    // 1. for all files, write LXATTRB
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
    ea_out.add(&EaEntryRaw {
        flags: 0,
        name: LXATTRB.as_bytes(),
        value: lxattrb_bytes,
    });

    // 2. for all files, write LXXATTR, from LX.*
    // TODO

    // write EA
    for ea in ea_to_remove {
        ea_out.add(&EaEntryRaw {
            flags: 0,
            name: ea.as_bytes(),
            value: "".as_bytes(),
        });
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