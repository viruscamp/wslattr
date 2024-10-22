use std::path::{self, Path, PathBuf};
use clap::{arg, command, Parser, Subcommand};

use path_utils::*;
use distro::Distro;
use winapi::shared::ntdef::ULONG;
use wsl_file::WslFile;
use wslfs::parse_reparse_tag;

mod distro;
mod path_utils;
mod wsl_file;
mod ea_io;
mod ea_parse;
mod lxfs;
mod wslfs;
mod vec_ex;

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
    Chmod,
    Downgrade,
}

/// inspect WSL1 lxfs or wslfs attributes from windows
fn main() {
    let args = Args::parse();
    println!("args: {:?}!", args);

    let mut wsl_file = load_wsl_file(&args.path, args.distro.as_ref());

    if let Some(mut wsl_file) = wsl_file {
        if args.command == Some(Command::Downgrade) {

            let mut ea_parsed = unsafe { ea_parse::parse_ea(&wsl_file.ea_buffer) };

            let lxattrb = ea_parsed.set_ea(lxfs::LXATTRB, &lxfs::EaLxattrbV1::default());


            let ea = ea_parsed.to_buf();
            unsafe { ea_io::write_ea(wsl_file.file_handle, &ea) };
        }
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
        println!("try load distro from current dir");
        try_get_distro_from_current_dir().and_then(|n| {
            distro::try_load(&n.to_string_lossy())
        })
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

fn load_wsl_file<S: AsRef<str>>(in_path: &Path, distro_from_arg: Option<S>) -> Option<WslFile> {
    let distro;
    let full_path;
    let real_path;

    if is_unix_absolute(in_path) {
        // unix path with root like r"/usr/bin"
        println!("unix path: {:?}", in_path);

        distro = try_load_distro(distro_from_arg);
        let d = distro.as_ref().expect("argument --distro is needed for unix path");

        let mut unix_path_comps = in_path.components();
        unix_path_comps.next(); // RootDir
        real_path = d.base_path.join("rootfs").join(unix_path_comps); // .skip(1)

        full_path = in_path.to_path_buf();
    } else {
        let abs_path = path::absolute(in_path).expect(&format!("invalid path: {:?}", in_path));
        let path_prefix = try_get_abs_path_prefix(&abs_path);
        if let Some(distro_name) = path_prefix.as_ref().and_then(try_get_distro_from_unc_prefix) {
            // wsl UNC path like r"\\wsl$\Arch\file"
            println!("try load distro from wsl path: {:?}!", distro_name);

            distro = distro::try_load_from_u16cstr(utfx::U16CString::from_os_str(&distro_name).unwrap());
            let d = distro.as_ref().expect(&format!("invalid distro: {:?}", distro_name));
          
            let mut abs_path_comps = abs_path.components();
            abs_path_comps.next(); // Prefix
            abs_path_comps.next(); // RootDir
            real_path = d.base_path.join("rootfs").join(abs_path_comps); // .skip(2)

            full_path = abs_path;
        } else if is_path_prefix_disk(&path_prefix) {
            // normal path like r"D:\file"
            real_path = abs_path.clone();
            full_path = abs_path;

            distro = try_load_distro(distro_from_arg);
        } else {
            dbg!(path_prefix);
            // unsupported path like r"\\remote\share\"
            panic!("unsupported path {:?}", abs_path);
        }
    }

    println!("full_path: {:?}", &full_path);
    println!("real_path: {:?}", &real_path);
    println!("distro: {:?}", distro);

    unsafe {
        let wsl_file = wsl_file::open_handle(&real_path).expect("failed to open file");


        if let Some(tag) = wsl_file.reparse_tag_raw {
            let reparse_tag = parse_reparse_tag(tag, wsl_file.file_handle).ok().unwrap();
            println!("{reparse_tag}");
        }

        let ea_parsed = ea_parse::parse_ea(&wsl_file.ea_buffer);
        {
            for ea in &ea_parsed {
                if ea.name == lxfs::LXATTRB {
                    let lxattrb = ea.get_ea::<lxfs::EaLxattrbV1>();
                    println!("{}: {:?}", ea.name, lxattrb);
                } else if ea.name == wslfs::LXUID {
                    let uid = ea.get_ea::<ULONG>();
                    println!("{}: {}", ea.name, uid);
                } else if ea.name == wslfs::LXGID {
                    let gid = ea.get_ea::<ULONG>();
                    println!("{}: {}", ea.name, gid);
                } else if ea.name == wslfs::LXMOD {
                    let st_mode = ea.get_ea::<ULONG>();
                    println!("{}: {:o}", ea.name, st_mode);
                } else if ea.name == wslfs::LXDEV {
                    let dev_type = ea.get_ea::<wslfs::Lxdev>();
                    println!("{}: {} {}", ea.name, dev_type.type_major, dev_type.type_minor);
                } else {
                    println!("{}", ea.name);
                }
            }
        }
        return Some(wsl_file);
    }
}