use std::path::{self, Path, PathBuf};
use clap::{arg, command, Parser, Subcommand};

use path_utils::*;
use distro::Distro;
use winapi::shared::ntdef::ULONG;
use wsl_file::{WslFile, WslFileAttributes};
use wslfs::parse_reparse_tag;

mod distro;
mod path_utils;
mod wsl_file;
mod ea_io;
mod ea_parse;
mod lxfs;
mod wslfs;
mod vec_ex;
mod time_utils;

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

    if let Some(wsl_file) = load_wsl_file(&args.path, args.distro.as_ref()) {
        if args.command == Some(Command::Downgrade) {
            if let Some(ea_buffer) = &wsl_file.ea_buffer {

                let mut ea_parsed = unsafe { ea_parse::parse_ea(ea_buffer) };

                let lxattrb = ea_parsed.set_ea(lxfs::LXATTRB, &lxfs::EaLxattrbV1::default());
    
                let ea = ea_parsed.to_buf();
                unsafe { ea_io::write_ea(wsl_file.file_handle, &ea) };
            }
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

        if let Some(ea_buffer) = &wsl_file.ea_buffer {
            let ea_parsed = ea_parse::parse_ea(ea_buffer);

            if let Ok(wslfs) = wslfs::WslfsParsed::try_load(&wsl_file, &ea_parsed) {
                println!("{wslfs}");
            }

            if let Ok(lxfs) = lxfs::LxfsParsed::try_load(&wsl_file, &ea_parsed) {
                println!("{lxfs}");
            }
        } else {
            println!("no EAs exist");
        }
        return Some(wsl_file);
    }
}
