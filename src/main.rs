use std::{path::{self, Path, PathBuf}};
use clap::{arg, command, Parser, Subcommand};

use ea_parse::{EaEntryRaw, EaOut};
use path_utils::*;
use distro::Distro;
use wsl_file::{reopen_to_write, WslFile, WslFileAttributes};

mod distro;
mod path_utils;
mod wsl_file;
mod ntfs_io;
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

    if let Some(mut wsl_file) = load_wsl_file(&args.path, args.distro.as_ref()) {
        if let Some(ea_buffer) = &wsl_file.ea_buffer {
            let ea_parsed = ea_parse::parse_ea(ea_buffer);
            print(&wsl_file, &ea_parsed);

            //test_ea_write(&mut wsl_file);
        } else {
            println!("no EAs exist");
        }

        if args.command == Some(Command::Downgrade) {

            if let Some(ea_buffer) = &wsl_file.ea_buffer {

                let mut ea_parsed = unsafe { ea_parse::parse_ea(ea_buffer) };

                //let lxattrb = ea_parsed.set_ea(lxfs::LXATTRB, &lxfs::EaLxattrbV1::default());
    
                //let ea = ea_parsed.to_buf();
                //unsafe { ntfs_io::write_ea(wsl_file.file_handle, &ea) };
            }
        }
    }
}

fn test_ea_write(wsl_file: &mut WslFile) {
    let ea_buffer = wsl_file.ea_buffer.as_ref().unwrap();
    let ea_parsed = ea_parse::parse_ea(ea_buffer);

    let mut ea_out = EaOut::default();
    for ea in ea_parsed {
        ea_out.add(&ea);
    }

    // read ea and construct a new buffer, they should be same

    println!("read_ea_len={} out_ea_len={}", ea_buffer.len(), ea_out.buff.len());
    assert_eq!(ea_buffer, &ea_out.buff);

    // add, change, delete
    let mut ea_out = EaOut::default();
    ea_out.add(&EaEntryRaw {
        flags: 0,
        name: "TT".as_bytes(),
        value: "".as_bytes(),
    });
    unsafe {
        reopen_to_write(wsl_file);
        for x in &ea_out.buff {
            print!("{x:0>2x}, ");
        }
        ntfs_io::write_ea(wsl_file.file_handle, &ea_out.buff);
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
        let wsl_file = wsl_file::open_handle(&real_path, false).expect("failed to open file");
        return Some(wsl_file);
    }
}

fn print<'a, 'b>(wsl_file: &'a WslFile, ea_parsed: &'b Vec<EaEntryRaw<'a>>) {
    if let Ok(wslfs) = wslfs::WslfsParsed::try_load(&wsl_file, &ea_parsed) {
        println!("{wslfs}");
    }

    if let Ok(lxfs) = lxfs::LxfsParsed::try_load(&wsl_file, &ea_parsed) {
        println!("{lxfs}");
    }
}
