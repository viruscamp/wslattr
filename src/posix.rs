use std::fs::File; 
use std::io::{BufRead, BufReader};
use std::path::Path;

pub const ST_MODE_TYPE_FIFO: u32 = 0o_0010000;
pub const ST_MODE_TYPE_CHR:  u32 = 0o_0020000;
pub const ST_MODE_TYPE_DIR:  u32 = 0o_0040000;
pub const ST_MODE_TYPE_BLK:  u32 = 0o_0060000;
pub const ST_MODE_TYPE_REG:  u32 = 0o_0100000;
pub const ST_MODE_TYPE_LNK:  u32 = 0o_0120000;
pub const ST_MODE_TYPE_SOCK: u32 = 0o_0140000;
/// type of file mask for st_mode 
pub const ST_MODE_TYPE_MASK: u32 = 0o_0170000;

pub const DEFAULT_MODE: u32 = 0o_0100644;

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[derive(PartialEq)]
pub enum StModeType {
    /// named pipe (fifo)
    FIFO = ST_MODE_TYPE_FIFO,
    /// character special
    CHR = ST_MODE_TYPE_CHR,
    /// directory
    DIR = ST_MODE_TYPE_DIR,
    /// block special
    BLK = ST_MODE_TYPE_BLK,
    /// regular
    REG = ST_MODE_TYPE_REG,
    /// symbolic link
    LNK = ST_MODE_TYPE_LNK,
    /// socket
    SOCK = ST_MODE_TYPE_SOCK,

    UNKNOWN = ST_MODE_TYPE_MASK,
}

impl StModeType {
    pub fn name(&self) -> (&'static str, char) {
        use StModeType::*;
        match self {
            FIFO => ("FIFO", 'p'),
            CHR => ("CHR", 'c'),
            BLK => ("BLK", 'b'),
            SOCK => ("SOCKET", 's'),
            LNK => ("SYMLINK", 'l'),
            DIR => ("DIRECTORY", 'd'),
            REG => ("FILE", '-'),
            _ => ("UNKNOWN", '?'),
        }
    }

    pub fn from_mode(st_mode: u32) -> StModeType {
        use StModeType::*;
        match st_mode & ST_MODE_TYPE_MASK {
            ST_MODE_TYPE_FIFO => FIFO,
            ST_MODE_TYPE_CHR => CHR,
            ST_MODE_TYPE_DIR => DIR,
            ST_MODE_TYPE_BLK => BLK,
            ST_MODE_TYPE_REG => REG,
            ST_MODE_TYPE_LNK => LNK,
            ST_MODE_TYPE_SOCK => SOCK,
            _ => UNKNOWN,
        }
    }
}

const S_ISUID: u32 = 0o_0004000;			/* set user id on execution */
const S_ISGID: u32 = 0o_0002000;			/* set group id on execution */
const S_ISTXT: u32 = 0o_0001000;			/* sticky bit */

const S_IRWXU: u32 = 0o_0000700;			/* RWX mask for owner */
const S_IRUSR: u32 = 0o_0000400;			/* R for owner */
const S_IWUSR: u32 = 0o_0000200;			/* W for owner */
const S_IXUSR: u32 = 0o_0000100;			/* X for owner */

const S_IRWXG: u32 = 0o_0000070;			/* RWX mask for group */
const S_IRGRP: u32 = 0o_0000040;			/* R for group */
const S_IWGRP: u32 = 0o_0000020;			/* W for group */
const S_IXGRP: u32 = 0o_0000010;			/* X for group */

const S_IRWXO: u32 = 0o_0000007;			/* RWX mask for other */
const S_IROTH: u32 = 0o_0000004;			/* R for other */
const S_IWOTH: u32 = 0o_0000002;			/* W for other */
const S_IXOTH: u32 = 0o_0000001;			/* X for other */

const RWX: [&'static str; 8] = [ "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" ];

/* Convert a mode field into "ls -l" type perms field. */
pub fn lsperms(mode: u32) -> String {
    let mut bits = ['-' as u8; 10];

    bits[0] = StModeType::from_mode(mode).name().1 as u8;

    let rwx = RWX[((mode >> 6) & 7) as usize];
    bits[1..4].copy_from_slice(rwx.as_bytes());

    let rwx = RWX[((mode >> 3) & 7) as usize];
    bits[4..7].copy_from_slice(rwx.as_bytes());

    let rwx = RWX[(mode & 7) as usize];
    bits[7..10].copy_from_slice(rwx.as_bytes());

    if (mode & S_ISUID) != 0 {
        bits[3] = if (mode & S_IXUSR) !=0 { 's' } else { 'S' } as u8;
    }
    if (mode & S_ISGID) != 0 {
        bits[6] = if (mode & S_IXGRP) !=0 { 's' } else { 'S' } as u8;
    }
    if (mode & S_ISTXT) != 0 {
        bits[9] = if (mode & S_IXOTH) !=0 { 't' } else { 'T' } as u8;
    }

    return String::from_utf8_lossy(&bits).into_owned();
}

pub fn chmod_all(mut mode: u32, mode_strs: &str) -> Result<u32, ()> {
    if let Ok(newmode) = u32::from_str_radix(mode_strs, 8) {
        if mode_strs.len() <= 4 {
            return Ok((mode & ST_MODE_TYPE_MASK) | (newmode & !ST_MODE_TYPE_MASK));
        } else {
            return Err(());
        }
    }

    for mode_str in mode_strs.split(',') {
        mode = chmod_part(mode, mode_str.trim())?;
    }
    return Ok(mode);
}

/// ugo +- rwx
/// ug +- s
/// o +- t
/// +- t
pub fn chmod_part(mut mode: u32, mode_str: &str) -> Result<u32, ()> {
    use regex_lite::Regex;
    use std::sync::LazyLock;

    static MODE_PATTERN: LazyLock<Regex> = LazyLock::new(|| 
        Regex::new(r"^([ugoa]?)([+-])([rwxst]+)$").unwrap()
    );

    if let Some(c) = MODE_PATTERN.captures(mode_str) {
        let found: (&str, [&str; 3]) = c.extract();
        let whoes = found.1[0];
        let act = found.1[1].chars().nth(0).unwrap();
        let whats = found.1[2];
        if whoes == "" && whats == "t" {
            mode = chmod_bit(mode, 'o', act, 't');
        } else {
            let who = whoes.chars().nth(0).unwrap();
            for what in whats.chars() {
                mode = chmod_bit(mode, who, act, what);
            }
        }
    } else {
        return Err(());
    }

    return Ok(mode);
}

pub fn chmod_bit(mut mode: u32, who: char, act: char, what: char) -> u32 {
    if who == 'a' {
        mode = chmod_bit(mode, 'u', act, what);
        mode = chmod_bit(mode, 'g', act, what);
        mode = chmod_bit(mode, 'o', act, what);
        return mode;
    }

    let mask = match (who, what) {
        ('u', 'r') => S_IRUSR,
        ('u', 'w') => S_IWUSR,
        ('u', 'x') => S_IXUSR,

        ('g', 'r') => S_IRGRP,
        ('g', 'w') => S_IWGRP,
        ('g', 'x') => S_IXGRP,

        ('o', 'r') => S_IROTH,
        ('o', 'w') => S_IWOTH,
        ('o', 'x') => S_IXOTH,

        ('u', 's') => S_ISUID,
        ('g', 's') => S_ISGID,
        ('o', 't') => S_ISTXT,
        _ => 0,
    };
    if act == '+' {
        mode |= mask;
    }
    if act == '-' {
        mode &= !mask;
    }
    return mode;
}

fn line_parse(line: &str) -> Result<(String, u32), ()> {
    let mut tokens = line.split(':').fuse();
    let name = tokens.next().ok_or(())?;
    tokens.next();
    let uid: u32 = tokens.next().ok_or(())?.parse().map_err(|_e| { () })?;
    Ok((name.to_string(), uid))
}

// name:x:uid:gid
#[derive(Debug)]
pub struct User {
    pub name: String,
    pub uid: u32,
}

pub fn load_users(rootfs: &Path) -> Option<Vec<User>> {
    let file = File::open(rootfs.join("etc/passwd")).ok()?;
    let reader = BufReader::new(file);

    let users = reader.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| line_parse(&l).ok())
    .map(|(name, uid)| User { name, uid } )
    .collect();

    Some(users)
}

// name:x:gid
#[derive(Debug)]
pub struct Group {
    pub name: String,
    pub gid: u32,
}

pub fn load_groups(rootfs: &Path) -> Option<Vec<Group>> {
    let file = File::open(rootfs.join("etc/group")).ok()?;
    let reader = BufReader::new(file);

    let groups = reader.lines()
    .filter_map(|l| l.ok())
    .filter_map(|l| line_parse(&l).ok())
    .map(|(name, gid)| Group { name, gid } )
    .collect();

    Some(groups)
}
