
pub const ST_MODE_TYPE_FIFO: u32 = 0o_0010000;
pub const ST_MODE_TYPE_CHR:  u32 = 0o_0020000;
pub const ST_MODE_TYPE_DIR:  u32 = 0o_0040000;
pub const ST_MODE_TYPE_BLK:  u32 = 0o_0060000;
pub const ST_MODE_TYPE_REG:  u32 = 0o_0100000;
pub const ST_MODE_TYPE_LNK:  u32 = 0o_0120000;
pub const ST_MODE_TYPE_SOCK: u32 = 0o_0140000;
/// type of file mask for st_mode 
pub const ST_MODE_TYPE_MASK: u32 = 0o_0170000;

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
    pub fn name(&self) -> &'static str {
        use StModeType::*;
        match self {
            FIFO => "FIFO",
            CHR => "CHR",
            BLK => "BLK",
            SOCK => "SOCKET",
            LNK => "SYMLINK",
            DIR => "DIRECTORY",
            REG => "FILE",
            _ => "UNKNOWN",
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
