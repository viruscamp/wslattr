use std::ffi::c_void;
use std::io::{Error, Result};
use std::mem::transmute;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows::core::PWSTR;
use windows::Wdk::Storage::FileSystem::{NtOpenFile, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_IO_REPARSE_TAG_NOT_HANDLED, STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING};
use windows::Win32::System::WindowsProgramming::RtlFreeUnicodeString;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Wdk::Foundation::{NtClose, OBJECT_ATTRIBUTES};

use windows::Win32::System::Kernel::{OBJ_CASE_INSENSITIVE, OBJ_IGNORE_IMPERSONATED_DEVICEMAP};

use windows::Win32::Storage::FileSystem::{FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};

use crate::ea_parse::EaEntryRaw;

pub trait WslFileAttributes<'a> : Sized {
    fn try_load<'b: 'a>(wsl_file: &'a WslFile, ea_parsed: &'b Vec<EaEntryRaw<'a>>) -> Result<Self>;

    fn maybe(&self) -> bool;

    fn get_uid(&self) -> Option<u32>;
    fn get_gid(&self) -> Option<u32>;
    fn get_mode(&self) -> Option<u32>;
    fn get_dev_major(&self) -> Option<u32>;
    fn get_dev_minor(&self) -> Option<u32>;

    fn set_uid(&mut self, uid: u32);
    fn set_gid(&mut self, gid: u32);
    fn set_mode(&mut self, mode: u32);
    fn set_dev_major(&mut self, dev_major: u32);
    fn set_dev_minor(&mut self, dev_minor: u32);
}

#[derive(Default)]
pub struct WslFile {
    pub full_path: UNICODE_STRING,

    pub file_handle: HANDLE,
    pub writable: bool,

    pub ea_buffer: Option<Vec<u8>>,
    pub reparse_tag: Option<u32>,
}

impl<'a> Drop for WslFile {
    fn drop(&mut self) {
        unsafe {
            if !self.full_path.Buffer.is_null() {
                RtlFreeUnicodeString(&mut self.full_path as *mut _);
            }
            if !self.file_handle.is_invalid() {
                NtClose(self.file_handle);
                self.file_handle = HANDLE::default();
            }
        }
    }
}

pub unsafe fn open_handle(path: &Path, writable: bool) -> Result<WslFile> {
    let mut wsl_file = WslFile::default();

    let mut path_u16: Vec<u16> = path.as_os_str().encode_wide().chain([0u16]).collect();
    let mut full_path = UNICODE_STRING::default();
    let nt_status = RtlDosPathNameToNtPathName_U_WithStatus(
        PWSTR(path_u16.as_mut_ptr()),
        &mut full_path as *mut _,
        null_mut(),
        null_mut(),
    );
    if nt_status.is_err() {
        println!("[ERROR] RtlDosPathNameToNtPathName_U_WithStatus: {:#x}", &nt_status.0);
        return Err(Error::from_raw_os_error(nt_status.0));
    }
    wsl_file.full_path = full_path;

    if let OpenFileType::ReparsePoint = open_file_inner(&mut wsl_file, writable)? {
        let mut file_attribute_tag_info = FILE_ATTRIBUTE_TAG_INFO::default();
        if let Err(err) = GetFileInformationByHandleEx(
            wsl_file.file_handle,
            FileAttributeTagInfo,
            transmute(&mut file_attribute_tag_info),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        ) {
            println!("[ERROR] GetFileInformationByHandleEx {}", &err);
            return Err(err.into());
        }
        wsl_file.reparse_tag = Some(file_attribute_tag_info.ReparseTag);
    }

    wsl_file.ea_buffer = crate::ntfs_io::read_ea_all(wsl_file.file_handle)?;
    wsl_file.writable = writable;
    return Ok(wsl_file);
}

pub enum OpenFileType {
    Normal,
    ReparsePoint,
}

extern "system" {
    fn RtlDosPathNameToNtPathName_U_WithStatus(
        DosFileName: PWSTR,
        NtFileName: *mut UNICODE_STRING,
        FilePart: *mut PWSTR,
        Reserved: *mut c_void,
    ) -> NTSTATUS;
}

pub unsafe fn open_file_inner(wsl_file: &mut WslFile, writable: bool) -> Result<OpenFileType> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut oa = OBJECT_ATTRIBUTES::default();

    oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    oa.ObjectName = &wsl_file.full_path as *const _;
    // donot use OBJ_DONT_REPARSE as it will stop at C:
    oa.Attributes = (OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP) as u32;

    let desire_access = if writable {
         // includes the required FILE_READ_EA and FILE_WRITE_EA access_mask!
        FILE_GENERIC_READ | FILE_GENERIC_WRITE
    } else {
         // includes the required FILE_READ_EA access_mask!
        FILE_GENERIC_READ
    };
    let share_access = if writable {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    let nt_status = NtOpenFile(
        &mut wsl_file.file_handle,
        desire_access.0,
        &mut oa,
        &mut isb,
        share_access.0,
        FILE_SYNCHRONOUS_IO_NONALERT.0,
    );
    if nt_status.is_err() {
        if nt_status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || nt_status == STATUS_REPARSE_POINT_ENCOUNTERED {
            let nt_status = NtOpenFile(
                &mut wsl_file.file_handle,
                desire_access.0,
                &mut oa,
                &mut isb,
                share_access.0,
                FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0
            );
            if nt_status.is_err() {
                println!("[ERROR] NtOpenFile: {:#x} , open as REPARSE_POINT", nt_status.0);
                return Err(Error::from_raw_os_error(nt_status.0));
            }
            return Ok(OpenFileType::ReparsePoint);
        } else {
            println!("[ERROR] NtOpenFile: {:#x}", nt_status.0);
            return Err(Error::from_raw_os_error(nt_status.0));
        }
    }
    return Ok(OpenFileType::Normal);
}

pub unsafe fn reopen_to_write(wsl_file: &mut WslFile) -> Result<()> {
    assert!(!wsl_file.writable);
    if !wsl_file.file_handle.is_invalid() {
        NtClose(wsl_file.file_handle);
        wsl_file.file_handle = HANDLE::default();
    }
    open_file_inner(wsl_file, true)?;
    return Ok(());
}
