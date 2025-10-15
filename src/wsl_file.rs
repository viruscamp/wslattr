use std::ffi::c_void;
use std::io::{Error, Result};
use std::mem::transmute;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows::core::PWSTR;
use windows::Wdk::Storage::FileSystem::{NtOpenFile, FILE_BASIC_INFORMATION, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_IO_REPARSE_TAG_NOT_HANDLED, STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING};
use windows::Win32::System::WindowsProgramming::RtlFreeUnicodeString;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Wdk::Foundation::{NtClose, OBJECT_ATTRIBUTES};

use windows::Win32::Foundation::{OBJ_CASE_INSENSITIVE, OBJ_IGNORE_IMPERSONATED_DEVICEMAP};

use windows::Win32::Storage::FileSystem::{FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};

use crate::distro::FsType;
use crate::ntfs_io::{ToIoError, query_file_basic_infomation, read_ea_all};

pub trait WslFileAttributes<'a> {
    fn fs_type(&self) -> FsType;

    fn fmt(&self, f: &mut dyn std::io::Write, distro: Option<&crate::distro::Distro>) -> std::io::Result<()>;

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

    fn set_attr(&mut self, name: &str, value: &[u8]);
    fn rm_attr(&mut self, name: &str);

    fn save(&mut self, wsl_file: &mut WslFile) -> std::io::Result<()> ;
}

#[derive(Default)]
pub struct WslFile {
    pub full_path: UNICODE_STRING,

    pub file_handle: HANDLE,
    pub writable: bool,

    pub reparse_tag: Option<u32>,

    pub basic_file_info: Option<FILE_BASIC_INFORMATION>,
}

impl WslFile {
    pub fn close(&mut self) {
        if !self.file_handle.is_invalid() {
            let nt_status = unsafe { NtClose(self.file_handle) };
            if nt_status.is_err() {
                println!("[ERROR] NtClose: {:#x}", nt_status.0);
            }
            self.file_handle = HANDLE::default();
        }
    }

    pub fn reopen_to_write(&mut self) -> Result<()> {
        assert!(!self.writable);
        self.close();
        unsafe { open_file_inner(self, true)? };
        return Ok(());
    }

    pub fn read_ea(&self) -> Result<Option<Vec<u8>>> {
        unsafe { read_ea_all(self.file_handle) }
    }
}

impl<'a> Drop for WslFile {
    fn drop(&mut self) {
        unsafe {
            if !self.full_path.Buffer.is_null() {
                RtlFreeUnicodeString(&mut self.full_path as *mut _);
            }
            self.close();
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
        return Err(nt_status.to_io_error());
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

    wsl_file.basic_file_info = query_file_basic_infomation(wsl_file.file_handle).ok();

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
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP;

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
                //println!("{}", error_msg_ntdll(nt_status.0 as u32).unwrap());
                return Err(nt_status.to_io_error());
            }
            return Ok(OpenFileType::ReparsePoint);
        } else {
            println!("[ERROR] NtOpenFile: {:#x}", nt_status.0);
            return Err(nt_status.to_io_error());
        }
    }
    return Ok(OpenFileType::Normal);
}
