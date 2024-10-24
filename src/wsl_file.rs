use std::io::{Error, Result};
use std::mem::transmute;
use std::path::Path;

use ntapi::ntioapi::*;
use ntapi::ntobapi::NtClose;
use ntapi::ntrtl::{RtlDosPathNameToNtPathName_U_WithStatus, RtlFreeUnicodeString};
use winapi::um::winbase::GetFileInformationByHandleEx;
use winapi::um::winnt::*;
use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::um::fileapi::*;
use winapi::shared::minwindef::DWORD;
use utfx::U16CString;

use crate::ea_parse::EaParsed;

pub type HANDLE = winapi::shared::ntdef::HANDLE;

pub trait WslFileAttributes<'a> : Sized {
    fn try_load(wsl_file: &'a WslFile, ea_parsed: &'a EaParsed) -> Result<Self>;

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

pub struct WslFile {
    pub file_name: UNICODE_STRING,
    pub file_handle: HANDLE,
    pub isb: IO_STATUS_BLOCK,
    pub oa: OBJECT_ATTRIBUTES,

    pub ea_buffer: Option<Vec<u8>>,
    pub reparse_tag: Option<DWORD>,
}

impl Default for WslFile {
    fn default() -> Self {
        Self {
            file_name: Default::default(),
            file_handle: NULL,
            isb: Default::default(),
            oa: Default::default(),
            ea_buffer: Default::default(),
            reparse_tag: None,
        }
    }
}
impl<'a> Drop for WslFile {
    fn drop(&mut self) {
        unsafe {
            if self.file_handle != NULL {
                NtClose(self.file_handle);
            }
            if self.file_name.Buffer != transmute(NULL) {
                RtlFreeUnicodeString(&mut self.file_name);
            }
        }
    }
}

pub unsafe fn open_handle(path: &Path) -> Result<WslFile> {
    let mut wsl_file = WslFile::default();

    let nt_status = RtlDosPathNameToNtPathName_U_WithStatus(
        transmute(U16CString::from_os_str_unchecked(path.as_os_str()).as_ptr()),
        &mut wsl_file.file_name,
        transmute(NULL),
        transmute(NULL),
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] RtlDosPathNameToNtPathName_U_WithStatus: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }

    InitializeObjectAttributes(
        &mut wsl_file.oa,
        &mut wsl_file.file_name,
        OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP, // donot use OBJ_DONT_REPARSE as it will stop at C:
        NULL,
        NULL
    );

    let nt_status = NtOpenFile(
        &mut wsl_file.file_handle,
        FILE_GENERIC_READ, // includes the required FILE_READ_EA access_mask!
        &mut wsl_file.oa,
        &mut wsl_file.isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    );
    if ! NT_SUCCESS(nt_status) {
        if nt_status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || nt_status == STATUS_REPARSE_POINT_ENCOUNTERED {
            // file is a REPARSE_POINT, maybe
            // IO_REPARSE_TAG_LX_SYMLINK
            // IO_REPARSE_TAG_LX_FIFO
            // IO_REPARSE_TAG_LX_CHR
            // IO_REPARSE_TAG_LX_BLK 
            // IO_REPARSE_TAG_AF_UNIX
            let nt_status = NtOpenFile(
                &mut wsl_file.file_handle,
                STANDARD_RIGHTS_READ | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA | SYNCHRONIZE, // FILE_GENERIC_READ without FILE_READ_DATA
                &mut wsl_file.oa,
                &mut wsl_file.isb,
                FILE_SHARE_READ,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
            );
            if ! NT_SUCCESS(nt_status) {
                println!("[ERROR] NtOpenFile: {:#x} , open as REPARSE_POINT", nt_status);
                return Err(Error::from_raw_os_error(nt_status));
            }
            let mut file_attribute_tag_info = FILE_ATTRIBUTE_TAG_INFO::default();
            if GetFileInformationByHandleEx(
                wsl_file.file_handle,
                ntapi::winapi::um::minwinbase::FileAttributeTagInfo,
                transmute(&mut file_attribute_tag_info),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ) == 0 {
                println!("[ERROR] GetFileInformationByHandleEx");
                return Err(Error::last_os_error());
            }
            wsl_file.reparse_tag = Some(file_attribute_tag_info.ReparseTag);
        } else {
            println!("[ERROR] NtOpenFile: {:#x}", nt_status);
            return Err(Error::from_raw_os_error(nt_status));
        }
    }
    wsl_file.ea_buffer = crate::ea_io::read_ea(wsl_file.file_handle)?;
    return Ok(wsl_file);
}

unsafe fn read_file_info(file_handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
    if GetFileInformationByHandle(file_handle, &mut file_info as *mut _) == 0 {
        println!("[ERROR] GetFileInformationByHandle");
        return Err(Error::last_os_error());
    }
    return Ok(file_info);
}
