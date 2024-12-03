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

use crate::ea_parse::EaEntryRaw;

pub type HANDLE = winapi::shared::ntdef::HANDLE;

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

pub struct WslFile {
    pub file_name: UNICODE_STRING,
    pub file_handle: HANDLE,
    pub writable: bool,

    pub ea_buffer: Option<Vec<u8>>,
    pub reparse_tag: Option<DWORD>,
}

impl Default for WslFile {
    fn default() -> Self {
        Self {
            file_name: Default::default(),
            file_handle: NULL,
            writable: false,
            ea_buffer: None,
            reparse_tag: None,
        }
    }
}
impl<'a> Drop for WslFile {
    fn drop(&mut self) {
        unsafe {
            if self.file_handle != NULL {
                NtClose(self.file_handle);
                self.file_handle = NULL;
            }
            if self.file_name.Buffer != transmute(NULL) {
                RtlFreeUnicodeString(&mut self.file_name);
                self.file_name = UNICODE_STRING::default();
            }
        }
    }
}

pub unsafe fn open_handle(path: &Path, writable: bool) -> Result<WslFile> {
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

    if let OpenFileType::ReparsePoint = open_file_inner(&mut wsl_file, writable)? {
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
    }

    wsl_file.ea_buffer = crate::ntfs_io::read_ea_all(wsl_file.file_handle)?;
    wsl_file.writable = writable;
    return Ok(wsl_file);
}

pub enum OpenFileType {
    Normal,
    ReparsePoint,
}

pub unsafe fn open_file_inner(wsl_file: &mut WslFile, writable: bool) -> Result<OpenFileType> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut oa = OBJECT_ATTRIBUTES::default();

    InitializeObjectAttributes(
        &mut oa,
        &mut wsl_file.file_name,
        OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP, // donot use OBJ_DONT_REPARSE as it will stop at C:
        NULL,
        NULL
    );
    let desire_access = if writable {
         // includes the required FILE_READ_EA and FILE_WRITE_EA access_mask!
        FILE_GENERIC_READ | FILE_GENERIC_WRITE
    } else {
         // includes the required FILE_READ_EA access_mask!
        FILE_GENERIC_READ
    };
    let share_acces = if writable {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    let nt_status = NtOpenFile(
        &mut wsl_file.file_handle,
        desire_access,
        &mut oa,
        &mut isb,
        share_acces,
        FILE_SYNCHRONOUS_IO_NONALERT
    );
    if ! NT_SUCCESS(nt_status) {
        if nt_status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || nt_status == STATUS_REPARSE_POINT_ENCOUNTERED {
            let nt_status = NtOpenFile(
                &mut wsl_file.file_handle,
                desire_access,
                &mut oa,
                &mut isb,
                share_acces,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
            );
            if ! NT_SUCCESS(nt_status) {
                println!("[ERROR] NtOpenFile: {:#x} , open as REPARSE_POINT", nt_status);
                return Err(Error::from_raw_os_error(nt_status));
            }
            return Ok(OpenFileType::ReparsePoint);
        } else {
            println!("[ERROR] NtOpenFile: {:#x}", nt_status);
            return Err(Error::from_raw_os_error(nt_status));
        }
    }
    return Ok(OpenFileType::Normal);
}

pub unsafe fn reopen_to_write(wsl_file: &mut WslFile) -> Result<()> {
    assert!(!wsl_file.writable);
    if wsl_file.file_handle != NULL {
        NtClose(wsl_file.file_handle);
        wsl_file.file_handle = NULL;
    }
    open_file_inner(wsl_file, true)?;
    return Ok(());
}
