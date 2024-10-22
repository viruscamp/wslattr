use std::io::{Error, Result};
use std::mem::transmute;
use std::path::Path;

use ntapi::ntioapi::*;
use ntapi::ntobapi::NtClose;
use ntapi::ntrtl::{RtlDosPathNameToNtPathName_U_WithStatus, RtlFreeUnicodeString};
use ntapi::winapi::um::winbase::GetFileInformationByHandleEx;
use ntapi::winapi::um::winnt::*;
use ntapi::winapi::shared::ntdef::*;
use ntapi::winapi::shared::ntstatus::*;
use ntapi::winapi::um::fileapi::*;
use ntapi::winapi::shared::minwindef::DWORD;
use utfx::U16CString;

pub type HANDLE = *mut ntapi::winapi::ctypes::c_void;

pub struct WslFile {
    pub file_name: UNICODE_STRING,
    pub file_handle: HANDLE,
    pub isb: IO_STATUS_BLOCK,
    pub oa: OBJECT_ATTRIBUTES,

    pub ea_buffer: Vec<u8>,
    pub reparse_tag_raw: Option<DWORD>,
}

impl Default for WslFile {
    fn default() -> Self {
        Self {
            file_name: Default::default(),
            file_handle: NULL,
            isb: Default::default(),
            oa: Default::default(),
            ea_buffer: Default::default(),
            reparse_tag_raw: None,
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
            wsl_file.reparse_tag_raw = Some(file_attribute_tag_info.ReparseTag);
        } else {
            println!("[ERROR] NtOpenFile: {:#x}", nt_status);
            return Err(Error::from_raw_os_error(nt_status));
        }
    }
    wsl_file.ea_buffer = crate::ea_io::read_ea(wsl_file.file_handle)?;
    return Ok(wsl_file);
}