use std::ffi::c_void;
use std::mem::{offset_of, transmute};
use std::io::{Error, Result};
use std::ptr::{addr_of, null_mut};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::core::{HRESULT, PCSTR, PWSTR};
use windows::Win32::Foundation::{STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW, ERROR_MORE_DATA, HANDLE, HLOCAL, MAX_PATH, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, STATUS_IO_REPARSE_TAG_NOT_HANDLED, STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING, WIN32_ERROR};
use windows::Wdk::Storage::FileSystem::{
    NtOpenFile, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    NtQueryInformationFile, FILE_BASIC_INFORMATION, FILE_STANDARD_INFORMATION, FileBasicInformation, FileStandardInformation,
    NtQueryEaFile, FILE_EA_INFORMATION, FileEaInformation,
    NtSetEaFile,
    NtReadFile,
    NtWriteFile,
    NtFsControlFile, REPARSE_DATA_BUFFER,
};
use windows::Win32::System::IO::{IO_STATUS_BLOCK};
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, REPARSE_GUID_DATA_BUFFER};
use windows::Win32::System::Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};

pub trait ToIoError {
    fn to_io_error(self) -> std::io::Error;
}
impl ToIoError for HRESULT {
    fn to_io_error(self) -> std::io::Error {
        Into::<windows::core::Error>::into(self).into()
    }
}
impl ToIoError for NTSTATUS {
    fn to_io_error(self) -> std::io::Error {
        Into::<windows::core::Error>::into(self).into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFileType {
    Normal,
    ReparsePoint,
}

pub unsafe fn open_file(file_path: &UNICODE_STRING, writable: bool) -> Result<(HANDLE, OpenFileType)> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut oa = OBJECT_ATTRIBUTES::default();

    oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    oa.ObjectName = file_path as *const _;
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
    let mut file_handle = HANDLE::default();
    let nt_status = NtOpenFile(
        &mut file_handle,
        desire_access.0,
        &mut oa,
        &mut isb,
        share_access.0,
        FILE_SYNCHRONOUS_IO_NONALERT.0,
    );
    if nt_status.is_err() {
        if nt_status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || nt_status == STATUS_REPARSE_POINT_ENCOUNTERED {
            let nt_status = NtOpenFile(
                &mut file_handle,
                desire_access.0,
                &mut oa,
                &mut isb,
                share_access.0,
                FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0
            );
            if nt_status.is_err() {
                
                println!("[ERROR] NtOpenFile: {:#x} {}, open as REPARSE_POINT", nt_status.0, nt_status.to_hresult().message());
                //println!("{}", error_msg_ntdll(nt_status.0 as u32).unwrap());
                return Err(nt_status.to_io_error());
            }
            return Ok((file_handle, OpenFileType::ReparsePoint));
        } else {
            println!("[ERROR] NtOpenFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
            return Err(nt_status.to_io_error());
        }
    }
    return Ok((file_handle, OpenFileType::Normal));
}

/// `NtQueryEaFile` can read known EA's, but there are 'LX.LINUX.ATTR.*', so we'd read all.
pub unsafe fn read_ea_all(file_handle: HANDLE) -> Result<Option<Vec<u8>>> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut ea_info = FILE_EA_INFORMATION::default();
  
    // Query the Extended Attribute length
    let nt_status = NtQueryInformationFile(
        file_handle,
        transmute(&mut isb),
        transmute(&mut ea_info),
        size_of::<FILE_EA_INFORMATION>() as u32,
        FileEaInformation
    );
    if nt_status.is_err() {
        println!("[ERROR] NtQueryInformationFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    if ea_info.EaSize == 0 {
        return Ok(None);
    }

    let mut buf = vec![0u8; ea_info.EaSize as usize];

    let nt_status = NtQueryEaFile(
        file_handle,
        &mut isb,
        transmute(buf.as_mut_ptr()),
        ea_info.EaSize,
        false, // read all ea entries to buffer
        None,
        0,
        None,
        true,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtQueryEaFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }

    return Ok(Some(buf));
}

/// It's safe to save only changed EA's.
pub unsafe fn write_ea(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtSetEaFile(
        file_handle,
        transmute(&mut isb),
        transmute(buf.as_ptr()),
        buf.len() as u32,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtSetEaFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    Ok(())
}

unsafe fn read_reparse_point_inner(file_handle: HANDLE, out_buf: &mut [u8]) -> (NTSTATUS, usize) {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtFsControlFile(
        file_handle,
        None, None, None,
        &mut isb as *mut _,
        FSCTL_GET_REPARSE_POINT,
        None,
        0,
        Some(out_buf.as_mut_ptr() as *mut c_void),
        out_buf.len() as u32,
    );
    return (nt_status, isb.Information);
}

pub unsafe fn read_reparse_point(file_handle: HANDLE) -> Result<Vec<u8>> {
    // a reasonable init buf size 64
    const BUF_SIZE_INIT: usize = 64;
    const _: () = assert!(BUF_SIZE_INIT >= size_of::<REPARSE_DATA_BUFFER>());
    let buf_size = BUF_SIZE_INIT;
    let mut buf = vec![0; buf_size];

    let (mut nt_status, mut bytes_returned) = read_reparse_point_inner(file_handle, &mut buf);
    if nt_status == STATUS_BUFFER_OVERFLOW {
        // retry with new buf
        let reparse_buf = buf.as_ptr() as *const REPARSE_GUID_DATA_BUFFER;
        // larger than need in most case
        let reparse_data_len = (*reparse_buf).ReparseDataLength as usize;
        let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + reparse_data_len;
        //let buf_size = offset_of!(REPARSE_GUID_DATA_BUFFER, ReparseGuid) + reparse_data_len; // actual
        buf = vec![0; buf_size];
        (nt_status, bytes_returned) = read_reparse_point_inner(file_handle, &mut buf);
    }
    if nt_status != STATUS_SUCCESS {
        println!("[ERROR] NtFsControlFile: {:#x} {}, cannot read symlink in reparse point", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    buf.truncate(bytes_returned);
    return Ok(buf);
}

pub unsafe fn write_reparse_point(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtFsControlFile(
        file_handle,
        None, None, None,
        &mut isb as *mut _,
        FSCTL_SET_REPARSE_POINT,
        Some(buf.as_ptr() as *const c_void),
        buf.len() as u32,
        None,
        0,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtFsControlFile: {:#x} {}, cannot write symlink in reparse point", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    Ok(())
}

pub unsafe fn delete_reparse_point(file_handle: HANDLE, tag: u32) -> Result<()> {
    let mut buf = REPARSE_DATA_BUFFER::default();
    buf.ReparseTag = tag;
    buf.ReparseDataLength = 0;
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtFsControlFile(
        file_handle,
        None, None, None,
        &mut isb as *mut _,
        FSCTL_DELETE_REPARSE_POINT,
        Some(addr_of!(buf) as *const c_void),
        offset_of!(REPARSE_DATA_BUFFER, Anonymous) as u32,
        None,
        0,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtFsControlFile: {:#x} {}, cannot delete symlink in reparse point", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    Ok(())
}

pub unsafe fn read_data(file_handle: HANDLE) -> Result<Vec<u8>> {
    let fsi = query_file_standard_infomation(file_handle)?;
    let filesize = fsi.EndOfFile;
    if filesize == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0; filesize as usize];
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtReadFile(
        file_handle,
        None, None, None,
        &mut isb as *mut _,
        buf.as_mut_ptr() as *mut c_void,
        buf.len() as u32,
        None, None,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtReadFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    buf.truncate(isb.Information as usize);
    return Ok(buf);
}

pub unsafe fn write_data(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtWriteFile(
        file_handle,
        None, None, None,
        &mut isb as *mut _,
        buf.as_ptr() as *const c_void,
        buf.len() as u32,
        None, None,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtWriteFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    return Ok(());
}

pub fn query_file_basic_infomation(file_handle: HANDLE) -> Result<FILE_BASIC_INFORMATION> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut fbi = FILE_BASIC_INFORMATION::default();
    let nt_status = unsafe { NtQueryInformationFile(
        file_handle,
        &mut isb,
        transmute(&mut fbi),
        size_of_val(&fbi) as u32,
        FileBasicInformation,
    ) };
    if nt_status.is_err() {
        println!("[ERROR] NtQueryInformationFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    Ok(fbi)
}

pub fn query_file_standard_infomation(file_handle: HANDLE) -> Result<FILE_STANDARD_INFORMATION> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut fsi = FILE_STANDARD_INFORMATION::default();
    let nt_status = unsafe { NtQueryInformationFile(
        file_handle,
        &mut isb,
        transmute(&mut fsi),
        size_of_val(&fsi) as u32,
        FileStandardInformation,
    ) };
    if nt_status.is_err() {
        println!("[ERROR] NtQueryInformationFile: {:#x} {}", nt_status.0, nt_status.to_hresult().message());
        return Err(nt_status.to_io_error());
    }
    Ok(fsi)
}