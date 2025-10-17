use std::ffi::c_void;
use std::mem::{offset_of, transmute};
use std::io::{Error, Result};
use std::ptr::{addr_of, null_mut};

use windows::core::{HRESULT, PCSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_MORE_DATA, HANDLE, HLOCAL, LocalFree, MAX_PATH, NTSTATUS, WIN32_ERROR};
use windows::Wdk::Storage::FileSystem::{FileBasicInformation, FileEaInformation, NtQueryEaFile, NtQueryInformationFile, NtSetEaFile, FILE_BASIC_INFORMATION, FILE_EA_INFORMATION, REPARSE_DATA_BUFFER};
use windows::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, REPARSE_GUID_DATA_BUFFER};
use windows::Win32::System::Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use windows::Win32::Foundation::GetLastError;
use windows::core::Free;

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
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status.0);
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
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status.0);
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
        println!("[ERROR] NtSetEaFile: {:#x}", nt_status.0);
        return Err(nt_status.to_io_error());
    }
    Ok(())
}

unsafe fn read_reparse_point_inner(file_handle: HANDLE, out_buf: &mut Vec<u8>) -> windows::core::Result<u32> {
    let mut bytes_returned = 0;
    match DeviceIoControl(
        file_handle,
        FSCTL_GET_REPARSE_POINT,
        None,
        0,
        Some(out_buf.as_mut_ptr() as *mut c_void),
        out_buf.len() as u32,
        Some(&mut bytes_returned),
        None,
    ) {
        Ok(()) => {
            out_buf.truncate(bytes_returned as usize);
            return Ok(bytes_returned);
        },
        Err(err) => Err(err),
    }
}

pub unsafe fn read_reparse_point(file_handle: HANDLE) -> Result<Vec<u8>> {
    // a reasonable init buf size 64
    const BUF_SIZE_INIT: usize = 64;
    const _: () = assert!(BUF_SIZE_INIT >= size_of::<REPARSE_DATA_BUFFER>());

    let buf_size = BUF_SIZE_INIT;
    let mut buf = vec![0; buf_size];
    match read_reparse_point_inner(file_handle, &mut buf) {
        Ok(bytes_returned) => return Ok(buf),
        Err(err) if err.code() == ERROR_MORE_DATA.to_hresult()  => {
            // retry with new buf
            let reparse_buf = buf.as_ptr() as *const REPARSE_GUID_DATA_BUFFER;
            // larger than need in most case
            let reparse_data_len = (*reparse_buf).ReparseDataLength as usize;
            let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + reparse_data_len;
            //let buf_size = offset_of!(REPARSE_GUID_DATA_BUFFER, ReparseGuid) + reparse_data_len; // actual
            let mut buf = vec![0; buf_size];
            match read_reparse_point_inner(file_handle, &mut buf) {
                Ok(bytes_returned) => return Ok(buf),
                Err(err) => {
                    println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                    return Err(err.into());
                }
            }
        },
        Err(err) => {
            println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
            return Err(err.into());
        },
    }
}

pub unsafe fn write_reparse_point(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    return DeviceIoControl(
        file_handle,
        FSCTL_SET_REPARSE_POINT,
        Some(buf.as_ptr() as *const c_void),
        buf.len() as u32,
        None,
        0,
        Some(&mut bytes_returned),
        None,
    ).map_err(|e| e.into());
}

pub unsafe fn delete_reparse_point(file_handle: HANDLE, tag: u32) -> Result<()> {
    let mut buf = REPARSE_DATA_BUFFER::default();
    buf.ReparseTag = tag;
    buf.ReparseDataLength = 0;
    let mut bytes_returned: u32 = 0;
    return DeviceIoControl(
        file_handle,
        FSCTL_DELETE_REPARSE_POINT,
        Some(addr_of!(buf) as *const c_void),
        offset_of!(REPARSE_DATA_BUFFER, Anonymous) as u32,
        None,
        0,
        Some(&mut bytes_returned),
        None,
    ).map_err(|e| e.into());
}

pub unsafe fn read_data(file_handle: HANDLE) -> Result<Vec<u8>> {
    let mut read_size: u32 = 0;
    let mut buf = vec![0u8; MAX_PATH as usize];
    if let Err(err) = ReadFile(
        file_handle,
        Some(buf.as_mut()),
        Some(&mut read_size),
        None,
    ) {
        println!("[ERROR] ReadFile: {}, Cannot read symlink from file content\n", &err);
        return Err(err.into());
    }
    buf.truncate(read_size as usize);
    return Ok(buf);
}

pub unsafe fn write_data(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut write_size: u32 = 0;
    if let Err(err) = WriteFile(
        file_handle,
        Some(buf),
        Some(&mut write_size),
        None,        
    ) {
        println!("[ERROR] WriteFile: {}, Cannot write symlink from file content\n", &err);
        return Err(err.into());
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
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status.0);
        return Err(nt_status.to_io_error());
    }
    Ok(fbi)
}
