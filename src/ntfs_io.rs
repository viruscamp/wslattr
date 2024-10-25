use std::mem::transmute;
use std::io::{Error, Result};

use ntapi::ntioapi::*;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::*;
use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::shared::winerror::ERROR_MORE_DATA;
use winapi::um::winioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use winapi::um::winnt::REPARSE_GUID_DATA_BUFFER;

pub unsafe fn read_ea(file_handle: HANDLE) -> Result<Option<Vec<u8>>> {
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
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
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
        FALSE, // read all ea entries to buffer
        NULL,
        0,
        transmute(NULL),
        TRUE,
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }

    return Ok(Some(buf));
}

pub unsafe fn write_ea(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtSetEaFile(
        file_handle,
        transmute(&mut isb), 
        transmute(buf.as_ptr()),
        buf.len() as ULONG,
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }
    Ok(())
}

unsafe fn read_reparse_point_inner(file_handle: HANDLE, buf: &mut Vec<u8>) -> Option<Error> {
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        transmute(buf.as_mut_ptr()),
        buf.len() as DWORD,
        &mut bytes_returned,
        transmute(NULL),
    ) != 0 {
        //dbg!(buf.len(), bytes_returned);
        buf.truncate(bytes_returned as usize);
        return None;
    }
    let err = Error::last_os_error();
    //dbg!(err.raw_os_error());
    return Some(err);
}

pub unsafe fn read_reparse_point(file_handle: HANDLE) -> Result<Vec<u8>> {
    // a reasonable init buf size 64
    let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + 36;
    let mut buf = vec![0; buf_size];
    match read_reparse_point_inner(file_handle, &mut buf) {
        None => return Ok(buf),
        Some(err) => {
            match err.raw_os_error() {
                Some(os_error) if os_error == ERROR_MORE_DATA as i32 => {
                    // retry with new buf
                    let reparse_buf = buf.as_ptr() as *const REPARSE_GUID_DATA_BUFFER;
                    // larger in most case
                    let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + (*reparse_buf).ReparseDataLength as usize;
                    let mut buf = vec![0; buf_size];
                    match read_reparse_point_inner(file_handle, &mut buf) {
                        None => return Ok(buf),
                        Some(err) => {
                            println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                            return Err(err);
                        }
                    }
                },
                _ => {
                    println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                    return Err(err);
                }
            }
        },
    }
}

pub unsafe fn write_reparse_point(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_SET_REPARSE_POINT,
        transmute(buf.as_ptr()),
        buf.len() as DWORD,
        NULL,
        0,
        &mut bytes_returned,
        transmute(NULL),
    ) != 0 {
        return Ok(());
    }
    let err = Error::last_os_error();
    //dbg!(err.raw_os_error());
    return Err(err);
}

pub unsafe fn read_file_info(file_handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
    if GetFileInformationByHandle(file_handle, &mut file_info as *mut _) == 0 {
        println!("[ERROR] GetFileInformationByHandle");
        return Err(Error::last_os_error());
    }
    return Ok(file_info);
}
