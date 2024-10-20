use std::{mem::transmute, ptr::slice_from_raw_parts};

use ntapi::ntioapi::FILE_FULL_EA_INFORMATION;
use winapi::shared::ntdef::*;

pub struct EaParsed(pub Vec<EaEntry>);

pub struct EaEntry {
    pub flags: UCHAR,
    /// ASCII only
    pub name: String,
    pub value: Vec<u8>,
}

/// 12, packed size, could not be used
const EA_BASE_SIZE_ALIGNED: usize = size_of::<FILE_FULL_EA_INFORMATION>();
/// 9, use this
const EA_BASE_SIZE_RAW: usize = size_of::<ULONG>() + size_of::<UCHAR>() + size_of::<UCHAR>() + size_of::<USHORT>() + size_of::<UCHAR>();
const EA_ALIGN: usize = size_of::<ULONG>();

fn ea_entry_size(pea: &FILE_FULL_EA_INFORMATION) -> usize {
    ea_entry_size_inner(pea.EaNameLength, pea.EaValueLength)
}

fn ea_entry_size_inner(name_len: UCHAR, value_len: USHORT) -> usize {
    let data_len = EA_BASE_SIZE_RAW + name_len as usize + value_len as usize;
    let full_len = (data_len + 1) / EA_ALIGN * EA_ALIGN;
    return full_len;
}

pub unsafe fn parse_ea(buf: &[u8]) -> Option<EaParsed> {
    let mut ea_entries = vec![];

    let buf_range = buf.as_ptr_range();
    let mut ea_ptr = buf.as_ptr();
    
    loop {
        let pea: &FILE_FULL_EA_INFORMATION = transmute(ea_ptr);

        let pea_end = ea_ptr.add(ea_entry_size(pea));

        // invalid ea data may cause read overflow
        assert!(pea_end <= buf_range.end);        

        let pname = &pea.EaName as *const i8 as *const u8;
        let name = &*slice_from_raw_parts(pname, pea.EaNameLength as usize);

        let pvalue =  pname.add(pea.EaNameLength as usize + 1);
        let value = &*slice_from_raw_parts(pvalue, pea.EaValueLength as usize);

        ea_entries.push(EaEntry {
            flags: pea.Flags,
            name: String::from_utf8_lossy(name).into_owned(), // should be ASCII
            value: value.into(),
        });

        if pea.NextEntryOffset == 0 {
            break;
        }
        ea_ptr = ea_ptr.add(pea.NextEntryOffset as usize);
    }
    
    Some(EaParsed(ea_entries))
}
