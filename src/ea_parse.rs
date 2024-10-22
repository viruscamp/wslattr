use std::{borrow::Cow, mem::transmute, ptr::slice_from_raw_parts};

use ntapi::ntioapi::FILE_FULL_EA_INFORMATION;
use winapi::shared::ntdef::*;

use crate::vec_ex::VecPushGetMut;

pub struct EaParsed<'a> {
    entries: Vec<EaEntry<'a>>,
    changed: bool,
}

impl<'a, 'b> IntoIterator for &'b EaParsed<'a> {
    type Item = &'b EaEntry<'a>;
    type IntoIter = std::slice::Iter<'b, EaEntry<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<'a> Default for EaParsed<'a> {
    fn default() -> Self {
        EaParsed {
            entries: vec![],
            changed: false,
        }
    }
}

impl<'a> EaParsed<'a> {
    pub fn set_ea_raw(&mut self, name: &str, value: Vec<u8>) -> &mut Vec<u8> {
        let e = self.entries.find_or_push(
            |e| e.name == name, 
            || EaEntry {
                flags: 0,
                name: Cow::Owned(name.to_string()),
                value: Cow::Owned(vec![]),
            }
        );
        e.set_ea_raw(value);
        self.changed = true;
        return e.value.to_mut();
    }

    pub fn set_ea<T: Sized>(&mut self, name: &str, value: &T) -> &mut T {
        let data = slice_from_raw_parts(value as *const _ as *const u8, size_of_val(value));
        let data = unsafe { &*data };
        let vec = self.set_ea_raw(name, data.to_vec());
        unsafe { &mut *(vec.as_mut_ptr() as *mut T) }
    }

    pub fn get_ea_raw(&'a self, name: &str) -> Option<impl AsRef<[u8]> + 'a> {
        for e in &self.entries {
            if e.name == name {
                return Some(&e.value);
            }
        }
        None
    }

    pub fn get_ea<T: Sized>(&self, name: &str) -> Option<&T> {
        for e in &self.entries {
            if e.name == name {
                return Some(e.get_ea());
            }
        }
        None
    }

    pub fn get_ea_mut<T: Sized>(&mut self, name: &str) -> Option<&mut T> {
        for e in &mut self.entries {
            if e.name == name {
                return Some(e.get_ea_mut());
            }
        }
        None
    }

    pub fn to_buf(&self) -> Vec<u8> {
        todo!()
    }
}

pub struct EaEntry<'a> {
    #[allow(dead_code)]
    pub flags: UCHAR,
    /// ASCII only
    pub name: Cow<'a, str>,
    pub value: Cow<'a, [u8]>,
}

impl<'a> EaEntry<'a> {    
    pub fn get_ea<T: Sized>(&self) -> &T {
        assert!(self.value.len() >= size_of::<T>());
        let data = self.value.as_ptr() as *const T;
        let data = unsafe { &* data };
        data
    }

    fn get_ea_mut<T: Sized>(&mut self) -> &mut T {
        assert!(self.value.len() >= size_of::<T>());
        let data = self.value.to_mut().as_mut_ptr() as *mut T;
        let data = unsafe { &mut *data };
        data
    }

    fn set_ea_raw(&mut self, value: Vec<u8>) {
        self.value = Cow::Owned(value);
    }

    fn set_ea<T: Sized>(&mut self, value: &T) {
        let data = slice_from_raw_parts(value as *const _ as *const u8, size_of_val(value));
        let data = unsafe { &*data };
        self.set_ea_raw(data.to_vec());
    }
}

/// 12, packed size, could not be used
#[allow(dead_code)] 
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

pub unsafe fn parse_ea(buf: &[u8]) -> EaParsed {
    let mut entries = vec![];

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

        entries.push(EaEntry {
            flags: pea.Flags,
            name: String::from_utf8_lossy(name), // should be ASCII
            value: value.into(),
        });

        if pea.NextEntryOffset == 0 {
            break;
        }
        ea_ptr = ea_ptr.add(pea.NextEntryOffset as usize);
    }
    
    EaParsed{
        entries,
        changed: false,
    }
}
