use std::ffi::c_void;

use windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
pub type PVOID = *mut c_void;

pub type NtSetInformationProcess = unsafe extern "system" fn(HANDLE, u32, PVOID, u32) -> i32;
pub type NtQueryVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, u32, PVOID, u32, *mut u32) -> i32;

pub type LoadLibraryA = unsafe extern "system" fn(*mut u8) -> usize;

extern "C" {
    pub fn medium();
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct HANDLE {
    pub id: isize,
}

pub type ULONG = u32;

#[repr(C)]
pub struct ProcessInstrumentationCallbackInformation {
    pub version: ULONG,
    pub reserved: ULONG,
    pub callback: PVOID,
}

#[allow(non_camel_case_types)]
pub type PMEMORY_BASIC_INFORMATION = *mut MEMORY_BASIC_INFORMATION;
pub type PCSTR = *const u8;
