use crate::{
    structs,
    structs::{LoadLibraryA, HANDLE, PVOID},
};
use obfstr::obfstr;
use std::{arch::asm, ffi, mem, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{FARPROC, HINSTANCE},
    System::{
        Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64},
        Kernel::LIST_ENTRY,
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        Threading::PEB,
        WindowsProgramming::LDR_DATA_TABLE_ENTRY,
    },
};

extern crate alloc;
use alloc::string::String;

#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

pub fn get_module_base_addr(module_name: &str) -> HINSTANCE {
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        let rf_peb: *const PEB = peb_offset as *const PEB;
        let peb = *rf_peb;

        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY =
            (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let buffer = core::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2,
            );
            let dll_name = String::from_utf16_lossy(buffer);
            if dll_name.to_lowercase().starts_with(module_name) {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return module_base;
            }
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                return core::ptr::null_mut();
            }
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

pub fn get_proc_addr(module_handle: HINSTANCE, function_name: &str) -> FARPROC {
    let mut address_array: u64;
    let mut name_array: u64;
    let mut name_ordinals: u64;
    let nt_headers: *const IMAGE_NT_HEADERS64;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let dos_headers: *const IMAGE_DOS_HEADER;
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        nt_headers =
            (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        data_directory =
            (&(*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64)
            as *const IMAGE_EXPORT_DIRECTORY;
        address_array =
            module_handle as u64 + (*export_directory).AddressOfFunctions as u64;
        name_array = module_handle as u64 + (*export_directory).AddressOfNames as u64;
        name_ordinals =
            module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64;
        loop {
            let name_offest: u32 = *(name_array as *const u32);
            let current_function_name =
                ffi::CStr::from_ptr((module_handle as u64 + name_offest as u64) as *const i8)
                    .to_str()
                    .unwrap();
            if current_function_name == function_name {
                address_array += *(name_ordinals as *const u16) as u64 * (mem::size_of::<u32>() as u64);
                let fun_addr: FARPROC =
                    mem::transmute(module_handle as u64 + *(address_array as *const u32) as u64);
                return fun_addr;
            }
            name_array += mem::size_of::<u32>() as u64;
            name_ordinals += mem::size_of::<u16>() as u64;
        }
    }
}

// https://github.com/Kudaes/DInvoke_rs

#[macro_export]
macro_rules! dynamic_invoke {
    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = get_proc_addr($a, $b);
        if function_ptr.is_some()
        {
            $c = std::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else {
            $d = None;
        }

    };
}

/// Dynamically calls LoadLibraryA.
///
/// It will return either the module's base address or 0.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a("ntdll.dll");
///
/// if ret != 0 { utils::println!("ntdll.dll base address is 0x{:X}.", addr) };
/// ```
pub fn load_library_a(module: &str) -> usize {
    unsafe {
        let ret: Option<usize>;
        let func_ptr: LoadLibraryA;
        let name = alloc::ffi::CString::new(String::from(module)).expect("");
        let module_name: *mut u8 = core::mem::transmute(name.as_ptr());
        let k32 = get_module_base_addr(obfstr!("kernel32.dll"));
        dynamic_invoke!(k32, &obfstr!("LoadLibraryA"), func_ptr, ret, module_name);

        ret.unwrap_or_default()
    }
}

pub fn nt_query_virtual_memory(
    handle: HANDLE,
    base_address: PVOID,
    memory_information_class: u32,
    memory_information: PVOID,
    memory_information_length: usize,
    return_length: *mut usize,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtQueryVirtualMemory;
        let ntdll = get_module_base_addr(obfstr!("ntdll.dll"));

        dynamic_invoke!(
            ntdll,
            &obfstr!("NtQueryVirtualMemory"),
            func_ptr,
            ret,
            handle,
            base_address,
            memory_information_class,
            memory_information,
            memory_information_length.try_into().unwrap(),
            null_mut()
        );
        ret.unwrap_or(-1)
    }
}

pub fn nt_set_information_process(
    handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: u32,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtSetInformationProcess;
        let ntdll = get_module_base_addr(obfstr!("ntdll.dll"));

        dynamic_invoke!(
            ntdll,
            &obfstr!("NtSetInformationProcess"),
            func_ptr,
            ret,
            handle,
            process_information_class,
            process_information,
            process_information_length
        );
        ret.unwrap_or(-1)
    }
}
