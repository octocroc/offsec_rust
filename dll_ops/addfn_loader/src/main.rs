extern crate libloading;

use libloading::{Library, Symbol};

fn main() {
    // Load the dynamic library
    let lib = Library::new("addfn_dll.dll").expect("Failed to load DLL");

    unsafe {
        // Load the symbol for the 'add' function
        let add_fn: Symbol<unsafe extern "C" fn(i32, i32) -> i32> = lib.get(b"add").expect("Failed to load symbol");

        // Call the 'add' function
        let result = add_fn(3, 5);
        println!("Result of adding from Rust DLL: {}", result);
    }
}