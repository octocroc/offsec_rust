#![windows_subsystem = "windows"]

extern crate libloading;

use libloading::{Library, Symbol};

fn main() {
    // Load the dynamic library
    let lib = Library::new("msgbox_dll.dll").expect("Failed to load DLL");
    unsafe {
        let add_fn: Symbol<unsafe extern "C" fn()>= lib.get(b"popit").expect("Failed to load symbol");
        add_fn();
    }
}