use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    // Connect to the server
    let mut stream = TcpStream::connect("192.168.0.3:8080")?;
    
    // Message to send
    let message = "Hello, server!";
    
    // Send the message
    stream.write_all(message.as_bytes())?;
    
    // Read the response
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    // Print the response
    println!("Response from server: {}", response);
    
    Ok(())
}
