use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    // Buffer to read incoming data
    let mut buffer = [0; 1024];
    
    // Read data from the client
    let bytes_read = stream.read(&mut buffer)?;
    
    // Convert the data to a string
    let received_message = String::from_utf8_lossy(&buffer[..bytes_read]);
    
    // Print the received message
    println!("Received message from client: {}", received_message);
    
    // Echo the message back to the client
    stream.write_all(&buffer[..bytes_read])?;
    
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Bind the server to the localhost address and port 8080
    // for windows
    //let listener = TcpListener::bind("::1:8080")?;
    // for unix like
    let listener = TcpListener::bind("0.0.0.0:8080")?;
    
    // Print a message indicating the server is running
    println!("Server is running and listening on port 8080...");
    
    // Accept incoming connections and handle them in separate threads
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Spawn a new thread to handle each client
                thread::spawn(move || {
                    // Handle the client connection
                    if let Err(err) = handle_client(stream) {
                        eprintln!("Error handling client: {}", err);
                    }
                });
            }
            Err(err) => {
                eprintln!("Error accepting connection: {}", err);
            }
        }
    }
    
    Ok(())
}
