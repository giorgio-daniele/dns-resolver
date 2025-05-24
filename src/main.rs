mod buffer;
mod contact;
mod dns;
mod resolver;
mod types;

use resolver::resolve;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::Mutex};
use types::{Dns, DnsError, DnsReadBuffer};

const ROOT_SERVER: &str = "198.41.0.4";
const MAX_DEPTH: usize = 20;

#[tokio::main]
async fn main() -> Result<(), DnsError> {
    let socket = Arc::new(Mutex::new(
        UdpSocket::bind("127.0.0.1:53")
            .await
            .map_err(|_| DnsError::SocketError)?,
    ));

    println!("DNS server listening on 127.0.0.1:53");
    let mut buf = [0u8; 4096];

    loop {
        let (len, client) = socket
            .lock()
            .await
            .recv_from(&mut buf)
            .await
            .map_err(|_| DnsError::SocketError)?;


        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Err(e) = handle_request(socket, client,  buf[..len].to_vec()).await {
                eprintln!("Error handling request from {}: {:?}", client, e);
            }
        });
    }
}

async fn handle_request(
    socket: Arc<Mutex<UdpSocket>>,
    client: SocketAddr,
    buffer: Vec<u8>,
) -> Result<(), DnsError> {


    /*
     * 
     * 
     * Decode the DNS request from the buffer, then extract the first
     * question from it (if it exists)
     * 
     * 
     */

    let mut dns = Dns::decode(&mut DnsReadBuffer::new(&buffer))?;
    let qrc = dns
        .questions
        .first()
        .cloned() // Clone the QueryRecord to avoid borrowing dns
        .ok_or_else(|| DnsError::IOError("no questions".into()))?;
    /*
     * 
     * Get the answers associated to the question and then add to the original
     * request the list of the responses
     * 
     */
    
    let answers = resolve(&qrc.qname, ROOT_SERVER, MAX_DEPTH).await?;
    dns.add_answers(&qrc, answers);

    let enc = dns.encode()?;

    // Send the response
    socket
        .lock()
        .await
        .send_to(&enc.data, client)
        .await
        .map_err(|_| DnsError::SocketError)?;

    Ok(())

}
