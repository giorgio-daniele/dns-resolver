use crate::types::DnsError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn contact<'a>(
    dns:     &[u8],           // The packet to be sent
    address: &str,            // The remote server address
    buffer:  &'a mut [u8],    // The buffer where store the result
) -> Result<&'a [u8], DnsError> {

    // Parse the address into a SocketAddr
    let addr: SocketAddr = address.parse().map_err(|_| DnsError::SocketError)?;

    // Create a socket binding on a random available local port
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| DnsError::SocketError)?;

    // Send the message
    sock.send_to(dns, &addr)
        .await
        .map_err(|_| DnsError::IOError("can't send DNS packet".into()))?;

    // Read the message
    let (size, _) = sock
        .recv_from(buffer)
        .await
        .map_err(|_| DnsError::IOError("can't read DNS packet".into()))?;

    // Return the portion of the buffer that contains the DNS response
    Ok(&buffer[..size])
}
