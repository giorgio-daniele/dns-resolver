mod buffer;
mod contact;
mod dns;
mod resolver;
mod types;

use resolver::resolve;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc};
use tokio::{net::UdpSocket};
use types::{AnswerRecord, Dns, DnsError, DnsReadBuffer, Flags, RData};

const ROOT_SERVER: &str = "198.41.0.4";
const MAX_DEPTH: usize = 20;

#[tokio::main]
async fn main() -> Result<(), DnsError> {

    // Generate a new UDP socket for listening incoming packets
    // from clients
    let sock = Arc::new(
        UdpSocket::bind("127.0.0.1:53")
            .await
            .map_err(|_| DnsError::SocketError)?,
    );

    let mut buf = [0u8; 4096];

    loop {

        // Read incoming packet from the socket.
        let (length, addr) = sock
            .recv_from(&mut buf)
            .await
            .map_err(|_| DnsError::SocketError)?;

        let sock_clone = Arc::clone(&sock);

        let data = buf[..length].to_vec();

        // Use an asyncio task, offloading the logic for resolving the IP
        // address of the requested domain
        tokio::spawn(async move {
            match async {
                let mut dns = Dns::decode(&mut DnsReadBuffer::new(&data))?;
                process(sock_clone, addr, &mut dns).await
            }.await {
                Ok(_) => (),
                Err(e) => eprintln!("DNS request processing error: {:?}", e),
            }
        });
    }
}

async fn process(
    sock:   Arc<UdpSocket>,
    addr:   SocketAddr,
    req:    & mut Dns,
) -> Result<(), DnsError> {

    // Get the first question from the DNS packet from the client
    let qrc = req
        .questions
        .first()
        .cloned()
        .ok_or_else(|| DnsError::IOError("no questions found".into()))?;

    let (ipv4_addresses, 
         ipv6_addresses, 
         cnonical_names) = resolve(&qrc.qname, ROOT_SERVER, MAX_DEPTH).await?;

    println!("IPv4 addresses={:?}", ipv4_addresses);
    println!("IPv6 addresses={:?}", ipv6_addresses);
    println!("Server Names={:?}",   cnonical_names);

    req.header.flags = Flags {
        qr:    true,  // This is a response
        opcode: 0,    // Standard query
        aa:    true,  // Authoritative answer
        tc:    false, // Not truncated
        rd:    true,  // Recursion desired
        ra:    true,  // Recursion available
        z:     0,     // Reserved
        rcode: 0,     // No error
    };

    // Add the answers
    for ip in ipv4_addresses {
        req.answers.push(AnswerRecord::new(qrc.qname.clone(), ip));
    }

    for ip in ipv6_addresses {
        req.answers.push(AnswerRecord::new(qrc.qname.clone(), ip));
    }

    for cname in cnonical_names {
        req.answers.push(AnswerRecord::new(qrc.qname.clone(), cname));
    }

    // Update answer count in the header
    req.header.an_count = req.answers.len() as u16;

    // Encode DNS response into binary format
    let enc = req.encode()?;

    // Send encoded DNS response to client
    sock
        .send_to(&enc.data, addr)
        .await
        .map_err(|_| DnsError::SocketError)?;

    Ok(())

}
