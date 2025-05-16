use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::dns::{Buffer, Dns, DnsError};

pub async fn proc(dns: Dns, addr: SocketAddr) -> Result<(), DnsError> {
    // Make the request mutable
    let mut dns = dns;

    // Set RD (Recursion Desired) to false
    dns.header.flags.rd = false;

    // Add EDNS0 OPT record to support larger UDP payloads
    dns.add_opt_record(4096);

    // Generate a socket and send data
    let data = dns.encode().data;

    // Generate the socket
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| 
            DnsError::SocketError)?;

    // Send the data to one roo
    sock.send_to(&data, "198.41.0.4:53")
        .await
        .map_err(|_| 
            DnsError::IOError(
                String::from("can't send dns packet to root")))?;

    let mut buf = [0u8; 4096];
    // Read from the socket
    let (size, _) = sock.recv_from(&mut buf)
        .await
        .map_err(|_| 
            DnsError::IOError(
                String::from("can't read dns packet from root")))?;

    /*
     * Once the DNS resolver has received the reply from the root server,
     * the DNS packet should contain in Authoritative section the list of
     * name servers - the final holder of the IP of the domain the client
     * is looking for. Usually, there are no answers
     */

    let dns = Dns::decode(&mut Buffer::new(buf[..size].to_vec()))?;

    for item in dns.authorities {
        println!("NAME={} CLASS={} TYPE={}", item.aname, item.aclass, item.atype)
    }

    // // You can then decode or process the response here if needed
    // println!("{:#?}", Dns::decode(&mut Buffer::new(buf.to_vec())));


    Ok(())
}
